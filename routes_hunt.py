"""
ZeroWatch - Hunt and learning routes: campaigns, generated rules and exports, labels, champion/challenger retraining,
shadow mode, model versions and rollback.

State and scoring live in app.py; this module only adds routes. `core` is the app module, so
`core.THRESHOLD` or `core.DETECTOR` always reads the current value, even after a retrain or a setting change.
"""
from typing import Literal

import numpy as np
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

import app as core
from features import encode
from learning import find_campaigns, retrain
from ops import incident_markdown, sigma_rule, stix_bundle

router = APIRouter()


@router.get("/campaigns")
def campaigns(_: str = core.analyst):
    if core.NORMAL_REF is None:
        raise HTTPException(503, "model/train_cache.npz is missing; run train.py")
    suspects = core.current_suspects()
    found = find_campaigns(suspects, core.NORMAL_REF)
    core.CAMPAIGNS.clear()
    core.CAMPAIGNS.update({c["id"]: c for c in found})
    done: dict = {}
    for r in core._read_labelled():
        if r.get("campaign"):
            d = done.setdefault(r["campaign"], {"id": r["campaign"], "label": r["label"], "flows": 0, "rule": r.get("rule")})
            d["flows"] += 1
    return {"suspects": len(suspects), "campaigns": [{k: v for k, v in c.items() if k != "flows"} | {
        "example": c["flows"][0]} for c in found], "labelled": core._labelled_counts(), "labelled_campaigns": list(done.values())}


class CampaignLabel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: Literal["attack", "benign"]


@router.post("/campaigns/{campaign_id}/label")
def label_campaign(campaign_id: str, body: CampaignLabel, role: str = core.analyst):
    c = core._campaign(campaign_id)
    core._add_labels([{"input": flow, "label": body.label, "campaign": campaign_id, "rule": c["signature"]["rule"]}
                 for flow in c["flows"]])
    core.audit(role, "label_campaign", campaign=campaign_id, label=body.label, flows=len(c["flows"]))
    return {"labelled": len(c["flows"]), "label": body.label, "totals": core._labelled_counts()}


@router.delete("/campaigns/{campaign_id}/label")
def unlabel_campaign(campaign_id: str, role: str = core.analyst):
    """Undo: drop this campaign's labels so its flows return to the hunt."""
    removed = core._remove_labels(lambda r: r.get("campaign") == campaign_id)
    if not removed:
        raise HTTPException(404, "No labels are stored for that campaign.")
    core.audit(role, "unlabel_campaign", campaign=campaign_id, flows=removed)
    return {"removed": removed, "totals": core._labelled_counts()}


@router.get("/campaigns/{campaign_id}/rule", response_class=PlainTextResponse)
def campaign_rule(campaign_id: str, _: str = core.analyst):
    """The generated rule in Sigma format (text/yaml)."""
    c = core._campaign(campaign_id)
    sig = c["signature"]
    return PlainTextResponse(sigma_rule(campaign_id, sig["conditions"], c["size"], sig["false_match_rate"]),
                             media_type="text/yaml",
                             headers={"content-disposition": f'attachment; filename="zerowatch-{campaign_id}.yml"'})


@router.get("/campaigns/{campaign_id}/rule/test")
def campaign_rule_test(campaign_id: str, _: str = core.analyst):
    return core._rule_test(core._campaign(campaign_id)["signature"]["conditions"])


@router.get("/campaigns/{campaign_id}/report", response_class=PlainTextResponse)
def campaign_report(campaign_id: str, _: str = core.analyst):
    """Incident report for one campaign, as Markdown."""
    c = core._campaign(campaign_id)
    fams = list(core.FAMILY.predict(np.array([encode(f) for f in c["flows"]])))
    fam = max(set(fams), key=fams.count)
    text = incident_markdown(c, core.MITRE.get(fam, []), core._rule_test(c["signature"]["conditions"]), core.model_version(),
                             core.PRED_LOG.head[:16])
    return PlainTextResponse(text, media_type="text/markdown",
                             headers={"content-disposition": f'attachment; filename="incident-{campaign_id}.md"'})


class RetrainIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["promote", "shadow"] = "promote"


@router.post("/learning/retrain")
def learning_retrain(body: RetrainIn | None = None, role: str = core.admin):
    """Champion/challenger retraining on the analyst-labelled flows. Takes about 10-20 s.
    A promoted challenger is saved to disk, so it survives a restart and can be rolled back."""
    if core.CACHE is None:
        raise HTTPException(503, "model/train_cache.npz is missing; run train.py")
    if not core._retrain_lock.acquire(blocking=False):
        raise HTTPException(409, "A retrain is already running. Wait for it to finish.")
    try:
        report = retrain(core.DETECTOR, core.META | {"threshold": core.THRESHOLD}, core.CACHE, core._read_labelled())
        new = report.pop("detector", None)
        report["mode"] = body.mode if body else "promote"
        if new is not None and report["mode"] == "shadow":
            # passed the checks, but runs beside the live model first instead of replacing it
            report["promoted"] = False
            report["reason"] = "Challenger passed the checks and is now running in shadow beside the live model."
            core._new_shadow(new, dict(report))
        elif new is not None:
            core._activate(core.REGISTRY.save(new, report))
        report["model_version"] = core.model_version()
        core.LEARNING["last_report"] = report
        core.audit(role, "retrain", mode=report["mode"], promoted=report["promoted"], labelled=report["labelled"],
              model_version=report["model_version"])
        return report
    finally:
        core._retrain_lock.release()


class Rollback(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    generation: int = Field(ge=0)


@router.post("/learning/rollback")
def learning_rollback(body: Rollback, role: str = core.admin):
    """Make an earlier model live again. Generation 0 is the model the image shipped with."""
    if core._retrain_lock.locked():
        raise HTTPException(409, "A retrain is running. Roll back after it finishes.")
    if body.generation and core.REGISTRY.load(body.generation) is None:
        raise HTTPException(404, "That model version does not exist or failed its integrity check.")
    core.REGISTRY.activate(body.generation)
    core._activate(body.generation)
    core.audit(role, "rollback", generation=body.generation)
    return {"active": body.generation, "model_version": core.model_version()}


@router.get("/learning/shadow")
def shadow_status():
    if core.SHADOW["detector"] is None:
        return {"active": False}
    return {"active": True, "since": core.SHADOW["since"], "report": core.SHADOW["report"], "stats": core.SHADOW["stats"]}


@router.post("/learning/shadow/promote")
def shadow_promote(role: str = core.admin):
    """Make the shadow challenger the live model."""
    if core.SHADOW["detector"] is None:
        raise HTTPException(404, "No challenger is running in shadow.")
    report = core.SHADOW["report"] | {"promoted": True, "shadow_stats": core.SHADOW["stats"]}
    core._activate(core.REGISTRY.save(core.SHADOW["detector"], report))
    core.SHADOW.update(detector=None, since=None, report=None, stats=None)
    core.audit(role, "shadow_promote", model_version=core.model_version())
    return {"active": core.LEARNING["generation"], "model_version": core.model_version()}


@router.delete("/learning/shadow")
def shadow_discard(role: str = core.admin):
    if core.SHADOW["detector"] is None:
        raise HTTPException(404, "No challenger is running in shadow.")
    core.SHADOW.update(detector=None, since=None, report=None, stats=None)
    core.audit(role, "shadow_discard")
    return {"active": False}


@router.get("/campaigns/{campaign_id}/stix")
def campaign_stix(campaign_id: str, _: str = core.analyst):
    """The campaign as a STIX 2.1 bundle (indicator with the Sigma rule + ATT&CK techniques)."""
    c = core._campaign(campaign_id)
    sig = c["signature"]
    fams = list(core.FAMILY.predict(np.array([encode(f) for f in c["flows"]])))
    bundle = stix_bundle(campaign_id, sig["rule"], sigma_rule(campaign_id, sig["conditions"], c["size"], sig["false_match_rate"]),
                         core.MITRE.get(max(set(fams), key=fams.count), []), c["size"])
    return JSONResponse(bundle, headers={"content-disposition": f'attachment; filename="zerowatch-{campaign_id}.stix.json"'})


@router.get("/learning/status")
def learning_status():
    st = core.REGISTRY.state()
    return {"active": core.LEARNING["generation"], "busy": core._retrain_lock.locked(), "labelled": core._labelled_counts(),
            "shadow": core.SHADOW["detector"] is not None, "auto_retrain": core.AUTO_RETRAIN,
            "model_version": core.model_version(),
            "versions": [{k: v for k, v in ver.items() if k != "file"} for ver in st["versions"]]}
