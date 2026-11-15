"""
ZeroWatch - Operations routes: drift and recent predictions, the action log, copilot, feedback, the alert queue,
the decision threshold, the alarm, sign-in status and the Overview summary.

State and scoring live in app.py; this module only adds routes. `core` is the app module, so
`core.THRESHOLD` or `core.DETECTOR` always reads the current value, even after a retrain or a setting change.
"""
import json
import os
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

import app as core
from copilot import answer as copilot_answer
from drift_check import drift_report, read_inputs
from learning import find_campaigns

router = APIRouter()


@router.get("/monitoring/drift")
def monitoring_drift(last: int = 2000):
    """Only real traffic counts (api, batch, uploaded captures); the replay and the sample capture are excluded."""
    return drift_report(read_inputs(core.LOG_FILE, max(30, min(last, 10000))), core.META["feature_stats"])


@router.get("/monitoring/recent")
def monitoring_recent(limit: int = 50):
    entries = core.read_log(300)[::-1]  # from the log, so history is there after a restart
    items = entries[:max(1, min(limit, 300))]
    counts = {}
    for e in entries:
        v = e["output"]["verdict"]
        counts[v] = counts.get(v, 0) + 1
    return {"total_in_memory": len(core.RECENT), "verdicts": counts, "items": items}


@router.get("/audit/actions")
def audit_actions(limit: int = 50, _: str = core.analyst):
    return {"items": core.AUDIT_LOG.read(max(1, min(limit, 500)))[::-1]}


# ---- copilot ----
class Question(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=3, max_length=300)


@router.post("/copilot")
def copilot(q: Question, _: str = core.analyst):
    entries = core.read_log(500)
    verdicts: dict = {}
    fam: dict = {}
    svc: dict = {}
    for e in entries:
        o = e["output"]
        verdicts[o["verdict"]] = verdicts.get(o["verdict"], 0) + 1
        if o["verdict"] == "attack":
            fam[o["attack_family"]] = fam.get(o["attack_family"], 0) + 1
            svc[e["input"]["service"]] = svc.get(e["input"]["service"], 0) + 1
    b = core.make_brief()
    context = {"flows": len(entries), "verdicts": verdicts,
               "attack_families": sorted(fam.items(), key=lambda kv: -kv[1])[:4],
               "top_services_attacked": sorted(svc.items(), key=lambda kv: -kv[1])[:4],
               "actions": b["actions"], "log_chain_valid": core.verify_logs()["valid"],
               "drift_status": drift_report(read_inputs(core.LOG_FILE, 2000), core.META["feature_stats"])["status"],
               "campaigns": len(find_campaigns(core.current_suspects(), core.NORMAL_REF)) if core.NORMAL_REF is not None else 0,
               "assets": [{"name": a["name"], "exposure": a["exposure"], "services": a["services"]} for a in core.ASSETS.values()],
               "model_version": core.model_version()}
    return copilot_answer(q.question, context)


@router.post("/feedback")
def feedback(fb: core.Feedback, role: str = core.analyst):
    """A verdict marked wrong becomes a labelled flow, so it reaches the next retrain."""
    entry = {"ts": datetime.now(UTC).isoformat(timespec="seconds"), **fb.model_dump()}
    try:
        with core._log_lock, core.FEEDBACK_FILE.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        raise HTTPException(503, "Feedback log is not writable") from None
    queued = False
    logged = core._entry(fb.request_id)
    if logged and (not fb.correct or fb.true_label):
        core._add_labels([{"input": logged["input"], "label": core._label_from_verdict(logged, fb.correct, fb.true_label),
                      "source": "feedback", "request_id": fb.request_id}])
        queued = True
    core.audit(role, "feedback", request_id=fb.request_id, correct=fb.correct, queued=queued)
    return {"stored": True, "queued_for_retraining": queued}


@router.get("/alerts")
def alerts_route(state: str = "open", limit: int = 200, _: str = core.analyst):
    return core.list_alerts(state, limit)


@router.get("/alerts/{request_id}")
def alert_detail(request_id: str, _: str = core.analyst):
    """One alert with its full flow (the list leaves flows out to stay small)."""
    logged = core._entry(request_id)
    if not logged:
        raise HTTPException(404, "No logged prediction with that request id.")
    return logged | core._alert_states().get(request_id, {"state": "new", "assignee": ""})


class AlertUpdate(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    state: Literal[core.ALERT_STATES]
    assignee: str = Field(default="", max_length=40, pattern=r"^[\w .@-]*$")


@router.patch("/alerts/{request_id}")
def update_alert(request_id: str, body: AlertUpdate, role: str = core.analyst):
    """Closing an alert is also a label: confirmed -> attack, false_positive -> benign."""
    logged = core._entry(request_id)
    if not logged:
        raise HTTPException(404, "No logged prediction with that request id.")
    states = core._alert_states()
    states[request_id] = {"state": body.state, "assignee": body.assignee}
    while len(states) > 5000:  # oldest first: the file must not grow forever
        states.pop(next(iter(states)))
    with core._log_lock:
        core.LOG_DIR.mkdir(parents=True, exist_ok=True)
        core.ALERT_FILE.write_text(json.dumps(states))
    # reopening an alert withdraws the label that closing it created
    core._remove_labels(lambda r: r.get("request_id") == request_id and r.get("source") == "triage")
    if body.state in ("confirmed", "false_positive"):
        core._add_labels([{"input": logged["input"], "label": "attack" if body.state == "confirmed" else "benign",
                      "source": "triage", "request_id": request_id}])
    core.audit(role, "triage", request_id=request_id, state=body.state, assignee=body.assignee)
    return states[request_id] | {"request_id": request_id}


# ---- settings: decision threshold ----
class ThresholdIn(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    threshold: float = Field(ge=0.05, le=0.95)


@router.post("/settings/threshold")
def set_threshold(body: ThresholdIn, role: str = core.admin):
    """Move the attack-probability cut-off. Lower catches more and raises more false alarms."""
    if body.threshold <= core.QHAT:
        raise HTTPException(422, f"Threshold must stay above the review band ({core.QHAT:.2f}).")
    old, core.THRESHOLD = core.THRESHOLD, round(body.threshold, 2)
    try:
        core.SETTINGS_FILE.write_text(json.dumps({"threshold": core.THRESHOLD}))
    except OSError:
        pass
    core.audit(role, "set_threshold", old=old, new=core.THRESHOLD)
    return {"threshold": core.THRESHOLD}


@router.get("/monitoring/alarm")
def alarm_state():
    return core.ALARM | {"webhook": bool(os.getenv("ALERT_WEBHOOK_URL")), "interval_seconds": core.ALARM_INTERVAL}


@router.post("/monitoring/alarm/test")
def alarm_test(role: str = core.admin):
    core.audit(role, "alarm_test")
    return core.check_alarm(force=True)


# ---- overview ----
@router.get("/auth/whoami")
def whoami(request: Request):
    role, user = core.identity(request)
    return {"role": role, "user": user, "open_mode": core.open_mode()}


@router.get("/overview")
def overview():
    entries = core.read_log()
    verdicts: dict = {}
    sources: dict = {}
    for e in entries:
        verdicts[e["output"]["verdict"]] = verdicts.get(e["output"]["verdict"], 0) + 1
        sources[e.get("source", "api")] = sources.get(e.get("source", "api"), 0) + 1
    queue = core.list_alerts("open", 500)
    distinct: dict = {}
    for a in queue["items"]:  # a flood is one finding, not 200 identical rows
        distinct.setdefault((a["connection"], a["verdict"]), a)
    queue["items"] = list(distinct.values())[:6]
    chain = core.verify_logs()
    minutes: dict = {}
    for e in entries:  # verdicts per minute, for the timeline chart
        m = minutes.setdefault(e["ts"][:16], dict.fromkeys(("attack", "zero_day_suspect", "uncertain", "benign"), 0))
        m[e["output"]["verdict"]] += 1
    return {"flows": len(entries), "verdicts": verdicts, "sources": sources,
            "timeline": [{"minute": k[11:], **v} for k, v in list(minutes.items())[-30:]],
            "shadow": core.SHADOW["detector"] is not None,
            "open_alerts": queue["counts"]["new"] + queue["counts"]["investigating"], "alert_counts": queue["counts"],
            "top_alerts": [{k: a[k] for k in ("request_id", "connection", "verdict", "risk_score", "priority", "state")}
                           for a in queue["items"]],
            "campaigns": len(find_campaigns(core.current_suspects(), core.NORMAL_REF)) if core.NORMAL_REF is not None else 0,
            "labelled": core._labelled_counts(),
            "drift": drift_report(read_inputs(core.LOG_FILE, 2000), core.META["feature_stats"])["status"],
            "chain": {"valid": chain["valid"], "entries": chain["entries"]},
            "model": {"version": core.model_version(), "generation": core.LEARNING["generation"], "threshold": core.THRESHOLD},
            "assets": sorted(({"name": a["name"], "exposure": a["exposure"], "grade": a["grade"]} for a in core.ASSETS.values()),
                             key=lambda a: -a["exposure"])[:4],
            "open_mode": core.open_mode()}
