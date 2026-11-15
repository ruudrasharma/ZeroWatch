"""
ZeroWatch - Traffic routes: labelled replay (and its event stream), what-if and evasion probes, packet-capture and
Zeek-log scoring, and the asset register with its exposure scan.

State and scoring live in app.py; this module only adds routes. `core` is the app module, so
`core.THRESHOLD` or `core.DETECTOR` always reads the current value, even after a retrain or a setting change.
"""
import json
import os
import time
from collections import deque
from typing import Literal

import numpy as np
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

import app as core
import recon
from features import SERVICES, encode
from learning import red_team

router = APIRouter()


@router.post("/counterfactual")
def counterfactual(flow: core.Flow):
    """Greedy what-if: keep resetting the most incriminating feature to its
    normal value until the flow would pass. Shows the analyst what actually
    separates this flow from benign traffic."""
    cur = flow.model_dump()
    first = core.analyse(cur, with_explanation=False, log=False)
    if first["verdict"] == "benign":
        return {"already_benign": True, "changes": [], "final_risk": first["risk_score"]}
    changes, risk, verdict = [], first["risk_score"], first["verdict"]
    for _ in range(8):
        x = encode(cur)
        p, nov = (float(v[0]) for v in core.score_matrix(np.array([x])))
        verdict, risk, _sev = core.fuse(p, nov)
        if verdict == "benign":
            break
        factors = [f for f in core.explain(cur, x, verdict, p, nov) if f["impact"] > 0]
        if not factors:
            break
        f = factors[0]
        changes.append({"feature": f["feature"], "from": f["value"], "to": f["typical"]})
        cur[f["feature"]] = f["typical"]
    else:
        x = encode(cur)
        p, nov = (float(v[0]) for v in core.score_matrix(np.array([x])))
        verdict, risk, _sev = core.fuse(p, nov)
    return {"already_benign": False, "changes": changes, "flips_to_benign": verdict == "benign",
            "start_risk": first["risk_score"], "final_risk": risk}


@router.get("/simulate")
def simulate(request: Request, n: int = 12):
    """Replays held-out KDDTest+ flows (true labels attached) through the live model."""
    if not 1 <= n <= 60:
        raise HTTPException(422, "n must be between 1 and 60")
    logged = core._may_log_demo(request)
    return {"events": core._replay(n, logged), "logged": logged}


@router.get("/simulate/stream")
def simulate_stream(request: Request, n: int = 8, ticks: int = 400, interval: float = 1.4):
    """The same replay pushed to the browser as Server-Sent Events, so the page does not poll."""
    if not (1 <= n <= 60 and 1 <= ticks <= 400 and 0 <= interval <= 10):
        raise HTTPException(422, "n must be 1-60, ticks 1-400, interval 0-10")
    logged = core._may_log_demo(request)

    def events():
        for i in range(ticks):
            yield "data: " + json.dumps({"events": core._replay(n, logged), "logged": logged}) + "\n\n"
            if i < ticks - 1:
                time.sleep(interval)

    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


@router.post("/redteam")
def redteam(flow: core.Flow):
    """Adversarial robustness: fewest attacker-controllable changes that make the flow pass."""
    return red_team(flow.model_dump(), core.META["feature_stats"], core.BASELINE, core.judge)


@router.post("/capture")
async def capture(request: Request, _: str = core.analyst):
    """Body: the raw bytes of a .pcap / .pcapng file or a Zeek conn.log (application/octet-stream), up to 5 MB."""
    data = await request.body()
    if len(data) > core.MAX_CAPTURE_BYTES:
        raise HTTPException(413, "Capture is larger than 5 MB. Trim it first, e.g. editcap -c 20000 in.pcap out.pcap")
    return core._capture_report(data, "uploaded capture", "capture")


@router.get("/capture/sample")
def capture_sample(request: Request):
    return core._capture_report((core.ROOT / "data" / "sample_capture.pcap").read_bytes(), "sample_capture.pcap (synthetic)",
                           "capture-sample", log=core._may_log_demo(request))


# ---- assets: recon fused into alert priority ----
class AssetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=40, pattern=r"^[\w .-]+$")
    url: str = Field(min_length=8, max_length=200)
    services: list[Literal[tuple(SERVICES)]] = Field(min_length=1, max_length=8)


@router.post("/assets")
def add_asset(body: AssetIn, request: Request, role: str = core.admin):
    if os.getenv("RECON_ENABLED", "1") != "1":
        raise HTTPException(503, "Asset scanning is switched off on this deployment (RECON_ENABLED=0).")
    q = core._scans.setdefault(core.client_ip(request), deque())
    now = time.time()
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= 6:  # each scan makes an outbound request, so this limit is much tighter than scoring
        raise HTTPException(429, "Scan limit reached: 6 per minute.")
    q.append(now)
    if len(core.ASSETS) >= 20 and body.name not in core.ASSETS:
        raise HTTPException(409, "Asset list is full (20). Remove one first.")
    try:
        result = recon.scan(body.url)
    except recon.ReconError as e:
        raise HTTPException(422, str(e)) from None
    core.ASSETS[body.name] = {"name": body.name, "services": body.services, **result}
    core.audit(role, "add_asset", name=body.name, url=body.url, exposure=result["exposure"])
    try:
        core.ASSET_FILE.write_text(json.dumps(core.ASSETS))
    except OSError:
        pass
    return core.ASSETS[body.name]


@router.get("/assets")
def list_assets():
    return {"assets": list(core.ASSETS.values()), "enabled": os.getenv("RECON_ENABLED", "1") == "1"}


@router.delete("/assets/{name}")
def delete_asset(name: str, role: str = core.admin):
    if core.ASSETS.pop(name, None) is None:
        raise HTTPException(404, "No asset with that name.")
    core.audit(role, "delete_asset", name=name)
    try:
        core.ASSET_FILE.write_text(json.dumps(core.ASSETS))
    except OSError:
        pass
    return {"removed": name}
