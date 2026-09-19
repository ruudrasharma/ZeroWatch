"""
ZeroWatch — Detection Runs router (Zero-Day Anomaly Engine).

Endpoints per API_SPEC.md:
  POST  /api/detection-runs
  GET   /api/detection-runs
  GET   /api/detection-runs/{id}
  WS    /api/detection-runs/{id}/stream

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from database import Alert, DetectionRun
from deps import get_db
from schemas import (
    AlertOut,
    DetectionRunCreatedResponse,
    DetectionRunDetail,
    DetectionRunRequest,
    DetectionRunWithAlerts,
    ErrorResponse,
)
from services import anomaly_engine

router = APIRouter(tags=["Anomaly Engine"])

VALID_MODELS = {"autoencoder", "isolation_forest", "random_forest"}
VALID_CATEGORIES = {"DoS", "Probe", "R2L", "U2R"}

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _build_detail(run: DetectionRun, db: Session) -> DetectionRunDetail:
    """Attach alert_count/highest_severity, aggregated from the alerts table
    (see schemas.DetectionRunDetail for why these aren't plain columns)."""
    alerts = db.query(Alert.severity).filter(Alert.detection_run_id == run.id).all()
    highest = None
    for (severity,) in alerts:
        if severity and (highest is None or _SEVERITY_RANK.get(severity, -1) > _SEVERITY_RANK.get(highest, -1)):
            highest = severity
    detail = DetectionRunDetail.model_validate(run)
    detail.alert_count = len(alerts)
    detail.highest_severity = highest
    return detail


def _build_detail_with_alerts(run: DetectionRun, db: Session) -> DetectionRunWithAlerts:
    """Like _build_detail, but also embeds the full persisted alert list (with
    parsed SHAP values) for GET /api/detection-runs/{id} — lets the frontend
    render a completed run's results from history without reconnecting to the
    WebSocket, which would re-trigger a fresh replay (see get_detection_run)."""
    base = _build_detail(run, db)
    rows = (
        db.query(Alert)
        .filter(Alert.detection_run_id == run.id)
        .order_by(Alert.flagged_at.desc())
        .all()
    )
    alerts_out = []
    for a in rows:
        try:
            shap_values = json.loads(a.shap_values) if a.shap_values else {}
        except (TypeError, ValueError):
            shap_values = {}
        alerts_out.append(
            AlertOut(
                flow_id=a.flow_id,
                anomaly_score=a.anomaly_score,
                severity=a.severity,
                src_ip=a.src_ip,
                dst_ip=a.dst_ip,
                protocol=a.protocol,
                shap_values=shap_values,
                explanation=a.explanation,
                flagged_at=a.flagged_at,
            )
        )
    return DetectionRunWithAlerts(**base.model_dump(), alerts=alerts_out)


# ─── POST /api/detection-runs ────────────────────────────────────────────────
@router.post(
    "/detection-runs",
    status_code=202,
    response_model=DetectionRunCreatedResponse,
    responses={400: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
async def start_detection_run(
    body: DetectionRunRequest,
    db: Session = Depends(get_db),
) -> DetectionRunCreatedResponse:
    """Start a new anomaly detection replay run."""

    if body.model not in VALID_MODELS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "code": "invalid_request",
                    "message": f"model must be one of {sorted(VALID_MODELS)}",
                }
            },
        )

    if body.held_out_category not in VALID_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "code": "invalid_request",
                    "message": f"held_out_category must be one of {sorted(VALID_CATEGORIES)}",
                }
            },
        )

    run = DetectionRun(
        held_out_category=body.held_out_category,
        model_used=body.model,
        threshold=body.threshold,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    return DetectionRunCreatedResponse(detection_run_id=run.id, status="running")


# ─── GET /api/detection-runs ─────────────────────────────────────────────────
@router.get("/detection-runs", response_model=list[DetectionRunDetail])
def list_detection_runs(db: Session = Depends(get_db)) -> list[DetectionRunDetail]:
    runs = db.query(DetectionRun).order_by(DetectionRun.started_at.desc()).limit(50).all()
    return [_build_detail(r, db) for r in runs]


# ─── GET /api/detection-runs/{id} ────────────────────────────────────────────
@router.get(
    "/detection-runs/{run_id}",
    response_model=DetectionRunWithAlerts,
    responses={404: {"model": ErrorResponse}},
)
def get_detection_run(run_id: int, db: Session = Depends(get_db)) -> DetectionRunWithAlerts:
    run = db.query(DetectionRun).filter(DetectionRun.id == run_id).first()
    if not run:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "not_found", "message": f"DetectionRun {run_id} not found"}},
        )
    return _build_detail_with_alerts(run, db)


# ─── WS /api/detection-runs/{id}/stream ──────────────────────────────────────
@router.websocket("/detection-runs/{run_id}/stream")
async def stream_detection_run(
    websocket: WebSocket,
    run_id: int,
    db: Session = Depends(get_db),
) -> None:
    """
    WebSocket live feed for anomaly detection replay.

    Server pushes:
      {"type":"flow",   "flow_id":"...", "src_ip":"...", "dst_ip":"...", "protocol":"TCP", "anomaly_score":0.12}
      {"type":"alert",  "flow_id":"...", "anomaly_score":0.91, "severity":"high", "shap_values":{...}, "explanation":"..."}
      {"type":"run_completed", "precision":0.88, "recall":0.91, "f1_score":0.895, "false_positive_rate":0.06}

    Client can send:
      {"type":"set_threshold", "value":0.8}
    """
    await websocket.accept()

    run = db.query(DetectionRun).filter(DetectionRun.id == run_id).first()
    if not run:
        await websocket.send_json({"error": {"code": "not_found", "message": "run not found"}})
        await websocket.close()
        return

    if run.completed_at is not None:
        # Reconnecting to an already-completed run (e.g. a History row click)
        # must NOT re-trigger a fresh replay — that would re-score another 200
        # flows onto this run's persisted alerts and overwrite its precision/
        # recall/f1/FPR with a new, different result each time it's viewed.
        # GET /api/detection-runs/{id} already returns the full historical
        # alert list for this case; the WS is for driving a live run only.
        await websocket.send_json(
            {
                "error": {
                    "code": "already_completed",
                    "message": "This run has already completed — fetch GET /api/detection-runs/{id} for its historical results instead of reconnecting to the stream.",
                }
            }
        )
        await websocket.close()
        return

    try:
        await anomaly_engine.replay_and_stream(websocket, run, db)
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001
        try:
            await websocket.send_json({"error": {"code": "internal_error", "message": str(exc)}})
            await websocket.close()
        except Exception:
            pass  # client already disconnected
