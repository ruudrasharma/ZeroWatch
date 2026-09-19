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
from typing import List

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from database import DetectionRun
from deps import get_db
from schemas import (
    DetectionRunCreatedResponse,
    DetectionRunDetail,
    DetectionRunRequest,
    ErrorResponse,
)
from services import anomaly_engine

router = APIRouter(tags=["Anomaly Engine"])

VALID_MODELS = {"autoencoder", "isolation_forest", "random_forest"}
VALID_CATEGORIES = {"DoS", "Probe", "R2L", "U2R"}


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
@router.get("/detection-runs", response_model=List[DetectionRunDetail])
def list_detection_runs(db: Session = Depends(get_db)) -> List[DetectionRunDetail]:
    runs = db.query(DetectionRun).order_by(DetectionRun.started_at.desc()).limit(50).all()
    return [DetectionRunDetail.model_validate(r) for r in runs]


# ─── GET /api/detection-runs/{id} ────────────────────────────────────────────
@router.get(
    "/detection-runs/{run_id}",
    response_model=DetectionRunDetail,
    responses={404: {"model": ErrorResponse}},
)
def get_detection_run(run_id: int, db: Session = Depends(get_db)) -> DetectionRunDetail:
    run = db.query(DetectionRun).filter(DetectionRun.id == run_id).first()
    if not run:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "not_found", "message": f"DetectionRun {run_id} not found"}},
        )
    return DetectionRunDetail.model_validate(run)


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

    try:
        await anomaly_engine.replay_and_stream(websocket, run, db)
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001
        await websocket.send_json({"error": {"code": "internal_error", "message": str(exc)}})
        await websocket.close()
