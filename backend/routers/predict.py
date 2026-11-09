"""
ZeroWatch — stateless model-serving endpoints (MLOps workshop: serving API).

POST /api/predict        score one raw NSL-KDD flow
POST /api/predict/batch  score up to MAX_BATCH flows in one call

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from schemas import (
    PredictBatchRequest,
    PredictBatchResponse,
    PredictRequest,
    PredictResponse,
)
from services import metrics
from services.model_loader import get_model_info, models_are_ready
from services.prediction import SCORERS, predict_records

router = APIRouter(prefix="/predict", tags=["predict"])

MAX_BATCH = 1000


def _err(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status, detail={"error": {"code": code, "message": message}}
    )


def _run(records: list[dict], model: str, threshold: float) -> list[dict]:
    if model not in SCORERS:
        metrics.PREDICT_ERRORS.labels("invalid_model").inc()
        raise _err(400, "invalid_request", f"model must be one of {sorted(SCORERS)}")
    if not 0.0 <= threshold <= 1.0:
        metrics.PREDICT_ERRORS.labels("invalid_threshold").inc()
        raise _err(400, "invalid_request", "threshold must be between 0 and 1")
    if not models_are_ready():
        metrics.PREDICT_ERRORS.labels("models_not_loaded").inc()
        raise _err(503, "models_unavailable", "Models are not loaded yet")
    try:
        return predict_records(records, model, threshold)
    except ValueError as exc:
        metrics.PREDICT_ERRORS.labels("invalid_input").inc()
        raise _err(422, "invalid_flow", str(exc)) from exc


@router.post("", response_model=PredictResponse)
async def predict(body: PredictRequest) -> PredictResponse:
    """Score one raw flow. score is in [0,1]; 0.5 equals the training threshold."""
    res = _run([body.flow], body.model, body.threshold)[0]
    return PredictResponse(
        model=body.model,
        threshold=body.threshold,
        model_fingerprint=get_model_info().get("fingerprint"),
        **res,
    )


@router.post("/batch", response_model=PredictBatchResponse)
async def predict_batch(body: PredictBatchRequest) -> PredictBatchResponse:
    if not body.flows or len(body.flows) > MAX_BATCH:
        raise _err(400, "invalid_request", f"flows must contain 1..{MAX_BATCH} records")
    return PredictBatchResponse(
        model=body.model,
        threshold=body.threshold,
        model_fingerprint=get_model_info().get("fingerprint"),
        results=_run(body.flows, body.model, body.threshold),
    )
