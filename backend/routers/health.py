"""
ZeroWatch — operational endpoints: /health (liveness), /ready (readiness), /metrics.

Mounted at the app root (no /api prefix) so Docker HEALTHCHECK, Kubernetes-style
probes and Prometheus use conventional paths.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from schemas import HealthResponse
from services import metrics
from services.model_loader import get_model_info, models_are_ready

router = APIRouter(tags=["ops"])

APP_VERSION = "0.5.0"


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Liveness: the process is up. Always 200; reports whether models loaded."""
    ready = models_are_ready()
    return HealthResponse(
        status="ok" if ready else "degraded",
        models_loaded=ready,
        model_fingerprint=get_model_info().get("fingerprint"),
        version=APP_VERSION,
    )


@router.get("/ready")
async def ready() -> JSONResponse:
    """Readiness: 200 only when every model artifact is loaded, else 503."""
    ok = models_are_ready()
    return JSONResponse(
        status_code=200 if ok else 503,
        content={"ready": ok, "model": get_model_info()},
    )


@router.get("/metrics", include_in_schema=False)
async def prometheus_metrics() -> Response:
    metrics.MODELS_LOADED.set(1 if models_are_ready() else 0)
    fp = get_model_info().get("fingerprint")
    if fp:
        metrics.MODEL_INFO.labels(fp).set(1)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
