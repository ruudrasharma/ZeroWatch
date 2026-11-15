"""
ZeroWatch — FastAPI application entry point.

Starts the backend per ARCHITECTURE.md (localhost:8000, /api base prefix).
All routes are defined in backend/routers/.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from database import init_db
from routers import dashboard, detection_runs, evaluations, health, predict, scans, settings
from services import metrics
from services.model_loader import load_all_models

# ─── Load env ────────────────────────────────────────────────────────────────
FRONTEND_ORIGIN: str = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")

# ─── App ─────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="ZeroWatch API",
    description=(
        "Local AI security platform — Recon Engine + Zero-Day Anomaly Detection.\n\n"
        "Authors: Bhavishyata Yadav (24CSU036), Bhavya Jain (24CSU037), "
        "Rudra Kumar Sharma (24CSU175) — B.Tech CSE (Cybersecurity), The NorthCap University."
    ),
    version="0.5.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ─── CORS (frontend ↔ backend on localhost, no cross-origin issues in prod) ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN, "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Routers (all mounted under /api per API_SPEC.md) ────────────────────────
app.include_router(scans.router, prefix="/api")
app.include_router(detection_runs.router, prefix="/api")
app.include_router(evaluations.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(settings.router, prefix="/api")
app.include_router(predict.router, prefix="/api")
app.include_router(health.router)  # /health /ready /metrics at root (probes + Prometheus)

# ─── Observability: request id, JSON access log, Prometheus HTTP metrics ─────
access_log = logging.getLogger("zerowatch.access")
if not access_log.handlers:  # uvicorn leaves non-uvicorn loggers at WARNING
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(message)s"))
    access_log.addHandler(_h)
    access_log.setLevel(logging.INFO)
    access_log.propagate = False


@app.middleware("http")
async def observability_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    start = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        response.headers["x-request-id"] = request_id
        return response
    finally:
        elapsed = time.perf_counter() - start
        route = request.scope.get("route")
        path = getattr(route, "path", "unmatched")  # template, keeps label cardinality low
        if path != "/metrics":
            metrics.HTTP_REQUESTS.labels(request.method, path, str(status)).inc()
            metrics.HTTP_LATENCY.labels(request.method, path).observe(elapsed)
            access_log.info(json.dumps({
                "request_id": request_id, "method": request.method,
                "path": request.url.path, "status": status,
                "duration_ms": round(elapsed * 1000, 2),
            }))


# ─── Startup ─────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event() -> None:
    """Initialize DB and pre-load ML models on startup."""
    init_db()
    load_all_models()
    from services.seed import seed_demo_history, seed_model_evaluations
    seed_model_evaluations()
    seed_demo_history()


@app.get("/", include_in_schema=False)
async def root() -> dict:
    return {"service": "ZeroWatch API", "docs": "/api/docs"}
