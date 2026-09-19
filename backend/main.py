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

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import init_db
from routers import dashboard, detection_runs, evaluations, scans, settings
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
    version="0.1.0",
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
