"""
ZeroWatch — Settings router.

Not part of the original API_SPEC.md (that doc covers Recon/Anomaly/Evaluation/
Dashboard only) — added because UI_UX_SPEC.md §3.7 requires a working Ollama
model selector and local-data reset button on the Settings page, and there was
nothing to call. See API_SPEC.md's "Settings" section for the documented
contract this implements.

Endpoints:
  GET  /api/settings                 — active model + what's actually pulled in Ollama
  POST /api/settings/ollama-model    — switch the active model (in-memory)
  POST /api/settings/reset           — clear local scan/detection-run history

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import Alert, DetectionRun, Finding, Scan
from deps import get_db
from schemas import ResetDataResponse, SetOllamaModelRequest, SettingsOut
from services import ollama_service

router = APIRouter(tags=["Settings"])


@router.get("/settings", response_model=SettingsOut)
async def get_settings() -> SettingsOut:
    """Active model + what's actually pulled in the local Ollama instance."""
    available: list[str] = []
    ollama_available = False
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{ollama_service.OLLAMA_BASE_URL}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            available = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
            ollama_available = True
    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError):
        pass

    return SettingsOut(
        ollama_base_url=ollama_service.OLLAMA_BASE_URL,
        active_model=ollama_service.get_active_model(),
        ollama_available=ollama_available,
        available_models=available,
    )


@router.post("/settings/ollama-model", response_model=SettingsOut)
async def set_ollama_model(body: SetOllamaModelRequest) -> SettingsOut:
    ollama_service.set_active_model(body.model)
    return await get_settings()


@router.post("/settings/reset", response_model=ResetDataResponse)
def reset_local_data(db: Session = Depends(get_db)) -> ResetDataResponse:
    """
    Clears local scan + detection-run history and their child findings/alerts.
    Deliberately leaves `model_evaluations` untouched — that's reference data
    from real model training, not user-generated demo history
    (DATABASE_SCHEMA.md: "standalone reference table, populated once during
    training/evaluation phase").

    Children are deleted explicitly rather than relying on the ORM's
    cascade="all, delete-orphan" relationship: that cascade only fires when
    objects are loaded and removed via Session.delete(), not for a bulk
    Query.delete() — and there's no ON DELETE CASCADE at the SQLite FK level
    either (DATABASE_SCHEMA.md notes "no cascading deletes configured by
    default"), so skipping this would silently orphan findings/alerts rows.
    """
    scans_deleted = db.query(Scan).count()
    runs_deleted = db.query(DetectionRun).count()
    db.query(Finding).delete()
    db.query(Alert).delete()
    db.query(Scan).delete()
    db.query(DetectionRun).delete()
    db.commit()
    return ResetDataResponse(scans_deleted=scans_deleted, detection_runs_deleted=runs_deleted)
