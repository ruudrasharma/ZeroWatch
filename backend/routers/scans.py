"""
ZeroWatch — Recon Engine router (scans).

Endpoints per API_SPEC.md:
  POST   /api/scans
  GET    /api/scans
  GET    /api/scans/{scan_id}
  GET    /api/scans/{scan_id}/stream   (SSE progress)
  GET    /api/scans/{scan_id}/pdf

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session

from database import Finding, Scan
from deps import get_db
from schemas import (
    ErrorDetail,
    ErrorResponse,
    FindingOut,
    ScanCreatedResponse,
    ScanDetailResponse,
    ScanListItem,
    ScanRequest,
)
from services import recon_engine

router = APIRouter(tags=["Recon Engine"])

# Map validation errors from Pydantic to the API_SPEC.md error envelope
AUTHORIZED_ERROR = JSONResponse(
    status_code=400,
    content={
        "error": {
            "code": "invalid_request",
            "message": "authorized must be true to start a scan",
        }
    },
)


# ─── POST /api/scans ─────────────────────────────────────────────────────────
@router.post(
    "/scans",
    status_code=202,
    response_model=ScanCreatedResponse,
    responses={400: {"model": ErrorResponse}},
)
async def start_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> ScanCreatedResponse:
    """Start a new recon scan. authorized must be true or 400 is returned
    before any scanning logic executes (SECURITY.md §1)."""

    # Hard reject — per SECURITY.md: validation happens BEFORE any scan logic
    if not body.authorized:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "code": "invalid_request",
                    "message": "authorized must be true to start a scan",
                }
            },
        )

    # Validate URL scheme (http/https only — SECURITY.md §2)
    url = str(body.target_url)
    if not url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "code": "invalid_request",
                    "message": "target_url must use http or https scheme",
                }
            },
        )

    # Create scan record in pending state
    scan = Scan(target_url=url, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Kick off async scan in background (doesn't block response)
    background_tasks.add_task(recon_engine.run_scan, scan.id, url)

    return ScanCreatedResponse(scan_id=scan.id, status="pending")


# ─── GET /api/scans ──────────────────────────────────────────────────────────
@router.get("/scans", response_model=list[ScanListItem])
def list_scans(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    min_severity: Optional[str] = Query(None),
    db: Session = Depends(get_db),
) -> list[ScanListItem]:
    """List scan history. Supports limit/offset/min_severity query params."""
    query = db.query(Scan).order_by(Scan.started_at.desc())
    scans = query.offset(offset).limit(limit).all()
    return [
        ScanListItem(
            scan_id=s.id,
            status=s.status,
            target_url=s.target_url,
            risk_score=s.risk_score,
            started_at=s.started_at,
            completed_at=s.completed_at,
        )
        for s in scans
    ]


# ─── GET /api/scans/{scan_id} ────────────────────────────────────────────────
@router.get(
    "/scans/{scan_id}",
    response_model=ScanDetailResponse,
    responses={404: {"model": ErrorResponse}},
)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> ScanDetailResponse:
    """Poll scan status/results."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "not_found", "message": f"Scan {scan_id} not found"}},
        )
    return ScanDetailResponse(
        scan_id=scan.id,
        status=scan.status,
        target_url=scan.target_url,
        risk_score=scan.risk_score,
        findings=[FindingOut.model_validate(f) for f in scan.findings],
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )


# ─── GET /api/scans/{scan_id}/stream (SSE) ───────────────────────────────────
@router.get("/scans/{scan_id}/stream")
async def stream_scan_progress(
    scan_id: int, db: Session = Depends(get_db)
) -> StreamingResponse:
    """Server-Sent Events stream of scan progress steps per API_SPEC.md."""

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "not found"}})

    async def event_generator():
        steps = [
            "checking_ssl",
            "fingerprinting",
            "checking_cves",
            "checking_exposure",
            "generating_report",
            "completed",
        ]
        last_status = None
        poll_count = 0
        while True:
            # Re-query in each iteration (fresh DB state)
            fresh_scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not fresh_scan:
                break
            current_status = fresh_scan.status

            if current_status in ("completed", "failed"):
                yield f"data: {json.dumps({'step': current_status})}\n\n"
                break

            # Emit current status if it changed
            if current_status != last_status:
                yield f"data: {json.dumps({'step': current_status})}\n\n"
                last_status = current_status

            poll_count += 1
            if poll_count > 120:  # 60s timeout
                yield f"data: {json.dumps({'step': 'timeout'})}\n\n"
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ─── GET /api/scans/{scan_id}/pdf ────────────────────────────────────────────
@router.get("/scans/{scan_id}/pdf")
async def export_scan_pdf(
    scan_id: int, db: Session = Depends(get_db)
) -> StreamingResponse:
    """Return the recon report as a PDF (application/pdf)."""
    from services.pdf_export import generate_scan_pdf

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "not found"}})
    if scan.status != "completed":
        raise HTTPException(
            status_code=409,
            detail={"error": {"code": "conflict", "message": "Scan not yet completed"}},
        )

    pdf_bytes = await generate_scan_pdf(scan)
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=zerowatch_scan_{scan_id}.pdf"},
    )
