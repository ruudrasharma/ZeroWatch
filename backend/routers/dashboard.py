"""
ZeroWatch — Dashboard router.

GET /api/dashboard/summary

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import Alert, DetectionRun, Scan
from deps import get_db
from schemas import ActivityItem, DashboardSummary

router = APIRouter(tags=["Dashboard"])


@router.get("/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(db: Session = Depends(get_db)) -> DashboardSummary:
    """Aggregate stats for the dashboard page per API_SPEC.md."""

    total_scans: int = db.query(Scan).count()

    avg_risk: float | None = (
        db.query(func.avg(Scan.risk_score))
        .filter(Scan.risk_score.isnot(None))
        .scalar()
    )

    # Anomalies flagged in the last 7 days
    cutoff = datetime.utcnow() - timedelta(days=7)
    anomalies_7d: int = (
        db.query(Alert)
        .filter(Alert.flagged_at >= cutoff)
        .count()
    )

    # Last 5 scans + detection runs merged and sorted by timestamp
    recent_scans = (
        db.query(Scan)
        .order_by(Scan.started_at.desc())
        .limit(5)
        .all()
    )
    recent_runs = (
        db.query(DetectionRun)
        .order_by(DetectionRun.started_at.desc())
        .limit(5)
        .all()
    )

    activity: list[ActivityItem] = []
    for s in recent_scans:
        activity.append(
            ActivityItem(type="scan", id=s.id, target=s.target_url, timestamp=s.started_at)
        )
    for r in recent_runs:
        activity.append(
            ActivityItem(
                type="detection",
                id=r.id,
                target=r.held_out_category,
                timestamp=r.started_at,
            )
        )

    # Sort combined list by timestamp descending, take 5
    activity.sort(key=lambda a: a.timestamp or datetime.min, reverse=True)
    activity = activity[:5]

    return DashboardSummary(
        total_scans=total_scans,
        avg_risk_score=round(avg_risk, 1) if avg_risk is not None else None,
        anomalies_flagged_7d=anomalies_7d,
        recent_activity=activity,
    )
