"""
ZeroWatch — Pydantic v2 schemas (request/response shapes per API_SPEC.md).

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


# ──────────────────────────────────────────────────────────────────────────────
# Shared error envelope  (API_SPEC.md §Error format)
# ──────────────────────────────────────────────────────────────────────────────
class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail


# ──────────────────────────────────────────────────────────────────────────────
# Recon Engine — scans
# ──────────────────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    """POST /api/scans — authorized must be true or 400 (checked in endpoint)."""

    target_url: str
    authorized: bool


class ScanCreatedResponse(BaseModel):
    """202 Accepted response for POST /api/scans."""

    scan_id: int
    status: str


class FindingOut(BaseModel):
    """Individual finding within a scan result."""

    id: int
    category: Optional[str] = None
    severity: Optional[str] = None
    title: str
    description: Optional[str] = None
    remediation: Optional[str] = None

    model_config = {"from_attributes": True}


class ScanDetailResponse(BaseModel):
    """GET /api/scans/{scan_id} — full scan result."""

    scan_id: int
    status: str
    target_url: str
    risk_score: Optional[int] = None
    findings: List[FindingOut] = []
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ScanListItem(BaseModel):
    scan_id: int
    status: str
    target_url: str
    risk_score: Optional[int] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ──────────────────────────────────────────────────────────────────────────────
# Zero-Day Anomaly Engine — detection runs
# ──────────────────────────────────────────────────────────────────────────────
class DetectionRunRequest(BaseModel):
    """POST /api/detection-runs."""

    held_out_category: str
    model: str  # autoencoder | isolation_forest | random_forest
    threshold: float


class DetectionRunCreatedResponse(BaseModel):
    """202 Accepted response for POST /api/detection-runs."""

    detection_run_id: int
    status: str


class DetectionRunDetail(BaseModel):
    id: int
    held_out_category: str
    model_used: str
    threshold: float
    status: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    false_positive_rate: Optional[float] = None

    model_config = {"from_attributes": True}


# ──────────────────────────────────────────────────────────────────────────────
# Evaluation
# ──────────────────────────────────────────────────────────────────────────────
class EvaluationOut(BaseModel):
    """GET /api/evaluations — leave-one-attack-out result rows."""

    model_name: str
    held_out_category: str
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    false_positive_rate: Optional[float] = None

    model_config = {"from_attributes": True}


# ──────────────────────────────────────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────────────────────────────────────
class ActivityItem(BaseModel):
    type: str          # "scan" | "detection"
    id: int
    target: str        # URL or held_out_category
    timestamp: Optional[datetime] = None


class DashboardSummary(BaseModel):
    """GET /api/dashboard/summary."""

    total_scans: int
    avg_risk_score: Optional[float] = None
    anomalies_flagged_7d: int
    recent_activity: List[ActivityItem] = []


# ──────────────────────────────────────────────────────────────────────────────
# WebSocket event shapes (API_SPEC.md §WS /api/detection-runs/{id}/stream)
# ──────────────────────────────────────────────────────────────────────────────
class WsFlowEvent(BaseModel):
    type: str = "flow"
    flow_id: str
    src_ip: str
    dst_ip: str
    protocol: str
    anomaly_score: float


class WsAlertEvent(BaseModel):
    type: str = "alert"
    flow_id: str
    anomaly_score: float
    severity: str
    shap_values: Dict[str, float]
    explanation: str


class WsRunCompletedEvent(BaseModel):
    type: str = "run_completed"
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float


class WsSetThresholdMessage(BaseModel):
    """Client → server mid-stream threshold adjustment."""

    type: str = "set_threshold"
    value: float
