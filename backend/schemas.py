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
    category: str | None = None
    severity: str | None = None
    title: str
    description: str | None = None
    remediation: str | None = None

    model_config = {"from_attributes": True}


class ScanDetailResponse(BaseModel):
    """GET /api/scans/{scan_id} — full scan result."""

    scan_id: int
    status: str
    target_url: str
    risk_score: int | None = None
    findings: list[FindingOut] = []
    started_at: datetime | None = None
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}


class ScanListItem(BaseModel):
    scan_id: int
    status: str
    target_url: str
    risk_score: int | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None

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
    status: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    precision: float | None = None
    recall: float | None = None
    f1_score: float | None = None
    false_positive_rate: float | None = None
    # Not in DATABASE_SCHEMA.md's detection_runs columns directly — aggregated
    # from the child `alerts` table at query time. UI_UX_SPEC.md §3.6 (History)
    # needs an alert count + severity per row; the data already exists per-alert,
    # it just wasn't being surfaced on the run-level response.
    alert_count: int = 0
    highest_severity: str | None = None

    model_config = {"from_attributes": True}


class AlertOut(BaseModel):
    """A single persisted alert row — mirrors WsAlertEvent's shape so the
    frontend's AlertCard/AlertDetailSheet components work identically whether
    fed from the live WebSocket or from history."""

    flow_id: str
    anomaly_score: float
    severity: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str | None = None
    shap_values: dict[str, float] = {}
    explanation: str | None = None
    flagged_at: datetime | None = None

    model_config = {"from_attributes": True}


class DetectionRunWithAlerts(DetectionRunDetail):
    """GET /api/detection-runs/{id} — includes the full persisted alert list
    so History can render a completed run's results without reconnecting to
    the WebSocket (reconnecting would re-trigger a full replay — see
    routers/detection_runs.py get_detection_run)."""

    alerts: list[AlertOut] = []


# ──────────────────────────────────────────────────────────────────────────────
# Evaluation
# ──────────────────────────────────────────────────────────────────────────────
class EvaluationOut(BaseModel):
    """GET /api/evaluations — leave-one-attack-out result rows."""

    model_name: str
    held_out_category: str
    precision: float | None = None
    recall: float | None = None
    f1_score: float | None = None
    false_positive_rate: float | None = None

    model_config = {"from_attributes": True}


# ──────────────────────────────────────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────────────────────────────────────
class ActivityItem(BaseModel):
    type: str          # "scan" | "detection"
    id: int
    target: str        # URL or held_out_category
    timestamp: datetime | None = None


class DashboardSummary(BaseModel):
    """GET /api/dashboard/summary."""

    total_scans: int
    avg_risk_score: float | None = None
    anomalies_flagged_7d: int
    recent_activity: list[ActivityItem] = []


# ──────────────────────────────────────────────────────────────────────────────
# Settings — UI_UX_SPEC.md §3.7 (not covered by the original API_SPEC.md; added
# alongside the Settings page since the page has nothing to call without it)
# ──────────────────────────────────────────────────────────────────────────────
class SettingsOut(BaseModel):
    ollama_base_url: str
    active_model: str
    ollama_available: bool
    available_models: list[str] = []


class SetOllamaModelRequest(BaseModel):
    model: str


class ResetDataResponse(BaseModel):
    scans_deleted: int
    detection_runs_deleted: int


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
    shap_values: dict[str, float]
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
