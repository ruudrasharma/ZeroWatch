// Types mirror backend/schemas.py exactly (API_SPEC.md is the contract).

export type Severity = "low" | "medium" | "high" | "critical";
export type ScanStatus = "pending" | "running" | "completed" | "failed";
export type ScanStep =
  | "pending"
  | "checking_ssl"
  | "fingerprinting"
  | "checking_cves"
  | "checking_exposure"
  | "generating_report"
  | "running"
  | "completed"
  | "failed"
  | "timeout";

export interface Finding {
  id: number;
  category: string | null;
  severity: Severity | null;
  title: string;
  description: string | null;
  remediation: string | null;
}

export interface ScanDetail {
  scan_id: number;
  status: ScanStatus;
  target_url: string;
  risk_score: number | null;
  findings: Finding[];
  started_at: string | null;
  completed_at: string | null;
}

export interface ScanListItem {
  scan_id: number;
  status: ScanStatus;
  target_url: string;
  risk_score: number | null;
  started_at: string | null;
  completed_at: string | null;
}

export interface ScanCreatedResponse {
  scan_id: number;
  status: string;
}

export type DetectionModel = "autoencoder" | "isolation_forest" | "random_forest";
export type HeldOutCategory = "DoS" | "Probe" | "R2L" | "U2R";

export const DETECTION_MODELS: { value: DetectionModel; label: string }[] = [
  { value: "autoencoder", label: "Autoencoder" },
  { value: "isolation_forest", label: "Isolation Forest" },
  { value: "random_forest", label: "Random Forest (baseline)" },
];

export const HELD_OUT_CATEGORIES: { value: HeldOutCategory; label: string }[] = [
  { value: "DoS", label: "DoS" },
  { value: "Probe", label: "Probe" },
  { value: "R2L", label: "R2L (Remote-to-Local)" },
  { value: "U2R", label: "U2R (User-to-Root)" },
];

export interface DetectionRunDetail {
  id: number;
  held_out_category: string;
  model_used: string;
  threshold: number;
  status?: string | null;
  started_at: string | null;
  completed_at: string | null;
  precision: number | null;
  recall: number | null;
  f1_score: number | null;
  false_positive_rate: number | null;
  alert_count: number;
  highest_severity: Severity | null;
  alerts: AnomalyAlert[];
}

export interface DetectionRunCreatedResponse {
  detection_run_id: number;
  status: string;
}

export interface EvaluationRow {
  model_name: string;
  held_out_category: string;
  precision: number | null;
  recall: number | null;
  f1_score: number | null;
  false_positive_rate: number | null;
}

export interface ActivityItem {
  type: "scan" | "detection";
  id: number;
  target: string;
  timestamp: string | null;
}

export interface DashboardSummary {
  total_scans: number;
  avg_risk_score: number | null;
  anomalies_flagged_7d: number;
  recent_activity: ActivityItem[];
}

// ─── WebSocket event shapes — WS /api/detection-runs/{id}/stream ──────────────
export interface WsFlowEvent {
  type: "flow";
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  anomaly_score: number;
}

// Shared shape between a live WS alert event and a persisted alert returned
// by GET /api/detection-runs/{id} (schemas.AlertOut) — AlertCard/
// AlertDetailSheet render either one identically.
export interface AnomalyAlert {
  flow_id: string;
  anomaly_score: number;
  severity: Severity;
  shap_values: Record<string, number>;
  explanation: string;
  signature_match?: string;
  flagged_at?: string | null;
}

export interface WsAlertEvent extends AnomalyAlert {
  type: "alert";
}

export interface WsRunCompletedEvent {
  type: "run_completed";
  precision: number;
  recall: number;
  f1_score: number;
  false_positive_rate: number;
}

export interface WsErrorEvent {
  error: { code: string; message: string };
}

export type WsEvent = WsFlowEvent | WsAlertEvent | WsRunCompletedEvent | WsErrorEvent;

export interface ApiErrorBody {
  error?: { code: string; message: string };
  detail?: { error?: { code: string; message: string } } | string;
}

// ─── Settings ───────────────────────────────────────────────────────────────
export interface SettingsOut {
  ollama_base_url: string;
  active_model: string;
  ollama_available: boolean;
  available_models: string[];
}

export interface ResetDataResponse {
  scans_deleted: number;
  detection_runs_deleted: number;
}
