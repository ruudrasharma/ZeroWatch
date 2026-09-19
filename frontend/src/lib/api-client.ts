import type {
  DashboardSummary,
  DetectionModel,
  DetectionRunCreatedResponse,
  DetectionRunDetail,
  EvaluationRow,
  HeldOutCategory,
  ResetDataResponse,
  ScanCreatedResponse,
  ScanDetail,
  ScanListItem,
  SettingsOut,
} from "./api-types";

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api";
export const WS_BASE_URL =
  process.env.NEXT_PUBLIC_WS_BASE_URL ?? "ws://localhost:8000/api";

export class ApiError extends Error {
  code: string;
  status: number;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });

  if (!res.ok) {
    let code = "unknown_error";
    let message = res.statusText || "Request failed";
    try {
      const body = await res.json();
      const err = body?.error ?? body?.detail?.error ?? body?.detail;
      if (err && typeof err === "object") {
        code = err.code ?? code;
        message = err.message ?? message;
      } else if (typeof body?.detail === "string") {
        message = body.detail;
      }
    } catch {
      // response wasn't JSON — keep statusText fallback
    }
    throw new ApiError(res.status, code, message);
  }

  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

// ─── Recon Engine ───────────────────────────────────────────────────────────
export function startScan(target_url: string, authorized: boolean) {
  return request<ScanCreatedResponse>("/scans", {
    method: "POST",
    body: JSON.stringify({ target_url, authorized }),
  });
}

export function getScan(scanId: number) {
  return request<ScanDetail>(`/scans/${scanId}`);
}

export function listScans(params?: {
  limit?: number;
  offset?: number;
  min_severity?: string;
}) {
  const qs = new URLSearchParams();
  if (params?.limit) qs.set("limit", String(params.limit));
  if (params?.offset) qs.set("offset", String(params.offset));
  if (params?.min_severity) qs.set("min_severity", params.min_severity);
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return request<ScanListItem[]>(`/scans${suffix}`);
}

export function scanPdfUrl(scanId: number) {
  return `${API_BASE_URL}/scans/${scanId}/pdf`;
}

export function scanStreamUrl(scanId: number) {
  return `${API_BASE_URL}/scans/${scanId}/stream`;
}

// ─── Zero-Day Anomaly Engine ────────────────────────────────────────────────
export function startDetectionRun(body: {
  held_out_category: HeldOutCategory;
  model: DetectionModel;
  threshold: number;
}) {
  return request<DetectionRunCreatedResponse>("/detection-runs", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function getDetectionRun(runId: number) {
  return request<DetectionRunDetail>(`/detection-runs/${runId}`);
}

export function listDetectionRuns() {
  return request<DetectionRunDetail[]>("/detection-runs");
}

export function detectionRunStreamUrl(runId: number) {
  return `${WS_BASE_URL}/detection-runs/${runId}/stream`;
}

// ─── Evaluation ─────────────────────────────────────────────────────────────
export function getEvaluations() {
  return request<EvaluationRow[]>("/evaluations");
}

// ─── Dashboard ──────────────────────────────────────────────────────────────
export function getDashboardSummary() {
  return request<DashboardSummary>("/dashboard/summary");
}

// ─── Settings ───────────────────────────────────────────────────────────────
export function getSettings() {
  return request<SettingsOut>("/settings");
}

export function setOllamaModel(model: string) {
  return request<SettingsOut>("/settings/ollama-model", {
    method: "POST",
    body: JSON.stringify({ model }),
  });
}

export function resetLocalData() {
  return request<ResetDataResponse>("/settings/reset", { method: "POST" });
}
