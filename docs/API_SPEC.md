# API Specification — ZeroWatch backend (FastAPI, localhost:8000)

Base URL: `http://localhost:8000/api`

Authentication: none required for local single-user use (v1). If a stub login is implemented, endpoints accept an optional `Authorization: Bearer <session-token>` header; unauthenticated requests are allowed by default in local mode (see SECURITY.md).

---

## Recon Engine

### `POST /api/scans`
Start a new recon scan.

**Request:**
```json
{
  "target_url": "https://example.com",
  "authorized": true
}
```
`authorized` must be `true` or the request is rejected with `400`.

**Response `202 Accepted`:**
```json
{
  "scan_id": 42,
  "status": "pending"
}
```

### `GET /api/scans/{scan_id}`
Poll scan status/results.

**Response `200 OK`:**
```json
{
  "scan_id": 42,
  "status": "completed",
  "target_url": "https://example.com",
  "risk_score": 63,
  "findings": [
    {
      "id": 101,
      "category": "headers",
      "severity": "medium",
      "title": "Missing Content-Security-Policy header",
      "description": "...",
      "remediation": "..."
    }
  ],
  "started_at": "2026-09-19T12:00:00Z",
  "completed_at": "2026-09-19T12:00:24Z"
}
```

### `GET /api/scans/{scan_id}/stream`
Server-Sent Events (or WebSocket) stream of scan progress steps: `checking_ssl`, `fingerprinting`, `checking_cves`, `checking_exposure`, `generating_report`, `completed`.

### `GET /api/scans/{scan_id}/pdf`
Returns the report as a rendered PDF (`application/pdf`).

### `GET /api/scans`
List scan history. Query params: `limit`, `offset`, `min_severity`.

---

## Zero-Day Anomaly Engine

### `POST /api/detection-runs`
Start a new detection run.

**Request:**
```json
{
  "held_out_category": "DDoS",
  "model": "autoencoder",
  "threshold": 0.75
}
```

**Response `202 Accepted`:**
```json
{
  "detection_run_id": 17,
  "status": "running"
}
```

### `WS /api/detection-runs/{id}/stream`
WebSocket. Server pushes events as traffic replays:

```json
{ "type": "flow", "flow_id": "f_00381", "src_ip": "...", "dst_ip": "...", "protocol": "TCP", "anomaly_score": 0.12 }
```
```json
{ "type": "alert", "flow_id": "f_00382", "anomaly_score": 0.91, "severity": "high", "shap_values": {"flow_duration": 0.31, "packet_rate": 0.22, "..."}, "explanation": "..." }
```
```json
{ "type": "run_completed", "precision": 0.88, "recall": 0.91, "f1_score": 0.895, "false_positive_rate": 0.06 }
```

Client can send `{ "type": "set_threshold", "value": 0.8 }` mid-stream to adjust live.

Reconnecting to this endpoint for a run whose `completed_at` is already set is
rejected with `{"error": {"code": "already_completed", ...}}` and the socket
is closed — the replay is not idempotent (each run appends new alerts and
overwrites precision/recall/f1/FPR), so re-running it for a completed row
(e.g. a History click) would silently corrupt that run's historical results.
Fetch `GET /api/detection-runs/{id}` instead, which returns the persisted
alerts for a completed run.

### `GET /api/detection-runs/{id}`
Fetch final results/summary for a completed run, including its full
persisted alert list (each shaped like the WS `alert` event above, plus
`flagged_at`) — this is what the frontend uses to render a completed run's
results from History without reconnecting to the WebSocket.

**Response `200 OK`:**
```json
{
  "id": 17,
  "held_out_category": "DoS",
  "model_used": "autoencoder",
  "threshold": 0.75,
  "started_at": "2026-09-19T12:00:00Z",
  "completed_at": "2026-09-19T12:00:24Z",
  "precision": 0.95,
  "recall": 1.0,
  "alerts": [
    { "flow_id": "f_00382", "anomaly_score": 0.91, "severity": "high", "src_ip": "...", "dst_ip": "...", "protocol": "TCP", "shap_values": {"...": 0.31}, "explanation": "...", "flagged_at": "2026-09-19T12:00:10Z" }
  ],
  "f1_score": 0.97,
  "false_positive_rate": 0.01,
  "alert_count": 42,
  "highest_severity": "critical"
}
```
`alert_count` and `highest_severity` are aggregated from the run's `alerts`
rows at request time (not stored columns — see DATABASE_SCHEMA.md's
`detection_runs` table) so the History page (UI_UX_SPEC.md §3.6) has an alert
count and severity to display per row without a separate request per run.

### `GET /api/detection-runs`
List detection run history. Each row has the same shape as above.

---

## Evaluation

### `GET /api/evaluations`
Returns leave-one-attack-out results across all evaluated models/categories, for the Evaluation page table and comparison chart.

```json
[
  {
    "model_name": "autoencoder",
    "held_out_category": "PortScan",
    "precision": 0.89,
    "recall": 0.92,
    "f1_score": 0.905,
    "false_positive_rate": 0.05
  }
]
```

---

## Dashboard

### `GET /api/dashboard/summary`
```json
{
  "total_scans": 34,
  "avg_risk_score": 47,
  "anomalies_flagged_7d": 12,
  "recent_activity": [ { "type": "scan", "id": 42, "target": "example.com", "timestamp": "..." } ]
}
```

---

## Settings

Not in the original draft of this document — added because UI_UX_SPEC.md §3.7
requires a working Ollama model selector and a local-data reset button on the
Settings page, and neither had a backend endpoint to call.

### `GET /api/settings`
Returns the currently active Ollama model plus whatever's actually pulled
locally (queried live from Ollama's own `/api/tags`, so it reflects reality
rather than a hardcoded list).
```json
{
  "ollama_base_url": "http://localhost:11434",
  "active_model": "llama3.1:8b",
  "ollama_available": true,
  "available_models": ["llama3.1:8b", "mistral:7b"]
}
```
`ollama_available: false` and an empty `available_models` mean Ollama isn't
reachable right now — report generation falls back to labeled placeholder
text in that case (see `services/ollama_service.py`), it doesn't error out.

### `POST /api/settings/ollama-model`
```json
{ "model": "mistral:7b" }
```
Switches the model used for subsequent report/explanation generation calls.
In-memory only — does not persist across a backend restart (this is a local
single-user tool; `OLLAMA_MODEL` in `.env` is still the value used on next
startup). Returns the same shape as `GET /api/settings`.

### `POST /api/settings/reset`
Clears local scan and detection-run history (`scans`, `findings`,
`detection_runs`, `alerts`) so a demo can start from a clean slate.
Deliberately does **not** touch `model_evaluations` — that table holds real
trained-model evaluation results, not user-generated history.
```json
{ "scans_deleted": 12, "detection_runs_deleted": 4 }
```

---

## Error format (all endpoints)

```json
{
  "error": {
    "code": "invalid_request",
    "message": "authorized must be true to start a scan"
  }
}
```

Standard status codes: `400` invalid input, `404` not found, `409` conflict (e.g. run already in progress), `500` internal error.

## Rate limiting

Local single-user tool — no internal rate limiting needed. Outbound calls to free external APIs (NVD, crt.sh, VirusTotal) are throttled server-side to respect their published limits (see SECURITY.md and ENVIRONMENT.md).
