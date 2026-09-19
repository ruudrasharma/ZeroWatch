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

### `GET /api/detection-runs/{id}`
Fetch final results/summary for a completed run.

### `GET /api/detection-runs`
List detection run history.

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
