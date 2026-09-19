# Architecture — ZeroWatch

## 1. High-level diagram

```
┌─────────────────────────────────────────────────────────┐
│ FRONTEND — Next.js 14 (App Router) + TypeScript            │
│ Tailwind + shadcn/ui, Recharts, WebSocket client            │
│ localhost:3000                                              │
└───────────────┬───────────────────────────────────────────┘
                │ REST + WebSocket (all localhost, no external network for UI)
┌───────────────▼───────────────────────────────────────────┐
│ BACKEND — FastAPI (Python 3.11+)                             │
│ localhost:8000                                               │
│                                                                │
│  ┌───────────────────┐   ┌──────────────────────────────┐   │
│  │ Recon Engine        │   │ Anomaly Detection Engine       │   │
│  │ - Playwright          │  │ - Autoencoder (PyTorch)          │  │
│  │ - SSL/TLS analyzer      │ │ - Isolation Forest                │ │
│  │ - Header/cookie checker  │ │ - Random Forest baseline           │ │
│  │ - Tech fingerprinting     │ │ - SHAP explainability                │
│  │ - CVE/NVD lookup            │ │ - pcap/flow replay engine              │
│  │ - Subdomain/DNS checks        │ │ - WebSocket live feed                    │
│  └─────────┬──────────┘   └───────────┬──────────────────┘   │
│            │                          │                        │
│  ┌─────────▼──────────────────────────▼──────────────────┐   │
│  │ AI Report Layer — calls local Ollama LLM                  │   │
│  │ Structured findings JSON → human-readable report,          │   │
│  │ remediation steps, plain-English SHAP explanations           │   │
│  └─────────────────────────┬──────────────────────────────┘   │
└────────────────────────────┼──────────────────────────────────┘
                             │ HTTP (localhost:11434)
                  ┌──────────▼──────────┐
                  │ Ollama (local LLM)     │
                  │ Llama 3.1 8B / Mistral 7B │
                  └────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ DATA LAYER                                                  │
│ - SQLite: users (optional), scan history, reports, alerts    │
│ - Local filesystem: pcap samples, exported PDFs, model         │
│   checkpoints                                                    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ EXTERNAL FREE APIs (outbound only, no auth key required       │
│ except VirusTotal)                                              │
│ - NVD CVE API, crt.sh, VirusTotal free tier                     │
└─────────────────────────────────────────────────────────────┘
```

## 2. Component responsibilities

### Frontend (Next.js)
Renders all UI (see UI_UX_SPEC.md). Talks to the FastAPI backend over REST for scan/detection requests and history, and over WebSocket for the live anomaly feed. No direct external API calls from the browser — everything is proxied through the backend to keep API keys and rate-limit logic server-side.

### Backend (FastAPI)
Single Python service exposing:
- REST endpoints for the Recon Engine (submit scan, poll/stream progress, fetch report)
- REST endpoints for model evaluation results and history
- WebSocket endpoint for live anomaly-detection traffic replay
- Internal service layer that calls Ollama for report/explanation text generation

### ML subsystem
Runs in-process inside the FastAPI backend (not a separate microservice, since this is a local single-user tool — simplifies the stack). Model checkpoints are loaded once at startup and reused across requests to avoid reload latency during the live demo.

### Local LLM (Ollama)
Runs as its own local process (`ollama serve`), exposing `http://localhost:11434`. The backend calls it exactly the way it would call any hosted LLM API, just pointed at localhost — this keeps the report-generation code swappable if a cloud LLM is added later.

### Database (SQLite)
Single file (`zerowatch.db`), no server process. Stores scan history, detection run history, and cached findings for the History and Dashboard pages.

## 3. Data flow — Recon Engine

1. User submits URL + authorization checkbox via frontend.
2. Backend validates input, checks authorization flag, enqueues scan.
3. Playwright loads the page; parallel checks run: SSL/TLS, headers, cookies, tech fingerprinting.
4. Fingerprinted tech + versions are cross-referenced against NVD CVE API.
5. Subdomain/DNS checks run against crt.sh.
6. All findings assembled into a structured JSON object.
7. JSON is sent to Ollama with a report-generation prompt; LLM returns human-readable explanations + remediation text per finding.
8. Composite risk score computed (weighted rule, documented in FEATURES.md).
9. Full report persisted to SQLite, returned to frontend, rendered on Results page.

## 4. Data flow — Zero-Day Anomaly Engine

1. User selects dataset category to hold out ("simulated zero-day") and starts replay.
2. Backend streams pre-processed flow records from the dataset over WebSocket, one at a time (simulated real-time pacing).
3. Each flow is scored by the active model (Autoencoder reconstruction error, or Isolation Forest anomaly score).
4. Score compared against the current threshold (adjustable live in UI); flows above threshold are flagged.
5. On flag, backend computes SHAP values for that instance and pushes an "alert" event over WebSocket with score + top contributing features.
6. Frontend renders the live feed, score chart, and alert list in real time.
7. Alert detail requests trigger an LLM call (via Ollama) to turn the SHAP output into a plain-English explanation.

## 5. Why this split (design rationale)

- **Single backend process** rather than separate microservices: this is a local, single-user demo tool — a microservice split would add deployment complexity with no real benefit at this scale.
- **WebSocket for anomaly feed**: anomaly scoring needs to feel "live" for the demo; polling REST would introduce visible lag.
- **SQLite over Postgres**: zero setup, single file, entirely appropriate for local single-user use; documented as a clear upgrade path if multi-user/production use is ever pursued.
- **Ollama over a cloud LLM**: removes API cost and internet dependency, reinforces the "nothing leaves this machine" positioning that matters for a security tool.

## 6. Upgrade path (documented, not built for v1)

If this were taken to production: split Recon Engine and Anomaly Engine into separate services behind an API gateway, move to Postgres + Redis, add real auth (NextAuth or similar), and replace dataset replay with real pcap ingestion from a network tap. This is intentionally out of scope for the local academic build but worth stating in the report to show awareness of production considerations.
