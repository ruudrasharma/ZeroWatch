# Changelog — ZeroWatch

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] — 2026-09-19 — Phase 2: Backend

### Added
- FastAPI project skeleton: routers (`scans`, `detection_runs`, `evaluations`, `dashboard`),
  Pydantic v2 schemas, SQLAlchemy 2.x ORM models — exactly matches `DATABASE_SCHEMA.md`
  (6 tables: users, scans, findings, detection_runs, alerts, model_evaluations; 6 indexes)
- SQLite DB setup via `Base.metadata.create_all()` on startup (no Alembic; noted in summary)
- Model-loading service: loads real Autoencoder (PyTorch), RandomForest, StandardScaler,
  LabelEncoders, and feature_cols from `backend/models/checkpoints/` at startup
- Recon Engine modules (each independently testable):
  - `ssl_check.py` — TLS expiry, self-signed, TLS 1.0/1.1, weak ciphers
  - `header_check.py` — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
  - `cookie_check.py` — Secure, HttpOnly, SameSite flag audit
  - `tech_fingerprint.py` — Wappalyzer-style header/body/meta heuristic rules
  - `cve_lookup.py` — NVD REST API v2 per fingerprinted tech+version, CVSS → severity mapping
  - `exposure_check.py` — 40+ curated sensitive paths, concurrent HTTP 200 checks
  - `subdomain_check.py` — crt.sh CT log enumeration + DNS resolution
- Risk scoring (`scoring.py`): weighted composite 0–100 (critical=25, high=15, medium=8, low=2)
- Ollama integration (`ollama_service.py`): structured JSON → LLM prompt, graceful fallback
- WebSocket endpoint for anomaly engine (`anomaly_engine.py`): paced replay, live threshold
  adjustment, Snort-style signature comparison, severity bucketing, alert persistence
- SHAP wrapper (`shap_wrapper.py`): version-agnostic format handling (list/2D/3D ndarray/Explanation)
- PDF export (`pdf_export.py`): reportlab-based structured report with severity color-coding
- SSRF guard (`ssrf_guard.py`): blocks private/loopback IP ranges per SECURITY.md
- Seed script (`seed.py`): populates `model_evaluations` with REAL numbers from `leave_one_out_results.csv`
- Pytest smoke tests covering all key API contracts
- `backend/.env.example`, `frontend/.env.local.example` per ENVIRONMENT.md
- Model checkpoints moved from `zerowatch_models/` to `backend/models/checkpoints/`

## [Unreleased]


### Planning
- Project scoped: unified platform combining a web vulnerability Recon Engine and an AI-based Zero-Day Anomaly Detection Engine
- Decided on fully local architecture: no cloud deployment, local LLM (Ollama) instead of paid API, free-tier external APIs only
- Full documentation set drafted: PRD, Architecture, UI/UX Spec, Database Schema, API Spec, Security, Tech Stack, User Flows, Features, Environment, Testing, Deployment

### Added
- (fill in as you build) e.g. "Initial FastAPI backend skeleton"
- (fill in as you build) e.g. "Autoencoder training script + leave-one-attack-out evaluation harness"

### Changed
- Pivoted from cloud deployment (Vercel + hosted Postgres/Redis) to fully local architecture (SQLite, Ollama, docker-compose) — see ARCHITECTURE.md §6 for the documented upgrade path if this changes again

### Notes on using this file going forward
Add an entry every time you complete a meaningful chunk of work — this becomes both your commit history narrative for the report and a quick way to show an evaluator project progression over time. Suggested cadence: one entry per week or per major feature, not per commit.

---

## Template for future entries

```
## [vX.Y] - YYYY-MM-DD

### Added
- ...

### Changed
- ...

### Fixed
- ...
```
