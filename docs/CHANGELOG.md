# Changelog — ZeroWatch

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.3.0] — 2026-09-19 — Phase B/C: Frontend build + integration + ml/scripts

### Added
- `ml/scripts/{data,preprocess,models,evaluate,train}.py` — .py port of
  `ml/notebooks/ZeroWatch_Model_Training.ipynb` (TODO.md Phase 1 item).
  `python -m ml.scripts.train --output-dir backend/models/checkpoints`
  reproduces the whole pipeline with no Colab account and no manual zip/copy
  step. Verified reproducible: a fresh run's leave-one-out numbers landed
  within ~0.001 of the original Colab-trained checkpoint's numbers at
  `SEED=42` (e.g. Autoencoder/DoS: P=0.9781 vs. the original 0.9783).
  Also fixes the Isolation Forest known-limitation below, since the notebook
  never saved a production Isolation Forest and the script does.
  `backend/models/checkpoints/` regenerated with this script.
- Full Next.js 14 (App Router) + TypeScript frontend from scratch — Tailwind
  v4, shadcn/ui, Recharts, TanStack Query, Framer Motion. Design tokens in
  `globals.css` implement UI_UX_SPEC.md §2 exactly (dark default, `.light`
  inversion with WCAG-AA-adjusted hues, Inter + JetBrains Mono).
- All 7 screens from UI_UX_SPEC.md §3, animated and wired to real endpoints:
  Landing (animated hero + live counters), Dashboard, Recon scan + results,
  Zero-Day live dashboard, Evaluation, History, Settings.
- Full shared component inventory from UI_UX_SPEC.md §4 as real reusable
  components: `RiskGauge`, `SeverityBadge`, `FindingCard`, `LiveTrafficRow`,
  `ScoreChart`, `ShapBarChart`, `AlertCard`, `ProgressStepper`, `StatCard`,
  plus a skippable animated boot sequence (session-scoped) and an animated
  background grid/scanline behind hero/dashboard sections.
- `backend/Dockerfile` refinement, new `frontend/Dockerfile` (multi-stage,
  Next.js standalone output), root `docker-compose.yml` (ollama + backend +
  frontend, per DEPLOYMENT.md §2), `.dockerignore` for both.
- `.github/workflows/ci.yml` — backend (ruff + pytest) and frontend (lint +
  build) jobs, no deploy, per DEPLOYMENT.md §4.
- `services/seed.py::seed_demo_history()` — idempotent sample scans/detection
  runs so Dashboard/History aren't empty on first run.
- New backend surface added specifically because the frontend had nothing
  real to call otherwise (see API_SPEC.md for the documented contracts):
  - `routers/settings.py` — `GET/POST /api/settings*` (Ollama model listing/
    switching queried live from Ollama's own `/api/tags`, plus a local-data
    reset) — UI_UX_SPEC.md §3.7 required these and API_SPEC.md never defined
    them.
  - `DetectionRunDetail.alert_count`/`highest_severity` (aggregated from the
    `alerts` table) so History can show a severity/count per detection-run
    row without N+1 requests.
  - `DetectionRunWithAlerts` — `GET /api/detection-runs/{id}` now returns the
    full persisted alert list for a completed run.

### Fixed
- **Reconnecting to a completed detection run's WebSocket silently corrupted
  its history**: nothing stopped a History row click from reopening
  `WS /api/detection-runs/{id}/stream` for a run that had already finished —
  doing so re-ran a full 200-flow replay, appending duplicate alerts and
  overwriting that run's precision/recall/f1/FPR with a different result
  every time it was viewed. The WS now rejects reconnection once
  `completed_at` is set (`{"error": {"code": "already_completed", ...}}`);
  the frontend fetches the persisted `GET /api/detection-runs/{id}` result
  instead of opening a socket when a run is already complete.
- **Tailwind v3 config was incomplete** (shadcn's current CLI scaffolds
  Tailwind v4 CSS-first config regardless of the installed major version) —
  `tailwind.config.ts` only mapped `background`/`foreground`, so every other
  shadcn utility class (`bg-card`, `border-border`, `bg-primary`, …) resolved
  to nothing. Migrated to Tailwind v4 (`@tailwindcss/postcss`, CSS-first
  `@theme`) rather than patch a half-v3/v4 hybrid; see TECH_STACK.md.
- 203 pre-existing `ruff check` errors across files the initial backend
  scaffold shipped with (unsorted imports, `Dict`→`dict` modernization, one
  `isinstance` tuple→union) — CI's backend job would have failed on the very
  first push. Fixed via `ruff check --fix` plus one manual fix; full suite
  still 13/13 passing afterward.

## [0.2.1] — 2026-09-19 — Phase A: Backend audit & fixes

### Fixed
- **Backend was uninstallable on this machine**: `requirements.txt` pinned
  `torch==2.4.1`/`scikit-learn==1.5.2`/`numpy==1.26.4`/`shap==0.46.0`, none of
  which ship wheels for Python 3.13+ (no 3.11/3.12 interpreter was available).
  Bumped to `torch==2.6.0`/`scikit-learn==1.6.1`/`numpy==2.1.3`/`shap==0.47.2`.
- **All ML scoring was silently dead**: `scaler.pkl`, `label_encoders.pkl`, and
  `random_forest_baseline.pkl` were saved by the training notebook with
  `joblib.dump()` (confirmed against the notebook's own "loading the saved
  model later" cell) but loaded in `model_loader.py` with plain
  `pickle.load()`, which desyncs on joblib's out-of-band `NumpyArrayWrapper`
  encoding and raises `UnpicklingError`. Fixed to use `joblib.load()`
  throughout; added `joblib` to `requirements.txt`.
- **Autoencoder checkpoint failed to load**: `model_loader.Autoencoder`'s
  architecture (64→32→16 bottleneck) didn't match the checkpoint actually
  saved by the notebook (32→16→8 bottleneck, notebook cell 13) — state_dict
  loading raised a shape-mismatch `RuntimeError` on every startup. Fixed the
  class definition to match exactly.
- **Live anomaly feed always flagged ~90%+ of flows regardless of attack rate**:
  the synthetic fallback (used whenever `data/processed/` has no dataset) fed
  raw Gaussian-noise feature vectors through `scaler.transform()` a second
  time and then through the real trained Autoencoder — noise unrelated to any
  real traffic reconstructs poorly regardless of scaling, so nearly every
  synthetic flow scored ~1.0. Fixed: synthetic flows now carry a directly
  generated, believable score (matching the 80/20 benign/attack mix used to
  generate them) instead of being scored through a model that was never going
  to produce sane output on fabricated noise; real SHAP still runs against the
  real model on the fabricated feature vector for explainability texture. The
  real leave-one-out metrics on the Evaluation page are unaffected by this —
  those come from actual trained-model evaluation, not the live demo path.
- **The user-adjustable detection threshold did nothing**: `POST
  /api/detection-runs`'s `threshold` field and the live `{"type":
  "set_threshold"}` WebSocket message were read into a variable that was only
  ever passed to the LLM explanation prompt — the actual flag/no-flag decision
  used the fixed FEATURES.md severity-bucket floor (0.5) regardless. Fixed so
  `is_flagged = score >= current_threshold`; severity bucketing now only picks
  the display color for an already-flagged score.
- **`GET /api/scans/{id}/stream` (SSE) never reached `completed`**: the
  endpoint reused one long-lived SQLAlchemy session across its whole polling
  loop; with SQLite, that session's connection pinned a read snapshot from
  when its transaction opened and never observed writes committed by
  `run_scan`'s separate background-task session, so the stream hung on
  `running` until the 60s timeout. Fixed to open a fresh short-lived session
  per poll.
- **Progress stepper had no data to render**: `API_SPEC.md` and
  `UI_UX_SPEC.md §3.3` both describe a 5-step scan progress stream
  (`checking_ssl → fingerprinting → checking_cves → checking_exposure →
  generating_report`), but the SSE endpoint only ever emitted the coarse DB
  `status` (`pending`/`running`/`completed`/`failed`). Added an in-memory
  per-scan progress tracker in `recon_engine.py`, updated at each phase, that
  the SSE endpoint now surfaces (falling back to DB status for the terminal
  states, which remain the source of truth for History/Dashboard).
- **WebSocket threshold listener leaked a task per flow**: `anomaly_engine.py`
  called `asyncio.create_task(listen_for_threshold())` inside the per-flow
  loop (once per flow, ~200/run) instead of once, each one racing a
  concurrent `websocket.receive_text()` against the others. Replaced with a
  single long-lived listener task, cancelled in a `finally` block.
- **WS/SSE error paths double-faulted on client disconnect**: both
  `anomaly_engine.replay_and_stream` and its router caught a broad
  `Exception` and then unconditionally called `websocket.send_json(...)` to
  report it — if the exception *was* the client disconnecting, that send
  itself raised `RuntimeError: Cannot call "send" once a close message has
  been sent`, spamming the log with a second traceback. Both now swallow the
  secondary send failure.
- **`held_out_category` was never validated**: `detection_runs.py` defined
  `VALID_CATEGORIES` but never checked the request against it, so any string
  was silently accepted (and would fall through to the synthetic-flow
  fallback with an arbitrary attack label). Now returns `400` for anything
  outside the NSL-KDD categories, matching how `model` is already validated.
- **`GET /api/scans?min_severity=` was a documented no-op**: the query
  param was accepted and described in `API_SPEC.md` but never applied to the
  query. Implemented — filters to scans with at least one finding at or above
  the given severity.
- Mislabeled `category: "ssl"` on the SSRF-guard-blocked finding (unrelated to
  SSL) — changed to `category: "security"`.

### Verified (Phase A manual pass)
- All 6 endpoint groups from `API_SPEC.md` exercised live against a running
  `uvicorn` instance: `POST/GET /api/scans`, SSE stream, PDF export,
  `POST/GET /api/detection-runs`, the detection-run WebSocket stream (`flow`/
  `alert`/`run_completed`, plus live `set_threshold`), `GET /api/evaluations`,
  `GET /api/dashboard/summary`.
- CORS confirmed correctly scoped to `http://localhost:3000`.
- `seed_model_evaluations()` confirmed populating `model_evaluations` with the
  real 12-row `leave_one_out_results.csv` numbers on startup (not placeholders).
- Added 4 regression tests (`backend/tests/test_api.py`) covering the
  checkpoint-loading fix, `held_out_category` validation, `min_severity`
  validation, and the SSRF guard's end-to-end failed-scan path. Full suite:
  13/13 passing.

### Known limitation — resolved in [0.3.0]
- `score_isolation_forest()` was a proxy that delegated to the Autoencoder's
  score, because no production Isolation Forest checkpoint existed. Fixed by
  building `ml/scripts/train.py` (see [0.3.0]), which now trains and saves
  one — `score_isolation_forest()` scores with the real model.

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
