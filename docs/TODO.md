# TODO — ZeroWatch

Living list of remaining work, tracked against the build order from PRD.md/prior planning. Move items to CHANGELOG.md as they're completed.

## Phase 1 — Data & ML foundation
- [x] Colab training notebook built: `ml/notebooks/ZeroWatch_Model_Training.ipynb` — loads NSL-KDD, preprocesses, runs leave-one-attack-out split, trains Autoencoder + Isolation Forest + Random Forest baseline, evaluates, runs SHAP, saves checkpoints
- [x] Convert the notebook's training logic into `ml/scripts/*.py` for automated/reproducible re-runs outside Colab — `python -m ml.scripts.train`, see `ml/README.md`
- [x] Run the pipeline end-to-end and record the real (not placeholder)
      precision/recall/F1/FPR numbers — `backend/models/checkpoints/` holds
      the real output; `services/seed.py` reads that CSV directly (not a
      copy-pasted table) so `model_evaluations` and the Evaluation page
      always match whatever checkpoints are actually loaded
- [x] Copy trained checkpoints into `backend/models/checkpoints/` — `ml/scripts/train.py --output-dir backend/models/checkpoints` does this directly, no manual zip/copy step
- [ ] (Optional) Swap dataset loader to CICIDS2017/2018 per `ml/README.md` notes, re-run, compare results

## Phase 2 — Backend
- [x] FastAPI project skeleton (routers, DB models, Pydantic schemas)
- [x] SQLite schema migration (per DATABASE_SCHEMA.md)
- [x] Recon Engine: SSL/TLS check module
- [x] Recon Engine: security header audit module
- [x] Recon Engine: cookie security check module
- [x] Recon Engine: tech fingerprinting module
- [x] Recon Engine: NVD CVE lookup integration
- [x] Recon Engine: exposed path checker
- [x] Recon Engine: crt.sh subdomain check
- [x] Risk scoring function
- [x] Ollama integration (report generation service)
- [x] WebSocket endpoint for anomaly live feed
- [x] Dataset replay engine (paced streaming from processed flow data; falls
      back to a believable synthetic score distribution when no processed
      CICIDS/NSL-KDD data is present in data/processed/)
- [x] PDF export (reportlab template)
- [x] Backend audit pass (Phase A) — installability + correctness fixes, see
      CHANGELOG.md [0.2.1] for the full list

## Phase 3 — Frontend
- [x] Next.js 14 (App Router) + TypeScript + Tailwind v4 + shadcn/ui (radix
      style) + Recharts + TanStack Query + Framer Motion scaffold; design
      tokens from UI_UX_SPEC.md §2 in `globals.css` (dark default, `.light`
      inversion, Inter/JetBrains Mono via next/font)
- [x] Landing page — animated hero, live counter strip from
      `GET /api/dashboard/summary`, skippable animated boot sequence
- [x] Dashboard page + 3 animated summary cards + recent activity feed + 2 launch cards
- [x] Recon scan page + 5-step animated progress stepper (SSE-driven)
- [x] Recon results page (animated risk gauge, collapsible severity-coded finding cards, PDF export)
- [x] Anomaly live dashboard (control bar, live traffic table, real-time score
      chart with threshold line, flagged-alerts panel, all WS-driven)
- [x] Alert detail slide-over (SHAP bar chart, confidence, signature-match vs AI-verdict)
- [x] Evaluation page (results table, per-category metrics heatmap, animated model-comparison chart)
- [x] History page (filterable/sortable, row click reuses Recon results / Anomaly detail views)
- [x] Settings page (theme toggle, Ollama model selector, data reset)
- [x] Dark/light theme toggle (next-themes)
- [x] Responsive layout pass — hamburger/bottom-tab nav <640px, anomaly
      3-column stacks <1024px, live feed truncates to 10 rows <640px

## Phase 4 — Integration & polish
- [x] Wire frontend to all backend endpoints end-to-end (no mock data —
      added `alert_count`/`highest_severity`/`alerts` to `DetectionRunDetail`
      and a whole `Settings` router that didn't exist before, since the
      Settings/History pages had nothing real to call otherwise)
- [x] Seed script for demo-ready sample History/Dashboard data
      (`services/seed.py::seed_demo_history`, idempotent, `SEED_DEMO_DATA=false` to disable)
- [x] docker-compose.yml for one-command run (`backend/Dockerfile`,
      `frontend/Dockerfile` with standalone Next.js output)
- [x] GitHub Actions CI (lint + test, no deploy) — `.github/workflows/ci.yml`
- [ ] Write demo script/narration matched to live UI flow
- [ ] Record backup demo video

## Known issues / risks to track
- [ ] Confirm Llama 3.1 8B runs acceptably on the actual demo machine's RAM — fall back to Mistral 7B/Phi-3 if not
- [ ] Confirm CICIDS2017/2018 download size and preprocessing time fits available time/disk
- [ ] Verify VirusTotal free-tier rate limit (4/min) doesn't stall the demo if multiple checks fire close together

## Stretch goals (only if core is done early)
- [ ] Shodan integration for exposed service/port checks
- [ ] Have I Been Pwned domain breach check
- [ ] Multi-profile local auth (stub login)
- [ ] Export detection run results as CSV in addition to PDF
