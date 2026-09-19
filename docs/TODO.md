# TODO — ZeroWatch

Living list of remaining work, tracked against the build order from PRD.md/prior planning. Move items to CHANGELOG.md as they're completed.

## Phase 1 — Data & ML foundation
- [x] Colab training notebook built: `ml/notebooks/ZeroWatch_Model_Training.ipynb` — loads NSL-KDD, preprocesses, runs leave-one-attack-out split, trains Autoencoder + Isolation Forest + Random Forest baseline, evaluates, runs SHAP, saves checkpoints
- [ ] Run the notebook end-to-end in Colab and record the real (not placeholder) precision/recall/F1/FPR numbers into `DATABASE_SCHEMA.md`'s `model_evaluations` table and the Evaluation page mock data
- [ ] (Optional) Swap dataset loader to CICIDS2017/2018 per `ml/README.md` notes, re-run, compare results
- [ ] Convert the notebook's training logic into `ml/scripts/*.py` for automated/reproducible re-runs outside Colab
- [ ] Copy downloaded `zerowatch_models.zip` contents into `backend/models/checkpoints/`

## Phase 2 — Backend
- [ ] FastAPI project skeleton (routers, DB models, Pydantic schemas)
- [ ] SQLite schema migration (per DATABASE_SCHEMA.md)
- [ ] Recon Engine: SSL/TLS check module
- [ ] Recon Engine: security header audit module
- [ ] Recon Engine: cookie security check module
- [ ] Recon Engine: tech fingerprinting module
- [ ] Recon Engine: NVD CVE lookup integration
- [ ] Recon Engine: exposed path checker
- [ ] Recon Engine: crt.sh subdomain check
- [ ] Risk scoring function
- [ ] Ollama integration (report generation service)
- [ ] WebSocket endpoint for anomaly live feed
- [ ] Dataset replay engine (paced streaming from processed flow data)
- [ ] PDF export (WeasyPrint/reportlab template)

## Phase 3 — Frontend
- [ ] Next.js project skeleton, design tokens from UI_UX_SPEC.md set up in Tailwind config
- [ ] Landing page
- [ ] Dashboard page + summary cards
- [ ] Recon scan page + progress stepper
- [ ] Recon results page (risk gauge, findings list)
- [ ] Anomaly live dashboard (traffic feed, score chart, alerts panel)
- [ ] Alert detail view (SHAP chart)
- [ ] Evaluation page (results table, confusion matrix, comparison chart)
- [ ] History page
- [ ] Settings page
- [ ] Dark/light theme toggle
- [ ] Responsive layout pass (mobile/tablet breakpoints)

## Phase 4 — Integration & polish
- [ ] Wire frontend to all backend endpoints end-to-end
- [ ] Seed script for demo-ready sample History/Dashboard data
- [ ] docker-compose.yml for one-command run
- [ ] GitHub Actions CI (lint + test, no deploy)
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
