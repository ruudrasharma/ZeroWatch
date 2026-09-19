# Testing — ZeroWatch

## 1. Testing philosophy

Given this is an academic/portfolio project with a hard demo deadline, prioritize tests that (a) prove the core "zero-day" claim is real and reproducible, and (b) prevent regressions in the live-demo path. Full production-grade coverage is not the goal.

## 2. Backend — unit tests (Pytest)

- **Scoring logic** (`services/scoring.py`): risk score calculation given known findings input → expected score.
- **Severity mapping**: anomaly score → severity bucket boundaries.
- **URL validation**: rejects private IP ranges, malformed URLs, non-http(s) schemes.
- **NVD/crt.sh/VirusTotal client wrappers**: mocked HTTP responses, verify correct parsing and rate-limit backoff behavior.
- **SHAP output formatting**: given a mock model + instance, verify top-N feature extraction and JSON shape.

## 3. Backend — integration tests

- Full scan flow against a local mock HTTP server (not a real external site) — verify a scan request produces a completed report with expected finding categories.
- Full detection-run flow using a small fixture dataset (a handful of labeled flows) instead of the full CICIDS dataset — verify WebSocket emits `flow` and `alert` events in the expected shape and a `run_completed` summary is produced.
- SQLite persistence: verify scans/findings/detection_runs/alerts round-trip correctly through the ORM.

## 4. ML evaluation tests (this is the credibility-critical section)

- **Leave-one-attack-out reproducibility**: given a fixed random seed, verify the same held-out category produces consistent precision/recall/F1 across runs (within tolerance) — this protects your demo numbers from silently drifting.
- **Model sanity checks**: verify the Autoencoder's reconstruction error is meaningfully higher on attack traffic than on normal traffic in a held-out validation split (a basic "is this model actually learning anything" check before trusting the live demo).
- **No data leakage check**: assert the held-out category's samples never appear in the training split for that evaluation run.

## 5. Frontend tests

- **Component tests** (Jest + React Testing Library): `RiskGauge` renders correct color per score range, `SeverityBadge` renders correct label/color per severity, `ProgressStepper` advances correctly given step state.
- **Hook tests**: WebSocket hook correctly parses `flow`/`alert`/`run_completed` message types and updates state.
- **Form validation**: scan submission form disables submit until URL is valid and authorization checkbox is checked.

## 6. End-to-end tests (Playwright, optional but recommended for demo confidence)

- Full user flow: land on Dashboard → start a recon scan against a local mock target → see results render → export PDF.
- Full user flow: start a detection run against fixture data → see live feed update → see an alert appear → open alert detail → see SHAP chart render.

## 7. Security-specific tests

- Verify a scan request with `authorized: false` is rejected with `400` and never reaches the scanning logic.
- Verify active-scan checks cannot be triggered against a non-allowlisted target regardless of request parameters.
- Verify SSRF guard rejects `http://localhost`, `http://127.0.0.1`, and private IP ranges (`10.x`, `192.168.x`, `172.16–31.x`) unless `ALLOW_LOCALHOST_SCAN_TARGETS=true`.

## 8. Manual pre-demo checklist

- [ ] Ollama warmed up (one dummy generation run) before demo starts
- [ ] SQLite seeded with sample history so Dashboard/History aren't empty
- [ ] Full recon scan run once against the actual demo target URL to confirm no surprises
- [ ] Full detection run run once against the actual demo held-out category to confirm live feed timing looks good on the projector
- [ ] Backup recorded video of the full flow, in case of live technical issues
