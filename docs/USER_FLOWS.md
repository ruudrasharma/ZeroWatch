# User Flows — ZeroWatch

## Flow 1: Run a vulnerability scan on a website

1. User lands on Dashboard, clicks "Recon Engine" launch card.
2. User enters a target URL.
3. User checks "I own this domain / have authorization" — submit button enables.
4. User clicks "Start Scan."
5. Progress stepper animates through: Checking SSL → Fingerprinting → Cross-referencing CVEs → Checking exposure → Generating report.
6. On completion, Results view renders: risk gauge, findings list.
7. User expands a finding to read the AI-generated explanation and remediation steps.
8. User clicks "Export PDF" → PDF downloads to local machine.
9. Scan appears in History page automatically.

**Edge cases:**
- Invalid URL → inline validation error, submit stays disabled.
- Target unreachable → scan marked `failed`, error message shown with reason (timeout, DNS failure, etc.).
- Authorization checkbox unchecked → submit stays disabled, no backend request made.

## Flow 2: Run a zero-day anomaly detection demo

1. User clicks "Zero-Day Engine" launch card from Dashboard.
2. User selects a held-out attack category from the dropdown (simulates "unseen" zero-day).
3. User selects a model (Autoencoder / Isolation Forest / RF baseline) and sets a detection threshold via slider (sensible default pre-set).
4. User clicks "Start Replay."
5. Live traffic feed begins scrolling; score chart updates in real time.
6. When a flow from the held-out category streams through, its anomaly score crosses threshold → row highlights, alert appears in the right panel.
7. User clicks the alert → detail view opens: SHAP feature contributions, model confidence, "Signature match: none" vs "AI verdict: anomalous."
8. Replay completes → summary metrics (precision/recall/F1/FPR) display at the top.
9. Run appears in History and contributes to the Evaluation page's results table.

**Edge cases:**
- User adjusts threshold mid-replay → subsequent scoring uses new threshold live; already-streamed flows are not retroactively re-flagged.
- User stops replay early → partial run saved with `status: stopped`, no summary metrics computed.

## Flow 3: Review evaluation results (academic/demo credibility check)

1. User navigates to Evaluation page from main nav.
2. Table shows all completed detection runs' leave-one-attack-out metrics, filterable by model.
3. User clicks a row → confusion matrix and per-category breakdown render below.
4. User toggles the model comparison chart to compare Autoencoder vs Isolation Forest vs RF baseline across the same held-out categories.

## Flow 4: Review past activity

1. User navigates to History page.
2. Table lists all past scans and detection runs, sortable by date/severity/type.
3. User filters by type = "Anomaly" and severity = "critical" to find high-priority past alerts.
4. User clicks a row → full report/alert detail re-renders exactly as it appeared originally (data pulled from SQLite, not re-computed).

## Flow 5: First-time local setup (developer/demo operator, not end user)

1. Clone repo.
2. Run `ollama pull llama3.1:8b`.
3. Start `ollama serve`.
4. `cd backend && pip install -r requirements.txt && uvicorn main:app --reload --port 8000`.
5. `cd frontend && npm install && npm run dev`.
6. Open `localhost:3000` — Dashboard loads with empty/seeded state.
7. (Optional) Run seed script to populate History/Dashboard with sample data before a live demo.
