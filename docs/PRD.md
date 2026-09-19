# Product Requirements Document — ZeroWatch

## 1. Problem statement

Signature-based intrusion detection systems (IDS) — Snort, Suricata, traditional AV — can only detect attacks that match a known rule or hash. A zero-day attack, by definition, has no existing signature, so these systems miss it entirely until a vendor ships an updated rule set, often days or weeks after exploitation begins.

Separately, most publicly-facing web applications carry known, catalogued vulnerabilities (missing headers, outdated libraries with published CVEs, exposed config files) that go undetected simply because no one runs a scan.

ZeroWatch addresses both gaps in one platform, fully local, with no cloud dependency.

## 2. Goals

- Detect anomalous network traffic that does not match any known attack signature, using unsupervised ML trained only on normal + a subset of known attack traffic (simulating true zero-day conditions via leave-one-attack-out evaluation).
- Scan any authorized website/URL for known, catalogued vulnerabilities and misconfigurations, and explain findings in plain English with remediation steps.
- Run entirely offline/local: no cloud deployment, no paid APIs, local LLM for report generation.
- Be demo-able end-to-end in under 10 minutes with real (not fabricated) metrics.

## 3. Non-goals

- ZeroWatch does **not** claim to discover genuinely novel vulnerabilities in arbitrary websites via AI (no tool can reliably do this). The Recon Engine finds **known** vulnerability classes and CVEs.
- ZeroWatch does **not** perform intrusive/exploitative testing against third-party sites without explicit authorization. Active checks are restricted to sandboxed targets (OWASP Juice Shop, DVWA, user-owned domains).
- Not a production SOC replacement — this is a research/demo-grade platform, explicitly labeled as such.

## 4. Target users

- Primary: the developer/student themselves, for academic evaluation, hackathon demos, and portfolio use.
- Secondary persona (for UX framing): a small security team or solo developer wanting a quick local vulnerability + anomaly check without SaaS subscriptions.

## 5. Core features (see FEATURES.md for full behavioral detail)

### 5.1 Recon Engine
- URL input with mandatory authorization checkbox
- SSL/TLS analysis
- Security header audit
- Cookie security flag check
- Tech stack fingerprinting
- CVE cross-reference (NVD API)
- Exposed sensitive path detection
- Subdomain/DNS misconfiguration check (crt.sh)
- Composite 0–100 risk score
- AI-generated (local LLM) remediation report per finding
- PDF export

### 5.2 Zero-Day Anomaly Engine
- Dataset-driven live traffic replay (CICIDS2017/2018)
- Real-time anomaly scoring via WebSocket stream
- Leave-one-attack-out evaluation mode
- Multi-model comparison: Autoencoder / Isolation Forest / Random Forest baseline
- SHAP-based per-alert explainability
- Adjustable detection threshold with live precision/recall feedback
- Signature-based (Snort-style) vs AI-based side-by-side comparison
- Alert severity bucketing

### 5.3 Platform
- Local-only auth (optional, stubbed or simple session-based)
- Scan/detection history (SQLite)
- Dashboard with aggregate stats
- PDF export for any report
- Dark/light theme

## 6. Success metrics (for evaluation/demo, not production KPIs)

- Detection rate on held-out attack category ≥ 85% (target; report actual)
- False positive rate on held-out category ≤ 10% (target; report actual)
- Recon engine returns full report for a live URL in under 30 seconds
- End-to-end demo runnable with zero internet dependency except optional free API calls

## 7. Constraints

- Must run entirely on localhost, no cloud deployment
- Must use only free-tier or no-key APIs plus a locally-hosted LLM
- Must run on a standard student laptop (target: 16GB RAM, works degraded on 8GB with smaller quantized model)

## 8. Assumptions

- User has Ollama installable locally (Windows/Mac/Linux all supported)
- User has Python 3.11+ and Node 18+ available
- Traffic "detection" is demonstrated via labeled dataset replay, not live packet capture from a production network (explicitly disclosed, not claimed as live NIDS deployment)

## 9. Out of scope for v1

- Multi-user concurrent access / role-based access control
- Real-time packet capture from a live NIC
- Mobile app
- Paid API integrations (Shodan paid tier, VirusTotal paid tier, etc.)
