# Security — ZeroWatch

This document covers both (a) how the platform itself is secured, and (b) the ethical/legal guardrails around what it's allowed to scan — the second is arguably more important for this project.

## 1. Scope and authorization guardrails (read this first)

ZeroWatch's Recon Engine is capable of active checks against arbitrary URLs. To stay legal and ethical:

- **Mandatory authorization checkbox**: every scan requires the user to confirm they own the target domain or have explicit permission to test it. The backend rejects any scan request without `authorized: true`.
- **Passive checks only, by default**: SSL/TLS grading, header inspection, cookie flag checks, tech fingerprinting, and CVE cross-referencing are all passive (equivalent to what a browser or curl already reveals) — these require no special authorization to be ethical, but the checkbox is still enforced for consistency and to build the habit.
- **Active checks (e.g. reflected-XSS/SQLi probing) are restricted to a hardcoded allowlist** of sandbox targets (OWASP Juice Shop, DVWA, localhost test instances) — never enabled against arbitrary user-submitted URLs, regardless of the authorization checkbox.
- **No credential harvesting, no exploitation, no data exfiltration** — findings are informational only.

## 2. Application-level security

### Input validation
- `target_url` validated as a well-formed URL, scheme restricted to `http`/`https`
- Rejects internal/private IP ranges and `localhost` variants for the Recon Engine by default (prevents SSRF against the host machine or local network), with an explicit dev-mode override flag for testing against local sandboxes
- All WebSocket messages validated against an expected schema before processing

### Authentication (if enabled)
- Optional stub session auth for local multi-profile use; not enabled by default since this is a single-user local tool
- If enabled: passwords hashed with bcrypt/argon2, sessions stored server-side, no plaintext credentials logged

### Data at rest
- SQLite file stored locally, not exposed over network
- No secrets (API keys) stored in the database — kept in `.env`, excluded from git via `.gitignore`

### Data in transit
- All frontend↔backend traffic is localhost-only in v1 (no TLS needed for localhost loopback traffic)
- Outbound calls to external free APIs (NVD, crt.sh, VirusTotal) use HTTPS

### Secrets management
- `.env` file for the one API key actually needed (VirusTotal free tier) — see ENVIRONMENT.md
- `.env.example` committed to the repo with placeholder values; real `.env` git-ignored

## 3. Threat model (documented for the report — shows security maturity)

| Threat | Mitigation |
|---|---|
| SSRF via Recon Engine scanning internal/private IPs | URL validation blocks private ranges by default |
| Misuse of active-scan features against non-consented third parties | Authorization checkbox + active checks restricted to sandbox allowlist |
| Prompt injection via scanned page content reaching the local LLM | Findings are structured/sanitized into JSON before being passed to Ollama; raw page HTML/scripts are never passed directly into the LLM prompt |
| Local LLM output containing inaccurate/hallucinated remediation advice | Reports are clearly labeled "AI-generated, verify before acting"; not presented as authoritative security advice |
| SQLite injection | All queries parameterized (SQLAlchemy ORM or equivalent), no raw string interpolation |
| Sensitive scan results exposed if the tool were ever network-exposed | Documented as local-only by design; if ever bound to `0.0.0.0` instead of `127.0.0.1`, auth becomes mandatory (noted as a hard requirement, not left implicit) |

## 4. Known limitations (disclose honestly in report/demo)

- No production-grade auth/authorization system (acceptable for a local single-user academic build, explicitly out of scope per PRD.md)
- Zero-day detection is demonstrated via labeled dataset replay, not live production traffic — false positive/negative rates reported are on that dataset, not a guarantee of real-world performance
- Local LLM (7–8B parameter class) has lower reasoning capability than frontier cloud models — remediation text quality reflects that tradeoff, made explicitly for the local-first/privacy-first design goal

## 5. Responsible disclosure note

If ZeroWatch is ever pointed at a real third-party site and finds a genuine vulnerability, standard responsible disclosure practice applies: report privately to the site owner/security contact, do not publicly disclose before a fix, and do not use findings for unauthorized access.
