# ZeroWatch

**AI-powered, fully local security platform combining a web vulnerability recon engine and an AI-based zero-day anomaly detection engine.**

No cloud deployment. No paid APIs. No data leaves your machine. Everything runs on `localhost` via Ollama (local LLM) and free-tier external APIs (NVD, crt.sh, VirusTotal free tier).

---

## What it does

ZeroWatch has two engines:

1. **Recon Engine** — paste a URL, get a full vulnerability report: SSL/TLS grade, security headers, cookie flags, tech fingerprinting, CVE cross-reference, exposed paths, subdomain enumeration — all explained in plain English by a locally-running LLM.
2. **Zero-Day Anomaly Engine** — replays labeled network traffic (CICIDS2017/2018) through an unsupervised Autoencoder trained only on "seen" traffic categories, and flags previously-unseen ("zero-day") attack patterns that a signature-based IDS would miss. Includes live SHAP explainability and leave-one-attack-out evaluation.

See [`docs/PRD.md`](docs/PRD.md) for full product scope and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the pieces fit together.

## Why local-only

- **Privacy**: a scanner that surfaces vulnerabilities is itself sensitive data — nothing should leave the machine it runs on.
- **Zero cost**: no cloud bill, no API metering, no rate-limit anxiety during a demo.
- **Reliability**: no cold starts, no network flakiness during evaluation or a live demo.

## Tech stack (summary — full detail in `docs/TECH_STACK.md`)

| Layer | Technology |
|---|---|
| Frontend | Next.js 14 (App Router) + TypeScript, Tailwind, shadcn/ui, Recharts |
| Backend | FastAPI (Python 3.11+), WebSockets |
| ML | PyTorch (Autoencoder), scikit-learn (Isolation Forest, Random Forest), SHAP |
| LLM | Ollama, running Llama 3.1 8B (or Mistral 7B on lower-spec machines) |
| Database | SQLite |
| External APIs (free tier) | NVD CVE API, crt.sh, VirusTotal free tier |

## Model training

The actual model training and evaluation lives in [`ml/notebooks/ZeroWatch_Model_Training.ipynb`](ml/notebooks/ZeroWatch_Model_Training.ipynb) — built to run directly in **Google Colab** with no manual dataset upload. It trains the Autoencoder, Isolation Forest, and Random Forest baseline, runs the leave-one-attack-out zero-day evaluation, and generates SHAP explanations. See [`ml/README.md`](ml/README.md) for details.

## Quick start

```bash
# 1. Start the local LLM
ollama serve
ollama pull llama3.1:8b

# 2. Start the backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# 3. Start the frontend
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

Full setup, environment variables, and troubleshooting: see [`docs/ENVIRONMENT.md`](docs/ENVIRONMENT.md) and [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Documentation index

| Document | Contents |
|---|---|
| [PRD.md](docs/PRD.md) | Full product requirements and features |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, data flow, services |
| [UI_UX_SPEC.md](docs/UI_UX_SPEC.md) | Screens, layout, components, design system |
| [DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) | Tables, relationships, indexes |
| [API_SPEC.md](docs/API_SPEC.md) | Endpoints, request/response formats |
| [SECURITY.md](docs/SECURITY.md) | Auth, encryption, validation, threat model |
| [TECH_STACK.md](docs/TECH_STACK.md) | Exact frameworks, versions, libraries |
| [USER_FLOWS.md](docs/USER_FLOWS.md) | Step-by-step user journeys |
| [FEATURES.md](docs/FEATURES.md) | Feature-by-feature behavior spec |
| [ENVIRONMENT.md](docs/ENVIRONMENT.md) | .env variables, local service setup |
| [TESTING.md](docs/TESTING.md) | Unit, integration, E2E, security testing |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Local run, Docker, CI/CD |
| [CHANGELOG.md](docs/CHANGELOG.md) | Development history |
| [TODO.md](docs/TODO.md) | Remaining work, known issues |

## Project context

Built by:
- Bhavishyata Yadav (Roll No. 24CSU036)
- Bhavya Jain (Roll No. 24CSU037)
- Rudra Kumar Sharma (Roll No. 24CSU175)

B.Tech CSE (Cybersecurity specialization), The NorthCap University — as a major AI/ML + cybersecurity project.

## License

MIT (or update as appropriate for your submission requirements).
