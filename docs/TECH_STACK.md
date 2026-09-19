# Tech Stack — ZeroWatch

Exact versions are pinned at project start and updated here as they change — keep this file in sync with `requirements.txt` / `package.json`.

## Frontend

| Component | Choice | Version (baseline) |
|---|---|---|
| Framework | Next.js (App Router) | 14.x |
| Language | TypeScript | 5.x |
| Styling | Tailwind CSS | 3.x |
| Component library | shadcn/ui | latest |
| Charts | Recharts | 2.x |
| State/data fetching | React Query (TanStack Query) | 5.x |
| WebSocket client | native `WebSocket` API, wrapped in a custom hook | — |
| Package manager | npm | 10.x |
| Node runtime | Node.js | 18.x LTS or 20.x LTS |

## Backend

| Component | Choice | Version (baseline) |
|---|---|---|
| Framework | FastAPI | 0.11x |
| ASGI server | Uvicorn | 0.30.x |
| Language | Python | 3.11+ |
| ORM | SQLAlchemy | 2.x |
| DB driver | `sqlite3` (stdlib) via SQLAlchemy | — |
| Headless browser | Playwright (Python) | 1.4x |
| HTTP client | `httpx` (async) | 0.2x |
| WebSocket support | native FastAPI/Starlette WebSocket | — |
| PDF generation | WeasyPrint or `reportlab` | latest |
| Data validation | Pydantic | 2.x |

## Machine learning

| Component | Choice | Notes |
|---|---|---|
| Deep learning | PyTorch | 2.x — Autoencoder implementation |
| Classical ML | scikit-learn | 1.x — Isolation Forest, Random Forest baseline |
| Explainability | SHAP | latest |
| Imbalance handling | imbalanced-learn (SMOTE) | latest |
| Data handling | pandas, NumPy | latest stable |
| Dataset | CICIDS2017 / CSE-CIC-IDS2018 | pre-extracted flow features |

## Local LLM

| Component | Choice | Notes |
|---|---|---|
| Runtime | Ollama | latest |
| Primary model | Llama 3.1 8B (quantized, e.g. Q4_K_M) | ~4.7GB, needs ~8-16GB RAM comfortably |
| Fallback model (lower-spec machines) | Mistral 7B or Phi-3 mini | for 8GB RAM machines |
| API | Ollama local HTTP API (`localhost:11434/api/generate`) | OpenAI-compatible endpoint also available via `/v1/chat/completions` |

## External free APIs

| API | Purpose | Auth |
|---|---|---|
| NVD CVE API | CVE lookup by product/version | none required (key optional, raises rate limit) |
| crt.sh | Certificate transparency / subdomain enumeration | none required |
| VirusTotal (free tier) | URL/domain reputation | free API key required |
| Have I Been Pwned (optional) | Domain breach check | free for domain search |
| Shodan (optional, free tier) | Exposed service/port lookup | free API key, 100 query credits |

## Data storage

| Component | Choice |
|---|---|
| Database | SQLite (single file, `zerowatch.db`) |
| File storage | Local filesystem (`/data/pcaps`, `/data/exports`, `/models/checkpoints`) |

## Dev tooling

| Purpose | Tool |
|---|---|
| Containerization (optional, for one-command run) | Docker + docker-compose |
| Linting (frontend) | ESLint + Prettier |
| Linting (backend) | Ruff + Black |
| Type checking | TypeScript strict mode (frontend), mypy (backend, optional) |
| Testing | Jest/React Testing Library (frontend), Pytest (backend) — see TESTING.md |
| Version control | Git + GitHub |
