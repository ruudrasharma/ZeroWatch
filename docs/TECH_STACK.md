# Tech Stack — ZeroWatch

Exact versions are pinned at project start and updated here as they change — keep this file in sync with `requirements.txt` / `package.json`.

## Frontend

| Component | Choice | Version (baseline) |
|---|---|---|
| Framework | Next.js (App Router) | 14.2.x (latest patch on the 14 line — kept per this doc's 14.x pin; `npm audit`'s remaining advisories concern internet-exposed deployments — SSRF via rewrites, cache poisoning, Image Optimization API — none of which apply to this localhost-only tool per SECURITY.md's threat model) |
| Language | TypeScript | 5.x |
| Styling | Tailwind CSS | **4.x** — bumped from the original 3.x pin: shadcn's current CLI scaffolds Tailwind v4 CSS-first config (`@theme`, `@custom-variant`) regardless of the installed major version, so a v3 install left most shadcn utility classes resolving to nothing; migrating to v4 was less risk than hand-maintaining a v3/v4 hybrid. See CHANGELOG.md [0.3.0]. |
| Component library | shadcn/ui | latest (radix style — the CLI's newer `base-nova`/`@base-ui/react` default was swapped for the more battle-tested Radix-backed style, since this build leans on deep custom theming) |
| Charts | Recharts | **3.x** — latest was 3.x at build time, not 2.x |
| State/data fetching | React Query (TanStack Query) | 5.x |
| Animation | Framer Motion | latest — additive per the build brief's quality bar, not a TECH_STACK deviation |
| WebSocket client | native `WebSocket` API, wrapped in a custom hook (`useDetectionStream`) | — |
| Package manager | npm | 10.x+ (Node 24 on the build machine ships npm 11) |
| Node runtime | Node.js | 18.x LTS or 20.x LTS (20-slim used in `frontend/Dockerfile`) |

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
| Deep learning | PyTorch | 2.6.x — Autoencoder implementation (bumped from 2.4.1; no wheels for Python 3.13, see CHANGELOG.md [0.2.1]) |
| Classical ML | scikit-learn | 1.6.x — Isolation Forest, Random Forest baseline (bumped from 1.5.2, same reason) |
| Model persistence | joblib | required, not optional — checkpoints (`scaler.pkl`, `label_encoders.pkl`, `random_forest_baseline.pkl`) are joblib-native format; loading with plain `pickle.load()` corrupts on the out-of-band numpy array encoding |
| Explainability | SHAP | 0.47.x |
| Imbalance handling | imbalanced-learn (SMOTE) | latest |
| Data handling | pandas, NumPy | pandas 2.2.x, NumPy 2.1.x (bumped from 1.26.4, same Python 3.13 reason) |
| Dataset | NSL-KDD (training notebook) — CICIDS2017/2018 documented as a drop-in swap, not yet done | pre-extracted flow features |

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
