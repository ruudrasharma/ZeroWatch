# Deployment — ZeroWatch (local-only)

ZeroWatch is designed to run entirely on `localhost`. There is no cloud deployment target for v1 — this document covers local run, Docker packaging for a one-command demo, and the CI pipeline that keeps the repo healthy (without deploying anywhere).

## 1. Manual local run (three terminals)

```bash
# Terminal 1 — local LLM
ollama serve
ollama pull llama3.1:8b     # first time only

# Terminal 2 — backend
cd backend
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # fill in VIRUSTOTAL_API_KEY at minimum
uvicorn main:app --reload --port 8000

# Terminal 3 — frontend
cd frontend
npm install
cp .env.local.example .env.local
npm run dev
```

Open `http://localhost:3000`.

## 2. One-command run via Docker Compose (recommended for demo day)

`docker-compose.yml` at repo root defines three services:

```yaml
services:
  ollama:
    image: ollama/ollama
    ports: ["11434:11434"]
    volumes: ["ollama_data:/root/.ollama"]

  backend:
    build: ./backend
    ports: ["8000:8000"]
    env_file: ./backend/.env
    depends_on: [ollama]
    volumes: ["./backend/data:/app/data"]

  frontend:
    build: ./frontend
    ports: ["3000:3000"]
    env_file: ./frontend/.env.local
    depends_on: [backend]

volumes:
  ollama_data:
```

```bash
docker-compose up --build
# first run: separately exec into the ollama container to pull the model
docker exec -it <ollama_container_id> ollama pull llama3.1:8b
```

Then open `http://localhost:3000`. This is the single strongest thing to show a judge: one command, fully offline after the initial model pull, zero cloud dependency.

## 3. Build commands (for CI / manual verification, no deploy step)

```bash
# Frontend production build (verifies it compiles cleanly)
cd frontend && npm run build

# Backend — no build step needed (interpreted), but verify imports/lint clean
cd backend && ruff check . && python -c "import main"
```

## 4. CI pipeline (GitHub Actions) — verification only, no deployment

`.github/workflows/ci.yml` should run on every push/PR:

1. **Backend job**: set up Python 3.11, install `requirements.txt`, run `ruff check`, run `pytest`.
2. **Frontend job**: set up Node 18, `npm ci`, `npm run lint`, `npm run build`.
3. (Optional) **ML job**: run a fast subset of the leave-one-attack-out evaluation on a small fixture dataset to catch training-pipeline regressions, kept separate from the full dataset run (which is too slow for CI).

No deploy job — CI exists purely to keep `main` in a known-good, demo-ready state.

## 5. Release/versioning for submission

- Tag the commit used for your final academic submission/demo: `git tag -a v1.0-submission -m "Final submission for [course/event]"` and push tags — this gives you (and evaluators) an exact, citable snapshot separate from ongoing development.

## 6. What's explicitly NOT here

- No Vercel/Netlify/cloud hosting config — intentional per project scope (see PRD.md §7 Constraints)
- No Kubernetes/orchestration — unnecessary at this scale
- No production secrets management (Vault, AWS Secrets Manager) — `.env` is sufficient for a local single-user tool, documented as an upgrade path in SECURITY.md
