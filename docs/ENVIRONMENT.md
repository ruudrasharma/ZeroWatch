# Environment — ZeroWatch

## Required local services

| Service | How to install | How to run |
|---|---|---|
| Ollama | https://ollama.com/download | `ollama serve` (runs on `localhost:11434`) |
| Python 3.11+ | python.org or pyenv | — |
| Node.js 18+ | nodejs.org or nvm | — |

## Backend `.env` (in `backend/.env`)

```bash
# Local LLM
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1:8b

# Database
DATABASE_URL=sqlite:///./zerowatch.db

# External free APIs
NVD_API_KEY=                # optional — raises rate limit from 5/30s to 50/30s, leave blank to use unauthenticated tier
VIRUSTOTAL_API_KEY=         # required for VirusTotal checks — get free key at virustotal.com
SHODAN_API_KEY=             # optional — only needed if Shodan checks are enabled

# App
BACKEND_PORT=8000
FRONTEND_ORIGIN=http://localhost:3000
ALLOW_LOCALHOST_SCAN_TARGETS=false   # set true only when testing against local sandbox targets (Juice Shop/DVWA)

# Rate limiting for outbound free-API calls (requests per window, seconds)
NVD_RATE_LIMIT=5
NVD_RATE_WINDOW_SECONDS=30
VIRUSTOTAL_RATE_LIMIT=4
VIRUSTOTAL_RATE_WINDOW_SECONDS=60
```

## Frontend `.env.local` (in `frontend/.env.local`)

```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000/api
NEXT_PUBLIC_WS_BASE_URL=ws://localhost:8000/api
```

## `.env.example` files

Both `backend/.env.example` and `frontend/.env.local.example` should be committed to the repo with the same keys and empty/placeholder values, so anyone cloning the repo knows exactly what to fill in. The real `.env` / `.env.local` files must be listed in `.gitignore`.

## Getting the required free API keys

- **VirusTotal**: sign up at virustotal.com → API key in account settings (free tier: 4 requests/minute, 500/day)
- **NVD API key (optional)**: request at nvd.nist.gov/developers/request-an-api-key — not required to function, just raises the rate limit
- **Shodan (optional)**: sign up at shodan.io → free tier gives 100 one-time query credits

## Model files (not committed to git)

- Ollama models are pulled locally via `ollama pull <model>` and stored in Ollama's own local model directory — never committed to the repo.
- Trained Autoencoder/Isolation Forest/RF checkpoints are saved to `backend/models/checkpoints/` and should be `.gitignore`d if large; provide a `scripts/train.py` so they can be regenerated instead of version-controlling binary model files. If checkpoint size is small enough to be worth keeping in the repo for reproducibility, use Git LFS.

## Dataset setup

- CICIDS2017/2018 is not redistributed in the repo (large, licensed for research use). `docs/ENVIRONMENT.md` should link to the official download source, and `scripts/prepare_data.py` should document the expected raw file layout under `data/raw/` and output the processed flow feature files to `data/processed/`.
