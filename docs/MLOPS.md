# ZeroWatch — MLOps

How the BrainMentors MLOps workshop topics map onto ZeroWatch. Everything runs locally; the
Render deployment from the workshop is intentionally skipped (the project is local-only by design).

| Workshop topic | ZeroWatch implementation |
|---|---|
| Model serving API | `POST /api/predict`, `POST /api/predict/batch` (`backend/routers/predict.py`) |
| Health checks | `GET /health` (liveness), `GET /ready` (503 until models load) |
| Experiment tracking | MLflow: `python -m scripts.train --mlflow` (`ml/scripts/tracking.py`) |
| Model registry | MLflow registered model `zerowatch-detector`, alias `production` |
| Containerisation | multi-stage, non-root, CPU-torch `backend/Dockerfile` + `docker-compose.yml` |
| CI/CD | `.github/workflows/ci.yml`: lint/test, leakage tests, Docker build + smoke test, opt-in Docker Hub push |
| Monitoring | Prometheus `/metrics`, Grafana dashboard (`monitoring/`) |
| Logging | one JSON access-log line per request with `x-request-id` |

## Serving

```bash
curl -s localhost:8000/ready
curl -s -X POST localhost:8000/api/predict -H 'content-type: application/json' \
  -d '{"model":"autoencoder","threshold":0.5,"flow":{ ...41 raw NSL-KDD fields... }}'
```

`score` is in [0, 1]; **0.5 equals the 95th-percentile-of-training-normal threshold**, so
`threshold=0.5` reproduces the models' training-time operating point. Responses carry
`model_fingerprint`, a SHA-256 prefix over all checkpoint files, tying every prediction to an exact
artifact set. Errors use the standard `{"error": {"code", "message"}}` envelope (400 bad model or
threshold, 422 missing fields, 503 models not loaded).

## Tracking and registry

```bash
pip install -r ml/requirements.txt
docker compose --profile mlops up -d mlflow          # UI at http://localhost:5000
python -m scripts.train --mlflow --mlflow-tracking-uri http://localhost:5000   # from ml/ with PYTHONPATH=ml
```

Each run logs parameters (seed, epochs, git sha, record count), per-category F1/recall/FPR/ROC-AUC/PR-AUC,
and the full checkpoint directory. The registry version is promoted to alias `production` **only if**
its mean Autoencoder ROC-AUC across held-out categories is at least that of the current production
version (a simple quality gate). `model_metadata.json` is written next to the checkpoints and exposed
via `/ready`.

## Monitoring

```bash
docker compose --profile mlops up --build      # backend, prometheus :9090, grafana :3001 (admin / zerowatch)
```

Metrics (prefix `zerowatch_`): HTTP request count and latency, prediction counts by model and verdict,
inference latency, anomaly-score histogram, replay flow/alert counters, model-loaded gauge and
model fingerprint. The **mean anomaly score** and **alert ratio** panels are the drift signal: if live traffic
stops looking like training-normal traffic, they climb above their baseline without any labels needed.

## CI/CD

`docker` job builds the image, starts it, waits for `/ready`, and checks `/health` and `/metrics`.
To publish, add repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`; pushes to `main` then
publish `:latest` and `:<sha>`. Without the secrets those steps are skipped.

Not verified locally: the Docker image build and compose stack (no Docker daemon in the development
sandbox) — the CI `docker` job is the first real build. Everything else was exercised directly.
