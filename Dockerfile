# ZeroWatch serving image. Serving dependencies only (requirements-serve.txt):
# no MLflow, pandas or pytest, which keeps the image small and the attack surface low.
# python:3.11-slim, pinned by digest so a rebuilt image starts from the same bytes (Dependabot bumps it)
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements-serve.txt .
# every package and its dependencies are locked to a SHA-256; pip refuses anything else
RUN pip install --require-hashes -r requirements-serve.txt

COPY app.py routes_hunt.py routes_ops.py routes_traffic.py features.py drift_check.py learning.py \
     pcap_flows.py recon.py copilot.py ops.py store.py ./
COPY model/ model/
COPY static/ static/
COPY data/sample_flows.json data/sample_capture.pcap data/

# run as a non-root user; logs/ is the only writable path
RUN useradd --create-home --uid 10001 zerowatch && mkdir -p logs && chown -R zerowatch logs
USER zerowatch

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://localhost:%s/health' % os.getenv('PORT','8000'))"

# PORT is injected by Render/Railway; defaults to 8000 locally
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}"]
