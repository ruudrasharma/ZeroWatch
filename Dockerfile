# ZeroWatch serving image. Serving dependencies only (requirements-serve.txt):
# no MLflow, pandas or pytest, which keeps the image small and the attack surface low.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements-serve.txt .
RUN pip install -r requirements-serve.txt

COPY app.py features.py drift_check.py learning.py pcap_flows.py recon.py copilot.py ./
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
