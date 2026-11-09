# ZeroWatch backend — multi-stage, non-root, CPU-only torch (MLOps workshop: Docker).
# Stage 1 builds wheels/venv with the compiler toolchain; stage 2 ships only the
# runtime, so the final image carries no build tools.

FROM python:3.11-slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libxml2-dev libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
# CPU wheels for torch (the +cpu build satisfies torch==2.6.0) keep the image
# ~1.5 GB smaller than the default CUDA build.
RUN pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu \
        -r requirements.txt

FROM python:3.11-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libxml2 libxslt1.1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 zerowatch
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1
WORKDIR /app
COPY --chown=zerowatch:zerowatch . .
RUN mkdir -p data/exports data/pcaps data/processed data/raw models/checkpoints \
    && chown -R zerowatch:zerowatch data models
USER zerowatch

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/ready').status==200 else 1)"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
