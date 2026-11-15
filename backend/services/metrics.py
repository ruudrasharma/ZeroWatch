"""
ZeroWatch — Prometheus metrics (MLOps workshop: monitoring).

All metrics live in the default prometheus_client registry and are exposed at
GET /metrics. Prometheus scrapes it (monitoring/prometheus.yml) and Grafana
charts it (monitoring/grafana/...).

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

HTTP_REQUESTS = Counter(
    "zerowatch_http_requests_total",
    "HTTP requests handled",
    ["method", "path", "status"],
)
HTTP_LATENCY = Histogram(
    "zerowatch_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)

PREDICTIONS = Counter(
    "zerowatch_predictions_total",
    "Flows scored, by model and verdict",
    ["model", "verdict"],
)
ANOMALY_SCORE = Histogram(
    "zerowatch_anomaly_score",
    "Normalised anomaly score of scored flows (0.5 == training threshold); "
    "a drifting distribution signals data drift",
    ["model"],
    buckets=(0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
)
INFERENCE_LATENCY = Histogram(
    "zerowatch_inference_duration_seconds",
    "Time spent preprocessing + scoring one request",
    ["model"],
    buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1),
)
PREDICT_ERRORS = Counter(
    "zerowatch_predict_errors_total", "Prediction requests that failed", ["reason"]
)

MODELS_LOADED = Gauge("zerowatch_models_loaded", "1 if all model artifacts are loaded")
MODEL_INFO = Gauge(
    "zerowatch_model_info",
    "Constant 1; labels identify the deployed model artifact set",
    ["fingerprint"],
)
REPLAY_ALERTS = Counter(
    "zerowatch_replay_alerts_total", "Alerts raised during WebSocket replay runs", ["model"]
)
REPLAY_FLOWS = Counter(
    "zerowatch_replay_flows_total", "Flows streamed during replay runs", ["model"]
)
