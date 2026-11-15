"""
ZeroWatch — stateless prediction service used by POST /api/predict[/batch].

Raw NSL-KDD records (41 fields) -> preprocessor (fitted on training rows only)
-> chosen model -> normalised score in [0, 1] where 0.5 == the 95th-percentile
-of-training-normal threshold. Instrumented with Prometheus metrics.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import time

import numpy as np
import pandas as pd

from services import metrics
from services.model_loader import (
    get_raw_feature_cols,
    score_autoencoder_batch,
    score_isolation_forest_batch,
    score_random_forest_batch,
    transform_flows,
)

SCORERS = {
    "autoencoder": score_autoencoder_batch,
    "isolation_forest": score_isolation_forest_batch,
    "random_forest": score_random_forest_batch,
}
DEFAULT_THRESHOLD = 0.5


def predict_records(
    records: list[dict], model: str, threshold: float = DEFAULT_THRESHOLD
) -> list[dict]:
    """Score raw flow records; returns one {score, is_anomaly} dict per record."""
    if model not in SCORERS:
        raise ValueError(f"unknown model {model!r}")
    start = time.perf_counter()
    df = pd.DataFrame(records)
    missing = [c for c in get_raw_feature_cols() if c not in df.columns]
    if missing:
        raise ValueError(f"missing fields: {missing[:5]}")
    scores = np.asarray(SCORERS[model](transform_flows(df)), dtype=float)
    metrics.INFERENCE_LATENCY.labels(model).observe(time.perf_counter() - start)

    out = []
    for s in scores:
        flagged = bool(s >= threshold)
        metrics.ANOMALY_SCORE.labels(model).observe(float(s))
        metrics.PREDICTIONS.labels(model, "anomaly" if flagged else "normal").inc()
        out.append({"score": round(float(s), 6), "is_anomaly": flagged})
    return out
