"""
ZeroWatch — MLflow experiment tracking + model registry (MLOps workshop).

Optional: train.py only imports this when --mlflow is passed, so the core
pipeline (and CI leakage tests) never depend on mlflow.

  * log_training_run  — params, per-category metrics, artifacts, one run
  * register_production — registers the shipped bundle in the MLflow Model
    Registry and points the `production` ALIAS at it (aliases replace the
    deprecated Staging/Production stages).
  * promote_if_better — only moves the alias when the new run beats the
    current production model on the gate metric (mean ROC-AUC).

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

REGISTERED_MODEL = "zerowatch-detector"
EXPERIMENT = "zerowatch-zero-day"
GATE_METRIC = "mean_roc_auc_autoencoder"


def _slug(text: str) -> str:
    return text.lower().replace(" ", "_")


def log_training_run(
    out_dir: Path, params: dict, results_df: pd.DataFrame, auc_df: pd.DataFrame,
    tracking_uri: str | None = None,
) -> str:
    """Log one training run; returns the MLflow run id."""
    import mlflow

    if tracking_uri:
        mlflow.set_tracking_uri(tracking_uri)
    mlflow.set_experiment(EXPERIMENT)
    with mlflow.start_run() as run:
        mlflow.log_params(params)
        for _, r in results_df.iterrows():
            key = f"{_slug(r['model'])}_{_slug(r['held_out_category'])}"
            mlflow.log_metrics({
                f"f1_{key}": r["f1_score"], f"recall_{key}": r["recall"],
                f"fpr_{key}": r["false_positive_rate"],
            })
        for _, r in auc_df.iterrows():
            key = f"{_slug(r['model'])}_{_slug(r['held_out_category'])}"
            mlflow.log_metrics({f"roc_auc_{key}": r["roc_auc"], f"pr_auc_{key}": r["pr_auc"]})
        for model, grp in auc_df.groupby("model"):
            mlflow.log_metric(f"mean_roc_auc_{_slug(model)}", float(grp["roc_auc"].mean()))
        mlflow.log_artifacts(str(out_dir), artifact_path="checkpoints")
        return run.info.run_id


def register_production(run_id: str, tracking_uri: str | None = None) -> str | None:
    """Register the run's checkpoints; promote to `production` only if better."""
    import mlflow
    from mlflow import MlflowClient

    if tracking_uri:
        mlflow.set_tracking_uri(tracking_uri)
    client = MlflowClient()
    new_score = client.get_run(run_id).data.metrics.get(GATE_METRIC)
    # The bundle is a set of sklearn/torch files (not one flavor model), so register
    # the run's checkpoints/ artifact directory directly as the model version source.
    try:
        client.create_registered_model(REGISTERED_MODEL)
    except Exception:  # already exists
        pass
    mv = client.create_model_version(
        REGISTERED_MODEL, source=f"runs:/{run_id}/checkpoints", run_id=run_id
    )

    try:
        current = client.get_model_version_by_alias(REGISTERED_MODEL, "production")
        cur_score = client.get_run(current.run_id).data.metrics.get(GATE_METRIC, -1.0)
    except Exception:  # no production alias yet
        cur_score = -1.0

    if new_score is not None and new_score >= cur_score:
        client.set_registered_model_alias(REGISTERED_MODEL, "production", mv.version)
        print(f"Promoted v{mv.version} to alias 'production' ({GATE_METRIC}={new_score:.4f} "
              f">= {cur_score:.4f})")
        return mv.version
    print(f"Kept current production model: new {GATE_METRIC}={new_score} < {cur_score:.4f}")
    return None
