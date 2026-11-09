"""
ZeroWatch — ML model loading service.

Loads ALL trained model artifacts from backend/models/checkpoints/ at startup.
Models are loaded once and cached in module-level singletons for reuse across
requests (avoids reload latency per ARCHITECTURE.md §ML subsystem).

Checkpoint files (real outputs from ml/scripts/train.py, a .py port of
ml/notebooks/ZeroWatch_Model_Training.ipynb — see ml/README.md):
  - autoencoder.pt                  PyTorch Autoencoder state dict
  - autoencoder_threshold.pkl       Reconstruction-error threshold scalar
  - preprocessor.pkl                sklearn ColumnTransformer (one-hot + log1p + scaling),
                                     fitted on TRAINING rows only; maps the 41 raw
                                     NSL-KDD columns → the model feature vector
  - raw_feature_cols.pkl            List[str] of the 41 raw input columns the
                                     preprocessor expects
  - feature_cols.pkl                List[str] of model feature names (preprocessor output)
  - random_forest_baseline.pkl      Trained RandomForestClassifier
  - isolation_forest.pkl            Trained IsolationForest (all-normal-traffic fit)
  - isolation_forest_threshold.pkl  Anomaly-score threshold scalar (same
                                     95th-percentile-of-training-normal
                                     convention as autoencoder_threshold.pkl)

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import torch
import torch.nn as nn

logger = logging.getLogger(__name__)

CHECKPOINT_DIR = Path(__file__).parent.parent / "models" / "checkpoints"

# ─── Global singletons (loaded once at startup) ───────────────────────────────
_autoencoder: Autoencoder | None = None
_ae_threshold: float | None = None
_preprocessor: Any | None = None
_raw_feature_cols: list[str] | None = None
_feature_cols: list[str] | None = None
_random_forest: Any | None = None
_isolation_forest: Any | None = None
_if_threshold: float | None = None
_models_ready: bool = False
_model_info: dict[str, Any] = {}


# ─── Autoencoder definition must match the one in the training notebook ───────
class Autoencoder(nn.Module):
    """
    Symmetric autoencoder used in ZeroWatch_Model_Training.ipynb (cell 13).
    Architecture: input_dim → 32 → 16 → 8 (bottleneck) → 16 → 32 → input_dim (ReLU).
    Must match exactly or the saved state_dict fails to load (shape mismatch).
    """

    def __init__(self, input_dim: int, bottleneck_dim: int = 8) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, bottleneck_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


def load_all_models() -> None:
    """
    Called once at FastAPI startup (main.py). Loads all checkpoint files.
    Logs warnings if files are missing (graceful degradation — REST endpoints
    still work, only anomaly scoring will return an error).
    """
    global _autoencoder, _ae_threshold, _preprocessor, _raw_feature_cols, _feature_cols
    global _random_forest, _isolation_forest, _if_threshold, _models_ready, _model_info

    if not CHECKPOINT_DIR.exists():
        logger.warning(
            "Checkpoint directory %s not found — anomaly scoring unavailable. "
            "Run: cp zerowatch_models/* backend/models/checkpoints/",
            CHECKPOINT_DIR,
        )
        return

    try:
        # NOTE: all .pkl checkpoints below were written with joblib.dump() by the
        # training notebook (scikit-learn's own convention for persisting
        # estimators/arrays). joblib wraps numpy arrays in a NumpyArrayWrapper with
        # out-of-band binary data, so loading with plain pickle.load() desyncs the
        # stream and raises UnpicklingError. joblib.load() transparently handles
        # both its own format and plain pickles, so it's used for all of them.

        # ── feature_cols ──────────────────────────────────────────────────────
        feature_cols_path = CHECKPOINT_DIR / "feature_cols.pkl"
        _feature_cols = joblib.load(feature_cols_path)
        logger.info("Loaded feature_cols: %d features", len(_feature_cols))

        # ── preprocessor (one-hot + log1p + scaling, fitted on train rows only) ──
        _preprocessor = joblib.load(CHECKPOINT_DIR / "preprocessor.pkl")
        _raw_feature_cols = joblib.load(CHECKPOINT_DIR / "raw_feature_cols.pkl")
        logger.info("Loaded preprocessor (%d raw columns → %d features)",
                    len(_raw_feature_cols), len(_feature_cols))

        # ── autoencoder threshold ─────────────────────────────────────────────
        threshold_path = CHECKPOINT_DIR / "autoencoder_threshold.pkl"
        _ae_threshold = joblib.load(threshold_path)
        logger.info("Loaded AE threshold: %.6f", _ae_threshold)

        # ── autoencoder weights ───────────────────────────────────────────────
        ae_path = CHECKPOINT_DIR / "autoencoder.pt"
        input_dim = len(_feature_cols)
        model = Autoencoder(input_dim)
        state = torch.load(ae_path, map_location="cpu", weights_only=True)
        model.load_state_dict(state)
        model.eval()
        _autoencoder = model
        logger.info("Loaded Autoencoder (input_dim=%d)", input_dim)

        # ── random forest baseline ────────────────────────────────────────────
        rf_path = CHECKPOINT_DIR / "random_forest_baseline.pkl"
        _random_forest = joblib.load(rf_path)
        logger.info("Loaded RandomForest baseline")

        # ── isolation forest ──────────────────────────────────────────────────
        if_path = CHECKPOINT_DIR / "isolation_forest.pkl"
        _isolation_forest = joblib.load(if_path)
        if_threshold_path = CHECKPOINT_DIR / "isolation_forest_threshold.pkl"
        _if_threshold = joblib.load(if_threshold_path)
        logger.info("Loaded IsolationForest (threshold=%.6f)", _if_threshold)

        _model_info = _build_model_info()
        _models_ready = True
        logger.info("✓ All ZeroWatch models loaded and ready")

    except FileNotFoundError as exc:
        logger.warning("Model file missing: %s — run the training notebook first", exc)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load models: %s", exc, exc_info=True)


# ─── Public scoring API ───────────────────────────────────────────────────────

def models_are_ready() -> bool:
    return _models_ready


def get_feature_cols() -> list[str]:
    if _feature_cols is None:
        raise RuntimeError("Models not loaded — call load_all_models() first")
    return _feature_cols


def get_preprocessor() -> Any:
    if _preprocessor is None:
        raise RuntimeError("Models not loaded")
    return _preprocessor


def get_raw_feature_cols() -> list[str]:
    if _raw_feature_cols is None:
        raise RuntimeError("Models not loaded")
    return _raw_feature_cols


def transform_flows(df: Any) -> np.ndarray:
    """
    Raw NSL-KDD flow records (DataFrame with the 41 raw columns) → model-ready
    float32 matrix, using the preprocessor fitted at training time. Unknown
    categorical values (a service never seen in training) become all-zero
    one-hot rows rather than errors.
    """
    cols = get_raw_feature_cols()
    return get_preprocessor().transform(df[cols]).astype(np.float32)


def get_autoencoder() -> Autoencoder:
    if _autoencoder is None:
        raise RuntimeError("Models not loaded")
    return _autoencoder


def get_ae_threshold() -> float:
    if _ae_threshold is None:
        raise RuntimeError("Models not loaded")
    return float(_ae_threshold)


def get_random_forest() -> Any:
    if _random_forest is None:
        raise RuntimeError("Models not loaded")
    return _random_forest


def get_isolation_forest() -> Any:
    if _isolation_forest is None:
        raise RuntimeError("Models not loaded")
    return _isolation_forest


def get_if_threshold() -> float:
    if _if_threshold is None:
        raise RuntimeError("Models not loaded")
    return float(_if_threshold)


def _build_model_info() -> dict[str, Any]:
    """
    Version information for the loaded checkpoints: a short SHA-256 fingerprint
    over every checkpoint file (so a deployed container can be tied to an exact
    artifact set) plus the training metadata written by ml/scripts/train.py
    (model_metadata.json: git sha, MLflow run id, seed, ...) when present.
    """
    digest = hashlib.sha256()
    for path in sorted(CHECKPOINT_DIR.glob("*")):
        if path.suffix in {".pt", ".pkl"}:
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
    info: dict[str, Any] = {
        "fingerprint": digest.hexdigest()[:12],
        "n_features": len(_feature_cols or []),
        "ae_threshold": float(_ae_threshold),
        "if_threshold": float(_if_threshold),
    }
    meta_path = CHECKPOINT_DIR / "model_metadata.json"
    if meta_path.exists():
        try:
            info["training"] = json.loads(meta_path.read_text())
        except (OSError, ValueError):
            logger.warning("Could not parse %s", meta_path)
    return info


def get_model_info() -> dict[str, Any]:
    """Fingerprint + training metadata of the loaded models ({} if not loaded)."""
    return dict(_model_info)


def score_autoencoder_batch(features: np.ndarray) -> np.ndarray:
    """
    Normalised Autoencoder reconstruction error for n flows (features: (n, d)).
    Returns shape (n,) in [0, 1]; 1.0 == at/above 2x the training-normal
    95th-percentile threshold (the UI gauge never exceeds 100%).
    """
    ae = get_autoencoder()
    threshold = get_ae_threshold()
    with torch.no_grad():
        x = torch.as_tensor(np.atleast_2d(features), dtype=torch.float32)
        mse = torch.mean((x - ae(x)) ** 2, dim=1).numpy()
    return np.minimum(mse / (threshold * 2.0), 1.0)


def score_isolation_forest_batch(features: np.ndarray) -> np.ndarray:
    """
    IsolationForest score for n flows, same normalisation as the autoencoder.
    sklearn's score_samples() is "lower = more abnormal", so it is negated.
    """
    iso = get_isolation_forest()
    threshold = get_if_threshold()
    raw = -iso.score_samples(np.atleast_2d(features))
    return np.clip(raw / (threshold * 2.0), 0.0, 1.0)


def score_random_forest_batch(features: np.ndarray) -> np.ndarray:
    """
    Random Forest attack score 1 - P(Normal) for n flows. sklearn orders
    predict_proba columns alphabetically (rf.classes_), so "Normal" is NOT
    column 0 — look its index up rather than assuming it.
    """
    rf = get_random_forest()
    proba = rf.predict_proba(np.atleast_2d(features))
    normal_idx = list(rf.classes_).index("Normal")
    return 1.0 - proba[:, normal_idx]


def score_autoencoder(features: np.ndarray) -> float:
    """Single-flow autoencoder score in [0, 1] (higher = more anomalous)."""
    return float(score_autoencoder_batch(features.reshape(1, -1))[0])


def score_isolation_forest(features: np.ndarray) -> float:
    """Single-flow IsolationForest score in [0, 1] (higher = more anomalous)."""
    return float(score_isolation_forest_batch(features.reshape(1, -1))[0])


def score_random_forest(features: np.ndarray) -> float:
    """Single-flow Random Forest attack score, 1 - P(Normal)."""
    return float(score_random_forest_batch(features.reshape(1, -1))[0])
