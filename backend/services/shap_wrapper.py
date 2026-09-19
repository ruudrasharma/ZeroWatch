"""
ZeroWatch — SHAP explainability wrapper.

Computes SHAP values for flagged anomaly instances.
Only called for flagged flows (not the full stream) per FEATURES.md for performance.

Handles SHAP's version-inconsistent output formats:
  - Older SHAP (< 0.41): shap_values is a list of 2D arrays, one per class
  - Newer SHAP: shap_values may be a 3D ndarray (n_samples, n_features, n_classes)
    or an Explanation object with .values attribute
Both formats are handled, matching the pattern proven in ZeroWatch_Model_Training.ipynb.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


def _extract_shap_array(shap_output: Any, sample_index: int = 0) -> np.ndarray | None:
    """
    Normalize the varied SHAP output formats into a 1D array of feature contributions.

    Handles:
      1. shap.Explanation object (.values attribute)
      2. 3D ndarray (n_samples, n_features, n_classes) — take class 1 (attack)
      3. list of 2D arrays [(n_samples, n_features), ...] — take class 1
      4. 2D ndarray (n_samples, n_features) — binary case
    """
    try:
        # Case 1: shap.Explanation object
        if hasattr(shap_output, "values"):
            values = shap_output.values
        else:
            values = shap_output

        values = np.asarray(values)

        if values.ndim == 3:
            # (n_samples, n_features, n_classes) — take attack class index
            attack_class_idx = min(1, values.shape[2] - 1)
            return values[sample_index, :, attack_class_idx]

        elif values.ndim == 2:
            return values[sample_index, :]

        elif values.ndim == 1:
            return values

        # list of arrays (one per class)
    except Exception:
        pass

    # list of 2D arrays fallback
    if isinstance(shap_output, list):
        try:
            # Take class 1 (attack class)
            class_array = np.asarray(shap_output[min(1, len(shap_output) - 1)])
            if class_array.ndim == 2:
                return class_array[sample_index, :]
            return class_array
        except Exception:
            pass

    return None


def compute_shap_for_instance(
    feature_vector: np.ndarray,
    feature_names: list[str],
    model_name: str = "autoencoder",
    top_n: int = 5,
) -> dict[str, float]:
    """
    Compute SHAP values for a single feature vector.

    For the Autoencoder, we use a KernelExplainer with a small background.
    For the RandomForest, we use TreeExplainer.

    Returns a dict mapping feature_name → SHAP contribution (top_n only).
    An empty dict is returned if SHAP is unavailable or computation fails.

    Per FEATURES.md: top 5 contributing features returned per alert.
    """
    try:
        import shap

        from services.model_loader import get_autoencoder, get_feature_cols, get_random_forest

        feature_names = feature_names or get_feature_cols()
        x = feature_vector.reshape(1, -1)

        if model_name == "random_forest":
            rf = get_random_forest()
            explainer = shap.TreeExplainer(rf)
            shap_output = explainer.shap_values(x)
        else:
            # Autoencoder — use reconstruction error as scoring function for KernelExplainer
            import torch
            ae = get_autoencoder()

            def ae_score_fn(data: np.ndarray) -> np.ndarray:
                """Returns reconstruction error per sample (shape: (n,))."""
                with torch.no_grad():
                    t = torch.FloatTensor(data)
                    recon = ae(t)
                    mse = torch.mean((t - recon) ** 2, dim=1).numpy()
                return mse

            # Small background for KernelExplainer (zeros = all-normal baseline)
            background = np.zeros((50, len(feature_names)))
            explainer = shap.KernelExplainer(ae_score_fn, background)
            shap_output = explainer.shap_values(x, nsamples=100, silent=True)

        # Normalise output format
        contributions = _extract_shap_array(shap_output, sample_index=0)

        if contributions is None:
            logger.warning("Could not extract SHAP array for model=%s", model_name)
            return {}

        # Map to dict and return top N by absolute value
        shap_dict = {
            fname: float(val)
            for fname, val in zip(feature_names, contributions)
        }
        top_features = dict(
            sorted(shap_dict.items(), key=lambda kv: abs(kv[1]), reverse=True)[:top_n]
        )
        return top_features

    except ImportError:
        logger.warning("SHAP not installed — skipping explainability")
        return {}
    except Exception as exc:  # noqa: BLE001
        logger.error("SHAP computation failed: %s", exc, exc_info=True)
        return {}
