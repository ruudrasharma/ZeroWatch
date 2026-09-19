"""
ZeroWatch — Zero-Day Anomaly Engine: dataset replay + WebSocket streaming.

Per ARCHITECTURE.md §4 Data flow and API_SPEC.md WS endpoint:

1. Loads pre-processed NSL-KDD flow records from data/processed/.
2. Streams them over WebSocket at a configurable pace (simulated real-time).
3. Each flow is scored by the active model (Autoencoder / IF / RF).
4. Flows above threshold → flagged as alerts with SHAP values + LLM explanation.
5. Client can send {"type":"set_threshold","value":X} mid-stream to adjust live.
6. On completion → {"type":"run_completed", metrics...}

Signature comparison (Snort-style — FEATURES.md):
  A small hardcoded set of known signatures checked per flow.
  "Signature match: none" is explicitly included in alert events for zero-day flows.

Severity bucketing per FEATURES.md:
  < 0.5: not flagged
  0.5–0.7: low
  0.7–0.85: medium
  0.85–0.95: high
  > 0.95: critical

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from fastapi import WebSocket
from sqlalchemy.orm import Session

from database import Alert, DetectionRun
from services.model_loader import (
    get_ae_threshold,
    get_feature_cols,
    get_label_encoders,
    get_scaler,
    models_are_ready,
    score_autoencoder,
    score_isolation_forest,
    score_random_forest,
)
from services.ollama_service import generate_shap_explanation
from services.shap_wrapper import compute_shap_for_instance

logger = logging.getLogger(__name__)

PROCESSED_DATA_DIR = Path(__file__).parent.parent / "data" / "processed"
REPLAY_DELAY_SECONDS: float = float(os.getenv("REPLAY_DELAY_SECONDS", "0.05"))  # 20 flows/sec default

# ─── Snort-style signature rules (hardcoded, per FEATURES.md §Signature comparison) ──
_SNORT_SIGNATURES: List[Dict[str, Any]] = [
    {"name": "SYN_FLOOD", "description": "High-rate SYN packets (DoS indicator)", "field": "syn_flag_count", "op": "gt", "threshold": 100},
    {"name": "PORT_SCAN", "description": "Single src hitting many dst ports", "field": "dst_port_count", "op": "gt", "threshold": 50},
    {"name": "LARGE_PAYLOAD", "description": "Abnormally large average payload", "field": "avg_packet_size", "op": "gt", "threshold": 1400},
    {"name": "HIGH_RATE", "description": "Anomalously high packet rate", "field": "packet_rate", "op": "gt", "threshold": 10000},
]


def _check_signatures(flow_features: Dict[str, float]) -> List[str]:
    """Return list of matched signature names (empty = no match)."""
    matched = []
    for sig in _SNORT_SIGNATURES:
        field = sig["field"]
        val = flow_features.get(field)
        if val is None:
            continue
        if sig["op"] == "gt" and val > sig["threshold"]:
            matched.append(sig["name"])
    return matched


def _score_to_severity(score: float) -> Optional[str]:
    """Map anomaly score to severity bucket per FEATURES.md."""
    if score < 0.5:
        return None  # not flagged
    elif score < 0.7:
        return "low"
    elif score < 0.85:
        return "medium"
    elif score < 0.95:
        return "high"
    else:
        return "critical"


def _load_dataset(held_out_category: str) -> Optional[pd.DataFrame]:
    """
    Load the pre-processed NSL-KDD flow records from data/processed/.
    Falls back to synthetic data if no real dataset is available.
    """
    # Try to load real processed data
    for candidate in [
        PROCESSED_DATA_DIR / "nsl_kdd_test.csv",
        PROCESSED_DATA_DIR / "nsl_kdd_train.csv",
        PROCESSED_DATA_DIR / "flows.csv",
    ]:
        if candidate.exists():
            logger.info("Loading dataset from %s", candidate)
            try:
                df = pd.read_csv(candidate, nrows=5000)  # cap for demo speed
                return df
            except Exception as exc:
                logger.warning("Failed to load %s: %s", candidate, exc)

    logger.warning("No processed dataset found in %s — using synthetic demo data", PROCESSED_DATA_DIR)
    return None


def _make_synthetic_flows(n: int = 200, held_out_category: str = "DoS") -> List[Dict[str, Any]]:
    """Generate synthetic flow records for demo purposes when dataset is unavailable."""
    rng = np.random.default_rng(42)
    flows = []
    for i in range(n):
        is_attack = (i % 5 == 0)  # 20% attack rate
        flows.append(
            {
                "flow_id": f"f_{i:05d}",
                "src_ip": f"192.168.{rng.integers(1, 255)}.{rng.integers(1, 255)}",
                "dst_ip": f"10.0.{rng.integers(1, 10)}.{rng.integers(1, 50)}",
                "protocol": rng.choice(["TCP", "UDP", "ICMP"]),
                "label": held_out_category if is_attack else "BENIGN",
                "features": rng.normal(1.0 if is_attack else 0.0, 0.5, 10).tolist(),
            }
        )
    return flows


async def replay_and_stream(
    websocket: WebSocket,
    run: DetectionRun,
    db: Session,
) -> None:
    """
    Core replay loop — streams flow events over WebSocket and persists alerts.
    Handles live threshold adjustment from client messages.
    """
    threshold = run.threshold
    model_name = run.model_used
    held_out = run.held_out_category

    if not models_are_ready():
        await websocket.send_json(
            {"error": {"code": "models_not_loaded", "message": "ML models not loaded — check backend logs"}}
        )
        return

    feature_cols = get_feature_cols()
    scaler = get_scaler()
    label_encoders = get_label_encoders()

    # Load dataset
    df = _load_dataset(held_out)

    # Track metrics
    tp = fp = tn = fn = 0
    alert_count = 0

    if df is not None:
        # Preprocess flow records using the fitted scaler
        cat_cols = list(label_encoders.keys()) if label_encoders else []

        # Encode categorical columns
        for col in cat_cols:
            if col in df.columns and col in label_encoders:
                le = label_encoders[col]
                df[col] = df[col].apply(
                    lambda v: le.transform([v])[0] if v in le.classes_ else 0
                )

        # Select and fill missing feature columns
        available = [c for c in feature_cols if c in df.columns]
        if not available:
            # Feature columns don't match — fall back to synthetic
            df = None

    use_synthetic = df is None
    if use_synthetic:
        synthetic_flows = _make_synthetic_flows(200, held_out)
        flow_iterator = iter(synthetic_flows)
    else:
        flow_iterator = df.iterrows()

    # WebSocket listener task for threshold updates
    threshold_update: Dict[str, Any] = {"value": threshold}

    async def listen_for_threshold():
        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=0.01)
                data = json.loads(msg)
                if data.get("type") == "set_threshold":
                    new_val = float(data.get("value", threshold))
                    threshold_update["value"] = new_val
                    logger.info("Threshold updated to %.3f", new_val)
            except (asyncio.TimeoutError, Exception):
                break

    flow_num = 0
    try:
        for item in flow_iterator:
            current_threshold = threshold_update["value"]

            # Check for threshold update message (non-blocking)
            asyncio.create_task(listen_for_threshold())

            if use_synthetic:
                flow_data = item
                flow_id = flow_data["flow_id"]
                src_ip = flow_data["src_ip"]
                dst_ip = flow_data["dst_ip"]
                protocol = flow_data["protocol"]
                true_label = flow_data["label"]
                raw_features = np.array(flow_data["features"])
                # Pad or truncate to feature_cols length
                n_feats = len(feature_cols)
                if len(raw_features) < n_feats:
                    raw_features = np.pad(raw_features, (0, n_feats - len(raw_features)))
                else:
                    raw_features = raw_features[:n_feats]
            else:
                idx, row = item
                flow_id = f"f_{flow_num:05d}"
                src_ip = str(row.get("src_ip", f"10.0.0.{flow_num % 255}"))
                dst_ip = str(row.get("dst_ip", f"192.168.1.{flow_num % 255}"))
                protocol = str(row.get("protocol_type", row.get("protocol", "TCP")))
                true_label = str(row.get("label", row.get("class", "BENIGN")))
                # Extract numeric features
                feat_vals = []
                for c in feature_cols:
                    feat_vals.append(float(row.get(c, 0.0)))
                raw_features = np.array(feat_vals)

            flow_num += 1

            # Scale features
            try:
                scaled = scaler.transform(raw_features.reshape(1, -1))[0]
            except Exception:
                scaled = raw_features

            # Score
            try:
                if model_name == "autoencoder":
                    score = score_autoencoder(scaled)
                elif model_name == "isolation_forest":
                    score = score_isolation_forest(scaled)
                elif model_name == "random_forest":
                    score = score_random_forest(scaled)
                else:
                    score = score_autoencoder(scaled)
            except Exception as exc:
                logger.warning("Scoring error on flow %s: %s", flow_id, exc)
                score = 0.0

            severity = _score_to_severity(score)
            is_flagged = severity is not None
            is_attack = true_label.upper() not in ("BENIGN", "NORMAL", "0")

            # Update metrics
            if is_flagged and is_attack:
                tp += 1
            elif is_flagged and not is_attack:
                fp += 1
            elif not is_flagged and not is_attack:
                tn += 1
            else:
                fn += 1

            # Send flow event
            await websocket.send_json(
                {
                    "type": "flow",
                    "flow_id": flow_id,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "anomaly_score": round(score, 4),
                }
            )

            if is_flagged:
                alert_count += 1

                # SHAP (only for flagged flows — performance optimization per FEATURES.md)
                flow_features_dict = {
                    fname: float(val)
                    for fname, val in zip(feature_cols, scaled)
                }
                shap_values = compute_shap_for_instance(
                    scaled, feature_cols, model_name=model_name
                )

                # Signature comparison
                matched_sigs = _check_signatures(flow_features_dict)
                sig_text = ", ".join(matched_sigs) if matched_sigs else "none"

                # LLM explanation
                explanation = await generate_shap_explanation(
                    shap_values=shap_values,
                    anomaly_score=score,
                    threshold=current_threshold,
                    flow_context={
                        "flow_id": flow_id,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": protocol,
                        "signature_match": sig_text,
                    },
                )

                # Persist alert
                alert = Alert(
                    detection_run_id=run.id,
                    flow_id=flow_id,
                    anomaly_score=score,
                    severity=severity,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    shap_values=json.dumps(shap_values),
                    explanation=explanation,
                )
                db.add(alert)
                try:
                    db.commit()
                except Exception:
                    db.rollback()

                # Send alert event
                await websocket.send_json(
                    {
                        "type": "alert",
                        "flow_id": flow_id,
                        "anomaly_score": round(score, 4),
                        "severity": severity,
                        "shap_values": shap_values,
                        "explanation": explanation,
                        "signature_match": sig_text,  # extra field for UI display
                    }
                )

            # Paced replay
            await asyncio.sleep(REPLAY_DELAY_SECONDS)

        # ── Compute final metrics ─────────────────────────────────────────────
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        # Update run record
        run.precision = precision
        run.recall = recall
        run.f1_score = f1
        run.false_positive_rate = fpr
        from datetime import datetime
        run.completed_at = datetime.utcnow()
        try:
            db.commit()
        except Exception:
            db.rollback()

        # Send run_completed event
        await websocket.send_json(
            {
                "type": "run_completed",
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4),
            }
        )

    except Exception as exc:  # noqa: BLE001
        logger.error("Replay error for run %d: %s", run.id, exc, exc_info=True)
        await websocket.send_json(
            {"error": {"code": "replay_error", "message": str(exc)}}
        )
