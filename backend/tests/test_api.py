"""
ZeroWatch — backend smoke tests.

Tests the endpoint contracts exactly as defined in API_SPEC.md.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

import os
import tempfile

# Use a file-based temp SQLite so all connections share the same DB
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp_db.name}"

from fastapi.testclient import TestClient  # noqa: E402

from database import init_db  # noqa: E402
from services.seed import seed_model_evaluations  # noqa: E402

# Initialize tables immediately (before any request)
init_db()
seed_model_evaluations()

from main import app  # noqa: E402

client = TestClient(app, raise_server_exceptions=True)


def test_root():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "ZeroWatch" in resp.json()["service"]


def test_post_scan_requires_authorized():
    """POST /api/scans must reject authorized:false with 400 per API_SPEC.md."""
    resp = client.post("/api/scans", json={"target_url": "https://example.com", "authorized": False})
    assert resp.status_code == 400
    detail = resp.json().get("detail", resp.json())
    assert detail.get("error", {}).get("code") == "invalid_request"


def test_post_scan_rejects_invalid_scheme():
    """Non-http/https schemes must be rejected."""
    resp = client.post("/api/scans", json={"target_url": "ftp://example.com", "authorized": True})
    assert resp.status_code == 400


def test_get_scan_not_found():
    resp = client.get("/api/scans/99999")
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert detail["error"]["code"] == "not_found"


def test_list_scans():
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_get_evaluations():
    """GET /api/evaluations returns seeded leave-one-out results (12 rows)."""
    resp = client.get("/api/evaluations")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 12
    models = {r["model_name"] for r in rows}
    assert "Autoencoder" in models
    assert "RandomForest" in models


def test_dashboard_summary():
    resp = client.get("/api/dashboard/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_scans" in data
    assert "anomalies_flagged_7d" in data
    assert "recent_activity" in data


def test_post_detection_run_invalid_model():
    resp = client.post(
        "/api/detection-runs",
        json={"held_out_category": "DoS", "model": "bad_model", "threshold": 0.75},
    )
    assert resp.status_code == 400


def test_post_detection_run_valid():
    resp = client.post(
        "/api/detection-runs",
        json={"held_out_category": "DoS", "model": "autoencoder", "threshold": 0.75},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert "detection_run_id" in data
    assert data["status"] == "running"


def test_post_detection_run_invalid_category():
    """held_out_category must be one of the NSL-KDD attack categories."""
    resp = client.post(
        "/api/detection-runs",
        json={"held_out_category": "not_a_real_category", "model": "autoencoder", "threshold": 0.75},
    )
    assert resp.status_code == 400


def test_model_checkpoints_load_successfully():
    """
    Regression test: checkpoints in backend/models/checkpoints/ were saved with
    joblib.dump() (preprocessor.pkl, random_forest_baseline.pkl all
    wrap numpy arrays in joblib.numpy_pickle.NumpyArrayWrapper) and the Autoencoder
    checkpoint was trained with a 32-16-8 bottleneck. Loading them with plain
    pickle.load() or a mismatched architecture both fail silently (model_loader
    only logs a warning/error — anomaly scoring then silently degrades without
    ever surfacing an API error). Calls the real startup entrypoint directly
    (app startup events don't fire under a bare TestClient(app), so this can't
    rely on main.py's @app.on_event("startup") having run) and asserts it
    actually loaded, against the real checkpoint files on disk.
    """
    from services import model_loader

    model_loader.load_all_models()

    assert model_loader.models_are_ready() is True
    assert len(model_loader.get_feature_cols()) > 0
    model_loader.get_autoencoder()  # raises RuntimeError if not loaded
    model_loader.get_random_forest()
    model_loader.get_preprocessor()
    assert len(model_loader.get_raw_feature_cols()) == 41

    # isolation_forest.pkl/isolation_forest_threshold.pkl — added by
    # ml/scripts/train.py; the original notebook never produced these, so
    # score_isolation_forest() used to silently delegate to the Autoencoder's
    # score instead of actually scoring with an Isolation Forest.
    model_loader.get_isolation_forest()
    assert model_loader.get_if_threshold() > 0


def test_list_scans_min_severity_rejects_invalid_value():
    resp = client.get("/api/scans", params={"min_severity": "not_a_severity"})
    assert resp.status_code == 400


def test_ssrf_guard_blocks_localhost_target():
    """A scan against a localhost target must be created then transition to
    failed (per SECURITY.md — ALLOW_LOCALHOST_SCAN_TARGETS defaults to false)."""
    import time

    resp = client.post(
        "/api/scans", json={"target_url": "http://localhost:9", "authorized": True}
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    for _ in range(20):
        detail = client.get(f"/api/scans/{scan_id}").json()
        if detail["status"] == "failed":
            break
        time.sleep(0.1)
    assert detail["status"] == "failed"
    assert any("SSRF" in f["description"] for f in detail["findings"])


def test_signature_rules_match_nsl_kdd_records():
    """
    Regression: the Snort-style rules used to reference CICIDS-only fields
    (syn_flag_count, packet_rate, ...) that NSL-KDD records don't have, so no
    rule could ever fire and the "signature match vs AI verdict" panel was dead.
    Rules now run on the raw NSL-KDD record.
    """
    from services.anomaly_engine import _check_signatures

    syn_flood = {"count": 300, "serror_rate": 1.0, "diff_srv_rate": 0.0, "rerror_rate": 0.0,
                 "num_failed_logins": 0, "root_shell": 0, "src_bytes": 0}
    assert "SYN_FLOOD" in _check_signatures(syn_flood)

    brute_force = {"count": 1, "serror_rate": 0.0, "num_failed_logins": 4, "root_shell": 0}
    assert "BRUTE_FORCE_LOGIN" in _check_signatures(brute_force)

    quiet_web_request = {"count": 3, "serror_rate": 0.0, "diff_srv_rate": 0.0, "rerror_rate": 0.0,
                         "num_failed_logins": 0, "root_shell": 0, "src_bytes": 230}
    assert _check_signatures(quiet_web_request) == []
    assert _check_signatures({}) == []  # synthetic flows carry no raw record → nothing fires


def test_random_forest_score_looks_up_the_normal_class():
    """
    Regression: score_random_forest() assumed class 0 was "Normal". sklearn orders
    predict_proba columns alphabetically, so with classes [DoS, Normal, R2L, U2R]
    the old code ignored the DoS probability and counted P(Normal) as an attack.
    """
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier

    from services import model_loader

    rng = np.random.RandomState(0)
    x = np.vstack([rng.normal(-3, 0.3, (40, 2)), rng.normal(0, 0.3, (40, 2)),
                   rng.normal(3, 0.3, (40, 2))])
    y = np.array(["DoS"] * 40 + ["Normal"] * 40 + ["R2L"] * 40)
    rf = RandomForestClassifier(n_estimators=25, random_state=0).fit(x, y)
    assert list(rf.classes_)[0] != "Normal"  # the trap the old code fell into

    original = model_loader._random_forest
    model_loader._random_forest = rf
    try:
        assert model_loader.score_random_forest(np.array([-3.0, -3.0])) > 0.9   # clear DoS
        assert model_loader.score_random_forest(np.array([0.0, 0.0])) < 0.1     # clear Normal
    finally:
        model_loader._random_forest = original


def test_transform_flows_matches_model_input_dim():
    """The saved preprocessor must turn raw NSL-KDD records into exactly the
    feature vector the Autoencoder was trained on, including unseen categories."""
    import numpy as np
    import pandas as pd

    from services import model_loader

    model_loader.load_all_models()
    raw_cols = model_loader.get_raw_feature_cols()
    row = {c: 0 for c in raw_cols}
    row.update({"protocol_type": "tcp", "service": "http", "flag": "SF"})
    unseen = dict(row, service="a_service_never_seen_in_training")

    x = model_loader.transform_flows(pd.DataFrame([row, unseen]))
    assert x.shape == (2, len(model_loader.get_feature_cols()))
    assert np.isfinite(x).all()
    assert 0.0 <= model_loader.score_autoencoder(x[0]) <= 1.0


# ─── MLOps: health / readiness / predict / metrics ───────────────────────────
_SAMPLE_FLOW = {
    "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF",
    "src_bytes": 181, "dst_bytes": 5450, "land": 0, "wrong_fragment": 0, "urgent": 0,
    "hot": 0, "num_failed_logins": 0, "logged_in": 1, "num_compromised": 0,
    "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
    "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0, "is_host_login": 0,
    "is_guest_login": 0, "count": 8, "srv_count": 8, "serror_rate": 0.0,
    "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
    "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
    "dst_host_count": 9, "dst_host_srv_count": 9, "dst_host_same_srv_rate": 1.0,
    "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 0.11,
    "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
    "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
    "dst_host_srv_rerror_rate": 0.0,
}


def test_health_and_ready() -> None:
    with TestClient(app) as c:
        h = c.get("/health").json()
        assert h["status"] == "ok" and h["models_loaded"] is True
        assert h["model_fingerprint"]
        assert c.get("/ready").status_code == 200


def test_predict_all_models_return_unit_scores() -> None:
    with TestClient(app) as c:
        for model in ("autoencoder", "isolation_forest", "random_forest"):
            r = c.post("/api/predict", json={"flow": _SAMPLE_FLOW, "model": model})
            assert r.status_code == 200, r.text
            body = r.json()
            assert 0.0 <= body["score"] <= 1.0
            assert body["is_anomaly"] == (body["score"] >= body["threshold"])


def test_predict_batch_matches_single() -> None:
    with TestClient(app) as c:
        one = c.post("/api/predict", json={"flow": _SAMPLE_FLOW}).json()["score"]
        batch = c.post("/api/predict/batch", json={"flows": [_SAMPLE_FLOW] * 3}).json()
        assert [r["score"] for r in batch["results"]] == [one] * 3


def test_predict_rejects_bad_input() -> None:
    with TestClient(app) as c:
        assert c.post("/api/predict", json={"flow": {"duration": 1}}).status_code == 422
        bad_model = c.post("/api/predict", json={"flow": _SAMPLE_FLOW, "model": "nope"})
        assert bad_model.status_code == 400
        assert c.post("/api/predict/batch", json={"flows": []}).status_code == 400


def test_metrics_and_request_id() -> None:
    with TestClient(app) as c:
        r = c.get("/health", headers={"x-request-id": "abc123"})
        assert r.headers["x-request-id"] == "abc123"
        c.post("/api/predict", json={"flow": _SAMPLE_FLOW})
        text = c.get("/metrics").text
        assert "zerowatch_predictions_total" in text
        assert "zerowatch_http_requests_total" in text
        assert "zerowatch_models_loaded 1.0" in text
