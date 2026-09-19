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
    joblib.dump() (scaler.pkl, label_encoders.pkl, random_forest_baseline.pkl all
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
    model_loader.get_scaler()

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
