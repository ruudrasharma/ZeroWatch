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
import pytest

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
