"""
ZeroWatch — Seed script: populates model_evaluations from real training results.

Seeds the model_evaluations table with REAL precision/recall/F1/FPR numbers
from backend/models/checkpoints/leave_one_out_results.csv — the actual output
of ml/scripts/train.py (see ml/README.md), the same file the training
notebook produces.

Run once at startup if the table is empty (called from main.py startup event).

Reads the CSV directly rather than hardcoding the numbers in this file: the
two drifted out of sync once already (hardcoded values here were the
original Colab run's numbers; a `python -m ml.scripts.train` re-run produces
slightly different — still real, not placeholder — numbers each time, per
floating-point/platform nondeterminism even at a fixed SEED). Reading the
CSV as the source of truth means the seeded `model_evaluations` table always
matches whatever checkpoints are actually loaded, with no separate step to
remember. A small hardcoded fallback covers a fresh clone that hasn't run
the training script yet — see _FALLBACK_SEED_DATA below.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import csv
import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy.orm import sessionmaker

from database import Alert, DetectionRun, Finding, ModelEvaluation, Scan, engine

logger = logging.getLogger(__name__)

_SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

_RESULTS_CSV = Path(__file__).parent.parent / "models" / "checkpoints" / "leave_one_out_results.csv"

# Used only if _RESULTS_CSV doesn't exist yet (a fresh clone before anyone has
# run `python -m ml.scripts.train`) — the original Colab-trained numbers, so
# the Evaluation page still shows real (if slightly stale) data rather than
# nothing.
_FALLBACK_SEED_DATA = [
    # (model_name, held_out_category, precision, recall, f1_score, false_positive_rate)
    ("Autoencoder",           "DoS",   0.9782952230451422, 0.9624627718358402, 0.9703144179019922, 0.04931649074234297),
    ("IsolationForest",       "DoS",   0.9755987347492092, 0.8896922471762788, 0.9306672675438167, 0.05139297456307319),
    ("RandomForest",          "DoS",   0.9978859733240345, 0.8576432464832262, 0.9224647681598855, 0.004196227721059007),
    ("Autoencoder",           "Probe", 0.9135066676599866, 0.871066278326348,  0.8917818181818182, 0.05022495241391244),
    ("IsolationForest",       "Probe", 0.8776014836183804, 0.6051005185764012, 0.7163099693058067, 0.05139297456307319),
    ("RandomForest",          "Probe", 0.9721806760394855, 0.23087305533849542, 0.373134328358209, 0.004023187402664821),
    ("Autoencoder",           "R2L",   0.5100781571369807, 0.31958762886597936, 0.3929646648708604, 0.05152275480186883),
    ("IsolationForest",       "R2L",   0.21739130434782608, 0.08505154639175258, 0.12226750648388292, 0.05139297456307319),
    ("RandomForest",          "R2L",   0.7219251336898396, 0.03479381443298969, 0.06638800098352594, 0.002249524139124416),
    ("Autoencoder",           "U2R",   0.06591639871382636, 0.6890756302521008, 0.12032281731474688, 0.05026821249351099),
    ("IsolationForest",       "U2R",   0.0214168039538715,  0.2184873949579832, 0.03900975243810953, 0.05139297456307319),
    ("RandomForest",          "U2R",   0.2781456953642384,  0.35294117647058826, 0.3111111111111111, 0.004715348676241564),
]


def _load_seed_rows() -> list[tuple[str, str, float, float, float, float]]:
    if not _RESULTS_CSV.exists():
        logger.warning(
            "%s not found — seeding model_evaluations from the fallback data "
            "baked into this file instead. Run `python -m ml.scripts.train "
            "--output-dir backend/models/checkpoints` to generate real checkpoints.",
            _RESULTS_CSV,
        )
        return _FALLBACK_SEED_DATA

    rows = []
    with open(_RESULTS_CSV, newline="") as f:
        for row in csv.DictReader(f):
            rows.append((
                row["model"],
                row["held_out_category"],
                float(row["precision"]),
                float(row["recall"]),
                float(row["f1_score"]),
                float(row["false_positive_rate"]),
            ))
    return rows


def seed_model_evaluations() -> None:
    """
    Insert real leave-one-out evaluation results into model_evaluations table.
    Skips if data already exists (idempotent).
    """
    db = _SessionLocal()
    try:
        existing = db.query(ModelEvaluation).count()
        if existing > 0:
            logger.info("model_evaluations already seeded (%d rows) — skipping", existing)
            return

        seed_rows = _load_seed_rows()
        for model_name, held_out, precision, recall, f1, fpr in seed_rows:
            row = ModelEvaluation(
                model_name=model_name,
                held_out_category=held_out,
                precision=precision,
                recall=recall,
                f1_score=f1,
                false_positive_rate=fpr,
            )
            db.add(row)

        db.commit()
        logger.info("Seeded %d model_evaluation rows from %s", len(seed_rows), _RESULTS_CSV.name)
    except Exception as exc:
        logger.error("Failed to seed model_evaluations: %s", exc, exc_info=True)
        db.rollback()
    finally:
        db.close()


# ──────────────────────────────────────────────────────────────────────────────
# Demo history — TODO.md Phase 4: "Seed script for demo-ready sample
# History/Dashboard data". Populates a handful of sample scans/detection runs
# so the Dashboard/History pages aren't empty on first run (USER_FLOWS.md Flow
# 5's optional pre-demo step). Skips if scans/detection_runs already have any
# rows — never runs against real scan data, and never touches a fresh-but-
# already-used database. Disable with SEED_DEMO_DATA=false in .env.
# ──────────────────────────────────────────────────────────────────────────────
_SAMPLE_SCANS = [
    {
        "target_url": "https://juice-shop.example-sandbox.local",
        "risk_score": 78,
        "days_ago": 1,
        "findings": [
            ("exposure", "critical", "Exposed .env file at /.env", "The file /.env was reachable and returned HTTP 200, exposing configuration that may include secrets.", "Move environment files outside the web root and add a server-level deny rule for dotfiles."),
            ("headers", "high", "Missing security header: Content-Security-Policy", "CSP prevents cross-site scripting (XSS) by restricting which content sources the browser will load.", "Add a Content-Security-Policy header starting from a strict default-src 'self' and loosen only as needed."),
            ("cookies", "high", "Session cookie missing Secure flag", "The session cookie is set without the Secure attribute, so it can be sent over plain HTTP.", "Set the Secure attribute on all session cookies once the site is served exclusively over HTTPS."),
            ("cve", "medium", "Outdated jQuery 1.12.4 with known CVEs", "Fingerprinted jQuery 1.12.4, which has several published XSS-related CVEs.", "Upgrade to a current jQuery release or remove the dependency if unused."),
            ("ssl", "low", "SSL/TLS configuration looks healthy", "Certificate is valid, protocol is TLS 1.2+, no weak ciphers detected.", "No action needed — informational pass."),
        ],
    },
    {
        "target_url": "https://staging.example-corp.dev",
        "risk_score": 23,
        "days_ago": 3,
        "findings": [
            ("headers", "medium", "Missing security header: X-Frame-Options", "Prevents the page from being embedded in iframes on other origins, protecting against clickjacking.", "Add X-Frame-Options: DENY or an equivalent frame-ancestors CSP directive."),
            ("subdomain", "low", "Stale subdomain found via crt.sh: old-api.example-corp.dev", "A certificate exists for a subdomain that no longer resolves to an active service.", "Revoke the unused certificate and remove the DNS record if the subdomain is decommissioned."),
            ("ssl", "low", "SSL/TLS configuration looks healthy", "Certificate is valid, protocol is TLS 1.2+, no weak ciphers detected.", "No action needed — informational pass."),
        ],
    },
    {
        "target_url": "https://blog.example-corp.dev",
        "risk_score": 100,
        "days_ago": 5,
        "findings": [
            ("exposure", "critical", "Exposed .git/config at /.git/config", "The Git repository metadata is publicly accessible, which can leak source code history and remote URLs.", "Block access to /.git/ at the web-server level or remove the directory from the deployed artifact."),
            ("exposure", "critical", "Exposed /.aws/credentials", "A file matching a common AWS credentials path returned HTTP 200.", "Rotate any exposed credentials immediately and remove the file from the web root."),
            ("cookies", "high", "Session cookie missing HttpOnly flag", "Without HttpOnly, the cookie is readable by JavaScript, widening the impact of any XSS.", "Set HttpOnly on all session/auth cookies."),
            ("cve", "high", "WordPress 5.2 with known CVEs", "Fingerprinted an outdated WordPress core version with several published high-severity CVEs.", "Upgrade WordPress core and all plugins to current releases."),
        ],
    },
    {
        "target_url": "https://api.example-corp.dev",
        "risk_score": None,
        "days_ago": 0,
        "status": "failed",
        "findings": [
            ("security", "critical", "Scan blocked by SSRF guard", "SSRF guard: 'api.example-corp.dev' resolves to a private IP. Set ALLOW_LOCALHOST_SCAN_TARGETS=true in .env to override.", None),
        ],
    },
]

_SAMPLE_RUNS = [
    {
        "held_out_category": "DoS",
        "model_used": "autoencoder",
        "threshold": 0.7,
        "days_ago": 1,
        "precision": 0.9783,
        "recall": 0.9625,
        "f1_score": 0.9703,
        "false_positive_rate": 0.0493,
        "alerts": [
            ("f_00042", 0.91, "high", "192.168.14.22", "10.0.2.9", "TCP", {"syn_flag_count": 0.41, "packet_rate": 0.33, "dst_port_count": 0.12}),
            ("f_00107", 0.97, "critical", "192.168.201.5", "10.0.4.18", "UDP", {"packet_rate": 0.52, "avg_packet_size": 0.29}),
        ],
    },
    {
        "held_out_category": "Probe",
        "model_used": "isolation_forest",
        "threshold": 0.65,
        "days_ago": 4,
        "precision": 0.8776,
        "recall": 0.6051,
        "f1_score": 0.7163,
        "false_positive_rate": 0.0514,
        "alerts": [
            ("f_00019", 0.72, "medium", "192.168.9.201", "10.0.1.4", "TCP", {"dst_port_count": 0.61, "same_srv_rate": -0.22}),
        ],
    },
]


def seed_demo_history() -> None:
    """Populate sample scans + detection runs for a demo-ready first run."""
    if os.getenv("SEED_DEMO_DATA", "true").lower() == "false":
        logger.info("SEED_DEMO_DATA=false — skipping demo history seed")
        return

    db = _SessionLocal()
    try:
        if db.query(Scan).count() > 0 or db.query(DetectionRun).count() > 0:
            logger.info("scans/detection_runs already have data — skipping demo history seed")
            return

        now = datetime.utcnow()

        for sample in _SAMPLE_SCANS:
            started = now - timedelta(days=sample["days_ago"], hours=2)
            status = sample.get("status", "completed")
            scan = Scan(
                target_url=sample["target_url"],
                status=status,
                risk_score=sample["risk_score"],
                started_at=started,
                completed_at=started + timedelta(seconds=18),
            )
            db.add(scan)
            db.flush()  # assign scan.id before creating findings
            for category, severity, title, description, remediation in sample["findings"]:
                db.add(
                    Finding(
                        scan_id=scan.id,
                        category=category,
                        severity=severity,
                        title=title,
                        description=description,
                        remediation=remediation,
                        raw_data=json.dumps({"seed": True}),
                    )
                )

        for sample in _SAMPLE_RUNS:
            started = now - timedelta(days=sample["days_ago"], hours=1)
            run = DetectionRun(
                held_out_category=sample["held_out_category"],
                model_used=sample["model_used"],
                threshold=sample["threshold"],
                started_at=started,
                completed_at=started + timedelta(seconds=12),
                precision=sample["precision"],
                recall=sample["recall"],
                f1_score=sample["f1_score"],
                false_positive_rate=sample["false_positive_rate"],
            )
            db.add(run)
            db.flush()
            for flow_id, score, severity, src_ip, dst_ip, protocol, shap in sample["alerts"]:
                db.add(
                    Alert(
                        detection_run_id=run.id,
                        flow_id=flow_id,
                        anomaly_score=score,
                        severity=severity,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol=protocol,
                        shap_values=json.dumps(shap),
                        explanation=(
                            "Sample seed data for demo purposes — not a live model call. "
                            "Run a real detection replay to see genuine AI-generated explanations."
                        ),
                        flagged_at=started + timedelta(seconds=5),
                    )
                )

        db.commit()
        logger.info(
            "Seeded demo history: %d scans, %d detection runs",
            len(_SAMPLE_SCANS),
            len(_SAMPLE_RUNS),
        )
    except Exception as exc:
        logger.error("Failed to seed demo history: %s", exc, exc_info=True)
        db.rollback()
    finally:
        db.close()
