"""
ZeroWatch — Seed script: populates model_evaluations from real training results.

Seeds the model_evaluations table with REAL precision/recall/F1/FPR numbers
from zerowatch_models/leave_one_out_results.csv (the actual notebook output).

Run once at startup if the table is empty (called from main.py startup event).

Real data (from leave_one_out_results.csv — do not replace with placeholders):
  Autoencoder, DoS:    P=0.9783, R=0.9625, F1=0.9703, FPR=0.0493
  Autoencoder, Probe:  P=0.9135, R=0.8711, F1=0.8918, FPR=0.0502
  Autoencoder, R2L:    P=0.5101, R=0.3196, F1=0.3930, FPR=0.0515
  Autoencoder, U2R:    P=0.0659, R=0.6891, F1=0.1203, FPR=0.0503
  IsolationForest, DoS:   P=0.9756, R=0.8897, F1=0.9307, FPR=0.0514
  IsolationForest, Probe:  P=0.8776, R=0.6051, F1=0.7163, FPR=0.0514
  IsolationForest, R2L:    P=0.2174, R=0.0851, F1=0.1223, FPR=0.0514
  IsolationForest, U2R:    P=0.0214, R=0.2185, F1=0.0390, FPR=0.0514
  RandomForest, DoS:   P=0.9979, R=0.8576, F1=0.9225, FPR=0.0042
  RandomForest, Probe: P=0.9722, R=0.2309, F1=0.3731, FPR=0.0040
  RandomForest, R2L:   P=0.7219, R=0.0348, F1=0.0664, FPR=0.0022
  RandomForest, U2R:   P=0.2781, R=0.3529, F1=0.3111, FPR=0.0047

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy.orm import Session, sessionmaker

from database import ModelEvaluation, engine

logger = logging.getLogger(__name__)

_SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Real results from zerowatch_models/leave_one_out_results.csv
_SEED_DATA = [
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

        for model_name, held_out, precision, recall, f1, fpr in _SEED_DATA:
            row = ModelEvaluation(
                model_name=model_name,
                held_out_category=held_out,
                precision=precision,
                recall=recall,
                f1_score=f1,
                false_positive_rate=fpr,
                evaluated_at=datetime(2026, 9, 1, 0, 0, 0),  # fixed date = notebook run
            )
            db.add(row)

        db.commit()
        logger.info("Seeded %d model_evaluation rows from leave_one_out_results.csv", len(_SEED_DATA))
    except Exception as exc:
        logger.error("Failed to seed model_evaluations: %s", exc, exc_info=True)
        db.rollback()
    finally:
        db.close()
