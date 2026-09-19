"""
ZeroWatch — Evaluations router.

GET /api/evaluations — returns leave-one-attack-out results for the Evaluation page.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import ModelEvaluation
from deps import get_db
from schemas import EvaluationOut

router = APIRouter(tags=["Evaluation"])


@router.get("/evaluations", response_model=list[EvaluationOut])
def get_evaluations(db: Session = Depends(get_db)) -> list[EvaluationOut]:
    """
    Returns leave-one-attack-out evaluation results across all models/categories.
    Seed data from zerowatch_models/leave_one_out_results.csv is loaded at startup
    (see services/seed.py).
    """
    rows = db.query(ModelEvaluation).order_by(
        ModelEvaluation.model_name, ModelEvaluation.held_out_category
    ).all()
    return [EvaluationOut.model_validate(r) for r in rows]
