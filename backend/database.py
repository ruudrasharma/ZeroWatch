"""
ZeroWatch — SQLAlchemy ORM models, exactly matching DATABASE_SCHEMA.md.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import os

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Text,
    create_engine,
    text,
)
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func

DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./zerowatch.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # needed for SQLite + async
    echo=False,
)


class Base(DeclarativeBase):
    pass


# ──────────────────────────────────────────────────────────────────────────────
# users  (optional stub — nullable foreign keys used throughout)
# ──────────────────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(Text, unique=True, nullable=False)
    display_name = Column(Text)
    created_at = Column(DateTime, server_default=func.current_timestamp())

    scans = relationship("Scan", back_populates="user")
    detection_runs = relationship("DetectionRun", back_populates="user")


# ──────────────────────────────────────────────────────────────────────────────
# scans  (Recon Engine runs)
# ──────────────────────────────────────────────────────────────────────────────
class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    target_url = Column(Text, nullable=False)
    # status: pending | running | completed | failed
    status = Column(Text, nullable=False, default="pending")
    risk_score = Column(Integer, nullable=True)  # 0–100
    started_at = Column(DateTime, server_default=func.current_timestamp())
    completed_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


# ──────────────────────────────────────────────────────────────────────────────
# findings  (one scan → many findings)
# ──────────────────────────────────────────────────────────────────────────────
class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    # category: ssl | headers | cookies | cve | exposure | subdomain
    category = Column(Text)
    # severity: low | medium | high | critical
    severity = Column(Text)
    title = Column(Text, nullable=False)
    description = Column(Text)
    remediation = Column(Text)  # AI-generated
    raw_data = Column(Text)  # JSON blob

    scan = relationship("Scan", back_populates="findings")


# ──────────────────────────────────────────────────────────────────────────────
# detection_runs  (Zero-Day Anomaly Engine sessions)
# ──────────────────────────────────────────────────────────────────────────────
class DetectionRun(Base):
    __tablename__ = "detection_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    held_out_category = Column(Text, nullable=False)
    # model_used: autoencoder | isolation_forest | random_forest
    model_used = Column(Text, nullable=False)
    threshold = Column(Float, nullable=False)
    started_at = Column(DateTime, server_default=func.current_timestamp())
    completed_at = Column(DateTime, nullable=True)
    # metrics filled at completion
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    false_positive_rate = Column(Float, nullable=True)

    user = relationship("User", back_populates="detection_runs")
    alerts = relationship("Alert", back_populates="detection_run", cascade="all, delete-orphan")


# ──────────────────────────────────────────────────────────────────────────────
# alerts  (individual flagged flows within a detection run)
# ──────────────────────────────────────────────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    detection_run_id = Column(Integer, ForeignKey("detection_runs.id"), nullable=False)
    flow_id = Column(Text, nullable=False)
    anomaly_score = Column(Float, nullable=False)
    # severity: low | medium | high | critical
    severity = Column(Text)
    src_ip = Column(Text)
    dst_ip = Column(Text)
    protocol = Column(Text)
    shap_values = Column(Text)   # JSON blob: feature name → contribution weight
    explanation = Column(Text)   # AI-generated plain-English explanation
    flagged_at = Column(DateTime, server_default=func.current_timestamp())

    detection_run = relationship("DetectionRun", back_populates="alerts")


# ──────────────────────────────────────────────────────────────────────────────
# model_evaluations  (leave-one-attack-out results — reference table)
# ──────────────────────────────────────────────────────────────────────────────
class ModelEvaluation(Base):
    __tablename__ = "model_evaluations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    model_name = Column(Text, nullable=False)
    held_out_category = Column(Text, nullable=False)
    precision = Column(Float)
    recall = Column(Float)
    f1_score = Column(Float)
    false_positive_rate = Column(Float)
    evaluated_at = Column(DateTime, server_default=func.current_timestamp())


# ──────────────────────────────────────────────────────────────────────────────
# Indexes (per DATABASE_SCHEMA.md)
# ──────────────────────────────────────────────────────────────────────────────
Index("ix_scans_target_url", Scan.target_url)
Index("ix_scans_status", Scan.status)
Index("ix_findings_scan_id", Finding.scan_id)
Index("ix_detection_runs_held_out_category", DetectionRun.held_out_category)
Index("ix_alerts_detection_run_id", Alert.detection_run_id)
Index("ix_alerts_severity", Alert.severity)


def init_db() -> None:
    """Create all tables if they don't already exist (simple create_all approach)."""
    Base.metadata.create_all(bind=engine)
