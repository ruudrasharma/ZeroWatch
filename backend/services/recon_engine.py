"""
ZeroWatch — Recon Engine orchestrator.

Runs all check modules in order per ARCHITECTURE.md §3 Data flow:
  1. SSRF guard (before any scan logic — SECURITY.md §1)
  2. Parallel: SSL/TLS, headers, cookies, tech fingerprinting
  3. CVE lookup (depends on fingerprinting output)
  4. Exposed path check
  5. Subdomain check
  6. Risk scoring
  7. AI remediation generation (Ollama) per finding
  8. Persist findings + score to SQLite

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
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy.orm import Session, sessionmaker

from database import Finding, Scan, engine
from services.ollama_service import generate_finding_remediation
from services.recon.cookie_check import check_cookies
from services.recon.cve_lookup import lookup_cves
from services.recon.exposure_check import check_exposed_paths
from services.recon.header_check import check_headers
from services.recon.ssl_check import check_ssl
from services.recon.subdomain_check import check_subdomains
from services.recon.tech_fingerprint import fingerprint_tech
from services.scoring import compute_risk_score
from services.ssrf_guard import check_ssrf_guard

logger = logging.getLogger(__name__)

_SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _get_db() -> Session:
    return _SessionLocal()


def _update_scan_status(scan_id: int, status: str) -> None:
    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = status
            db.commit()
    finally:
        db.close()


async def run_scan(scan_id: int, url: str) -> None:
    """
    Background task: runs all recon checks and persists results.
    Called by the /api/scans POST endpoint via BackgroundTasks.
    """
    db = _get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error("Scan %d not found in DB", scan_id)
            return

        # ── 1. SSRF guard ─────────────────────────────────────────────────────
        try:
            check_ssrf_guard(url)
        except ValueError as exc:
            scan.status = "failed"
            db.add(
                Finding(
                    scan_id=scan_id,
                    category="ssl",
                    severity="critical",
                    title="Scan blocked by SSRF guard",
                    description=str(exc),
                    raw_data=json.dumps({"url": url}),
                )
            )
            scan.completed_at = datetime.utcnow()
            db.commit()
            return

        scan.status = "running"
        db.commit()

        all_findings: List[Dict[str, Any]] = []

        # ── 2. Parallel checks ────────────────────────────────────────────────
        ssl_task = asyncio.create_task(_safe(check_ssl, url))
        headers_task = asyncio.create_task(_safe(check_headers, url))
        cookies_task = asyncio.create_task(_safe(check_cookies, url))
        fp_task = asyncio.create_task(_safe(fingerprint_tech, url))

        ssl_findings, headers_findings, cookies_findings, fp_result = await asyncio.gather(
            ssl_task, headers_task, cookies_task, fp_task
        )

        all_findings.extend(ssl_findings)
        all_findings.extend(headers_findings)
        all_findings.extend(cookies_findings)

        # fp_result is a tuple: (findings, tech_list)
        fp_findings, tech_list = fp_result if isinstance(fp_result, tuple) else (fp_result, [])
        all_findings.extend(fp_findings)

        # ── 3. CVE lookup ────────────────────────────────────────────────────
        if tech_list:
            cve_findings = await _safe(lookup_cves, tech_list)
            all_findings.extend(cve_findings)

        # ── 4. Exposed paths ─────────────────────────────────────────────────
        exposure_findings = await _safe(check_exposed_paths, url)
        all_findings.extend(exposure_findings)

        # ── 5. Subdomains ────────────────────────────────────────────────────
        subdomain_findings = await _safe(check_subdomains, url)
        all_findings.extend(subdomain_findings)

        # ── 6. Risk score ────────────────────────────────────────────────────
        risk_score = compute_risk_score(all_findings)

        # ── 7. AI remediation per finding (Ollama) ────────────────────────────
        remediation_tasks = [
            generate_finding_remediation(f)
            for f in all_findings
        ]
        remediations = await asyncio.gather(*remediation_tasks, return_exceptions=True)

        # ── 8. Persist to DB ──────────────────────────────────────────────────
        for finding_data, remediation in zip(all_findings, remediations):
            remediation_text = (
                remediation if isinstance(remediation, str)
                else f"[Error generating remediation: {remediation}]"
            )
            db_finding = Finding(
                scan_id=scan_id,
                category=finding_data.get("category"),
                severity=finding_data.get("severity"),
                title=finding_data.get("title", ""),
                description=finding_data.get("description"),
                remediation=remediation_text,
                raw_data=json.dumps(finding_data.get("raw_data", {})),
            )
            db.add(db_finding)

        scan.risk_score = risk_score
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()
        logger.info("Scan %d completed — risk_score=%d, findings=%d", scan_id, risk_score, len(all_findings))

    except Exception as exc:  # noqa: BLE001
        logger.error("Scan %d failed: %s", scan_id, exc, exc_info=True)
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.completed_at = datetime.utcnow()
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


async def _safe(fn, *args, **kwargs):
    """Run a check function safely, returning [] on failure."""
    try:
        result = fn(*args, **kwargs)
        if asyncio.iscoroutine(result):
            return await result
        return result
    except Exception as exc:  # noqa: BLE001
        logger.warning("Check %s failed: %s", getattr(fn, "__name__", fn), exc)
        return []
