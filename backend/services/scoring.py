"""
ZeroWatch — Risk scoring function.

Weighted composite risk score 0–100 per FEATURES.md:
  "critical findings weighted heaviest, informational passes reduce score toward 0"

Formula (documented here and in sync with FEATURES.md as required):
  Base score = sum of finding weights
  Finding weights:
    critical → 25
    high     → 15
    medium   →  8
    low      →  2  (penalty for noise / informational issues)
    pass     →  0  (all-clear findings actively reduce toward 0)

  score = min(100, base_score)  — capped at 100
  If ALL findings are passes → score = 0

  The intent is that a single critical finding (e.g. exposed .env) yields ≥25 points,
  a site with 4+ critical findings is 100, and a clean site converges to ~0.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

from typing import Any

# Weight per severity level
SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 2,
    "info": 0,
    "pass": 0,
}

# All-clear finding titles contain these keywords — count them as passes (weight 0)
PASS_KEYWORDS = (
    "looks healthy",
    "all recommended",
    "all cookies have",
    "no sensitive paths",
    "no subdomains found",
    "no recognisable",
    "informational",
)


def _is_pass_finding(finding: dict[str, Any]) -> bool:
    """Detect informational 'all clear' findings that should not increase score."""
    severity = (finding.get("severity") or "").lower()
    title = (finding.get("title") or "").lower()
    if severity in ("info", "pass"):
        return True
    if any(kw in title for kw in PASS_KEYWORDS):
        return True
    return False


def compute_risk_score(findings: list[dict[str, Any]]) -> int:
    """
    Compute a composite risk score 0–100 from a list of finding dicts.

    Each finding must have a 'severity' key.
    Returns an integer in [0, 100].
    """
    if not findings:
        return 0

    total = 0
    for f in findings:
        if _is_pass_finding(f):
            continue
        severity = (f.get("severity") or "low").lower()
        total += SEVERITY_WEIGHTS.get(severity, 2)

    return min(100, total)
