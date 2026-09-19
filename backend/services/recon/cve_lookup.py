"""
ZeroWatch — Recon Engine: NVD CVE lookup.

For each fingerprinted tech + version, queries the NIST NVD REST API v2.0
for known CVEs. Per FEATURES.md: findings include CVE ID, CVSS score (→ severity),
and a short description that the Ollama service will later expand.

Rate limiting: respects NVD_RATE_LIMIT/NVD_RATE_WINDOW_SECONDS env vars.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List, Optional

import httpx

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY: Optional[str] = os.getenv("NVD_API_KEY") or None
NVD_RATE_LIMIT: int = int(os.getenv("NVD_RATE_LIMIT", "5"))
NVD_RATE_WINDOW: float = float(os.getenv("NVD_RATE_WINDOW_SECONDS", "30"))

# Semaphore to enforce rate limiting across concurrent calls
_semaphore = asyncio.Semaphore(NVD_RATE_LIMIT)


def _cvss_to_severity(score: float) -> str:
    """Map CVSS v3 base score to ZeroWatch severity bucket."""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    else:
        return "low"


async def lookup_cves_for_tech(name: str, version: Optional[str]) -> List[Dict[str, Any]]:
    """
    Query NVD CVE API v2 for a single technology name + version.

    Returns a list of finding dicts (category='cve').
    """
    findings: List[Dict[str, Any]] = []

    # Build keyword query
    keyword = name
    if version and version != "unknown":
        keyword = f"{name} {version}"

    params: Dict[str, Any] = {
        "keywordSearch": keyword,
        "resultsPerPage": 5,
        "startIndex": 0,
    }
    headers: Dict[str, str] = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    async with _semaphore:
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(NVD_BASE, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 403:
                return [
                    {
                        "category": "cve",
                        "severity": "low",
                        "title": f"NVD rate limit reached for {name}",
                        "description": "NVD API returned 403 (rate limited). Set NVD_API_KEY in .env to raise limit.",
                        "raw_data": {"tech": name, "version": version},
                    }
                ]
            return []
        except (httpx.RequestError, ValueError):
            return []

    vulnerabilities = data.get("vulnerabilities", [])
    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        eng_desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )

        # Extract CVSS score (prefer v3.1, fall back to v3.0, then v2)
        metrics = cve.get("metrics", {})
        cvss_score: Optional[float] = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics:
                metric_data = metrics[metric_key]
                if isinstance(metric_data, list) and metric_data:
                    score_data = metric_data[0].get("cvssData", {})
                    cvss_score = score_data.get("baseScore")
                    break

        severity = _cvss_to_severity(cvss_score) if cvss_score is not None else "medium"

        findings.append(
            {
                "category": "cve",
                "severity": severity,
                "title": f"{cve_id}: {name} {version or ''} — CVSS {cvss_score or 'N/A'}",
                "description": eng_desc[:500],  # truncate for DB storage
                "raw_data": {
                    "cve_id": cve_id,
                    "tech": name,
                    "version": version,
                    "cvss_score": cvss_score,
                },
            }
        )

    return findings


async def lookup_cves(tech_list: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """
    Run CVE lookups for all fingerprinted technologies concurrently.
    Returns combined finding list.
    """
    tasks = [
        lookup_cves_for_tech(t["name"], t.get("version"))
        for t in tech_list
        if t.get("name")
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings: List[Dict[str, Any]] = []
    for r in results:
        if isinstance(r, list):
            findings.extend(r)
    return findings
