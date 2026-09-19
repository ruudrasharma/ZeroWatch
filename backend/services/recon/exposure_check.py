"""
ZeroWatch — Recon Engine: Exposed sensitive path detection.

Per FEATURES.md: checks a curated list of common sensitive paths via HTTP.
Any path returning HTTP 200 → critical finding.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from urllib.parse import urljoin

import httpx

# Curated list of sensitive paths per FEATURES.md
SENSITIVE_PATHS: List[str] = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/admin",
    "/admin.php",
    "/administrator",
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/.ssh/authorized_keys",
    "/config.php",
    "/config.yml",
    "/config.yaml",
    "/config.json",
    "/database.yml",
    "/db.php",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/swagger.json",
    "/swagger-ui.html",
    "/openapi.json",
    "/api-docs",
    "/backup.sql",
    "/dump.sql",
    "/site.tar.gz",
    "/backup.zip",
    "/.DS_Store",
    "/Thumbs.db",
    "/robots.txt",   # not critical but informational
    "/sitemap.xml",  # informational
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]

# Paths that are informational even if 200 (not inherently secrets)
INFORMATIONAL_PATHS = {"/robots.txt", "/sitemap.xml"}

# Concurrency limit to avoid flooding the target
_CONCURRENCY = 5


async def _check_path(client: httpx.AsyncClient, base_url: str, path: str) -> Dict[str, Any] | None:
    """Check a single path. Returns a finding dict or None if not exposed."""
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        resp = await client.get(url, follow_redirects=False)
        if resp.status_code == 200:
            severity = "critical"
            title = f"Sensitive path accessible: {path}"
            description = (
                f"The path '{path}' returned HTTP 200, suggesting it is publicly accessible. "
                "This may expose credentials, configuration secrets, or internal system information."
            )
            if path in INFORMATIONAL_PATHS:
                severity = "low"
                title = f"Informational path accessible: {path}"
                description = f"'{path}' is publicly accessible — check for unintended disclosures."

            return {
                "category": "exposure",
                "severity": severity,
                "title": title,
                "description": description,
                "raw_data": {
                    "path": path,
                    "url": url,
                    "status_code": resp.status_code,
                    "content_length": resp.headers.get("content-length"),
                },
            }
    except httpx.RequestError:
        pass
    return None


async def check_exposed_paths(url: str) -> List[Dict[str, Any]]:
    """
    Check the curated sensitive path list against the target.

    Returns a list of finding dicts for any exposed paths.
    If nothing is exposed, returns a single informational all-clear.
    """
    findings: List[Dict[str, Any]] = []
    semaphore = asyncio.Semaphore(_CONCURRENCY)

    async def bounded_check(client, path):
        async with semaphore:
            return await _check_path(client, url, path)

    async with httpx.AsyncClient(
        timeout=10.0,
        verify=False,
        headers={"User-Agent": "ZeroWatch-SecurityScanner/0.1"},
    ) as client:
        tasks = [bounded_check(client, p) for p in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, dict):
            findings.append(r)

    if not findings:
        findings.append(
            {
                "category": "exposure",
                "severity": "low",
                "title": "No sensitive paths exposed",
                "description": (
                    f"Checked {len(SENSITIVE_PATHS)} common sensitive paths — "
                    "none returned HTTP 200."
                ),
                "raw_data": {"paths_checked": len(SENSITIVE_PATHS)},
            }
        )

    return findings
