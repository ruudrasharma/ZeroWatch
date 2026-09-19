"""
ZeroWatch — Recon Engine: Technology fingerprinting.

Heuristic-style detection (Wappalyzer-inspired) from response headers,
meta tags, and known JS file signatures per FEATURES.md.
Output feeds directly into the CVE cross-reference step.

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

import httpx
from bs4 import BeautifulSoup


# ─── Detection rules: (name, pattern, version_group_index, source) ───────────
#  source: "header:<header-name>" | "body" | "meta"
_RULES: List[Tuple[str, str, int, str]] = [
    # Frameworks / servers detected via headers
    ("nginx", r"nginx(?:/(\d+\.\d+[\.\d]*))? ?", 1, "header:server"),
    ("apache", r"apache(?:/(\d+\.\d+[\.\d]*))?", 1, "header:server"),
    ("iis", r"microsoft-iis(?:/(\d+\.\d+))?", 1, "header:server"),
    ("php", r"php(?:/(\d+\.\d+[\.\d]*))?", 1, "header:x-powered-by"),
    ("asp.net", r"asp\.net", 0, "header:x-powered-by"),
    ("express", r"express", 0, "header:x-powered-by"),
    # CMS/JS library via body patterns
    ("wordpress", r"wp-content|wp-includes", 0, "body"),
    ("wordpress", r"<meta name=['\"]generator['\"] content=['\"]WordPress (\d+\.\d+[\.\d]*)['\"]/?>", 1, "meta"),
    ("drupal", r"drupal\.settings|Drupal\.behaviors", 0, "body"),
    ("joomla", r"/media/jui/|joomla!", 0, "body"),
    ("jquery", r"jquery(?:\.min)?\.js\?ver=(\d+\.\d+[\.\d]*)", 1, "body"),
    ("jquery", r"jquery[/-](\d+\.\d+[\.\d]*)(?:\.min)?\.js", 1, "body"),
    ("react", r"react(?:\.production|\.development)?\.min\.js", 0, "body"),
    ("react", r"__REACT_DEVTOOLS_GLOBAL_HOOK__", 0, "body"),
    ("vue", r"vue(?:\.min)?\.js|vue\.runtime", 0, "body"),
    ("angular", r"ng-version=['\"](\d+\.\d+[\.\d]*)['\"]", 1, "body"),
    ("bootstrap", r"bootstrap(?:\.min)?\.css\?v=(\d+\.\d+[\.\d]*)", 1, "body"),
    ("bootstrap", r"bootstrap(?:\.bundle)?\.min\.js", 0, "body"),
    ("laravel", r"laravel_session|laravel_token", 0, "header:set-cookie"),
    ("rails", r"_rails_session|X-Powered-By: Phusion Passenger", 0, "header:set-cookie"),
    ("django", r"csrftoken|django", 0, "header:set-cookie"),
    ("cloudflare", r"cloudflare", 0, "header:server"),
    ("cloudflare", r"__cfduid|__cfuid|cf_clearance", 0, "header:set-cookie"),
    ("woocommerce", r"woocommerce|wc-session-expiry", 0, "body"),
    ("magento", r"PHPSESSID|frontend=|skin/frontend", 0, "body"),
    ("shopify", r"cdn\.shopify\.com|shopify\.com/s/", 0, "body"),
]


async def fingerprint_tech(url: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    """
    Detect technologies and versions from the target URL.

    Returns:
        findings: list of finding dicts (category='cve' placeholder, one per detected tech)
        tech_list: list of {"name": str, "version": str|None} for CVE lookup
    """
    findings: List[Dict[str, Any]] = []
    detected: Dict[str, Optional[str]] = {}  # name → version (deduplicated)

    try:
        async with httpx.AsyncClient(
            timeout=20.0,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "ZeroWatch-SecurityScanner/0.1"},
        ) as client:
            resp = await client.get(url)
            body = resp.text
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except httpx.RequestError as exc:
        return (
            [
                {
                    "category": "fingerprinting",
                    "severity": "medium",
                    "title": "Could not load page for fingerprinting",
                    "description": str(exc),
                    "raw_data": {"error": str(exc)},
                }
            ],
            [],
        )

    for tech_name, pattern, ver_group, source in _RULES:
        text_to_search = ""
        if source.startswith("header:"):
            hdr = source[len("header:"):]
            text_to_search = headers.get(hdr, "")
        elif source == "body":
            text_to_search = body
        elif source == "meta":
            text_to_search = body  # match against full HTML including meta tags

        m = re.search(pattern, text_to_search, re.IGNORECASE)
        if m:
            version: Optional[str] = None
            if ver_group > 0:
                try:
                    version = m.group(ver_group) or None
                except IndexError:
                    pass
            # Keep most specific version if already detected
            if tech_name not in detected or (version and not detected[tech_name]):
                detected[tech_name] = version

    # Build tech list for CVE lookup and informational findings
    tech_list: List[Dict[str, str]] = []
    for name, version in detected.items():
        tech_list.append({"name": name, "version": version or "unknown"})
        findings.append(
            {
                "category": "fingerprinting",
                "severity": "low",
                "title": f"Detected: {name}" + (f" {version}" if version else ""),
                "description": (
                    f"Technology '{name}' (version: {version or 'unknown'}) was identified. "
                    "This information will be cross-referenced with the NVD CVE database."
                ),
                "raw_data": {"tech": name, "version": version},
            }
        )

    if not tech_list:
        findings.append(
            {
                "category": "fingerprinting",
                "severity": "low",
                "title": "No recognisable technology fingerprints detected",
                "description": "The site may use a custom stack or obfuscate technology signatures.",
                "raw_data": {},
            }
        )

    return findings, tech_list
