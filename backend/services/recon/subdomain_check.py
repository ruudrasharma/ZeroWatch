"""
ZeroWatch — Recon Engine: Subdomain/DNS check via crt.sh.

Per FEATURES.md:
  - Queries crt.sh certificate transparency log for subdomains of the target domain.
  - Flags subdomains that resolve (DNS lookup) but appear potentially unmaintained
    (best-effort heuristic, disclosed as such per FEATURES.md).

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

import httpx

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
_MAX_SUBDOMAINS_TO_RESOLVE = 30  # avoid slowdown on domains with 100s of certs


def _extract_domain(url: str) -> str:
    """Extract root domain (or hostname) from URL."""
    parsed = urlparse(url)
    host = parsed.hostname or url
    # Strip www prefix for crt.sh query
    if host.startswith("www."):
        host = host[4:]
    return host


def _resolve_hostname(hostname: str) -> bool:
    """Return True if hostname resolves in DNS."""
    try:
        socket.getaddrinfo(hostname, None, timeout=3)
        return True
    except (socket.gaierror, socket.timeout, OSError):
        return False


async def check_subdomains(url: str) -> List[Dict[str, Any]]:
    """
    Enumerate subdomains via crt.sh and flag those that resolve.

    Returns a list of finding dicts.
    """
    findings: List[Dict[str, Any]] = []
    domain = _extract_domain(url)

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(
                CRTSH_URL.format(domain=domain),
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
    except (httpx.RequestError, ValueError, httpx.HTTPStatusError) as exc:
        return [
            {
                "category": "subdomain",
                "severity": "low",
                "title": "Could not query crt.sh for subdomain data",
                "description": f"crt.sh request failed: {exc}. This check is best-effort.",
                "raw_data": {"domain": domain, "error": str(exc)},
            }
        ]

    # Deduplicate subdomains from crt.sh results
    subdomains: Set[str] = set()
    for entry in data:
        name = entry.get("name_value", "")
        for sub in name.splitlines():
            sub = sub.strip().lower()
            # Skip wildcard entries and the root domain itself
            if sub and not sub.startswith("*") and sub != domain:
                subdomains.add(sub)

    if not subdomains:
        findings.append(
            {
                "category": "subdomain",
                "severity": "low",
                "title": f"No subdomains found in crt.sh for {domain}",
                "description": "No certificate transparency log entries found for subdomains. "
                "This may mean the site has no subdomains or uses a private CA.",
                "raw_data": {"domain": domain, "crtsh_entries": len(data)},
            }
        )
        return findings

    # Add informational finding listing discovered subdomains
    subdomain_list = sorted(subdomains)
    findings.append(
        {
            "category": "subdomain",
            "severity": "low",
            "title": f"Found {len(subdomain_list)} subdomain(s) via crt.sh",
            "description": "Certificate transparency logs revealed these subdomains. "
            "Review each for unintended exposure or outdated services.",
            "raw_data": {
                "domain": domain,
                "subdomains": subdomain_list[:50],  # cap for DB storage
                "total_found": len(subdomain_list),
            },
        }
    )

    # Resolve a subset and flag ones that actually resolve (best-effort heuristic)
    to_resolve = subdomain_list[:_MAX_SUBDOMAINS_TO_RESOLVE]
    loop = asyncio.get_event_loop()
    resolve_tasks = [
        loop.run_in_executor(None, _resolve_hostname, sub)
        for sub in to_resolve
    ]
    resolved_flags = await asyncio.gather(*resolve_tasks)

    resolving_subs = [sub for sub, ok in zip(to_resolve, resolved_flags) if ok]

    if resolving_subs:
        findings.append(
            {
                "category": "subdomain",
                "severity": "medium",
                "title": f"{len(resolving_subs)} subdomain(s) resolve — verify they are intentional",
                "description": (
                    "The following subdomains appear in crt.sh and resolve in DNS. "
                    "Unmaintained or forgotten subdomains can be targets for takeover or exploitation. "
                    "This is a best-effort heuristic — manual review recommended."
                ),
                "raw_data": {
                    "domain": domain,
                    "resolving_subdomains": resolving_subs,
                },
            }
        )

    return findings
