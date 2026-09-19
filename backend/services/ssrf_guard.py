"""
ZeroWatch — SSRF guard: blocks scan targets resolving to private/localhost IPs.

Per SECURITY.md §2 and ENVIRONMENT.md: private ranges are blocked by default;
set ALLOW_LOCALHOST_SCAN_TARGETS=true in .env to allow (sandbox testing only).

Authors:
    Bhavishyata Yadav (24CSU036)
    Bhavya Jain (24CSU037)
    Rudra Kumar Sharma (24CSU175)
B.Tech CSE (Cybersecurity), The NorthCap University.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

ALLOW_LOCALHOST: bool = os.getenv("ALLOW_LOCALHOST_SCAN_TARGETS", "false").lower() == "true"

# RFC 1918 + loopback + link-local + CGNAT private ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("169.254.0.0/16"),    # link-local
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]

_LOCALHOST_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


def is_private_address(ip_str: str) -> bool:
    """Return True if the IP string is in any private/loopback range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def check_ssrf_guard(url: str) -> None:
    """
    Resolve the host of `url` and raise ValueError if it resolves to a
    private/loopback address and ALLOW_LOCALHOST_SCAN_TARGETS is False.

    Raises:
        ValueError: with an explanatory message if the target is blocked.
    """
    if ALLOW_LOCALHOST:
        return  # dev-mode override, allow localhost targets

    parsed = urlparse(url)
    host = parsed.hostname or ""

    # Direct localhost name check
    if host.lower() in _LOCALHOST_NAMES:
        raise ValueError(
            f"SSRF guard: scan target '{host}' is a localhost alias. "
            "Set ALLOW_LOCALHOST_SCAN_TARGETS=true in .env to override (testing only)."
        )

    # DNS resolution check
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip = info[4][0]
            if is_private_address(ip):
                raise ValueError(
                    f"SSRF guard: '{host}' resolves to private IP {ip}. "
                    "Set ALLOW_LOCALHOST_SCAN_TARGETS=true in .env to override."
                )
    except socket.gaierror:
        # DNS resolution failed — let the scanner attempt it (will fail gracefully)
        pass
