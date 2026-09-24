"""Scanner registry.

Adding a tool means writing one Scanner subclass and listing it here; the
pipeline, the dashboard's tool panel and the report all pick it up from this
registry with no further wiring.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from .bandit_scanner import BanditScanner
from .base import ScanResult, Scanner, ScannerError
from .checkov_scanner import CheckovScanner
from .gitleaks_scanner import GitleaksScanner
from .osv_scanner import OsvScanner
from .semgrep_scanner import SemgrepScanner
from .trivy_scanner import TrivyScanner

SCANNER_CLASSES = [
    SemgrepScanner,
    BanditScanner,
    GitleaksScanner,
    TrivyScanner,
    CheckovScanner,
    OsvScanner,
]


def build_scanners(scan_history: bool = False) -> list[Scanner]:
    """Instantiate every scanner for one run."""
    scanners: list[Scanner] = []
    for cls in SCANNER_CLASSES:
        if cls is GitleaksScanner:
            scanners.append(GitleaksScanner(scan_history=scan_history))
        else:
            scanners.append(cls())
    return scanners


_STATUS_CACHE: tuple[float, list[dict]] | None = None
_STATUS_TTL = 300.0


def tool_status(refresh: bool = False) -> list[dict]:
    """What is installed right now - drives the dashboard's tool panel.

    Each `--version` call is a process launch, and semgrep alone takes seconds,
    so the probes run concurrently and the result is cached: installed tools do
    not change while the server is up, and the dashboard polls this on load.
    """
    global _STATUS_CACHE
    now = time.monotonic()
    if not refresh and _STATUS_CACHE and now - _STATUS_CACHE[0] < _STATUS_TTL:
        return _STATUS_CACHE[1]

    scanners = build_scanners()
    with ThreadPoolExecutor(max_workers=len(scanners)) as pool:
        versions = dict(
            zip(scanners, pool.map(lambda s: s.version() if s.available() else "", scanners))
        )

    status = [
        {
            "name": s.name,
            "category": s.category,
            "description": s.description,
            "available": bool(versions[s]) or s.available(),
            "version": versions[s],
            "install_hint": s.install_hint,
        }
        for s in scanners
    ]
    _STATUS_CACHE = (now, status)
    return status


__all__ = [
    "SCANNER_CLASSES",
    "ScanResult",
    "Scanner",
    "ScannerError",
    "build_scanners",
    "tool_status",
]
