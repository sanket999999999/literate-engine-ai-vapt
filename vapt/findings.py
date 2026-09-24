"""The normalized finding every scanner is translated into, plus dedupe."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Every severity vocabulary the supported scanners emit, folded onto ours.
_SEVERITY_ALIASES = {
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "HIGH": "HIGH",
    "WARNING": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
    "NOTE": "INFO",
    "LOW": "LOW",
    "UNKNOWN": "INFO",
    "NONE": "INFO",
}

CATEGORIES = ("sast", "secret", "dependency", "iac")


def normalize_severity(value: str | None) -> str:
    if not value:
        return "INFO"
    return _SEVERITY_ALIASES.get(str(value).strip().upper(), "INFO")


def severity_sort_key(severity: str) -> int:
    return SEVERITY_RANK.get(severity, len(SEVERITY_ORDER))


@dataclass
class Finding:
    """One normalized issue. `scanner` is the tool that first reported it."""

    scanner: str
    category: str
    rule_id: str
    title: str
    description: str
    severity: str
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    code_snippet: str = ""
    cwe: list[str] = field(default_factory=list)
    cve: str = ""
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    reference: str = ""
    # Filled in when more than one scanner reports the same issue.
    corroborated_by: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.file_path = _posix(self.file_path)
        if self.line_end < self.line_start:
            self.line_end = self.line_start

    @property
    def dedupe_key(self) -> str:
        """Identity of the *issue*, deliberately independent of which tool found it.

        A CVE in a package is the same issue wherever it is reported from, so
        dependency findings key on the CVE. Everything else keys on location
        plus rule, which is what makes two scanners agreeing collapse into one
        corroborated finding instead of two near-duplicates in the report.
        """
        if self.category == "dependency" and self.cve:
            return f"dep|{self.package.lower()}|{self.installed_version}|{self.cve.upper()}"
        if self.category == "secret":
            # Same secret on the same line, however it was matched.
            return f"secret|{self.file_path}|{self.line_start}"
        return f"{self.category}|{self.file_path}|{self.line_start}|{self.rule_id}"

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.dedupe_key.encode("utf-8")).hexdigest()[:16]

    @property
    def location(self) -> str:
        if not self.file_path:
            return "-"
        if self.line_start:
            return f"{self.file_path}:{self.line_start}"
        return self.file_path


def _posix(path: str) -> str:
    if not path:
        return ""
    return str(path).replace("\\", "/").lstrip("./")


def merge(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicates, recording corroborating scanners on the survivor."""
    by_key: dict[str, Finding] = {}
    for f in findings:
        existing = by_key.get(f.dedupe_key)
        if existing is None:
            by_key[f.dedupe_key] = f
            continue
        # Keep the more severe report; the other becomes corroboration.
        winner, loser = existing, f
        if severity_sort_key(f.severity) < severity_sort_key(existing.severity):
            winner, loser = f, existing
            winner.corroborated_by = existing.corroborated_by
        if loser.scanner != winner.scanner and loser.scanner not in winner.corroborated_by:
            winner.corroborated_by.append(loser.scanner)
        # Prefer whichever report actually carried context.
        if not winner.code_snippet and loser.code_snippet:
            winner.code_snippet = loser.code_snippet
        winner.cwe = sorted(set(winner.cwe) | set(loser.cwe))
        by_key[f.dedupe_key] = winner

    out = list(by_key.values())
    out.sort(key=lambda f: (severity_sort_key(f.severity), f.file_path, f.line_start))
    return out


def attach_snippets(findings: list[Finding], repo_root: Path, context: int = 6) -> None:
    """Widen each finding to `context` lines either side, one pass per file.

    Scanners hand back only the matched line or two, which is rarely enough to
    judge reachability. Reading the surrounding lines is what lets triage tell
    a real sink from a sanitized one, so this overwrites the scanner's narrow
    snippet whenever the file can actually be read.

    Secrets are the exception: gitleaks deliberately redacts the matched value,
    and re-reading the file would copy the live credential into the database,
    the report and the triage prompt. Those keep the redacted version.
    """
    wanted: dict[str, list[Finding]] = {}
    for f in findings:
        if f.category == "secret":
            continue
        if f.file_path and f.line_start:
            wanted.setdefault(f.file_path, []).append(f)

    for rel, group in wanted.items():
        target = (repo_root / rel).resolve()
        try:
            # Refuse to read outside the clone even if a scanner emits `../`.
            target.relative_to(repo_root.resolve())
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except (OSError, ValueError):
            continue
        for f in group:
            start = max(0, f.line_start - 1 - context)
            end = min(len(lines), (f.line_end or f.line_start) + context)
            numbered = [f"{n + 1:>5} | {lines[n]}" for n in range(start, end)]
            # A line number past the end of the file would otherwise blank out
            # the snippet the scanner did give us.
            if numbered:
                f.code_snippet = "\n".join(numbered)[:4000]


def counts_by_severity(findings: list[Finding]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out
