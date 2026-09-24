"""Gitleaks - hardcoded secret detection, including git history."""

from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from .base import Scanner, find_tool, load_json, run_command


class GitleaksScanner(Scanner):
    name = "gitleaks"
    category = "secret"
    description = "Entropy and pattern based secret detection across the commit history"
    install_hint = "python scripts/install_tools.py"

    def __init__(self, scan_history: bool = True) -> None:
        # Only meaningful on a full clone; a --depth 1 clone has no history to
        # walk, so the pipeline passes False and we scan the worktree instead.
        self.scan_history = scan_history

    def command(self) -> list[str] | None:
        path = find_tool("gitleaks")
        return [path] if path else None

    def scan(self, repo: Path, workdir: Path) -> list[Finding]:
        out = workdir / "gitleaks.json"
        args = list(self.command() or [])
        args += [
            "detect",
            "--source", ".",
            "--report-format", "json",
            "--report-path", str(out),
            "--no-banner",
            "--redact",          # keep the raw secret values out of our database
            "--exit-code", "0",
        ]
        if not self.scan_history:
            args.append("--no-git")

        run_command(args, cwd=repo, ok_codes=(0, 1))
        data = load_json(out) or []

        findings = []
        for r in data:
            commit = (r.get("Commit") or "")[:8]
            origin = " (commit " + commit + ")" if commit else ""
            author = r.get("Author") or ""
            description = (
                (r.get("Description") or "") + origin
                + "\nMatched value is redacted. Entropy: "
                + str(r.get("Entropy", "n/a")) + "."
            )
            if author:
                description += "\nCommitted by: " + author

            findings.append(
                Finding(
                    scanner=self.name,
                    category=self.category,
                    rule_id=r.get("RuleID", ""),
                    title="Hardcoded secret: "
                          + (r.get("Description") or r.get("RuleID") or "secret"),
                    description=description,
                    # A committed credential is a breach until proven rotated.
                    severity="HIGH",
                    file_path=r.get("File", ""),
                    line_start=int(r.get("StartLine") or 0),
                    line_end=int(r.get("EndLine") or 0),
                    code_snippet=(r.get("Match") or "")[:500],
                    cwe=["CWE-798"],
                    raw={
                        "commit": r.get("Commit", ""),
                        "date": r.get("Date", ""),
                        "in_history": bool(commit),
                    },
                )
            )
        return findings
