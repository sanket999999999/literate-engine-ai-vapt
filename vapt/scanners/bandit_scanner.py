"""Bandit - Python-specific static analysis."""

from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from .base import Scanner, find_python_tool, load_json, run_command


class BanditScanner(Scanner):
    name = "bandit"
    category = "sast"
    description = "Python AST analysis for insecure API use and crypto misuse"
    install_hint = "pip install bandit"

    def command(self) -> list[str] | None:
        return find_python_tool("bandit", "bandit")

    def scan(self, repo: Path, workdir: Path) -> list[Finding]:
        # Nothing to do unless the repo actually contains Python.
        if next(repo.rglob("*.py"), None) is None:
            return []

        out = workdir / "bandit.json"
        args = list(self.command() or [])
        args += [
            "-r", ".",
            "-f", "json",
            "-o", str(out),
            "-q",
            "--exclude", "./node_modules,./venv,./.venv,./build,./dist",
        ]
        # Exit 1 means issues were found.
        run_command(args, cwd=repo, ok_codes=(0, 1))
        data = load_json(out) or {}

        findings = []
        for r in data.get("results", []):
            cwe_info = r.get("issue_cwe") or {}
            cwe_id = cwe_info.get("id")
            line_range = r.get("line_range") or [r.get("line_number", 0)]
            findings.append(
                Finding(
                    scanner=self.name,
                    category=self.category,
                    rule_id=r.get("test_id", ""),
                    title=r.get("test_name", "") or r.get("issue_text", "")[:120],
                    description=r.get("issue_text", ""),
                    severity=r.get("issue_severity", "INFO"),
                    file_path=r.get("filename", ""),
                    line_start=int(r.get("line_number") or 0),
                    line_end=int(max(line_range) if line_range else 0),
                    code_snippet=(r.get("code") or "")[:2000],
                    cwe=["CWE-" + str(cwe_id)] if cwe_id else [],
                    reference=r.get("more_info", "") or cwe_info.get("link", ""),
                    raw={"confidence": r.get("issue_confidence", "")},
                )
            )
        return findings
