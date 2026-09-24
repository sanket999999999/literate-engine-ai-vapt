"""Semgrep - multi-language static analysis (SAST)."""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..findings import Finding
from .base import Scanner, find_python_tool, load_json, run_command

DEFAULT_RULESETS = "p/security-audit,p/owasp-top-ten,p/secrets"
_CWE_RE = re.compile(r"(CWE-\d+)")


class SemgrepScanner(Scanner):
    name = "semgrep"
    category = "sast"
    description = "Multi-language taint and pattern analysis across 30+ languages"
    install_hint = "pip install semgrep"

    def command(self) -> list[str] | None:
        return find_python_tool("semgrep", "semgrep")

    def scan(self, repo: Path, workdir: Path) -> list[Finding]:
        out = workdir / "semgrep.json"
        rulesets = os.getenv("VAPT_SEMGREP_CONFIG", DEFAULT_RULESETS)
        args = list(self.command() or [])
        args += ["scan", "--json", "--output", str(out), "--quiet", "--metrics=off"]
        for ruleset in [r.strip() for r in rulesets.split(",") if r.strip()]:
            args += ["--config", ruleset]
        args.append(".")

        # Exit 1 simply means "rules matched"; only 2+ is a real failure.
        run_command(args, cwd=repo, ok_codes=(0, 1))
        data = load_json(out) or {}
        return [self._to_finding(r) for r in data.get("results", [])]

    def _to_finding(self, result: dict) -> Finding:
        extra = result.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        check_id = result.get("check_id", "semgrep")
        refs = meta.get("references") or []

        cwes = []
        for item in _as_list(meta.get("cwe")):
            match = _CWE_RE.search(str(item))
            if match:
                cwes.append(match.group(1))

        owasp = ", ".join(str(o) for o in _as_list(meta.get("owasp")))
        message = (extra.get("message") or "").strip()
        description = message
        if owasp:
            description += "\n\nOWASP: " + owasp

        return Finding(
            scanner=self.name,
            category=self.category,
            rule_id=check_id,
            title=_title_from_rule(check_id, message),
            description=description,
            severity=extra.get("severity", "INFO"),
            file_path=result.get("path", ""),
            line_start=int((result.get("start") or {}).get("line") or 0),
            line_end=int((result.get("end") or {}).get("line") or 0),
            code_snippet=(extra.get("lines") or "")[:2000],
            cwe=cwes,
            reference=refs[0] if refs else "",
            raw={"confidence": meta.get("confidence", ""), "owasp": owasp},
        )


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _title_from_rule(check_id: str, message: str) -> str:
    """Semgrep messages are whole paragraphs; the rule's last path segment
    makes a far better headline."""
    leaf = check_id.rsplit(".", 1)[-1].replace("-", " ").replace("_", " ").strip()
    if leaf:
        return leaf[:1].upper() + leaf[1:]
    return message.split(".")[0][:120] or check_id
