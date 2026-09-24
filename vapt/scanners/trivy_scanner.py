"""Trivy - dependency vulnerabilities plus IaC and container misconfiguration."""

from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from .base import Scanner, find_tool, load_json, run_command


class TrivyScanner(Scanner):
    name = "trivy"
    category = "dependency"
    description = "Lockfile CVE lookup and Dockerfile/Kubernetes/Terraform misconfiguration"
    install_hint = "python scripts/install_tools.py"

    def command(self) -> list[str] | None:
        path = find_tool("trivy")
        return [path] if path else None

    def scan(self, repo: Path, workdir: Path) -> list[Finding]:
        out = workdir / "trivy.json"
        args = list(self.command() or [])
        args += [
            "fs",
            "--scanners", "vuln,misconfig,secret",
            "--format", "json",
            "--output", str(out),
            "--quiet",
            "--exit-code", "0",
            "--skip-dirs", "node_modules,venv,.venv,vendor,dist,build",
            ".",
        ]
        run_command(args, cwd=repo)
        data = load_json(out) or {}

        findings: list[Finding] = []
        for result in data.get("Results") or []:
            target = result.get("Target", "")
            findings += [self._vuln(v, target) for v in result.get("Vulnerabilities") or []]
            findings += [self._misconf(m, target) for m in result.get("Misconfigurations") or []]
            findings += [self._secret(s, target) for s in result.get("Secrets") or []]
        return findings

    def _vuln(self, v: dict, target: str) -> Finding:
        pkg = v.get("PkgName", "")
        installed = v.get("InstalledVersion", "")
        fixed = v.get("FixedVersion", "")
        cve = v.get("VulnerabilityID", "")
        title = v.get("Title") or (cve + " in " + pkg)

        description = (v.get("Description") or "")[:3000]
        if fixed:
            description += "\n\nFixed in: " + fixed
        else:
            description += "\n\nNo fixed version is published yet."

        return Finding(
            scanner=self.name,
            category="dependency",
            rule_id=cve,
            title=title,
            description=description,
            severity=v.get("Severity", "UNKNOWN"),
            file_path=target,
            cwe=v.get("CweIDs") or [],
            cve=cve,
            package=pkg,
            installed_version=installed,
            fixed_version=fixed,
            reference=v.get("PrimaryURL", ""),
            raw={"cvss": _best_cvss(v), "status": v.get("Status", "")},
        )

    def _misconf(self, m: dict, target: str) -> Finding:
        cause = m.get("CauseMetadata") or {}
        resolution = m.get("Resolution") or ""
        description = (m.get("Description") or "") + "\n\n" + (m.get("Message") or "")
        if resolution:
            description += "\n\nResolution: " + resolution

        return Finding(
            scanner=self.name,
            category="iac",
            rule_id=m.get("ID", ""),
            title=m.get("Title", "") or m.get("ID", ""),
            description=description.strip(),
            severity=m.get("Severity", "UNKNOWN"),
            file_path=target,
            line_start=int(cause.get("StartLine") or 0),
            line_end=int(cause.get("EndLine") or 0),
            reference=m.get("PrimaryURL", ""),
            raw={"type": m.get("Type", ""), "resource": cause.get("Resource", "")},
        )

    def _secret(self, s: dict, target: str) -> Finding:
        return Finding(
            scanner=self.name,
            category="secret",
            rule_id=s.get("RuleID", ""),
            title="Hardcoded secret: " + (s.get("Title") or s.get("RuleID") or "secret"),
            description=(
                "Trivy matched a " + (s.get("Category") or "credential")
                + " pattern in this file."
            ),
            severity=s.get("Severity", "HIGH"),
            file_path=target,
            line_start=int(s.get("StartLine") or 0),
            line_end=int(s.get("EndLine") or 0),
            code_snippet=(s.get("Match") or "")[:500],
            cwe=["CWE-798"],
        )


def _best_cvss(v: dict) -> str:
    """Trivy reports CVSS per source (nvd, redhat, ...); any V3 vector will do."""
    for entry in (v.get("CVSS") or {}).values():
        vector = entry.get("V3Vector") or entry.get("V2Vector")
        score = entry.get("V3Score") or entry.get("V2Score")
        if vector:
            return str(score) + " " + vector
    return ""
