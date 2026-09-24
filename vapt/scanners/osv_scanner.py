"""OSV-Scanner - lockfile dependency vulnerabilities from the OSV database."""

from __future__ import annotations

import json
from pathlib import Path

from ..findings import Finding
from .base import Scanner, ScannerError, find_tool, run_command

# Present in a repo means there is something for OSV to resolve.
_LOCKFILES = (
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
    "Pipfile.lock", "poetry.lock", "go.sum", "Gemfile.lock", "composer.lock",
    "Cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts", "uv.lock",
)


class OsvScanner(Scanner):
    name = "osv-scanner"
    category = "dependency"
    description = "Transitive dependency CVEs resolved from lockfiles via the OSV database"
    install_hint = "python scripts/install_tools.py"

    def command(self) -> list[str] | None:
        path = find_tool("osv-scanner")
        return [path] if path else None

    def scan(self, repo: Path, workdir: Path) -> list[Finding]:
        if not self._has_lockfile(repo):
            return []

        args = list(self.command() or [])
        args += [
            "--format", "json",
            "--recursive",
            # Without this, osv-scanner applies every .gitignore it can find -
            # including ones *above* the clone - and can silently skip the
            # entire tree. A security scan wants the files regardless.
            "--no-ignore",
            ".",
        ]
        # Exit 1 means vulnerabilities were found; 128 means nothing scannable.
        proc = run_command(args, cwd=repo, ok_codes=(0, 1, 128))

        if not proc.stdout.strip():
            return []
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise ScannerError("could not parse output: " + str(exc)) from exc

        findings: list[Finding] = []
        for result in data.get("results") or []:
            source = ((result.get("source") or {}).get("path") or "")
            source = _relative(source, repo)
            for entry in result.get("packages") or []:
                pkg = entry.get("package") or {}
                max_sev = _max_group_severity(entry.get("groups") or [])
                for vuln in entry.get("vulnerabilities") or []:
                    findings.append(self._to_finding(vuln, pkg, source, max_sev))
        return findings

    def _has_lockfile(self, repo: Path) -> bool:
        for name in _LOCKFILES:
            if next(repo.rglob(name), None) is not None:
                return True
        return False

    def _to_finding(self, vuln: dict, pkg: dict, source: str, max_sev: float) -> Finding:
        aliases = vuln.get("aliases") or []
        cve = next((a for a in aliases if str(a).upper().startswith("CVE-")), "")
        osv_id = vuln.get("id", "")
        name = pkg.get("name", "")
        version = pkg.get("version", "")

        summary = vuln.get("summary") or osv_id
        details = (vuln.get("details") or "")[:3000]
        fixed = _fixed_version(vuln, name)

        description = details
        if fixed:
            description += "\n\nFixed in: " + fixed
        description += "\nAdvisory: " + osv_id
        if aliases:
            description += " (" + ", ".join(str(a) for a in aliases[:6]) + ")"

        return Finding(
            scanner=self.name,
            category=self.category,
            rule_id=osv_id,
            title=summary[:200],
            description=description.strip(),
            severity=_severity_from_score(max_sev, vuln),
            file_path=source,
            cve=cve or osv_id,
            package=name,
            installed_version=version,
            fixed_version=fixed,
            reference="https://osv.dev/vulnerability/" + osv_id if osv_id else "",
            raw={"ecosystem": pkg.get("ecosystem", ""), "cvss_score": max_sev},
        )


def _relative(path: str, repo: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(repo.resolve())).replace("\\", "/")
    except (ValueError, OSError):
        return path.replace("\\", "/")


def _max_group_severity(groups: list) -> float:
    best = 0.0
    for group in groups:
        try:
            best = max(best, float(group.get("max_severity") or 0))
        except (TypeError, ValueError):
            continue
    return best


def _severity_from_score(score: float, vuln: dict) -> str:
    """OSV records carry a CVSS score but not always a label; fall back to the
    ecosystem's own label when no score is present."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    label = (vuln.get("database_specific") or {}).get("severity")
    return label or "MEDIUM"


def _fixed_version(vuln: dict, package_name: str) -> str:
    """The first fixed *version*, not a commit.

    OSV records usually carry both a GIT range (whose `fixed` events are commit
    SHAs) and an ECOSYSTEM/SEMVER range (whose events are release versions).
    A developer needs the version to write into a requirements file, so GIT
    ranges are only a last resort.
    """
    git_fallback = ""
    for affected in vuln.get("affected") or []:
        if (affected.get("package") or {}).get("name") != package_name:
            continue
        for rng in affected.get("ranges") or []:
            kind = (rng.get("type") or "").upper()
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if not fixed:
                    continue
                if kind == "GIT":
                    git_fallback = git_fallback or str(fixed)
                else:
                    return str(fixed)
    return git_fallback
