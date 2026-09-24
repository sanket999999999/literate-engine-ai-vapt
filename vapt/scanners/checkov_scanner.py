"""Checkov - deep infrastructure-as-code policy checks."""

from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from .base import Scanner, find_python_tool, load_json, run_command

# Checkov's OSS rules mostly carry no severity (that is a paid feature), so a
# failed policy check lands at MEDIUM unless the rule is in this list.
_HIGH_SIGNAL_PREFIXES = (
    "CKV_SECRET",      # committed credentials
    "CKV_AWS_18",      # no access logging
    "CKV_AWS_19",      # unencrypted storage
    "CKV_AWS_20",      # public S3 read
    "CKV_AWS_21",      # no versioning
    "CKV_AWS_57",      # public S3 write
    "CKV_DOCKER_1",    # exposed SSH / root
    "CKV_DOCKER_3",    # no USER instruction
    "CKV_K8S_16",      # privileged container
    "CKV_K8S_20",      # allowPrivilegeEscalation
    "CKV_K8S_23",      # root container
)

_IAC_FRAMEWORKS = (
    "terraform", "cloudformation", "kubernetes", "helm", "dockerfile",
    "serverless", "arm", "bicep", "github_actions", "gitlab_ci", "azure_pipelines",
)


class CheckovScanner(Scanner):
    name = "checkov"
    category = "iac"
    description = "Policy-as-code checks for Terraform, Kubernetes, Dockerfiles and CI config"
    install_hint = "pip install checkov"

    def command(self) -> list[str] | None:
        return find_python_tool("checkov", "checkov")

    def scan(self, repo: Path, workdir: Path) -> list[Finding]:
        outdir = workdir / "checkov"
        outdir.mkdir(parents=True, exist_ok=True)

        args = list(self.command() or [])
        args += [
            "--directory", ".",
            "--output", "json",
            "--output-file-path", str(outdir),
            "--compact",
            "--quiet",
            "--soft-fail",       # a failed policy must not look like a crashed tool
            "--framework", ",".join(_IAC_FRAMEWORKS),
            "--skip-path", "node_modules",
            "--skip-path", "venv",
        ]
        run_command(args, cwd=repo, ok_codes=(0, 1))

        data = load_json(outdir / "results_json.json")
        if data is None:
            return []
        # Checkov emits a bare object for one framework and a list for several.
        blocks = data if isinstance(data, list) else [data]

        findings = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            check_type = block.get("check_type", "iac")
            results = block.get("results") or {}
            for check in results.get("failed_checks") or []:
                findings.append(self._to_finding(check, check_type))
        return findings

    def _to_finding(self, check: dict, check_type: str) -> Finding:
        check_id = check.get("check_id", "")
        line_range = check.get("file_line_range") or [0, 0]
        resource = check.get("resource", "")
        guideline = check.get("guideline") or ""

        description = check.get("check_name", "")
        if resource:
            description += "\n\nResource: " + resource
        description += "\nFramework: " + check_type

        return Finding(
            scanner=self.name,
            category=self.category,
            rule_id=check_id,
            title=check.get("check_name", "") or check_id,
            description=description,
            severity=check.get("severity") or _default_severity(check_id),
            file_path=(check.get("file_path") or "").lstrip("/"),
            line_start=int(line_range[0] or 0),
            line_end=int(line_range[-1] or 0),
            code_snippet=_render_code_block(check.get("code_block")),
            reference=guideline,
            raw={"resource": resource, "framework": check_type},
        )


def _default_severity(check_id: str) -> str:
    return "HIGH" if check_id.startswith(_HIGH_SIGNAL_PREFIXES) else "MEDIUM"


def _render_code_block(block) -> str:
    """code_block is [[line_no, text], ...] when --compact is off."""
    if not block:
        return ""
    lines = []
    for entry in block:
        if isinstance(entry, (list, tuple)) and len(entry) >= 2:
            lines.append("{:>5} | {}".format(entry[0], str(entry[1]).rstrip()))
    return "\n".join(lines)[:2000]
