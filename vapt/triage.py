"""Provider-agnostic triage orchestration.

The batching, budget cap, prompt assembly and failure handling live here; the
provider only turns one request into one response. Adding a backend means
writing a TriageProvider, not touching this file.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from . import config
from .findings import Finding, SEVERITY_ORDER, severity_sort_key
from .providers import TriageError, TriageProvider, TriagedFinding

log = logging.getLogger(__name__)


class Triage:
    """Wraps one provider for the duration of one scan."""

    def __init__(self, provider: TriageProvider) -> None:
        self.provider = provider

    @property
    def usage(self):
        return self.provider.usage

    @property
    def label(self) -> str:
        return "{} / {}".format(self.provider.label, self.provider.model)

    # ---------------------------------------------------------------- triage

    def triage(
        self,
        findings: list[Finding],
        on_progress: Callable[[int, int], None] | None = None,
    ) -> dict[int, TriagedFinding]:
        """Triage findings, returning {position in `findings` -> verdict}.

        Worst-first, so if the budget cap cuts the run short, what got reviewed
        is what mattered most.
        """
        order = sorted(
            range(len(findings)),
            key=lambda i: (severity_sort_key(findings[i].severity), findings[i].file_path),
        )
        capped = order[: config.TRIAGE_MAX_FINDINGS]
        if len(order) > len(capped):
            self.usage.errors.append(
                "Triage capped at {} of {} findings (VAPT_TRIAGE_MAX_FINDINGS).".format(
                    len(capped), len(order)
                )
            )

        size = self.provider.batch_size or config.TRIAGE_BATCH_SIZE
        batches = [capped[i : i + size] for i in range(0, len(capped), size)]

        results: dict[int, TriagedFinding] = {}
        for batch_no, batch in enumerate(batches, start=1):
            payload = [_finding_payload(i, findings[i]) for i in batch]
            try:
                verdicts = self.provider.triage_batch(payload, set(batch))
                results.update({v.index: v for v in verdicts})
            except Exception as exc:
                # A failed batch leaves those findings untriaged and visibly so
                # in the report; it does not sink the scan.
                message = "Triage batch {}/{} failed: {}".format(
                    batch_no, len(batches), _short(exc)
                )
                log.warning(message)
                self.usage.errors.append(message[:300])
            if on_progress:
                on_progress(batch_no, len(batches))
        return results

    # ---------------------------------------------------------------- report

    def executive_summary(
        self,
        repo_url: str,
        languages: list[str],
        findings: list[Finding],
        verdicts: dict[int, TriagedFinding],
        scanner_runs: list[dict],
    ) -> str:
        top = _top_findings_digest(findings, verdicts, limit=25)
        counts = _counts_digest(findings, verdicts)
        skipped = [r for r in scanner_runs if r.get("status") != "ok"]

        prompt = (
            "Repository: {repo}\n"
            "Primary languages: {langs}\n\n"
            "Finding counts after triage:\n{counts}\n\n"
            "Coverage notes (scanners that did not complete):\n{skipped}\n\n"
            "Most significant findings:\n<findings>\n{top}\n</findings>\n\n"
            "Write the report narrative in Markdown with exactly these sections:\n\n"
            "## Executive Summary\n"
            "Three to five sentences an engineering manager can act on: the overall "
            "security posture, the single most serious issue, and whether this "
            "codebase is safe to ship as-is.\n\n"
            "## Risk Overview\n"
            "A short paragraph on the themes behind the findings - what classes of "
            "mistake recur and what that says about the codebase.\n\n"
            "## Priority Remediation Plan\n"
            "A numbered list of at most seven concrete actions in the order they "
            "should be done. Each item names the file(s) involved and the fix. Put "
            "anything that is exploitable today first.\n\n"
            "## Coverage and Limitations\n"
            "What this scan did and did not cover. Name any scanner that was skipped "
            "or failed and what that leaves unexamined. This was a static analysis of "
            "source code only - no running application was tested - so say so.\n"
        ).format(
            repo=repo_url,
            langs=", ".join(languages) or "unknown",
            counts=counts,
            skipped="\n".join(
                "- {}: {} ({})".format(r.get("name"), r.get("status"), r.get("message", ""))
                for r in skipped
            ) or "- none, every scanner completed",
            top=top or "No findings survived triage.",
        )
        return self.provider.narrative(prompt)


def _short(exc: Exception) -> str:
    text = str(exc).strip() or type(exc).__name__
    return text if isinstance(exc, TriageError) else "{}: {}".format(type(exc).__name__, text)


def _finding_payload(index: int, f: Finding) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "index": index,
        "scanner": f.scanner,
        "category": f.category,
        "rule_id": f.rule_id,
        "title": f.title,
        "scanner_severity": f.severity,
        "message": f.description[:1500],
        "location": f.location,
    }
    if f.cwe:
        payload["cwe"] = f.cwe
    if f.code_snippet:
        payload["code"] = f.code_snippet[:3000]
    if f.category == "dependency":
        payload["package"] = f.package
        payload["installed_version"] = f.installed_version
        payload["fixed_version"] = f.fixed_version or "none published"
    if f.corroborated_by:
        payload["also_reported_by"] = f.corroborated_by
    return payload


def _counts_digest(findings: list[Finding], verdicts: dict[int, TriagedFinding]) -> str:
    rows = []
    for severity in SEVERITY_ORDER:
        confirmed = sum(
            1
            for i, f in enumerate(findings)
            if _effective_severity(i, f, verdicts) == severity
            and i in verdicts
            and verdicts[i].verdict == "true_positive"
        )
        total = sum(
            1 for i, f in enumerate(findings)
            if _effective_severity(i, f, verdicts) == severity
        )
        if total:
            rows.append("- {}: {} total, {} confirmed".format(severity, total, confirmed))
    dismissed = sum(1 for v in verdicts.values() if v.verdict == "false_positive")
    rows.append("- dismissed as false positives: {}".format(dismissed))
    return "\n".join(rows)


def _top_findings_digest(
    findings: list[Finding], verdicts: dict[int, TriagedFinding], limit: int
) -> str:
    ranked = []
    for i, f in enumerate(findings):
        v = verdicts.get(i)
        if v and v.verdict == "false_positive":
            continue
        ranked.append((severity_sort_key(_effective_severity(i, f, verdicts)), i, f, v))
    ranked.sort(key=lambda row: row[0])

    lines = []
    for _, i, f, v in ranked[:limit]:
        entry = "- [{}] {} ({}) at {}".format(
            _effective_severity(i, f, verdicts), f.title, f.scanner, f.location
        )
        if v:
            entry += "\n  verdict: {} ({} confidence)".format(v.verdict, v.confidence)
            if v.attack_scenario:
                entry += "\n  attack: " + v.attack_scenario[:400]
            if v.remediation:
                entry += "\n  fix: " + v.remediation[:400]
        lines.append(entry)
    return "\n".join(lines)


def _effective_severity(
    index: int, f: Finding, verdicts: dict[int, TriagedFinding]
) -> str:
    v = verdicts.get(index)
    return v.severity if v else f.severity
