"""Scan orchestration: clone, run every scanner, triage, persist, report."""

from __future__ import annotations

import logging
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from . import config, report as report_mod, repo as repo_mod
from .db import FindingRow, Scan, session_scope, utcnow
from .findings import Finding, attach_snippets, counts_by_severity, merge, severity_sort_key
from .providers import ProviderUnavailable, TriagedFinding, get_provider
from .scanners import ScanResult, build_scanners
from .triage import Triage

log = logging.getLogger(__name__)

# Severity weights behind the 0-100 risk score.
_RISK_WEIGHTS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 3, "LOW": 1, "INFO": 0}


class Progress:
    """Writes stage and percentage straight to the scan row so the dashboard
    can poll a single endpoint for live status."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id

    def set(self, stage: str, percent: int, **fields) -> None:
        with session_scope() as session:
            scan = session.get(Scan, self.scan_id)
            if scan is None:
                return
            scan.stage = stage
            scan.progress = max(0, min(100, percent))
            for key, value in fields.items():
                setattr(scan, key, value)


def run_scan(scan_id: str) -> None:
    """Execute one queued scan to completion. Runs on a worker thread."""
    progress = Progress(scan_id)
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            log.error("scan %s vanished before it started", scan_id)
            return
        repo_url = scan.repo_url
        branch = scan.branch or ""
        deep_history = bool(scan.deep_history)
        want_triage = bool(scan.ai_triage)
        want_provider = scan.ai_provider or ""
        want_model = scan.ai_model or ""
        scan.status = "running"
        scan.started_at = utcnow()

    clone_path: Path | None = None
    try:
        # ---------------------------------------------------------- clone
        progress.set("cloning repository", 5)
        info = repo_mod.clone(repo_url, scan_id, branch=branch, deep_history=deep_history)
        clone_path = info.path
        progress.set(
            "cloned " + info.commit_sha[:8], 12,
            provider=info.provider,
            branch=info.branch,
            commit_sha=info.commit_sha,
            languages=info.languages,
        )

        # --------------------------------------------------------- scanners
        results = _run_scanners(info.path, deep_history, progress)
        raw = [f for r in results for f in r.findings]
        findings = merge(raw)
        attach_snippets(findings, info.path)

        progress.set(
            "{} findings from {} scanners".format(len(findings), len(results)), 55,
            scanner_runs=[r.to_dict() for r in results],
        )

        # ----------------------------------------------------------- triage
        verdicts: dict[int, TriagedFinding] = {}
        narrative = ""
        usage: dict = {}

        provider = None
        if want_triage and findings:
            try:
                provider = get_provider(want_provider, want_model or None)
            except ProviderUnavailable as exc:
                # Not fatal: report what the scanners found and say why triage
                # did not run, rather than throwing the whole scan away.
                log.warning("triage provider unavailable: %s", exc)
                usage = {"errors": [str(exc)]}

        if provider is not None:
            triage = Triage(provider)
            progress.set("AI triage via {}".format(triage.label), 56)

            def on_batch(done: int, total: int) -> None:
                progress.set(
                    "AI triage {}/{} batches ({})".format(done, total, provider.label),
                    55 + int(30 * done / max(total, 1)),
                )

            verdicts = triage.triage(findings, on_progress=on_batch)
            progress.set("writing report narrative", 88)
            try:
                narrative = triage.executive_summary(
                    repo_url, info.languages, findings, verdicts,
                    [r.to_dict() for r in results],
                )
            except Exception as exc:  # a missing narrative must not fail the scan
                log.warning("narrative generation failed: %s", exc)
                triage.usage.errors.append("Narrative generation failed: {}".format(exc)[:300])

            usage = triage.usage.to_dict()
            usage["provider"] = provider.key
            usage["provider_label"] = provider.label
            usage["model"] = provider.model

        # ---------------------------------------------------------- persist
        progress.set("saving results", 92)
        summary = _summarize(findings, verdicts)
        _persist(scan_id, findings, verdicts, summary, narrative, usage,
                 [r.to_dict() for r in results],
                 provider.key if provider else "none",
                 provider.model if provider else "")

        # ----------------------------------------------------------- report
        progress.set("rendering report", 96)
        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            report_mod.write_all(scan)

        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            if scan is not None:
                scan.status = "completed"
                scan.stage = "completed"
                scan.progress = 100
                scan.finished_at = utcnow()

    except Exception as exc:
        log.exception("scan %s failed", scan_id)
        with session_scope() as session:
            scan = session.get(Scan, scan_id)
            if scan is not None:
                scan.status = "failed"
                scan.stage = "failed"
                scan.error = "{}: {}".format(type(exc).__name__, exc)[:2000]
                scan.finished_at = utcnow()
    finally:
        # The clone can be gigabytes; nothing downstream needs it once the
        # snippets have been copied into the findings.
        if clone_path is not None:
            repo_mod.remove_tree(clone_path)


def _run_scanners(repo: Path, deep_history: bool, progress: Progress) -> list[ScanResult]:
    """Run every installed scanner in parallel - they are subprocess-bound, so
    threads give real concurrency here."""
    scanners = build_scanners(scan_history=deep_history)
    results: list[ScanResult] = []
    done = 0

    with tempfile.TemporaryDirectory(prefix="vapt-") as tmp:
        workdir = Path(tmp)
        # Each scanner gets its own output directory, created before it starts.
        dirs = {}
        for scanner in scanners:
            dirs[scanner.name] = workdir / scanner.name
            dirs[scanner.name].mkdir(parents=True, exist_ok=True)

        with ThreadPoolExecutor(max_workers=min(4, len(scanners))) as pool:
            futures = {
                pool.submit(s.run, repo, dirs[s.name]): s for s in scanners
            }
            for future in as_completed(futures):
                scanner = futures[future]
                result = future.result()
                results.append(result)
                done += 1
                progress.set(
                    "scanning ({}/{}) - {} {}".format(
                        done, len(scanners), scanner.name, result.status
                    ),
                    12 + int(40 * done / len(scanners)),
                )

    results.sort(key=lambda r: r.name)
    return results


def _summarize(findings: list[Finding], verdicts: dict[int, TriagedFinding]) -> dict:
    effective = []
    confirmed = 0
    dismissed = 0
    needs_review = 0
    for i, f in enumerate(findings):
        v = verdicts.get(i)
        if v is None:
            effective.append(f.severity)
            continue
        if v.verdict == "false_positive":
            dismissed += 1
            continue
        if v.verdict == "needs_review":
            needs_review += 1
        else:
            confirmed += 1
        effective.append(v.severity)

    counts = {s: 0 for s in _RISK_WEIGHTS}
    for severity in effective:
        counts[severity] = counts.get(severity, 0) + 1

    raw_counts = counts_by_severity(findings)
    score = min(100, sum(_RISK_WEIGHTS.get(s, 0) * n for s, n in counts.items()))

    return {
        "total_findings": len(findings),
        "counts": counts,
        "raw_counts": raw_counts,
        "confirmed": confirmed,
        "dismissed": dismissed,
        "needs_review": needs_review,
        "untriaged": len(findings) - len(verdicts),
        "risk_score": score,
        "grade": _grade(score, counts),
    }


def _grade(score: int, counts: dict[str, int]) -> str:
    if counts.get("CRITICAL"):
        return "F"
    if score >= 60:
        return "E"
    if score >= 35:
        return "D"
    if score >= 15:
        return "C"
    if score > 0:
        return "B"
    return "A"


def _persist(
    scan_id: str,
    findings: list[Finding],
    verdicts: dict[int, TriagedFinding],
    summary: dict,
    narrative: str,
    usage: dict,
    scanner_runs: list[dict],
    provider_key: str,
    provider_model: str,
) -> None:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        scan.summary = summary
        scan.executive_summary = narrative
        scan.triage_usage = usage
        scan.scanner_runs = scanner_runs
        scan.ai_provider = provider_key
        scan.ai_model = provider_model

        for i, f in enumerate(findings):
            v = verdicts.get(i)
            session.add(
                FindingRow(
                    scan_id=scan_id,
                    fingerprint=f.fingerprint,
                    scanner=f.scanner,
                    category=f.category,
                    rule_id=f.rule_id,
                    title=f.title,
                    description=f.description,
                    severity=f.severity,
                    file_path=f.file_path,
                    line_start=f.line_start,
                    line_end=f.line_end,
                    code_snippet=f.code_snippet,
                    cwe=f.cwe,
                    cve=f.cve,
                    package=f.package,
                    installed_version=f.installed_version,
                    fixed_version=f.fixed_version,
                    reference=f.reference,
                    corroborated_by=f.corroborated_by,
                    triaged=1 if v else 0,
                    verdict=v.verdict if v else "",
                    confidence=v.confidence if v else "",
                    ai_severity=v.severity if v else "",
                    attack_scenario=v.attack_scenario if v else "",
                    remediation=v.remediation if v else "",
                    triage_rationale=v.rationale if v else "",
                    raw=f.raw,
                )
            )
