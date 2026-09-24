"""SQLite persistence for scans and their findings."""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

from . import config

config.ensure_dirs()

_engine = create_engine(
    f"sqlite:///{config.DB_PATH}",
    future=True,
    # The worker pool touches the DB from threads other than the request thread.
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True)
    repo_url = Column(String(1024), nullable=False)
    provider = Column(String(32), default="")
    branch = Column(String(255), default="")
    commit_sha = Column(String(64), default="")

    status = Column(String(32), default="queued", index=True)
    stage = Column(String(64), default="queued")
    progress = Column(Integer, default=0)
    error = Column(Text, default="")

    deep_history = Column(Integer, default=0)
    ai_triage = Column(Integer, default=1)
    ai_provider = Column(String(32), default="")
    ai_model = Column(String(128), default="")

    created_at = Column(DateTime, default=utcnow)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    languages = Column(JSON, default=list)
    scanner_runs = Column(JSON, default=list)  # [{name, status, duration, findings, message}]
    summary = Column(JSON, default=dict)       # severity counts + risk score
    executive_summary = Column(Text, default="")
    triage_usage = Column(JSON, default=dict)  # token + cost accounting

    findings = relationship(
        "FindingRow",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def to_dict(self, include_findings: bool = False) -> dict[str, Any]:
        d = {
            "id": self.id,
            "repo_url": self.repo_url,
            "provider": self.provider,
            "branch": self.branch,
            "commit_sha": self.commit_sha,
            "status": self.status,
            "stage": self.stage,
            "progress": self.progress,
            "error": self.error or "",
            "deep_history": bool(self.deep_history),
            "ai_triage": bool(self.ai_triage),
            "ai_provider": self.ai_provider or "",
            "ai_model": self.ai_model or "",
            "created_at": _iso(self.created_at),
            "started_at": _iso(self.started_at),
            "finished_at": _iso(self.finished_at),
            "languages": self.languages or [],
            "scanner_runs": self.scanner_runs or [],
            "summary": self.summary or {},
            "executive_summary": self.executive_summary or "",
            "triage_usage": self.triage_usage or {},
        }
        if include_findings:
            d["findings"] = [f.to_dict() for f in self.findings]
        return d


class FindingRow(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    fingerprint = Column(String(32), index=True)

    scanner = Column(String(64))
    category = Column(String(32), index=True)
    rule_id = Column(String(255))
    title = Column(Text)
    description = Column(Text)
    severity = Column(String(16), index=True)

    file_path = Column(Text, default="")
    line_start = Column(Integer, default=0)
    line_end = Column(Integer, default=0)
    code_snippet = Column(Text, default="")

    cwe = Column(JSON, default=list)
    cve = Column(String(64), default="")
    package = Column(String(255), default="")
    installed_version = Column(String(128), default="")
    fixed_version = Column(String(128), default="")
    reference = Column(Text, default="")
    corroborated_by = Column(JSON, default=list)

    # --- AI triage output ---
    triaged = Column(Integer, default=0)
    verdict = Column(String(32), default="")          # true_positive | false_positive | needs_review
    confidence = Column(String(16), default="")       # high | medium | low
    ai_severity = Column(String(16), default="")
    attack_scenario = Column(Text, default="")
    remediation = Column(Text, default="")
    triage_rationale = Column(Text, default="")

    raw = Column(JSON, default=dict)

    scan = relationship("Scan", back_populates="findings")

    @property
    def effective_severity(self) -> str:
        return self.ai_severity or self.severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "scanner": self.scanner,
            "category": self.category,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "effective_severity": self.effective_severity,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "cwe": self.cwe or [],
            "cve": self.cve or "",
            "package": self.package or "",
            "installed_version": self.installed_version or "",
            "fixed_version": self.fixed_version or "",
            "reference": self.reference or "",
            "corroborated_by": self.corroborated_by or [],
            "triaged": bool(self.triaged),
            "verdict": self.verdict or "",
            "confidence": self.confidence or "",
            "ai_severity": self.ai_severity or "",
            "attack_scenario": self.attack_scenario or "",
            "remediation": self.remediation or "",
            "triage_rationale": self.triage_rationale or "",
        }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def init_db() -> None:
    Base.metadata.create_all(_engine)


@contextmanager
def session_scope() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
