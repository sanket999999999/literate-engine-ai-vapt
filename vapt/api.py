"""FastAPI application: REST API plus the dashboard."""

from __future__ import annotations

import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config, report as report_mod, repo as repo_mod
from .db import FindingRow, Scan, SessionLocal, init_db, session_scope
from .pipeline import run_scan
from .providers import (
    NONE,
    ProviderUnavailable,
    default_provider_key,
    get_provider,
    provider_status,
)
from .scanners import tool_status

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("vapt")

WEB_DIR = Path(__file__).parent / "web"

# Scans are long and subprocess-heavy; a small pool keeps a burst of
# submissions from starving the machine while still overlapping work.
_pool: ThreadPoolExecutor | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pool
    config.ensure_dirs()
    init_db()
    _requeue_interrupted()
    _pool = ThreadPoolExecutor(
        max_workers=config.MAX_CONCURRENT_SCANS, thread_name_prefix="vapt-scan"
    )
    # Probing six tools for their version takes seconds; do it off the startup
    # path so the dashboard's first /api/tools call is served from cache.
    threading.Thread(target=_warm_tool_cache, daemon=True).start()
    log.info("vapt-ai ready - AI triage %s", "enabled" if config.ai_enabled() else "DISABLED")
    yield
    if _pool is not None:
        _pool.shutdown(wait=False, cancel_futures=True)


app = FastAPI(
    title="vapt-ai",
    description="Automated VAPT pipeline for GitHub and GitLab repositories.",
    version="0.1.0",
    lifespan=lifespan,
)


def _warm_tool_cache() -> None:
    try:
        found = tool_status(refresh=True)
        log.info(
            "scanners ready: %s",
            ", ".join(t["name"] for t in found if t["available"]) or "none installed",
        )
    except Exception:
        log.exception("could not probe scanner versions")


def _requeue_interrupted() -> None:
    """A scan left 'running' by a crash or restart can never finish; mark it."""
    with session_scope() as session:
        stale = session.scalars(select(Scan).where(Scan.status == "running")).all()
        for scan in stale:
            scan.status = "failed"
            scan.stage = "interrupted"
            scan.error = "Server restarted while this scan was running."


def get_session() -> Session:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


# ------------------------------------------------------------------ schemas


class ScanRequest(BaseModel):
    repo_url: str = Field(
        description="GitHub or GitLab repository URL, or owner/repo shorthand.",
        examples=["https://github.com/owner/repo"],
    )
    branch: str = Field(default="", description="Branch to scan. Defaults to the repo's HEAD.")
    deep_history: bool = Field(
        default=False,
        description="Clone the full history so secrets can be traced through past commits.",
    )
    ai_triage: bool = Field(
        default=True, description="Run AI triage over the raw findings."
    )
    provider: str = Field(
        default="auto",
        description=(
            'Triage backend: "auto" (first configured), "none", or one of '
            'anthropic / openai / gemini / ollama.'
        ),
    )
    model: str = Field(default="", description="Model id. Empty uses the provider default.")


class ScanCreated(BaseModel):
    id: str
    status: str


# --------------------------------------------------------------------- API


@app.get("/api/health")
def health() -> dict:
    default = default_provider_key()
    return {
        "status": "ok",
        "ai_triage": default != NONE,
        "default_provider": default,
        "max_concurrent_scans": config.MAX_CONCURRENT_SCANS,
    }


@app.get("/api/providers")
def providers() -> dict:
    """Every triage backend and whether it is usable right now."""
    entries = provider_status()
    return {
        "providers": entries,
        "default": default_provider_key(),
        "available": sum(1 for p in entries if p["available"] and p["key"] != NONE),
    }


@app.get("/api/tools")
def tools() -> dict:
    status = tool_status()
    return {
        "tools": status,
        "installed": sum(1 for t in status if t["available"]),
        "total": len(status),
    }


@app.post("/api/scans", response_model=ScanCreated, status_code=201)
def create_scan(request: ScanRequest) -> ScanCreated:
    try:
        provider, canonical = repo_mod.parse_repo_url(request.repo_url)
    except repo_mod.RepoError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    provider_key = (request.provider or "auto").strip().lower()
    if provider_key == "auto":
        provider_key = default_provider_key()
    if not request.ai_triage:
        provider_key = NONE

    if provider_key != NONE:
        # Surface a misconfigured provider now, rather than 10 minutes into a
        # scan when the findings are already in hand.
        try:
            get_provider(provider_key, request.model or None)
        except ProviderUnavailable as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan_id = str(uuid.uuid4())
    with session_scope() as session:
        session.add(
            Scan(
                id=scan_id,
                repo_url=canonical,
                provider=provider,
                branch=request.branch.strip(),
                status="queued",
                stage="queued",
                progress=0,
                deep_history=int(request.deep_history),
                ai_triage=int(provider_key != NONE),
                ai_provider=provider_key,
                ai_model=request.model.strip(),
                languages=[],
                scanner_runs=[],
                summary={},
                triage_usage={},
            )
        )

    if _pool is None:
        raise HTTPException(status_code=503, detail="Worker pool is not running.")
    _pool.submit(run_scan, scan_id)
    log.info("queued scan %s for %s", scan_id, canonical)
    return ScanCreated(id=scan_id, status="queued")


@app.get("/api/scans")
def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    session: Session = Depends(get_session),
) -> dict:
    scans = session.scalars(
        select(Scan).order_by(Scan.created_at.desc()).limit(limit)
    ).all()
    return {"scans": [s.to_dict() for s in scans]}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, session: Session = Depends(get_session)) -> dict:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="No such scan.")
    return scan.to_dict()


@app.get("/api/scans/{scan_id}/findings")
def get_findings(
    scan_id: str,
    severity: str = Query(default="", description="Comma-separated severity filter."),
    category: str = Query(default="", description="Comma-separated category filter."),
    include_dismissed: bool = Query(default=False),
    session: Session = Depends(get_session),
) -> dict:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="No such scan.")

    rows = [f.to_dict() for f in scan.findings]
    if not include_dismissed:
        rows = [f for f in rows if f["verdict"] != "false_positive"]
    if severity:
        wanted = {s.strip().upper() for s in severity.split(",") if s.strip()}
        rows = [f for f in rows if f["effective_severity"] in wanted]
    if category:
        wanted = {c.strip().lower() for c in category.split(",") if c.strip()}
        rows = [f for f in rows if f["category"] in wanted]

    order = {s: i for i, s in enumerate(report_mod.SEVERITY_ORDER)}
    rows.sort(key=lambda f: (order.get(f["effective_severity"], 99), f["file_path"]))
    return {"findings": rows, "count": len(rows)}


@app.get("/api/scans/{scan_id}/report")
def get_report(
    scan_id: str,
    fmt: str = Query(default="html", pattern="^(html|md|json)$"),
    session: Session = Depends(get_session),
):
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="No such scan.")
    if scan.status != "completed":
        raise HTTPException(
            status_code=409,
            detail="Report is available once the scan completes (status: {}).".format(scan.status),
        )

    path = report_mod.report_paths(scan_id)[fmt]
    if not path.exists():
        # Regenerate rather than 404 - the DB is the source of truth.
        report_mod.write_all(scan)

    media = {
        "html": "text/html",
        "md": "text/markdown",
        "json": "application/json",
    }[fmt]
    if fmt == "html":
        return HTMLResponse(path.read_text(encoding="utf-8"))
    return FileResponse(
        path,
        media_type=media,
        filename="vapt-report-{}.{}".format(scan_id[:8], fmt),
    )


@app.delete("/api/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str):
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="No such scan.")
        if scan.status == "running":
            raise HTTPException(status_code=409, detail="Cannot delete a running scan.")
        session.delete(scan)

    repo_mod.remove_tree(config.REPORT_DIR / scan_id)
    repo_mod.remove_tree(config.CLONE_DIR / scan_id)
    return JSONResponse(status_code=204, content=None)


# ---------------------------------------------------------------- dashboard

DIST_DIR = WEB_DIR / "dist"


@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    index = DIST_DIR / "index.html"
    if not index.exists():
        # A source checkout has no build yet; say so instead of 404ing.
        return HTMLResponse(
            "<h1>vapt-ai</h1>"
            "<p>The dashboard has not been built yet. Run:</p>"
            "<pre>cd frontend &amp;&amp; npm install &amp;&amp; npm run build</pre>"
            "<p>The API is already up - see <a href='/docs'>/docs</a>.</p>",
            status_code=503,
        )
    return HTMLResponse(index.read_text(encoding="utf-8"))


if DIST_DIR.exists():
    # Mounted last so it never shadows an /api route. `html=True` serves
    # index.html for unknown paths, which is what a single-page app needs.
    app.mount("/", StaticFiles(directory=DIST_DIR, html=True), name="dashboard")
