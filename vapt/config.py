"""Runtime configuration, read once from the environment."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = Path(os.getenv("VAPT_DATA_DIR", ROOT / "data")).resolve()
CLONE_DIR = DATA_DIR / "clones"
REPORT_DIR = DATA_DIR / "reports"
TOOLS_DIR = ROOT / "tools"
DB_PATH = DATA_DIR / "vapt.db"

# Triage backend. "auto" picks the first configured provider (Claude first),
# "none" disables AI entirely; anything else names a provider explicitly.
DEFAULT_PROVIDER = os.getenv("VAPT_PROVIDER", "auto")
DEFAULT_MODEL = os.getenv("VAPT_MODEL", "")

# Read by the provider classes through os.getenv; listed here so that
# load_dotenv() above is guaranteed to have run before anything reads them.
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY") or ""
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") or ""
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or ""
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN") or ""
GITLAB_TOKEN = os.getenv("GITLAB_TOKEN") or ""

SCANNER_TIMEOUT = int(os.getenv("VAPT_SCANNER_TIMEOUT", "900"))
MAX_CONCURRENT_SCANS = int(os.getenv("VAPT_MAX_CONCURRENT_SCANS", "2"))

# Findings sent to the triage engine in one request. Larger batches cost less per
# finding but risk a truncated response; 12 keeps each request comfortably
# inside max_tokens even when every finding carries a code snippet.
TRIAGE_BATCH_SIZE = int(os.getenv("VAPT_TRIAGE_BATCH_SIZE", "12"))

# Findings above this count are triaged highest-severity-first and the tail is
# left untriaged, so a pathological repo cannot run up an unbounded bill.
TRIAGE_MAX_FINDINGS = int(os.getenv("VAPT_TRIAGE_MAX_FINDINGS", "400"))


def ensure_dirs() -> None:
    for d in (DATA_DIR, CLONE_DIR, REPORT_DIR, TOOLS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def ai_enabled() -> bool:
    """True when at least one triage provider is usable right now."""
    from .providers import NONE, default_provider_key

    return default_provider_key() != NONE
