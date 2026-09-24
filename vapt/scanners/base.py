"""Scanner plumbing: tool discovery and subprocess execution."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .. import config
from ..findings import Finding


class ScannerError(RuntimeError):
    pass


@dataclass
class ScanResult:
    name: str
    status: str            # ok | skipped | error
    findings: list[Finding]
    duration: float
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "findings": len(self.findings),
            "duration": round(self.duration, 1),
            "message": self.message,
        }


def find_tool(name: str) -> str | None:
    """Look in our own tools/ dir first, then PATH.

    tools/ holds binaries fetched by scripts/install_tools.py, so a project
    install never depends on what happens to be on the user's PATH.
    """
    exts = [".exe", ".cmd", ".bat", ""] if os.name == "nt" else [""]
    for ext in exts:
        candidate = config.TOOLS_DIR / f"{name}{ext}"
        if candidate.is_file():
            return str(candidate)
    return shutil.which(name)


def find_python_tool(console_script: str, module: str) -> list[str] | None:
    """Resolve a pip-installed tool.

    The console script is preferred - semgrep deprecates `python -m semgrep`,
    and several of these tools resolve their plugins relative to argv[0]. The
    module form is the fallback for environments where the shim did not land
    on PATH. `find_spec` checks importability without actually importing, which
    matters because importing checkov alone loads its whole plugin registry.
    """
    path = find_tool(console_script)
    if path:
        return [path]
    if importlib.util.find_spec(module) is not None:
        return [sys.executable, "-m", module]
    return None


def run_command(
    args: Sequence[str],
    cwd: Path,
    timeout: int | None = None,
    ok_codes: Sequence[int] = (0,),
) -> subprocess.CompletedProcess[str]:
    """Run a scanner. Most scanners exit non-zero simply because they found
    something, so callers declare which codes mean success."""
    timeout = timeout or config.SCANNER_TIMEOUT
    env = dict(os.environ)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        proc = subprocess.run(
            list(args),
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"timed out after {timeout}s") from exc
    except FileNotFoundError as exc:
        raise ScannerError(f"executable not found: {args[0]}") from exc

    if proc.returncode not in ok_codes:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        tail = " / ".join(detail[-3:])[:500] if detail else "no output"
        raise ScannerError(f"exit {proc.returncode}: {tail}")
    return proc


def load_json(path: Path) -> Any:
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ScannerError(f"could not parse output: {exc}") from exc


class Scanner(ABC):
    """One security tool, normalized into Findings."""

    name: str = ""
    category: str = ""
    description: str = ""
    install_hint: str = ""

    @abstractmethod
    def command(self) -> list[str] | None:
        """Command prefix for the tool, or None when it is not installed."""

    @abstractmethod
    def scan(self, repo: Path, workdir: Path) -> list[Finding]:
        """Run against `repo`, writing any temp output into `workdir`."""

    def available(self) -> bool:
        return self.command() is not None

    def version(self) -> str:
        cmd = self.command()
        if not cmd:
            return ""
        try:
            proc = subprocess.run(
                cmd + ["--version"], capture_output=True, text=True, timeout=60
            )
            return (proc.stdout or proc.stderr).strip().splitlines()[0][:80]
        except (OSError, subprocess.SubprocessError, IndexError):
            return ""

    def run(self, repo: Path, workdir: Path) -> ScanResult:
        started = time.monotonic()
        if not self.available():
            return ScanResult(
                self.name, "skipped", [], 0.0,
                f"not installed - {self.install_hint}",
            )
        try:
            findings = self.scan(repo, workdir)
        except ScannerError as exc:
            return ScanResult(self.name, "error", [], time.monotonic() - started, str(exc))
        except Exception as exc:  # a broken parser must not kill the whole scan
            return ScanResult(
                self.name, "error", [], time.monotonic() - started,
                f"{type(exc).__name__}: {exc}"[:500],
            )
        return ScanResult(self.name, "ok", findings, time.monotonic() - started)
