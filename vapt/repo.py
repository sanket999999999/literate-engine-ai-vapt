"""Cloning and lightweight inventory of the target repository."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlparse, urlunparse

from . import config

_SUPPORTED_HOSTS = {
    "github.com": "github",
    "www.github.com": "github",
    "gitlab.com": "gitlab",
    "www.gitlab.com": "gitlab",
}

_LANG_BY_EXT = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".go": "Go",
    ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".hpp": "C++", ".rs": "Rust", ".kt": "Kotlin",
    ".scala": "Scala", ".swift": "Swift", ".sh": "Shell", ".tf": "Terraform",
    ".yaml": "YAML", ".yml": "YAML", ".dockerfile": "Docker", ".sql": "SQL",
}

_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "vendor", "dist", "build",
    "__pycache__", ".mypy_cache", ".pytest_cache", "target", ".next",
}


class RepoError(RuntimeError):
    pass


@dataclass
class RepoInfo:
    path: Path
    provider: str
    branch: str
    commit_sha: str
    languages: list[str]
    file_count: int


def parse_repo_url(url: str) -> tuple[str, str]:
    """Return (provider, canonical https url). Rejects anything not GitHub/GitLab.

    Restricting the scheme and host is what stops a scan request from turning
    into 'git clone whatever the submitter wants', including local paths and
    ssh:// URLs that would run arbitrary commands via core.sshCommand.
    """
    url = (url or "").strip()
    if not url:
        raise RepoError("Repository URL is required.")

    # Accept the shorthand `owner/repo` for GitHub.
    if re.fullmatch(r"[\w.-]+/[\w.-]+", url):
        url = f"https://github.com/{url}"

    if url.startswith("git@"):
        host, _, path = url[4:].partition(":")
        url = f"https://{host}/{path}"

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise RepoError("Only http(s) GitHub or GitLab URLs are supported.")

    provider = _SUPPORTED_HOSTS.get(parsed.netloc.lower())
    if provider is None:
        raise RepoError(
            f"Unsupported host '{parsed.netloc}'. Only github.com and gitlab.com are allowed."
        )

    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if len(path.strip("/").split("/")) < 2:
        raise RepoError("URL must point at a repository, e.g. https://github.com/owner/repo")

    canonical = urlunparse(("https", parsed.netloc.lower(), path + ".git", "", "", ""))
    return provider, canonical


def _authenticated_url(url: str, provider: str) -> str:
    """Inject a token for private repos. Never logged - see _run()."""
    token = config.GITHUB_TOKEN if provider == "github" else config.GITLAB_TOKEN
    if not token:
        return url
    parsed = urlparse(url)
    user = "oauth2" if provider == "gitlab" else "x-access-token"
    netloc = f"{quote(user)}:{quote(token)}@{parsed.netloc}"
    return urlunparse(parsed._replace(netloc=netloc))


def _run(args: list[str], cwd: Path | None = None, timeout: int = 600) -> str:
    env = dict(os.environ)
    # Any credential prompt would otherwise hang the worker thread forever.
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "echo"
    proc = subprocess.run(
        args, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env
    )
    if proc.returncode != 0:
        raise RepoError(_redact(proc.stderr.strip() or proc.stdout.strip()))
    return proc.stdout


def _redact(message: str) -> str:
    """Strip any credentials that git echoed back into an error message."""
    message = re.sub(r"https://[^@\s]+@", "https://", message)
    for token in (config.GITHUB_TOKEN, config.GITLAB_TOKEN):
        if token:
            message = message.replace(token, "***")
    return message[:2000]


def clone(url: str, scan_id: str, branch: str = "", deep_history: bool = False) -> RepoInfo:
    provider, canonical = parse_repo_url(url)
    dest = config.CLONE_DIR / scan_id
    remove_tree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    args = ["git", "clone", "--quiet"]
    if not deep_history:
        # Shallow is enough for code scanning; history scanning needs it all.
        args += ["--depth", "1"]
    if branch:
        args += ["--branch", branch, "--single-branch"]
    args += [_authenticated_url(canonical, provider), str(dest)]

    try:
        _run(args, timeout=900)
    except subprocess.TimeoutExpired as exc:
        raise RepoError("Clone timed out after 15 minutes.") from exc

    commit = _run(["git", "rev-parse", "HEAD"], cwd=dest).strip()
    actual_branch = branch or _run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=dest
    ).strip()

    languages, file_count = inventory(dest)
    return RepoInfo(
        path=dest,
        provider=provider,
        branch=actual_branch,
        commit_sha=commit,
        languages=languages,
        file_count=file_count,
    )


def inventory(root: Path) -> tuple[list[str], int]:
    counter: Counter[str] = Counter()
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            total += 1
            if name.lower().startswith("dockerfile"):
                counter["Docker"] += 1
                continue
            lang = _LANG_BY_EXT.get(Path(name).suffix.lower())
            if lang:
                counter[lang] += 1
    return [lang for lang, _ in counter.most_common(12)], total


def remove_tree(path: Path) -> None:
    """rmtree that survives git's read-only pack files on Windows."""
    if not path.exists():
        return

    def on_error(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass

    shutil.rmtree(path, onerror=on_error)
