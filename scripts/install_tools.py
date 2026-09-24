"""Install the scanner binaries that do not come from PyPI.

Semgrep, Bandit and Checkov arrive with `pip install -r requirements.txt`.
Gitleaks, Trivy and OSV-Scanner ship as single Go binaries, which this script
fetches from each project's latest GitHub release into ./tools/.

    python scripts/install_tools.py
    python scripts/install_tools.py --only gitleaks,trivy
"""

from __future__ import annotations

import argparse
import io
import json
import os
import platform
import re
import stat
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = ROOT / "tools"

# Each entry maps a tool to the GitHub repo and the asset-name pattern for this
# platform. Patterns are matched case-insensitively against the asset filename.
TOOLS = {
    "gitleaks": {
        "repo": "gitleaks/gitleaks",
        "assets": {
            ("windows", "amd64"): r"gitleaks_.*_windows_x64\.zip",
            ("windows", "arm64"): r"gitleaks_.*_windows_arm64\.zip",
            ("linux", "amd64"): r"gitleaks_.*_linux_x64\.tar\.gz",
            ("linux", "arm64"): r"gitleaks_.*_linux_arm64\.tar\.gz",
            ("darwin", "amd64"): r"gitleaks_.*_darwin_x64\.tar\.gz",
            ("darwin", "arm64"): r"gitleaks_.*_darwin_arm64\.tar\.gz",
        },
        "member": "gitleaks",
    },
    "trivy": {
        "repo": "aquasecurity/trivy",
        "assets": {
            ("windows", "amd64"): r"trivy_.*_windows-64bit\.zip",
            ("linux", "amd64"): r"trivy_.*_Linux-64bit\.tar\.gz",
            ("linux", "arm64"): r"trivy_.*_Linux-ARM64\.tar\.gz",
            ("darwin", "amd64"): r"trivy_.*_macOS-64bit\.tar\.gz",
            ("darwin", "arm64"): r"trivy_.*_macOS-ARM64\.tar\.gz",
        },
        "member": "trivy",
    },
    "osv-scanner": {
        "repo": "google/osv-scanner",
        "assets": {
            ("windows", "amd64"): r"osv-scanner.*windows_amd64(\.exe)?$",
            ("linux", "amd64"): r"osv-scanner.*linux_amd64$",
            ("linux", "arm64"): r"osv-scanner.*linux_arm64$",
            ("darwin", "amd64"): r"osv-scanner.*darwin_amd64$",
            ("darwin", "arm64"): r"osv-scanner.*darwin_arm64$",
        },
        "member": None,  # bare binary, not an archive
    },
}


def detect_platform() -> tuple[str, str]:
    system = platform.system().lower()
    if system.startswith("win"):
        system = "windows"
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = machine
    return system, arch


def latest_release(repo: str) -> dict:
    url = "https://api.github.com/repos/{}/releases/latest".format(repo)
    request = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": "vapt-ai"}
    )
    token = os.getenv("GITHUB_TOKEN")
    if token:
        # Lifts the 60/hour unauthenticated rate limit.
        request.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def pick_asset(release: dict, pattern: str) -> dict | None:
    regex = re.compile(pattern, re.IGNORECASE)
    for asset in release.get("assets", []):
        name = asset.get("name", "")
        if regex.search(name) and not name.endswith((".sig", ".pem", ".sbom", ".json")):
            return asset
    return None


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "vapt-ai"})
    with urllib.request.urlopen(request, timeout=600) as response:
        return response.read()


def extract(data: bytes, asset_name: str, member: str | None, dest_name: str) -> Path:
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    suffix = ".exe" if platform.system().lower().startswith("win") else ""
    target = TOOLS_DIR / (dest_name + suffix)

    if member is None:
        target.write_bytes(data)
    elif asset_name.lower().endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            name = _find_member(archive.namelist(), member)
            target.write_bytes(archive.read(name))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            name = _find_member(archive.getnames(), member)
            extracted = archive.extractfile(name)
            if extracted is None:
                raise RuntimeError("could not read {} from archive".format(name))
            target.write_bytes(extracted.read())

    target.chmod(target.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return target


def _find_member(names: list[str], wanted: str) -> str:
    for name in names:
        base = name.rsplit("/", 1)[-1]
        if base in (wanted, wanted + ".exe"):
            return name
    raise RuntimeError("{} not found in archive".format(wanted))


def install(tool: str, spec: dict, system: str, arch: str) -> bool:
    pattern = spec["assets"].get((system, arch))
    if pattern is None:
        print("  ! no {} build for {}/{}".format(tool, system, arch))
        return False

    try:
        release = latest_release(spec["repo"])
    except urllib.error.HTTPError as exc:
        hint = " (set GITHUB_TOKEN to lift the rate limit)" if exc.code == 403 else ""
        print("  ! could not reach GitHub for {}: {}{}".format(tool, exc, hint))
        return False
    except OSError as exc:
        print("  ! could not reach GitHub for {}: {}".format(tool, exc))
        return False

    asset = pick_asset(release, pattern)
    if asset is None:
        print("  ! release {} has no asset matching {}".format(
            release.get("tag_name", "?"), pattern))
        return False

    size_mb = asset.get("size", 0) / 1_048_576
    print("  downloading {} {} ({:.1f} MB)".format(
        tool, release.get("tag_name", ""), size_mb))
    try:
        data = download(asset["browser_download_url"])
        path = extract(data, asset["name"], spec["member"], tool)
    except (OSError, RuntimeError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print("  ! failed to install {}: {}".format(tool, exc))
        return False

    print("  installed -> {}".format(path))
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--only",
        default="",
        help="Comma-separated subset of: " + ", ".join(TOOLS),
    )
    args = parser.parse_args()

    system, arch = detect_platform()
    print("Installing scanner binaries for {}/{} into {}\n".format(system, arch, TOOLS_DIR))

    wanted = [t.strip() for t in args.only.split(",") if t.strip()] or list(TOOLS)
    unknown = [t for t in wanted if t not in TOOLS]
    if unknown:
        parser.error("unknown tool(s): " + ", ".join(unknown))

    installed = 0
    for tool in wanted:
        print(tool + ":")
        if install(tool, TOOLS[tool], system, arch):
            installed += 1
        print()

    print("{}/{} binaries installed.".format(installed, len(wanted)))
    print("\nPyPI scanners (semgrep, bandit, checkov) come from:")
    print("  pip install -r requirements.txt")
    return 0 if installed == len(wanted) else 1


if __name__ == "__main__":
    sys.exit(main())
