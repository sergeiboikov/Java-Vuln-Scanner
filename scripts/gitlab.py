import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

RETRY_ATTEMPTS = 3
RESOLVE_BRANCH_TIMEOUT_SEC = 60
TOKEN_ENV_VAR = "VULN_SCANNER_TOKEN"

ASKPASS_HELPER = """import os
import sys

prompt = " ".join(sys.argv[1:]).lower()
sys.stdout.write("oauth2" if "username" in prompt else os.environ.get("VULN_SCANNER_TOKEN", ""))
"""


class CloneError(RuntimeError):
    pass


def build_clone_url(git_base_url: str, project_path: str) -> str:
    parts = urlsplit(git_base_url.rstrip("/"))
    prefix = parts.path.rstrip("/")
    path = f"{prefix}/{project_path.strip('/')}.git"
    return urlunsplit((parts.scheme or "https", f"oauth2@{parts.netloc}", path, "", ""))


def _askpass_launcher(workspace: Path) -> Path:
    helper = workspace / "askpass.py"
    helper.write_text(ASKPASS_HELPER, encoding="utf-8")

    if os.name == "nt":
        launcher = workspace / "askpass.cmd"
        launcher.write_text(f'@echo off\r\n"{sys.executable}" "{helper}" %*\r\n', encoding="utf-8")
    else:
        launcher = workspace / "askpass.sh"
        launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{helper}" "$@"\n', encoding="utf-8")
        launcher.chmod(0o700)
    return launcher


def clone_repository(
    clone_url: str,
    destination: Path,
    branch: str | None,
    token: str,
    timeout_sec: int,
) -> None:
    launcher = _askpass_launcher(destination.parent)

    environment = os.environ.copy()
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_ASKPASS"] = str(launcher)
    environment[TOKEN_ENV_VAR] = token

    command = ["git", "clone", "--depth", "1", "--single-branch", "--quiet"]
    if branch:
        command += ["--branch", branch]
    command += [clone_url, str(destination)]

    last_error = "unknown error"
    for attempt in range(RETRY_ATTEMPTS):
        if destination.exists():
            shutil.rmtree(destination, ignore_errors=True)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                env=environment,
                timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired:
            last_error = f"clone timeout ({timeout_sec} s)"
        else:
            if result.returncode == 0:
                return
            last_error = (
                result.stderr.strip() or result.stdout.strip() or f"return code {result.returncode}"
            )
        if attempt < RETRY_ATTEMPTS - 1:
            time.sleep(2**attempt)
    raise CloneError(f"git clone failed: {last_error}")


def resolve_branch(destination: Path, requested: str | None) -> str:
    if requested:
        return requested
    for arguments in (
        ["git", "-C", str(destination), "symbolic-ref", "--short", "HEAD"],
        ["git", "-C", str(destination), "rev-parse", "--abbrev-ref", "HEAD"],
    ):
        try:
            result = subprocess.run(
                arguments, capture_output=True, text=True, timeout=RESOLVE_BRANCH_TIMEOUT_SEC
            )
        except subprocess.TimeoutExpired:
            continue
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    return "(unknown)"
