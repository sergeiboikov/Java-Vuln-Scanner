import json
import subprocess
import uuid
from collections.abc import Callable
from pathlib import Path

from .config import Config

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


class TrivyError(RuntimeError):
    pass


def _run(command: list[str], timeout_sec: int, description: str, input_text: str | None = None):
    try:
        result = subprocess.run(
            command, input=input_text, capture_output=True, text=True, timeout=timeout_sec
        )
    except subprocess.TimeoutExpired as exc:
        raise TrivyError(f"{description}: timeout ({timeout_sec} s)") from exc
    except OSError as exc:
        raise TrivyError(f"{description}: {exc}") from exc
    return result


def _image_exists(image: str, timeout_sec: int) -> bool:
    result = _run(
        ["docker", "image", "inspect", image], timeout_sec, f"docker image inspect {image}"
    )
    return result.returncode == 0


def ensure_image(config: Config) -> None:
    if _image_exists(config.trivy_image, config.docker_timeout_sec):
        return
    raise TrivyError(
        f"Trivy image not found locally: {config.trivy_image}\n"
        f"Hint: run 'docker pull {config.trivy_image}' manually."
    )


def count_vulnerabilities(payload: dict) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for result in payload.get("Results") or []:
        for vulnerability in result.get("Vulnerabilities") or []:
            severity = str(vulnerability.get("Severity") or "").upper()
            if severity in counts:
                counts[severity] += 1
    return counts


def _host_path(path: Path) -> str:
    """Translate a Windows path to the docker host mount style (/mnt/<drive>/...)."""
    text = str(path)
    if len(text) >= 2 and text[1] == ":":
        drive = text[0].lower()
        rest = text[2:].replace("\\", "/").lstrip("/")
        return f"/mnt/{drive}/{rest}"
    if text.startswith("\\\\"):
        return text
    return text.replace("\\", "/")


def _build_command(
    config: Config, directory: Path, output_dir: Path, container_name: str
) -> list[str]:
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "-v",
        f"{_host_path(directory)}:/scan:ro",
        "-v",
        f"{_host_path(output_dir)}:/out:rw",
        "-v",
        f"{config.trivy_cache_volume}:/root/.cache/trivy",
        "-e",
        "TRIVY_NO_PROGRESS=true",
    ]
    command += [config.trivy_image, "fs", "--scanners", "vuln", "--format", "json", "--quiet", "--skip-db-update", "--output", "/out/report.json", "/scan"]
    return command


def scan_directory(config: Config, directory: Path, log: Callable[[str], None]) -> dict[str, int]:
    output_dir = directory.parent / "out"
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.json"
    report_path.unlink(missing_ok=True)
    container_name = f"vuln-scan-{uuid.uuid4().hex[:12]}"
    try:
        try:
            result = subprocess.run(
                _build_command(config, directory, output_dir, container_name),
                capture_output=True,
                text=True,
                timeout=config.scan_timeout_sec,
            )
        except subprocess.TimeoutExpired as exc:
            subprocess.run(
                ["docker", "rm", "-f", container_name], capture_output=True, text=True
            )
            raise TrivyError(f"trivy fs: scan timeout ({config.scan_timeout_sec} s)") from exc
        except OSError as exc:
            raise TrivyError(f"trivy fs: {exc}") from exc
        if result.returncode != 0:
            message = (result.stderr or "").strip() or f"return code {result.returncode}"
            raise TrivyError(f"trivy fs: {message}")
        if result.stderr and result.stderr.strip():
            log(result.stderr.strip()[-2000:])
        if not report_path.is_file():
            raise TrivyError("trivy fs: no report produced")
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise TrivyError(f"could not parse Trivy JSON output: {exc}") from exc
        return count_vulnerabilities(payload)
    finally:
        report_path.unlink(missing_ok=True)
