import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from .config import Config
from .trivy import TrivyError, _host_path

CACHE_DIR = "/root/.cache/trivy"
DB_DIR = f"{CACHE_DIR}/db"
JAVA_DB_DIR = f"{CACHE_DIR}/java-db"
EXPECTED_FILES = (
    f"{DB_DIR}/trivy.db",
    f"{DB_DIR}/metadata.json",
    f"{JAVA_DB_DIR}/trivy-java.db",
    f"{JAVA_DB_DIR}/metadata.json",
)


def _run(
    command: list[str],
    timeout_sec: int,
    description: str,
    log: Callable[[str], None] | None = None,
) -> subprocess.CompletedProcess:
    if log is not None:
        log(f"$ {' '.join(command)}")
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.TimeoutExpired as exc:
        raise TrivyError(f"{description}: timeout ({timeout_sec} s)") from exc
    except OSError as exc:
        raise TrivyError(f"{description}: {exc}") from exc


def _fail_on_error(result: subprocess.CompletedProcess, description: str) -> None:
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip() or f"return code {result.returncode}"
        raise TrivyError(f"{description}: {message}")


def pull_image(config: Config, log: Callable[[str], None]) -> None:
    log(f"pulling Trivy image: {config.trivy_image}")
    result = _run(
        ["docker", "pull", config.trivy_image],
        config.docker_timeout_sec,
        f"docker pull {config.trivy_image}",
        log,
    )
    _fail_on_error(result, f"docker pull {config.trivy_image}")


def _run_in_container(
    config: Config,
    script: str,
    description: str,
    log: Callable[[str], None],
) -> str:
    """Run a shell script inside Trivy with the cache volume mounted.

    Some Docker/red-docker (WSL2) setups do not attach ``docker run`` stdout,
    so the script writes its output to a file on a mounted host directory that
    is read back here.
    """
    output_dir = Path(tempfile.mkdtemp(prefix="trivy-db-"))
    result_path = output_dir / "result.txt"
    wrapped = f"{{ {script} ; }} > /out/result.txt 2>&1"
    try:
        result = _run(
            [
                "docker", "run", "--rm",
                "-v", f"{config.trivy_cache_volume}:{CACHE_DIR}",
                "-v", f"{_host_path(output_dir)}:/out:rw",
                "--entrypoint", "sh",
                config.trivy_image, "-c", wrapped,
            ],
            config.db_install_timeout_sec,
            description,
            log,
        )
        output = result_path.read_text(encoding="utf-8", errors="replace") if result_path.is_file() else ""
        if output.strip():
            log(output.strip())
        if result.returncode != 0:
            message = output.strip() or (result.stderr or result.stdout or "").strip()
            raise TrivyError(f"{description}: {message or f'return code {result.returncode}'}")
        return output
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)


def install_databases(config: Config, log: Callable[[str], None]) -> None:
    script = (
        f"wget -q --no-check-certificate -O /tmp/db.tgz '{config.trivy_db_url}' && "
        f"rm -rf {DB_DIR} && mkdir -p {DB_DIR} && "
        f"tar -xzf /tmp/db.tgz -C {DB_DIR} && rm -f /tmp/db.tgz && "
        f"wget -q --no-check-certificate -O /tmp/java.tgz '{config.trivy_java_db_url}' && "
        f"rm -rf {JAVA_DB_DIR} && mkdir -p {CACHE_DIR} && "
        f"tar -xzf /tmp/java.tgz -C {CACHE_DIR} && rm -f /tmp/java.tgz && "
        + _list_files()
    )
    log(f"installing Trivy databases into volume '{config.trivy_cache_volume}'")
    _run_in_container(config, script, "install Trivy databases", log)


def update_main_database(config: Config, log: Callable[[str], None]) -> None:
    script = (
        f"wget -q --no-check-certificate -O /tmp/db.tgz '{config.trivy_db_url}' && "
        f"rm -rf {DB_DIR} && mkdir -p {DB_DIR} && "
        f"tar -xzf /tmp/db.tgz -C {DB_DIR} && rm -f /tmp/db.tgz && " + _list_files()
    )
    log(f"updating Trivy main database in volume '{config.trivy_cache_volume}'")
    _run_in_container(config, script, "update Trivy main database", log)


def verify_databases(config: Config, log: Callable[[str], None]) -> list[str]:
    script = (
        f"for f in {' '.join(EXPECTED_FILES)}; do "
        f'if [ -f "$f" ]; then echo "OK $f"; else echo "MISSING $f"; fi; done'
    )
    output = _run_in_container(config, script, "verify Trivy databases", log)
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return [line.split(" ", 1)[1] for line in lines if line.startswith("MISSING")]


def _list_files() -> str:
    return "find /root/.cache/trivy -maxdepth 2 -type f"
