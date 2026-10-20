import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

DEFAULT_GIT_BASE_URL = "https://gitlabsvr.nsd.ru/gitlab"
DEFAULT_REGISTRY_URL = "artifactory.nsd.ru:18079"
DEFAULT_WORKERS = 4
DEFAULT_REPOSITORIES_FILE = "repositories.json"
DEFAULT_OUTPUT_FOLDER = "reports"
DEFAULT_CACHE_VOLUME = "trivy-cache"
DEFAULT_CLONE_TIMEOUT_SEC = 600
DEFAULT_DOCKER_TIMEOUT_SEC = 600
DEFAULT_SCAN_TIMEOUT_SEC = 1800
DEFAULT_DB_INSTALL_TIMEOUT_SEC = 1800
DEFAULT_TRIVY_VERSION = "0.71.2"
DEFAULT_TRIVY_DB_URL = (
    "https://proxyp.nsd.ru/dmzart1/repository/raw_hosted_repo/aquasec/trivy-offline.db.v2.tgz"
)
DEFAULT_TRIVY_JAVA_DB_URL = (
    "https://proxyp.nsd.ru/dmzart1/repository/raw_hosted_repo/aquasec/trivy-java-db.tar.gz"
)
TRUE_VALUES = {"1", "true", "yes", "on"}


class ConfigError(RuntimeError):
    pass


@dataclass
class Config:
    git_token: str
    git_base_url: str
    workers: int
    registry_url: str
    trivy_version: str
    trivy_image: str
    repositories_file: Path
    output_folder: Path
    trivy_cache_volume: str
    trivy_db_url: str
    trivy_java_db_url: str
    clone_timeout_sec: int
    docker_timeout_sec: int
    scan_timeout_sec: int
    db_install_timeout_sec: int


def _optional(value: str | None) -> str | None:
    cleaned = (value or "").strip()
    return cleaned or None


def _resolve_path(value: str | None, base_dir: Path, default: str) -> Path:
    raw = _optional(value) or default
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path


def _parse_positive_int(name: str, value: str | None, default: int) -> int:
    raw = _optional(value) or str(default)
    try:
        number = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got: {raw!r}") from exc
    if number < 1:
        raise ConfigError(f"{name} must be >= 1")
    return number


def load_config(env_file: Path) -> Config:
    if not env_file.is_file():
        raise ConfigError(f"Environment file not found: {env_file}")
    load_dotenv(env_file)
    base_dir = env_file.resolve().parent

    git_token = _optional(os.environ.get("GIT_TOKEN"))
    if not git_token:
        raise ConfigError("GIT_TOKEN is not set (see .env)")

    git_base_url = _optional(os.environ.get("GIT_BASE_URL")) or DEFAULT_GIT_BASE_URL
    registry_url = _optional(os.environ.get("REGISTRY_URL")) or DEFAULT_REGISTRY_URL

    trivy_version = _optional(os.environ.get("TRIVY_VERSION")) or DEFAULT_TRIVY_VERSION
    trivy_image=f"{registry_url}/aquasec/trivy:{trivy_version}"

    return Config(
        git_token=git_token,
        git_base_url=git_base_url,
        workers=_parse_positive_int("WORKERS", os.environ.get("WORKERS"), DEFAULT_WORKERS),
        registry_url=registry_url,
        trivy_version=trivy_version,
        trivy_image=trivy_image,
        repositories_file=_resolve_path(
            os.environ.get("REPOSITORIES_FILE"), base_dir, DEFAULT_REPOSITORIES_FILE
        ),
        output_folder=_resolve_path(os.environ.get("OUTPUT_FOLDER"), base_dir, DEFAULT_OUTPUT_FOLDER),
        trivy_cache_volume=_optional(os.environ.get("TRIVY_CACHE_VOLUME")) or DEFAULT_CACHE_VOLUME,
        trivy_db_url=_optional(os.environ.get("TRIVY_DB_URL")) or DEFAULT_TRIVY_DB_URL,
        trivy_java_db_url=_optional(os.environ.get("TRIVY_JAVA_DB_URL")) or DEFAULT_TRIVY_JAVA_DB_URL,
        clone_timeout_sec=_parse_positive_int(
            "CLONE_TIMEOUT_SEC", os.environ.get("CLONE_TIMEOUT_SEC"), DEFAULT_CLONE_TIMEOUT_SEC
        ),
        docker_timeout_sec=_parse_positive_int(
            "DOCKER_TIMEOUT_SEC", os.environ.get("DOCKER_TIMEOUT_SEC"), DEFAULT_DOCKER_TIMEOUT_SEC
        ),
        scan_timeout_sec=_parse_positive_int(
            "SCAN_TIMEOUT_SEC", os.environ.get("SCAN_TIMEOUT_SEC"), DEFAULT_SCAN_TIMEOUT_SEC
        ),
        db_install_timeout_sec=_parse_positive_int(
            "DB_INSTALL_TIMEOUT_SEC",
            os.environ.get("DB_INSTALL_TIMEOUT_SEC"),
            DEFAULT_DB_INSTALL_TIMEOUT_SEC,
        ),
    )
