import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .config import Config
from .gitlab import build_clone_url, clone_repository, resolve_branch
from .report import ReportRow
from .repositories import Repository
from .trivy import scan_directory


def scan_repository(repository: Repository, config: Config, log) -> ReportRow:
    workspace: Path | None = None
    try:
        workspace = Path(tempfile.mkdtemp(prefix="vuln-scan-"))
        checkout = workspace / "repo"
        clone_url = build_clone_url(config.git_base_url, repository.path)
        log(f"[{repository.path}] cloning (branch: {repository.branch or 'default'})")
        clone_repository(
            clone_url, checkout, repository.branch, config.git_token, config.clone_timeout_sec
        )
        branch = resolve_branch(checkout, repository.branch)
        log(f"[{repository.path}] running Trivy (branch: {branch})")
        counts = scan_directory(config, checkout, log)
        log(
            f"[{repository.path}] done: "
            f"CRITICAL={counts['CRITICAL']} HIGH={counts['HIGH']} "
            f"MEDIUM={counts['MEDIUM']} LOW={counts['LOW']}"
        )
        return ReportRow(
            name=repository.path,
            url=repository.url,
            team=repository.team,
            branch=branch,
            trivy_version=config.trivy_version,
            counts=counts,
        )
    except Exception as exc:
        message = str(exc)
        log(f"[{repository.path}] ERROR: {message}")
        return ReportRow(
            name=repository.path,
            url=repository.url,
            team=repository.team,
            branch=repository.branch or "",
            trivy_version=config.trivy_version,
            error=message,
        )
    finally:
        if workspace is not None:
            shutil.rmtree(workspace, ignore_errors=True)


def scan_all(repositories: list[Repository], config: Config, log) -> list[ReportRow]:
    workers = max(1, min(config.workers, len(repositories)))
    rows: list[ReportRow] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_repository, repository, config, log): repository
            for repository in repositories
        }
        for future in as_completed(futures):
            repository = futures[future]
            try:
                rows.append(future.result())
            except Exception as exc:
                log(f"[{repository.path}] ERROR: {exc}")
                rows.append(
                    ReportRow(
                        name=repository.path,
                        url=repository.url,
                        team=repository.team,
                        branch=repository.branch or "",
                        trivy_version=config.trivy_version,
                        error=str(exc),
                    )
                )
    return rows
