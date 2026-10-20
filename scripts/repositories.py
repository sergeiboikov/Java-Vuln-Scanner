import json
from dataclasses import dataclass
from pathlib import Path

PROJECT_KEY = "group/project"


class RepositoryError(RuntimeError):
    pass


@dataclass
class Repository:
    path: str
    url: str
    team: str
    branch: str | None


def build_web_url(base_url: str, project_path: str) -> str:
    return f"{base_url.rstrip('/')}/{project_path.strip('/')}"


def load_repositories(file_path: Path, git_base_url: str) -> tuple[list[Repository], list[str]]:
    if not file_path.is_file():
        raise RepositoryError(f"Repository file not found: {file_path}")

    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RepositoryError(f"Invalid JSON in {file_path}: {exc}") from exc

    if not isinstance(data, list):
        raise RepositoryError(f"{file_path}: expected a JSON array of objects")

    repositories: list[Repository] = []
    warnings: list[str] = []
    seen: set[str] = set()

    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            warnings.append(f"#{index}: item is not an object, skipped")
            continue

        project_path = str(item.get(PROJECT_KEY) or "").strip().strip("/")
        if not project_path:
            warnings.append(f"#{index}: empty {PROJECT_KEY!r}, skipped")
            continue
        if project_path in seen:
            warnings.append(f"#{index}: duplicate {project_path!r}, skipped")
            continue

        url = str(item.get("URL") or "").strip()
        if not url:
            url = build_web_url(git_base_url, project_path)
            warnings.append(f"#{index}: empty 'URL', substituted with {url}")

        team = str(item.get("Team") or "").strip()
        if not team:
            warnings.append(f"#{index}: empty 'Team' ({project_path})")

        branch = str(item.get("branch") or "").strip() or None
        if branch is None:
            warnings.append(
                f"#{index}: empty 'branch' ({project_path}), the default branch will be used"
            )

        seen.add(project_path)
        repositories.append(Repository(path=project_path, url=url, team=team, branch=branch))

    return repositories, warnings
