import csv
import re
from dataclasses import dataclass, field
from pathlib import Path

from .trivy import SEVERITIES

HEADER = [
    "Название репозитория",
    "URL",
    "Team",
    "Ветка",
    "Версия Trivy",
    "Статус проверки",
    "Кол-во уязвимостей (CRITICAL)",
    "Кол-во уязвимостей (HIGH)",
    "Кол-во уязвимостей (MEDIUM)",
    "Кол-во уязвимостей (LOW)",
    "Комментарий",
]

STATUS_SUCCESS = "Success"
STATUS_FAILED = "Failed"


@dataclass
class ReportRow:
    name: str
    url: str
    team: str
    branch: str
    trivy_version: str
    counts: dict[str, int] = field(default_factory=dict)
    error: str | None = None


FORMULA_PREFIXES = ("=", "+", "-", "@")


def _sanitize(value: object) -> str:
    text = "" if value is None else str(value)
    if text[:1] in FORMULA_PREFIXES:
        return "'" + text
    return text


def _sanitize_error(value: object) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.split())
    return _sanitize(text)


def _row_values(row: ReportRow) -> list[object]:
    if row.error:
        return [
            _sanitize(row.name),
            _sanitize(row.url),
            _sanitize(row.team),
            _sanitize(row.branch),
            _sanitize(row.trivy_version),
            STATUS_FAILED,
            "",
            "",
            "",
            "",
            _sanitize_error(row.error),
        ]
    return [
        _sanitize(row.name),
        _sanitize(row.url),
        _sanitize(row.team),
        _sanitize(row.branch),
        _sanitize(row.trivy_version),
        STATUS_SUCCESS,
        row.counts.get("CRITICAL", 0),
        row.counts.get("HIGH", 0),
        row.counts.get("MEDIUM", 0),
        row.counts.get("LOW", 0),
        "",
    ]


REPORT_NAME_PREFIX = "vuln_report_"
REPORT_NAME_SUFFIX = ".csv"


def resolve_report_path(output_folder: Path, report_date: str) -> Path:
    output_folder.mkdir(parents=True, exist_ok=True)
    prefix = f"{REPORT_NAME_PREFIX}{report_date}_"
    pattern = re.compile(rf"^{re.escape(prefix)}(\d+){re.escape(REPORT_NAME_SUFFIX)}$")
    max_number = 0
    for path in output_folder.iterdir():
        match = pattern.fullmatch(path.name)
        if match:
            max_number = max(max_number, int(match.group(1)))
    return output_folder / f"{prefix}{max_number + 1}{REPORT_NAME_SUFFIX}"


def write_report(rows: list[ReportRow], output_file: Path) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(rows, key=lambda row: row.name.casefold())
    with output_file.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle, delimiter=";")
        writer.writerow(HEADER)
        for row in ordered:
            writer.writerow(_row_values(row))


__all__ = ["ReportRow", "write_report", "resolve_report_path", "HEADER", "SEVERITIES"]
