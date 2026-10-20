import argparse
import sys
from datetime import date
from pathlib import Path

from scripts.config import ConfigError, load_config
from scripts.report import resolve_report_path, write_report
from scripts.repositories import RepositoryError, load_repositories
from scripts.scanner import scan_all
from scripts.trivy import TrivyError, ensure_image


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _configure_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="java-vuln-scanner",
        description="Vulnerability report for GitLab repositories powered by Trivy (CSV).",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to the environment file (default: .env in the current directory)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    _configure_streams()
    report_date = date.today().strftime("%Y%m%d")
    args = build_parser().parse_args(argv)
    try:
        config = load_config(Path(args.env_file))
        repositories, warnings = load_repositories(config.repositories_file, config.git_base_url)
        for warning in warnings:
            log(f"warning: {warning}")

        if not repositories:
            log("no repositories to scan")
            return 1

        log(f"repositories: {len(repositories)}; workers: {config.workers}")
        ensure_image(config)
        rows = scan_all(repositories, config, log)
        report_path = resolve_report_path(config.output_folder, report_date)
        write_report(rows, report_path)

        failed = sum(1 for row in rows if row.error)
        log(f"report: {report_path} (rows: {len(rows)}, errors: {failed})")
        return 0
    except (ConfigError, RepositoryError, TrivyError) as exc:
        log(f"error: {exc}")
        return 1
    except OSError as exc:
        log(f"runtime error (are docker/git available?): {exc}")
        return 1
    except KeyboardInterrupt:
        log("interrupted by user")
        return 130
    except Exception as exc:
        log(f"unexpected error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
