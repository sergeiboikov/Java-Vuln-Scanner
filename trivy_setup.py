import argparse
import sys
from pathlib import Path

from scripts.config import ConfigError, load_config
from scripts.trivy import TrivyError
from scripts.trivy_db import install_databases, pull_image, update_main_database, verify_databases


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _configure_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="java-vuln-scanner-setup",
        description="Prepare Trivy image and vulnerability databases for java-vuln-scanner.",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to the environment file (default: .env in the current directory)",
    )
    parser.add_argument(
        "command",
        choices=("all", "image", "db-install", "db-update", "verify"),
        help="all: pull image + install databases; image: pull Trivy image; "
        "db-install: (re)install both databases; db-update: update main database only; "
        "verify: check databases in the cache volume",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    _configure_streams()
    args = build_parser().parse_args(argv)
    try:
        config = load_config(Path(args.env_file))

        if args.command in ("all", "image"):
            pull_image(config, log)

        if args.command == "db-install":
            install_databases(config, log)
        elif args.command == "db-update":
            update_main_database(config, log)
        elif args.command == "all":
            install_databases(config, log)
        elif args.command == "verify":
            missing = verify_databases(config, log)
            if missing:
                log(f"missing files: {', '.join(missing)}")
                return 1

        log("done")
        return 0
    except ConfigError as exc:
        log(f"error: {exc}")
        return 1
    except TrivyError as exc:
        log(f"error: {exc}")
        return 1
    except OSError as exc:
        log(f"runtime error (is docker available?): {exc}")
        return 1
    except KeyboardInterrupt:
        log("interrupted by user")
        return 130
    except Exception as exc:
        log(f"unexpected error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
