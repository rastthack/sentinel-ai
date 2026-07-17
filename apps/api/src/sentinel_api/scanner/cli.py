"""Command-line interface for the shared static repository scan service."""

import argparse
import json
from pathlib import Path

from sentinel_api.scanner.exceptions import ScannerError
from sentinel_api.scanner.service import build_scan_service


def main() -> int:
    """Run a safe local scan and write formatted JSON to standard output."""
    parser = argparse.ArgumentParser(description="Statically inspect an allowed local repository")
    parser.add_argument(
        "repository_path",
        help="Repository path, relative to the current directory",
    )
    parser.add_argument(
        "--scan-root",
        type=Path,
        help="Allowed scan root; defaults to SENTINEL_SCAN_ROOT or the Sentinel repository",
    )
    arguments = parser.parse_args()

    requested = Path(arguments.repository_path).expanduser()
    if not requested.is_absolute():
        requested = (Path.cwd() / requested).resolve()

    try:
        response = build_scan_service(arguments.scan_root).scan(requested)
    except ScannerError as error:
        print(json.dumps({"error": {"code": error.code, "message": error.public_message}}))
        return 2

    print(response.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
