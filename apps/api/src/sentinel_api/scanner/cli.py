"""Command-line interface for the shared static repository scan service."""

import argparse
import json
from pathlib import Path

from sentinel_api.scanner.exceptions import ScannerError
from sentinel_api.scanner.models import RepositoryScanResponse
from sentinel_api.scanner.service import build_scan_service


def _summary(response: RepositoryScanResponse) -> str:
    """Render a concise structure summary without source contents."""
    lines = [
        f"Repository: {response.repository.name}",
        "Technology stack: " + ", ".join(item.name for item in response.technologies),
        (
            f"Routes: {response.summary.route_count} "
            f"({response.summary.protected_route_count} protected, "
            f"{response.summary.public_route_count} public)"
        ),
    ]
    lines.extend(
        f"  {route.method:6} {route.path:24} auth={route.authentication_required}"
        for route in response.routes
    )
    mechanisms = ", ".join(item.name for item in response.authentication.mechanisms)
    lines.append(f"Authentication: {mechanisms or 'none detected'}")
    lines.append(
        "Prisma models: "
        + (", ".join(model.name for model in response.data_model.models) or "none")
    )
    ownership = ", ".join(
        f"{candidate.model}.{candidate.field}"
        for candidate in response.data_model.ownership_candidates
    )
    lines.append(f"Ownership candidates: {ownership or 'none'}")
    lines.append("Route/model mappings:")
    lines.extend(
        f"  {mapping.route_id} -> {mapping.model}.{mapping.operation}"
        for mapping in response.route_model_mappings
    )
    return "\n".join(lines)


def main() -> int:
    """Run a safe local scan and write JSON or a human-readable summary."""
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
    parser.add_argument(
        "--format",
        choices=("json", "summary"),
        default="json",
        help="Output format (default: json)",
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

    if arguments.format == "summary":
        print(_summary(response))
    else:
        print(response.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
