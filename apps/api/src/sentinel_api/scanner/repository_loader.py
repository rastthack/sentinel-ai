"""Resolve and validate local repository paths without modifying them."""

import os
from pathlib import Path

from sentinel_api.scanner.exceptions import (
    RepositoryNotDirectoryError,
    RepositoryNotFoundError,
    RepositoryOutsideRootError,
    ScanConfigurationError,
    UnsafeRepositoryPathError,
)
from sentinel_api.scanner.models import LoadedRepository


def default_scan_root() -> Path:
    """Return the Sentinel repository root from the installed source layout."""
    return Path(__file__).resolve().parents[5]


def configured_scan_root() -> Path:
    """Resolve the explicitly configured root or the safe local repository default."""
    configured = os.getenv("SENTINEL_SCAN_ROOT")
    root = Path(configured).expanduser() if configured else default_scan_root()
    try:
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ScanConfigurationError("The configured scan root is unavailable") from error
    if not resolved.is_dir():
        raise ScanConfigurationError("The configured scan root must be a directory")
    if resolved == Path(resolved.anchor):
        raise ScanConfigurationError("The filesystem root cannot be used as the scan root")
    return resolved


class RepositoryLoader:
    """Validate requested paths against one immutable allowed root."""

    def __init__(self, allowed_root: Path) -> None:
        try:
            self.allowed_root = allowed_root.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ScanConfigurationError("The configured scan root is unavailable") from error
        if not self.allowed_root.is_dir() or self.allowed_root == Path(self.allowed_root.anchor):
            raise ScanConfigurationError("The configured scan root is unsafe")

    def load(self, requested_path: str | Path) -> LoadedRepository:
        """Return validated repository metadata or a typed safety error."""
        raw_path = Path(requested_path).expanduser()
        if ".." in raw_path.parts:
            raise UnsafeRepositoryPathError("Repository path traversal is not allowed")

        candidate = raw_path if raw_path.is_absolute() else self.allowed_root / raw_path
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError as error:
            raise RepositoryNotFoundError("The requested repository does not exist") from error
        except (OSError, RuntimeError) as error:
            raise UnsafeRepositoryPathError("The requested repository path is unsafe") from error

        if resolved == Path(resolved.anchor):
            raise UnsafeRepositoryPathError("The filesystem root cannot be scanned")
        if not resolved.is_relative_to(self.allowed_root):
            raise RepositoryOutsideRootError(
                "The requested repository is outside the configured scan root"
            )
        if not resolved.is_dir():
            raise RepositoryNotDirectoryError("The requested repository must be a directory")

        relative = resolved.relative_to(self.allowed_root).as_posix()
        return LoadedRepository(
            root=resolved,
            allowed_root=self.allowed_root,
            name=resolved.name,
            relative_path=relative if relative != "." else resolved.name,
        )
