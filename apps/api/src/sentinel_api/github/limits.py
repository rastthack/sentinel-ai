"""Metadata-only resource limits for already acquired repositories."""

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from sentinel_api.github.exceptions import (
    GitHubRepositoryInspectionError,
    GitHubRepositoryInvalidLayoutError,
    GitHubRepositoryTooLargeError,
    GitHubRepositoryTooManyFilesError,
)


@dataclass(frozen=True, slots=True)
class RepositoryLimits:
    """Server-controlled bounds for one acquired repository."""

    max_repository_bytes: int = 50 * 1024 * 1024
    max_file_count: int = 5_000
    max_individual_file_bytes: int = 1 * 1024 * 1024
    max_inspected_bytes: int = 20 * 1024 * 1024

    def __post_init__(self) -> None:
        if any(
            value <= 0
            for value in (
                self.max_repository_bytes,
                self.max_file_count,
                self.max_individual_file_bytes,
                self.max_inspected_bytes,
            )
        ):
            raise ValueError("Repository limits must be positive")


@dataclass(frozen=True, slots=True)
class RepositoryFile:
    """Internal metadata for a regular file eligible for later scanner inspection."""

    relative_path: Path
    size_bytes: int


@dataclass(frozen=True, slots=True)
class RepositoryLimitReport:
    """Deterministic metadata-only limit result for one repository."""

    total_repository_bytes: int
    total_file_count: int
    eligible_file_count: int
    skipped_large_file_count: int
    inspected_bytes: int
    eligible_files: tuple[RepositoryFile, ...]


class RepositoryLimitEnforcer:
    """Enforce bounds without opening repository files or following symlinks."""

    def __init__(self, limits: RepositoryLimits | None = None) -> None:
        self.limits = limits or RepositoryLimits()

    def enforce(self, repository_root: Path) -> RepositoryLimitReport:
        """Inspect only sorted filesystem metadata below a safe repository root."""
        root = _validate_root(repository_root)
        state = _LimitState()
        try:
            self._walk(root, root, state)
        except (GitHubRepositoryTooLargeError, GitHubRepositoryTooManyFilesError):
            raise
        except GitHubRepositoryInvalidLayoutError:
            raise
        except OSError as error:
            raise GitHubRepositoryInspectionError() from error
        return RepositoryLimitReport(
            total_repository_bytes=state.total_repository_bytes,
            total_file_count=state.total_file_count,
            eligible_file_count=len(state.eligible_files),
            skipped_large_file_count=state.skipped_large_file_count,
            inspected_bytes=state.inspected_bytes,
            eligible_files=tuple(state.eligible_files),
        )

    def _walk(self, root: Path, directory: Path, state: "_LimitState") -> None:
        with os.scandir(directory) as entries:
            ordered_entries = sorted(entries, key=lambda entry: entry.name)
        for entry in ordered_entries:
            path = Path(entry.path)
            relative_path = path.relative_to(root)
            if entry.name == ".git" and entry.is_dir(follow_symlinks=False):
                continue
            if entry.is_symlink():
                continue
            entry_stat = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(entry_stat.st_mode):
                if not _is_within_root(path, root):
                    continue
                self._walk(root, path, state)
            elif stat.S_ISREG(entry_stat.st_mode):
                if not _is_within_root(path, root):
                    continue
                self._record_file(relative_path, entry_stat.st_size, state)

    def _record_file(self, relative_path: Path, size_bytes: int, state: "_LimitState") -> None:
        state.total_file_count += 1
        if state.total_file_count > self.limits.max_file_count:
            raise GitHubRepositoryTooManyFilesError()
        state.total_repository_bytes += size_bytes
        if state.total_repository_bytes > self.limits.max_repository_bytes:
            raise GitHubRepositoryTooLargeError()
        if size_bytes > self.limits.max_individual_file_bytes:
            state.skipped_large_file_count += 1
            return
        if state.inspected_bytes + size_bytes > self.limits.max_inspected_bytes:
            return
        state.inspected_bytes += size_bytes
        state.eligible_files.append(
            RepositoryFile(relative_path=relative_path, size_bytes=size_bytes)
        )


@dataclass(slots=True)
class _LimitState:
    total_repository_bytes: int = 0
    total_file_count: int = 0
    skipped_large_file_count: int = 0
    inspected_bytes: int = 0
    eligible_files: list[RepositoryFile] = field(default_factory=list)


def _validate_root(repository_root: Path) -> Path:
    """Return a real non-symlink directory root or a safe layout error."""
    try:
        root_stat = repository_root.lstat()
        if repository_root.is_symlink() or not stat.S_ISDIR(root_stat.st_mode):
            raise GitHubRepositoryInvalidLayoutError()
        return repository_root.resolve(strict=True)
    except FileNotFoundError as error:
        raise GitHubRepositoryInvalidLayoutError() from error
    except OSError as error:
        raise GitHubRepositoryInspectionError() from error


def _is_within_root(path: Path, root: Path) -> bool:
    """Return false for entries that resolve outside the repository root."""
    try:
        return path.resolve(strict=True).is_relative_to(root)
    except OSError:
        return False
