"""Metadata-only resource-limit tests for acquired repositories."""

from pathlib import Path
from typing import NoReturn

import pytest

from sentinel_api.config import github_repository_limits
from sentinel_api.github.exceptions import (
    GitHubRepositoryInspectionError,
    GitHubRepositoryInvalidLayoutError,
    GitHubRepositoryTooLargeError,
    GitHubRepositoryTooManyFilesError,
)
from sentinel_api.github.limits import (
    RepositoryLimitEnforcer,
    RepositoryLimitReport,
    RepositoryLimits,
)


def _write(root: Path, relative_path: str, size: int) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)


def _enforce(root: Path, **limits: int) -> RepositoryLimitReport:
    return RepositoryLimitEnforcer(RepositoryLimits(**limits)).enforce(root)


def test_empty_repository_has_empty_report(tmp_path: Path) -> None:
    report = RepositoryLimitEnforcer().enforce(tmp_path)

    assert report.total_repository_bytes == 0
    assert report.total_file_count == 0
    assert report.eligible_files == ()


def test_normal_repository_has_deterministic_sorted_eligible_files(tmp_path: Path) -> None:
    _write(tmp_path, "z.ts", 2)
    _write(tmp_path, "a/second.ts", 3)
    _write(tmp_path, "a/first.ts", 1)

    report = RepositoryLimitEnforcer().enforce(tmp_path)

    assert report.total_repository_bytes == 6
    assert report.total_file_count == 3
    assert [item.relative_path.as_posix() for item in report.eligible_files] == [
        "a/first.ts",
        "a/second.ts",
        "z.ts",
    ]


def test_reads_metadata_without_opening_file_contents(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _write(tmp_path, "source.ts", 3)

    def fail_read(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("file contents must not be read")

    monkeypatch.setattr(Path, "read_bytes", fail_read)

    assert RepositoryLimitEnforcer().enforce(tmp_path).total_repository_bytes == 3


def test_repository_byte_boundaries(tmp_path: Path) -> None:
    _write(tmp_path, "a.ts", 3)
    _write(tmp_path, "b.ts", 2)
    assert _enforce(tmp_path, max_repository_bytes=5).total_repository_bytes == 5

    with pytest.raises(GitHubRepositoryTooLargeError):
        _enforce(tmp_path, max_repository_bytes=4)


def test_file_count_boundaries(tmp_path: Path) -> None:
    _write(tmp_path, "a.ts", 1)
    _write(tmp_path, "b.ts", 1)
    assert _enforce(tmp_path, max_file_count=2).total_file_count == 2

    with pytest.raises(GitHubRepositoryTooManyFilesError):
        _enforce(tmp_path, max_file_count=1)


def test_individual_file_boundary_and_oversized_skip(tmp_path: Path) -> None:
    _write(tmp_path, "allowed.ts", 3)
    _write(tmp_path, "oversized.ts", 4)

    report = _enforce(tmp_path, max_individual_file_bytes=3)

    assert [item.relative_path.as_posix() for item in report.eligible_files] == ["allowed.ts"]
    assert report.skipped_large_file_count == 1
    assert report.total_repository_bytes == 7


def test_inspection_budget_is_exact_and_deterministically_skips_later_files(tmp_path: Path) -> None:
    _write(tmp_path, "a.ts", 4)
    _write(tmp_path, "b.ts", 3)
    _write(tmp_path, "c.ts", 1)

    report = _enforce(tmp_path, max_inspected_bytes=5)

    assert report.inspected_bytes == 5
    assert [item.relative_path.as_posix() for item in report.eligible_files] == ["a.ts", "c.ts"]


def test_git_directory_and_symlinks_are_not_inspected(tmp_path: Path) -> None:
    _write(tmp_path, ".git/internal/objects", 100)
    _write(tmp_path, "inside.ts", 2)
    external = tmp_path.parent / "external.ts"
    external.write_bytes(b"outside")
    (tmp_path / "linked-file.ts").symlink_to(external)
    external_directory = tmp_path.parent / "external-directory"
    external_directory.mkdir()
    _write(external_directory, "outside.ts", 2)
    (tmp_path / "linked-directory").symlink_to(external_directory, target_is_directory=True)
    (tmp_path / "broken-link.ts").symlink_to(tmp_path / "missing.ts")

    report = RepositoryLimitEnforcer().enforce(tmp_path)

    assert report.total_file_count == 1
    assert report.total_repository_bytes == 2
    assert [item.relative_path.as_posix() for item in report.eligible_files] == ["inside.ts"]


@pytest.mark.parametrize("root_kind", ["missing", "file", "symlink"])
def test_invalid_roots_map_to_safe_layout_error(tmp_path: Path, root_kind: str) -> None:
    root = tmp_path / "repository"
    if root_kind == "file":
        root.write_text("not a directory", encoding="utf-8")
    elif root_kind == "symlink":
        target = tmp_path / "target"
        target.mkdir()
        root.symlink_to(target, target_is_directory=True)

    with pytest.raises(GitHubRepositoryInvalidLayoutError) as raised:
        RepositoryLimitEnforcer().enforce(root)

    assert str(root) not in str(raised.value)


def test_unexpected_filesystem_error_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fail_scandir(_: Path) -> NoReturn:
        raise PermissionError("private filesystem detail")

    monkeypatch.setattr("sentinel_api.github.limits.os.scandir", fail_scandir)
    with pytest.raises(GitHubRepositoryInspectionError) as raised:
        RepositoryLimitEnforcer().enforce(tmp_path)

    assert str(tmp_path) not in str(raised.value)
    assert "private filesystem detail" not in str(raised.value)


def test_defaults_and_invalid_server_limit_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    defaults = github_repository_limits()
    assert defaults == RepositoryLimits()

    for value in ("0", "-1", "not-an-integer"):
        monkeypatch.setenv("SENTINEL_GITHUB_MAX_FILE_COUNT", value)
        with pytest.raises(ValueError, match="Invalid GitHub repository limit configuration"):
            github_repository_limits()
    monkeypatch.delenv("SENTINEL_GITHUB_MAX_FILE_COUNT", raising=False)
