"""Repository path boundary tests."""

from pathlib import Path

import pytest

from sentinel_api.scanner.exceptions import (
    RepositoryNotDirectoryError,
    RepositoryNotFoundError,
    RepositoryOutsideRootError,
    ScanConfigurationError,
    UnsafeRepositoryPathError,
)
from sentinel_api.scanner.repository_loader import RepositoryLoader


def test_valid_repository_loads(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    loaded = RepositoryLoader(tmp_path).load("repository")

    assert loaded.root == repository
    assert loaded.relative_path == "repository"


def test_missing_repository_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(RepositoryNotFoundError):
        RepositoryLoader(tmp_path).load("missing")


def test_file_instead_of_directory_is_rejected(tmp_path: Path) -> None:
    file_path = tmp_path / "package.json"
    file_path.write_text("{}", encoding="utf-8")

    with pytest.raises(RepositoryNotDirectoryError):
        RepositoryLoader(tmp_path).load("package.json")


def test_path_traversal_is_rejected(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    with pytest.raises(UnsafeRepositoryPathError):
        RepositoryLoader(tmp_path).load("repository/../repository")


def test_path_outside_allowed_root_is_rejected(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()

    with pytest.raises(RepositoryOutsideRootError):
        RepositoryLoader(allowed).load(outside)


def test_symlink_escape_is_rejected(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (allowed / "escape").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RepositoryOutsideRootError):
        RepositoryLoader(allowed).load("escape")


def test_filesystem_root_cannot_be_the_allowed_root() -> None:
    with pytest.raises(ScanConfigurationError):
        RepositoryLoader(Path(Path.cwd().anchor))
