"""Bounded file inventory tests."""

from pathlib import Path

import pytest

from sentinel_api.scanner.file_indexer import FileIndexer
from sentinel_api.scanner.models import IndexLimits, IndexResult
from sentinel_api.scanner.repository_loader import RepositoryLoader


def index_repository(path: Path, limits: IndexLimits | None = None) -> IndexResult:
    loaded = RepositoryLoader(path.parent).load(path.name)
    return FileIndexer(limits).index(loaded)


def test_ignored_directories_and_environment_contents_are_not_read(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "src").mkdir()
    (repository / "src" / "app.ts").write_text("export const app = true;", encoding="utf-8")
    (repository / "node_modules").mkdir()
    (repository / "node_modules" / "secret.js").write_text("do not inspect", encoding="utf-8")
    (repository / ".git").mkdir()
    (repository / ".git" / "config").write_text("private remote", encoding="utf-8")
    (repository / ".env").write_text("SECRET=never-return-this", encoding="utf-8")

    result = index_repository(repository)
    paths = {file.relative_path for file in result.files}
    environment = next(file for file in result.files if file.relative_path == ".env")

    assert "src/app.ts" in paths
    assert not any(path.startswith("node_modules/") for path in paths)
    assert not any(path.startswith(".git/") for path in paths)
    assert environment.content_inspected is False
    assert environment.skip_reason == "environment_file"
    assert "never-return-this" not in result.contents.values()


def test_binary_and_database_files_are_skipped(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "unknown.bin").write_bytes(b"text\x00binary")
    (repository / "local.sqlite").write_bytes(b"SQLite format")

    result = index_repository(repository)
    files = {file.relative_path: file for file in result.files}

    assert files["unknown.bin"].skip_reason == "binary_extension"
    assert files["unknown.bin"].content_inspected is False
    assert files["local.sqlite"].skip_reason == "database_file"
    assert files["local.sqlite"].content_inspected is False


def test_oversized_file_is_skipped_with_warning(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "large.ts").write_text("x" * 20, encoding="utf-8")

    result = index_repository(repository, IndexLimits(max_file_size_bytes=10))

    assert result.files[0].skip_reason == "file_size_limit"
    assert any("Oversized file" in warning for warning in result.warnings)


def test_nested_symlink_outside_repository_is_not_followed(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    outside = tmp_path / "outside"
    repository.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("outside secret", encoding="utf-8")
    (repository / "escape").symlink_to(outside, target_is_directory=True)

    result = index_repository(repository)

    assert result.files[0].skip_reason == "symlink_outside_repository"
    assert "outside secret" not in result.contents.values()


def test_total_read_limit_produces_warning(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "a.ts").write_text("12345", encoding="utf-8")
    (repository / "b.ts").write_text("67890", encoding="utf-8")

    result = index_repository(repository, IndexLimits(max_total_bytes_read=5))

    assert sum(file.content_inspected for file in result.files) == 1
    assert any("total read budget" in warning for warning in result.warnings)


def test_allowed_relative_paths_only_reads_the_eligible_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    allowed = repository / "allowed.ts"
    excluded = repository / "excluded.ts"
    allowed.write_text("export const allowed = true;", encoding="utf-8")
    excluded.write_text("export const excluded = true;", encoding="utf-8")
    read_paths: list[Path] = []
    original_read_bytes = Path.read_bytes

    def record_read(path: Path) -> bytes:
        read_paths.append(path)
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", record_read)

    loaded = RepositoryLoader(tmp_path).load("repository")
    result = FileIndexer().index(loaded, allowed_relative_paths=[Path("allowed.ts")])

    assert [file.relative_path for file in result.files] == ["allowed.ts"]
    assert read_paths == [allowed]


@pytest.mark.parametrize("allowed_path", [Path("/tmp/outside.ts"), Path("../escape.ts")])
def test_allowed_relative_paths_reject_absolute_and_traversal_paths(
    tmp_path: Path,
    allowed_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.ts").write_text("export {};", encoding="utf-8")
    loaded = RepositoryLoader(tmp_path).load("repository")

    with pytest.raises(ValueError, match="relative file paths"):
        FileIndexer().index(loaded, allowed_relative_paths=[allowed_path])


def test_allowed_relative_paths_reject_symlinks(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    target = tmp_path / "target.ts"
    target.write_text("export const target = true;", encoding="utf-8")
    (repository / "linked.ts").symlink_to(target)
    loaded = RepositoryLoader(tmp_path).load("repository")

    with pytest.raises(ValueError, match="regular file"):
        FileIndexer().index(loaded, allowed_relative_paths=[Path("linked.ts")])
