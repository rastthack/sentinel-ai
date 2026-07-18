"""Bounded, read-only repository file inventory."""

import os
import stat
from collections.abc import Collection
from pathlib import Path

from sentinel_api.scanner.models import (
    FileCategory,
    IndexedFile,
    IndexLimits,
    IndexResult,
    LoadedRepository,
)

IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".idea",
        ".mypy_cache",
        ".next",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".venv",
        ".vscode",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "generated",
        "node_modules",
        "out",
        "venv",
    }
)
SOURCE_EXTENSIONS = frozenset(
    {".css", ".html", ".js", ".jsx", ".py", ".sql", ".ts", ".tsx"}
)
CONFIG_EXTENSIONS = frozenset({".json", ".prisma", ".toml", ".yaml", ".yml"})
CONFIG_NAMES = frozenset(
    {
        "dockerfile",
        "makefile",
        "package.json",
        "postcss.config.js",
        "postcss.config.mjs",
        "pyproject.toml",
        "requirements-dev.txt",
        "requirements.txt",
        "tsconfig.json",
    }
)
LOCK_FILE_NAMES = frozenset(
    {"package-lock.json", "pnpm-lock.yaml", "poetry.lock", "yarn.lock", "pipfile.lock"}
)
BINARY_EXTENSIONS = frozenset(
    {
        ".7z",
        ".a",
        ".avi",
        ".bin",
        ".class",
        ".dylib",
        ".eot",
        ".exe",
        ".gif",
        ".gz",
        ".ico",
        ".jar",
        ".jpeg",
        ".jpg",
        ".mov",
        ".mp3",
        ".mp4",
        ".o",
        ".otf",
        ".pdf",
        ".png",
        ".so",
        ".tar",
        ".ttf",
        ".wasm",
        ".webp",
        ".woff",
        ".woff2",
        ".zip",
    }
)
DATABASE_EXTENSIONS = frozenset({".db", ".db3", ".sqlite", ".sqlite3"})
PRIVATE_EXTENSIONS = frozenset({".cer", ".crt", ".der", ".key", ".p12", ".pem", ".pfx"})
PRIVATE_NAMES = frozenset({"id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"})
SENSITIVE_NAME_MARKERS = ("credential", "private_key", "private-key", "service-account", "secret")


class FileIndexer:
    """Inventory relevant files while enforcing strict static-read budgets."""

    def __init__(self, limits: IndexLimits | None = None) -> None:
        self.limits = limits or IndexLimits()

    def index(
        self,
        repository: LoadedRepository,
        *,
        allowed_relative_paths: Collection[Path] | None = None,
    ) -> IndexResult:
        """Index a repository without following directory or file symlinks."""
        result = IndexResult()
        state = _IndexState()
        if allowed_relative_paths is None:
            self._walk(repository.root, repository.root, 0, result, state)
        else:
            self._index_allowed_files(repository, allowed_relative_paths, result, state)
        result.files.sort(key=lambda item: item.relative_path)
        return result

    def _index_allowed_files(
        self,
        repository: LoadedRepository,
        allowed_relative_paths: Collection[Path],
        result: IndexResult,
        state: "_IndexState",
    ) -> None:
        """Read only a validated, deterministic subset of regular repository files."""
        allowed_paths = sorted(
            {self._validate_allowed_path(repository.root, path) for path in allowed_relative_paths},
            key=lambda path: path.as_posix(),
        )
        for relative_path in allowed_paths:
            if state.file_count >= self.limits.max_file_count:
                self._warn_once(
                    result,
                    state,
                    "count",
                    "Maximum file count of "
                    f"{self.limits.max_file_count} reached; remaining files were skipped",
                )
                return
            path = repository.root / relative_path
            state.file_count += 1
            self._index_file(path, relative_path.as_posix(), result, state)

    @staticmethod
    def _validate_allowed_path(repository_root: Path, relative_path: Path) -> Path:
        """Return one safe regular path without resolving or reading unapproved files."""
        if relative_path.is_absolute() or ".." in relative_path.parts or relative_path == Path("."):
            raise ValueError("Allowed scanner paths must be relative file paths")
        if relative_path.parts[0] == ".git":
            raise ValueError("Allowed scanner paths cannot include Git metadata")

        candidate = repository_root / relative_path
        try:
            metadata = candidate.lstat()
        except OSError as error:
            raise ValueError("Allowed scanner path is unavailable") from error
        if candidate.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Allowed scanner path must be a regular file")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise ValueError("Allowed scanner path is unavailable") from error
        if not resolved.is_relative_to(repository_root):
            raise ValueError("Allowed scanner path is outside the repository")
        return relative_path

    def _walk(
        self,
        repository_root: Path,
        directory: Path,
        depth: int,
        result: IndexResult,
        state: "_IndexState",
    ) -> None:
        if depth > self.limits.max_directory_depth:
            self._warn_once(
                result,
                state,
                "depth",
                "Maximum directory depth of "
                f"{self.limits.max_directory_depth} reached; deeper entries were skipped",
            )
            return

        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name.casefold())
        except OSError:
            result.warnings.append("A directory could not be read and was skipped")
            return

        for entry in entries:
            if state.file_count >= self.limits.max_file_count:
                self._warn_once(
                    result,
                    state,
                    "count",
                    "Maximum file count of "
                    f"{self.limits.max_file_count} reached; remaining files were skipped",
                )
                return

            path = Path(entry.path)
            relative_path = path.relative_to(repository_root).as_posix()
            try:
                if entry.is_symlink():
                    self._record_symlink(repository_root, path, relative_path, result)
                    state.file_count += 1
                elif entry.is_dir(follow_symlinks=False):
                    if entry.name.casefold() in IGNORED_DIRECTORIES:
                        result.ignored_file_count += 1
                    else:
                        self._walk(repository_root, path, depth + 1, result, state)
                elif entry.is_file(follow_symlinks=False):
                    state.file_count += 1
                    self._index_file(path, relative_path, result, state)
            except OSError:
                result.ignored_file_count += 1
                result.warnings.append(f"File metadata could not be read: {relative_path}")

    def _record_symlink(
        self,
        repository_root: Path,
        path: Path,
        relative_path: str,
        result: IndexResult,
    ) -> None:
        try:
            target = path.resolve(strict=True)
            outside = not target.is_relative_to(repository_root)
        except (OSError, RuntimeError):
            outside = True
        reason = "symlink_outside_repository" if outside else "symbolic_link_not_followed"
        result.files.append(
            IndexedFile(
                relative_path=relative_path,
                extension=path.suffix.lower(),
                category="other",
                size_bytes=path.lstat().st_size,
                content_inspected=False,
                skip_reason=reason,
            )
        )
        result.ignored_file_count += 1
        if outside:
            result.warnings.append(
                f"Symlink target outside the repository was not followed: {relative_path}"
            )

    def _index_file(
        self,
        path: Path,
        relative_path: str,
        result: IndexResult,
        state: "_IndexState",
    ) -> None:
        size = path.stat(follow_symlinks=False).st_size
        extension = path.suffix.lower()
        category, skip_reason = self._classify(path)

        if skip_reason is not None:
            self._append_file(result, relative_path, extension, category, size, False, skip_reason)
            result.ignored_file_count += 1
            return
        if size > self.limits.max_file_size_bytes:
            self._append_file(
                result,
                relative_path,
                extension,
                category,
                size,
                False,
                "file_size_limit",
            )
            result.ignored_file_count += 1
            result.warnings.append(f"Oversized file was not inspected: {relative_path}")
            return
        if state.total_bytes_read + size > self.limits.max_total_bytes_read:
            self._append_file(
                result,
                relative_path,
                extension,
                category,
                size,
                False,
                "total_read_limit",
            )
            result.ignored_file_count += 1
            self._warn_once(
                result,
                state,
                "bytes",
                "Maximum total read budget of "
                f"{self.limits.max_total_bytes_read} bytes reached; "
                "additional contents were skipped",
            )
            return

        try:
            raw_content = path.read_bytes()
            state.total_bytes_read += len(raw_content)
            if b"\x00" in raw_content[:8_192]:
                self._append_file(
                    result,
                    relative_path,
                    extension,
                    "binary",
                    size,
                    False,
                    "binary_content",
                )
                result.ignored_file_count += 1
                return
            content = raw_content.decode("utf-8")
        except UnicodeDecodeError:
            self._append_file(
                result,
                relative_path,
                extension,
                "binary",
                size,
                False,
                "non_utf8_content",
            )
            result.ignored_file_count += 1
            return
        except OSError:
            self._append_file(
                result,
                relative_path,
                extension,
                category,
                size,
                False,
                "read_error",
            )
            result.ignored_file_count += 1
            result.warnings.append(f"A file could not be inspected: {relative_path}")
            return

        self._append_file(result, relative_path, extension, category, size, True, None)
        result.contents[relative_path] = content

    @staticmethod
    def _classify(path: Path) -> tuple[FileCategory, str | None]:
        name = path.name.casefold()
        extension = path.suffix.lower()
        if name == ".env" or name.startswith(".env."):
            return "sensitive", "environment_file"
        if (
            extension in PRIVATE_EXTENSIONS
            or name in PRIVATE_NAMES
            or name in {".npmrc", ".pypirc"}
            or any(marker in name for marker in SENSITIVE_NAME_MARKERS)
        ):
            return "sensitive", "sensitive_file"
        if extension in DATABASE_EXTENSIONS:
            return "database", "database_file"
        if extension in BINARY_EXTENSIONS:
            return "binary", "binary_extension"
        if name in LOCK_FILE_NAMES:
            return "configuration", "lock_file_not_inspected"
        if name.endswith(".min.js") or name.endswith(".min.css") or ".generated." in name:
            return "generated", "generated_file"
        if extension in SOURCE_EXTENSIONS or extension == ".prisma":
            return "source", None
        if extension in CONFIG_EXTENSIONS or name in CONFIG_NAMES or name.startswith("dockerfile"):
            return "configuration", None
        if extension in {".md", ".mdx", ".rst", ".txt"}:
            return "documentation", "documentation_not_inspected"
        return "other", "unsupported_file_type"

    @staticmethod
    def _append_file(
        result: IndexResult,
        relative_path: str,
        extension: str,
        category: FileCategory,
        size: int,
        inspected: bool,
        skip_reason: str | None,
    ) -> None:
        result.files.append(
            IndexedFile(
                relative_path=relative_path,
                extension=extension,
                category=category,
                size_bytes=size,
                content_inspected=inspected,
                skip_reason=skip_reason,
            )
        )

    @staticmethod
    def _warn_once(
        result: IndexResult,
        state: "_IndexState",
        key: str,
        warning: str,
    ) -> None:
        if key not in state.warning_keys:
            state.warning_keys.add(key)
            result.warnings.append(warning)


class _IndexState:
    """Mutable counters kept private to one index operation."""

    def __init__(self) -> None:
        self.file_count = 0
        self.total_bytes_read = 0
        self.warning_keys: set[str] = set()
