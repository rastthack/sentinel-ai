"""Application-owned temporary workspaces for future GitHub repository acquisition."""

import shutil
import tempfile
from pathlib import Path
from types import TracebackType
from typing import Literal

from sentinel_api.config import github_workspace_parent

_WORKSPACE_PREFIX = "sentinel-github-"


class TemporaryRepositoryWorkspace:
    """Create and reliably remove one isolated workspace with a repository child."""

    def __init__(self, parent_dir: Path | None = None) -> None:
        self._parent_dir = parent_dir if parent_dir is not None else github_workspace_parent()
        self._workspace_path: Path | None = None
        self._repository_path: Path | None = None

    @property
    def workspace_path(self) -> Path:
        """Return the generated workspace path while the context is active."""
        if self._workspace_path is None:
            raise RuntimeError("Workspace has not been created")
        return self._workspace_path

    @property
    def repository_path(self) -> Path:
        """Return the fixed repository child path while the context is active."""
        if self._repository_path is None:
            raise RuntimeError("Workspace has not been created")
        return self._repository_path

    def __enter__(self) -> "TemporaryRepositoryWorkspace":
        """Create the unique workspace and its empty repository child directory."""
        if self._workspace_path is not None:
            raise RuntimeError("GitHub workspace is already active")
        parent = self._parent_dir.expanduser().resolve(strict=True)
        if not parent.is_dir():
            raise RuntimeError("GitHub workspace parent must be a directory")
        workspace = Path(tempfile.mkdtemp(prefix=_WORKSPACE_PREFIX, dir=parent))
        repository = workspace / "repository"
        repository.mkdir()
        self._workspace_path = workspace
        self._repository_path = repository
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        """Always remove the application-created workspace without suppressing errors."""
        self.cleanup()
        return False

    def cleanup(self) -> None:
        """Remove only this generated workspace; repeated cleanup is safe."""
        workspace = self._workspace_path
        if workspace is None:
            return

        parent = self._parent_dir.expanduser().resolve(strict=True)
        resolved_workspace = workspace.resolve(strict=False)
        if (
            not resolved_workspace.is_relative_to(parent)
            or not resolved_workspace.name.startswith(_WORKSPACE_PREFIX)
        ):
            raise RuntimeError("Refusing to clean an unsafe GitHub workspace path")

        try:
            shutil.rmtree(resolved_workspace)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise RuntimeError("GitHub workspace cleanup failed") from error

        self._workspace_path = None
        self._repository_path = None
