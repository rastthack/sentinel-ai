"""Safe shallow acquisition of already-validated public GitHub repositories."""

import os
import subprocess
from pathlib import Path

from sentinel_api.github.exceptions import (
    GitHubAcquisitionError,
    GitHubCloneTimedOutError,
    GitHubRepositoryUnavailableError,
)
from sentinel_api.github.models import AcquiredRepository, GitHubRepositoryUrl
from sentinel_api.github.workspace import TemporaryRepositoryWorkspace

_UNAVAILABLE_MARKERS = (
    b"authentication failed",
    b"could not read username",
    b"repository not found",
    b"not found",
    b"access denied",
    b"permission denied",
)


class RepositoryAcquirer:
    """Clone a validated public repository without executing its contents."""

    def __init__(self, clone_timeout_seconds: float) -> None:
        if clone_timeout_seconds <= 0:
            raise ValueError("Clone timeout must be positive")
        self.clone_timeout_seconds = clone_timeout_seconds

    def acquire(
        self,
        repository: GitHubRepositoryUrl,
        workspace: TemporaryRepositoryWorkspace,
    ) -> AcquiredRepository:
        """Perform a fixed, noninteractive shallow clone into the active workspace."""
        if not isinstance(repository, GitHubRepositoryUrl):
            raise TypeError("Repository acquisition requires a validated GitHub repository URL")

        destination = self._prepare_destination(workspace)
        command = self._clone_command(repository, destination)
        try:
            result = subprocess.run(
                command,
                check=False,
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=self.clone_timeout_seconds,
                env=_git_environment(),
            )
        except subprocess.TimeoutExpired as error:
            raise GitHubCloneTimedOutError() from error
        except OSError as error:
            raise GitHubAcquisitionError() from error

        if result.returncode != 0:
            if _is_unavailable(result.stdout, result.stderr):
                raise GitHubRepositoryUnavailableError()
            raise GitHubAcquisitionError()
        if not destination.exists() or not destination.is_dir():
            raise GitHubAcquisitionError()

        return AcquiredRepository(
            repository_path=destination,
            display_name=repository.display_name,
            normalized_url=repository.normalized_url,
        )

    def _prepare_destination(self, workspace: TemporaryRepositoryWorkspace) -> Path:
        """Remove only the empty repository child created by the active workspace."""
        workspace_path = workspace.workspace_path
        destination = workspace.repository_path
        expected = workspace_path / "repository"
        if (
            destination != expected
            or destination.parent != workspace_path
            or destination.is_symlink()
            or not destination.is_dir()
        ):
            raise GitHubAcquisitionError()
        try:
            next(destination.iterdir())
        except StopIteration:
            pass
        else:
            raise GitHubAcquisitionError()
        try:
            destination.rmdir()
        except OSError as error:
            raise GitHubAcquisitionError() from error
        return destination

    @staticmethod
    def _clone_command(repository: GitHubRepositoryUrl, destination: Path) -> list[str]:
        """Build the fixed Git command without user-controlled arguments."""
        return [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "credential.helper=",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--no-tags",
            "--no-recurse-submodules",
            repository.normalized_url,
            str(destination),
        ]


def _git_environment() -> dict[str, str]:
    """Return a minimal noninteractive environment for the Git subprocess."""
    return {
        "PATH": os.environ.get("PATH", ""),
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "Never",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }


def _is_unavailable(stdout: bytes | None, stderr: bytes | None) -> bool:
    """Classify common inaccessible-repository failures without exposing diagnostics."""
    diagnostics = (stdout or b"") + b"\n" + (stderr or b"")
    lowered = diagnostics.lower()
    return any(marker in lowered for marker in _UNAVAILABLE_MARKERS)
