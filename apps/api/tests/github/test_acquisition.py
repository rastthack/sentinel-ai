"""Offline tests for fixed-argument public GitHub repository acquisition."""

import subprocess
from pathlib import Path

import pytest

from sentinel_api.github.acquisition import RepositoryAcquirer
from sentinel_api.github.exceptions import (
    GitHubAcquisitionError,
    GitHubCloneTimedOutError,
    GitHubRepositoryUnavailableError,
)
from sentinel_api.github.models import GitHubRepositoryUrl
from sentinel_api.github.urls import parse_public_github_repository_url
from sentinel_api.github.workspace import TemporaryRepositoryWorkspace


def _repository() -> GitHubRepositoryUrl:
    return parse_public_github_repository_url("https://github.com/openai/sentinel-ai")


def _successful_run(destination: Path) -> subprocess.CompletedProcess[bytes]:
    destination.mkdir()
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")


def test_runs_fixed_safe_shallow_clone(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "workspaces"
    parent.mkdir()
    calls: list[dict[str, object]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append({"command": command, **kwargs})
        return _successful_run(Path(command[-1]))

    monkeypatch.setattr("sentinel_api.github.acquisition.subprocess.run", fake_run)
    with TemporaryRepositoryWorkspace(parent) as workspace:
        acquired = RepositoryAcquirer(12.5).acquire(_repository(), workspace)
        assert acquired.repository_path == workspace.repository_path
        assert acquired.display_name == "openai/sentinel-ai"
        assert acquired.normalized_url == "https://github.com/openai/sentinel-ai.git"

    call = calls[0]
    assert call["command"] == [
        "git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "clone",
        "--depth", "1", "--single-branch", "--no-tags", "--no-recurse-submodules",
        "https://github.com/openai/sentinel-ai.git", str(acquired.repository_path),
    ]
    assert call["shell"] is False
    assert call["stdin"] is subprocess.DEVNULL
    assert call["timeout"] == 12.5
    environment = call["env"]
    assert isinstance(environment, dict)
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["GCM_INTERACTIVE"] == "Never"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"]


def test_rejects_unvalidated_input(tmp_path: Path) -> None:
    parent = tmp_path / "workspaces"
    parent.mkdir()
    with TemporaryRepositoryWorkspace(parent) as workspace, pytest.raises(TypeError):
        RepositoryAcquirer(1).acquire("https://github.com/openai/sentinel-ai", workspace)  # type: ignore[arg-type]


def test_rejects_nonempty_or_unexpected_destination(tmp_path: Path) -> None:
    parent = tmp_path / "workspaces"
    parent.mkdir()
    repository = _repository()
    with TemporaryRepositoryWorkspace(parent) as workspace:
        (workspace.repository_path / "unexpected").write_text("content", encoding="utf-8")
        with pytest.raises(GitHubAcquisitionError):
            RepositoryAcquirer(1).acquire(repository, workspace)
        assert (workspace.repository_path / "unexpected").exists()

    workspace = TemporaryRepositoryWorkspace(parent)
    with workspace:
        workspace._repository_path = workspace.workspace_path / "other"
        with pytest.raises(GitHubAcquisitionError):
            RepositoryAcquirer(1).acquire(repository, workspace)


def test_requires_destination_after_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "workspaces"
    parent.mkdir()
    monkeypatch.setattr(
        "sentinel_api.github.acquisition.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, b"", b""),
    )
    with TemporaryRepositoryWorkspace(parent) as workspace, pytest.raises(GitHubAcquisitionError):
        RepositoryAcquirer(1).acquire(_repository(), workspace)


def test_maps_timeout_and_sanitizes_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "workspaces"
    parent.mkdir()
    credential = "private-password"

    def timeout(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired("git", 1, stderr=credential.encode())

    monkeypatch.setattr("sentinel_api.github.acquisition.subprocess.run", timeout)
    with TemporaryRepositoryWorkspace(parent) as workspace, pytest.raises(
        GitHubCloneTimedOutError
    ) as raised:
        RepositoryAcquirer(1).acquire(_repository(), workspace)
    assert credential not in str(raised.value)
    assert str(parent) not in str(raised.value)


@pytest.mark.parametrize(
    ("stderr", "error_type", "code"),
    [
        (
            b"fatal: Authentication failed",
            GitHubRepositoryUnavailableError,
            "github_repository_unavailable",
        ),
        (
            b"fatal: repository not found",
            GitHubRepositoryUnavailableError,
            "github_repository_unavailable",
        ),
        (b"fatal: unexpected transport failure", GitHubAcquisitionError, "github_clone_failed"),
    ],
)
def test_maps_nonzero_clone_errors_safely(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stderr: bytes,
    error_type: type[GitHubAcquisitionError],
    code: str,
) -> None:
    parent = tmp_path / "workspaces"
    parent.mkdir()
    monkeypatch.setattr(
        "sentinel_api.github.acquisition.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 128, b"", stderr),
    )
    with TemporaryRepositoryWorkspace(parent) as workspace, pytest.raises(error_type) as raised:
        RepositoryAcquirer(1).acquire(_repository(), workspace)

    assert raised.value.code == code
    assert stderr.decode() not in str(raised.value)
    assert str(parent) not in str(raised.value)
