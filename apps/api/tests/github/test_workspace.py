"""Tests for application-owned temporary repository workspaces."""

import shutil
from pathlib import Path

import pytest

from sentinel_api.github.workspace import TemporaryRepositoryWorkspace


def test_creates_workspace_and_repository_child_under_configured_parent(tmp_path: Path) -> None:
    parent = tmp_path / "application-workspaces"
    parent.mkdir()

    with TemporaryRepositoryWorkspace(parent) as workspace:
        created_path = workspace.workspace_path
        assert workspace.workspace_path.is_dir()
        assert workspace.workspace_path.parent == parent
        assert workspace.workspace_path.name.startswith("sentinel-github-")
        assert workspace.repository_path.is_dir()
        assert workspace.repository_path == workspace.workspace_path / "repository"
        assert workspace.repository_path.is_relative_to(workspace.workspace_path)

    assert not created_path.exists()
    assert not any(parent.iterdir())


def test_cleans_up_after_exception(tmp_path: Path) -> None:
    parent = tmp_path / "application-workspaces"
    parent.mkdir()

    with pytest.raises(
        RuntimeError, match="expected failure"
    ), TemporaryRepositoryWorkspace(parent) as workspace:
        created_path = workspace.workspace_path
        raise RuntimeError("expected failure")

    assert not created_path.exists()
    assert not any(parent.iterdir())


def test_cleans_up_after_nested_exception(tmp_path: Path) -> None:
    parent = tmp_path / "application-workspaces"
    parent.mkdir()

    with pytest.raises(
        ValueError, match="nested failure"
    ), TemporaryRepositoryWorkspace(parent) as workspace:
        created_path = workspace.workspace_path
        try:
            raise RuntimeError("inner failure")
        except RuntimeError as error:
            raise ValueError("nested failure") from error

    assert not created_path.exists()


def test_cleanup_is_idempotent(tmp_path: Path) -> None:
    parent = tmp_path / "application-workspaces"
    parent.mkdir()
    workspace = TemporaryRepositoryWorkspace(parent)

    with workspace:
        created_path = workspace.workspace_path
        workspace.cleanup()
        workspace.cleanup()

    assert not created_path.exists()
    assert not any(parent.iterdir())


def test_missing_workspace_is_treated_as_successfully_cleaned(tmp_path: Path) -> None:
    parent = tmp_path / "application-workspaces"
    parent.mkdir()
    workspace = TemporaryRepositoryWorkspace(parent)
    workspace.__enter__()
    created_path = workspace.workspace_path
    shutil.rmtree(created_path)

    workspace.cleanup()

    with pytest.raises(RuntimeError, match="has not been created"):
        _ = workspace.workspace_path


def test_cleanup_failure_is_sanitized_and_retains_internal_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "application-workspaces"
    parent.mkdir()
    workspace = TemporaryRepositoryWorkspace(parent)
    workspace.__enter__()
    created_path = workspace.workspace_path
    repository_path = workspace.repository_path

    def fail_removal(_: Path) -> None:
        raise PermissionError("private filesystem failure")

    monkeypatch.setattr("sentinel_api.github.workspace.shutil.rmtree", fail_removal)

    with pytest.raises(RuntimeError, match="GitHub workspace cleanup failed") as raised:
        workspace.cleanup()

    assert str(created_path) not in str(raised.value)
    assert workspace.workspace_path == created_path
    assert workspace.repository_path == repository_path
    monkeypatch.undo()
    workspace.cleanup()


def test_reentering_active_workspace_is_rejected(tmp_path: Path) -> None:
    parent = tmp_path / "application-workspaces"
    parent.mkdir()
    workspace = TemporaryRepositoryWorkspace(parent)

    workspace.__enter__()
    try:
        with pytest.raises(RuntimeError, match="GitHub workspace is already active"):
            workspace.__enter__()
    finally:
        workspace.cleanup()


def test_generates_distinct_workspace_names(tmp_path: Path) -> None:
    parent = tmp_path / "application-workspaces"
    parent.mkdir()

    with TemporaryRepositoryWorkspace(parent) as first:
        first_name = first.workspace_path.name
    with TemporaryRepositoryWorkspace(parent) as second:
        second_name = second.workspace_path.name

    assert first_name != second_name


def test_parent_is_not_derived_from_user_supplied_repository_value(tmp_path: Path) -> None:
    configured_parent = tmp_path / "application-workspaces"
    configured_parent.mkdir()
    untrusted_text = "../../outside/repository"

    with TemporaryRepositoryWorkspace(configured_parent) as workspace:
        assert untrusted_text not in str(workspace.workspace_path)
        assert workspace.workspace_path.is_relative_to(configured_parent)
