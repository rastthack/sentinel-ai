"""GitHub scan orchestration tests without network or subprocess activity."""

from collections.abc import Collection
from pathlib import Path
from typing import cast

import pytest

from sentinel_api.github.exceptions import (
    GitHubRepositoryUnavailableError,
    GitHubScanError,
    GitHubUrlError,
)
from sentinel_api.github.limits import (
    RepositoryLimitEnforcer,
    RepositoryLimitReport,
    RepositoryLimits,
)
from sentinel_api.github.models import AcquiredRepository, GitHubRepositoryUrl
from sentinel_api.github.service import GitHubScanService
from sentinel_api.github.workspace import TemporaryRepositoryWorkspace
from sentinel_api.scanner.models import IndexLimits, RepositoryScanResponse


class RecordingAcquirer:
    """A no-network acquisition double that creates controlled repository files."""

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.repository_url: GitHubRepositoryUrl | None = None

    def acquire(
        self,
        repository_url: GitHubRepositoryUrl,
        workspace: TemporaryRepositoryWorkspace,
    ) -> AcquiredRepository:
        self.events.append("acquire")
        self.repository_url = repository_url
        (workspace.repository_path / "allowed.ts").write_text("ok;", encoding="utf-8")
        (workspace.repository_path / "large.ts").write_text("x" * 8, encoding="utf-8")
        return AcquiredRepository(
            repository_path=workspace.repository_path,
            display_name=repository_url.display_name,
            normalized_url=repository_url.normalized_url,
        )


class RecordingLimitEnforcer(RepositoryLimitEnforcer):
    """Record resource-limit enforcement while keeping the real implementation."""

    def __init__(self, events: list[str], limits: RepositoryLimits) -> None:
        super().__init__(limits)
        self.events = events

    def enforce(self, repository_root: Path) -> RepositoryLimitReport:
        self.events.append("limits")
        return super().enforce(repository_root)


class RecordingScanner:
    """A deterministic scanner double exposing the requested repository subset."""

    def __init__(self, events: list[str], response: RepositoryScanResponse) -> None:
        self.events = events
        self.response = response
        self.repository_path: str | Path | None = None
        self.allowed_relative_paths: Collection[Path] | None = None

    def scan(
        self,
        repository_path: str | Path,
        *,
        explain: bool | None = None,
        allowed_relative_paths: Collection[Path] | None = None,
    ) -> RepositoryScanResponse:
        self.events.append("scan")
        self.repository_path = repository_path
        self.allowed_relative_paths = allowed_relative_paths
        return self.response


def test_scan_validates_acquires_limits_and_scans_only_eligible_files(tmp_path: Path) -> None:
    events: list[str] = []
    response = cast(RepositoryScanResponse, object())
    acquirer = RecordingAcquirer(events)
    limits = RepositoryLimits(max_individual_file_bytes=4)
    enforcer = RecordingLimitEnforcer(events, limits)
    scanner = RecordingScanner(events, response)
    factory_roots: list[Path] = []

    def factory(allowed_root: Path, index_limits: IndexLimits) -> RecordingScanner:
        factory_roots.append(allowed_root)
        assert index_limits.max_file_size_bytes == limits.max_individual_file_bytes
        return scanner

    service = GitHubScanService(
        acquirer,
        enforcer,
        scan_service_factory=factory,
        workspace_factory=lambda: TemporaryRepositoryWorkspace(tmp_path),
    )

    assert service.scan_repository_url("https://github.com/owner/repository") is response
    assert events == ["acquire", "limits", "scan"]
    assert acquirer.repository_url is not None
    assert acquirer.repository_url.normalized_url == "https://github.com/owner/repository.git"
    assert scanner.repository_path == "repository"
    assert list(scanner.allowed_relative_paths or []) == [Path("allowed.ts")]
    assert len(factory_roots) == 1
    assert factory_roots[0].parent == tmp_path
    assert not factory_roots[0].exists()


def test_invalid_url_does_not_create_a_workspace(tmp_path: Path) -> None:
    workspace_calls = 0

    def workspace_factory() -> TemporaryRepositoryWorkspace:
        nonlocal workspace_calls
        workspace_calls += 1
        return TemporaryRepositoryWorkspace(tmp_path)

    service = GitHubScanService(
        RecordingAcquirer([]),
        RepositoryLimitEnforcer(),
        workspace_factory=workspace_factory,
    )

    with pytest.raises(GitHubUrlError):
        service.scan_repository_url("https://gitlab.com/owner/repository")

    assert workspace_calls == 0


@pytest.mark.parametrize("failure", ["acquisition", "limits", "scanner"])
def test_workspace_is_cleaned_after_each_failure(tmp_path: Path, failure: str) -> None:
    class FailingAcquirer(RecordingAcquirer):
        def acquire(
            self,
            repository_url: GitHubRepositoryUrl,
            workspace: TemporaryRepositoryWorkspace,
        ) -> AcquiredRepository:
            acquired = super().acquire(repository_url, workspace)
            if failure == "acquisition":
                raise GitHubRepositoryUnavailableError()
            return acquired

    class FailingEnforcer(RepositoryLimitEnforcer):
        def enforce(self, repository_root: Path) -> RepositoryLimitReport:
            if failure == "limits":
                raise GitHubRepositoryUnavailableError()
            return super().enforce(repository_root)

    class FailingScanner(RecordingScanner):
        def scan(
            self,
            repository_path: str | Path,
            *,
            explain: bool | None = None,
            allowed_relative_paths: Collection[Path] | None = None,
        ) -> RepositoryScanResponse:
            if failure == "scanner":
                raise RuntimeError("private scanner failure")
            return super().scan(
                repository_path,
                explain=explain,
                allowed_relative_paths=allowed_relative_paths,
            )

    def factory(_: Path, __: IndexLimits) -> FailingScanner:
        return FailingScanner([], cast(RepositoryScanResponse, object()))

    service = GitHubScanService(
        FailingAcquirer([]),
        FailingEnforcer(),
        scan_service_factory=factory,
        workspace_factory=lambda: TemporaryRepositoryWorkspace(tmp_path),
    )

    expected_exception = (
        GitHubRepositoryUnavailableError if failure != "scanner" else GitHubScanError
    )
    with pytest.raises(expected_exception):
        service.scan_repository_url("https://github.com/owner/repository")

    assert list(tmp_path.iterdir()) == []


def test_unexpected_failure_is_sanitized_without_workspace_path(tmp_path: Path) -> None:
    class UnexpectedAcquirer(RecordingAcquirer):
        def acquire(
            self,
            repository_url: GitHubRepositoryUrl,
            workspace: TemporaryRepositoryWorkspace,
        ) -> AcquiredRepository:
            raise RuntimeError(str(workspace.workspace_path))

    service = GitHubScanService(
        UnexpectedAcquirer([]),
        RepositoryLimitEnforcer(),
        workspace_factory=lambda: TemporaryRepositoryWorkspace(tmp_path),
    )

    with pytest.raises(GitHubScanError) as raised:
        service.scan_repository_url("https://github.com/owner/repository")

    assert str(tmp_path) not in str(raised.value)
    assert "private" not in str(raised.value)
