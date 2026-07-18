"""Safe orchestration for scanning one validated public GitHub repository."""

from collections.abc import Callable, Collection
from pathlib import Path
from typing import Protocol

from sentinel_api.github.exceptions import GitHubAcquisitionError, GitHubScanError
from sentinel_api.github.limits import RepositoryLimitEnforcer, RepositoryLimits
from sentinel_api.github.models import AcquiredRepository, GitHubRepositoryUrl
from sentinel_api.github.urls import parse_public_github_repository_url
from sentinel_api.github.workspace import TemporaryRepositoryWorkspace
from sentinel_api.scanner.exceptions import ScannerError
from sentinel_api.scanner.models import IndexLimits, RepositoryScanResponse
from sentinel_api.scanner.service import build_scan_service


class _ScanExecutor(Protocol):
    """The narrow deterministic scanner dependency needed by this service."""

    def scan(
        self,
        repository_path: str | Path,
        *,
        explain: bool | None = None,
        allowed_relative_paths: Collection[Path] | None = None,
    ) -> RepositoryScanResponse: ...


class _RepositoryAcquirer(Protocol):
    """The bounded acquisition dependency required before static scanning."""

    def acquire(
        self,
        repository: GitHubRepositoryUrl,
        workspace: TemporaryRepositoryWorkspace,
    ) -> AcquiredRepository: ...


ScanServiceFactory = Callable[[Path, IndexLimits], _ScanExecutor]
WorkspaceFactory = Callable[[], TemporaryRepositoryWorkspace]


class GitHubScanService:
    """Coordinate bounded acquisition output through the existing scanner only."""

    def __init__(
        self,
        acquirer: _RepositoryAcquirer,
        limit_enforcer: RepositoryLimitEnforcer,
        *,
        scan_service_factory: ScanServiceFactory | None = None,
        workspace_factory: WorkspaceFactory = TemporaryRepositoryWorkspace,
    ) -> None:
        self._acquirer = acquirer
        self._limit_enforcer = limit_enforcer
        self._scan_service_factory = scan_service_factory or _build_scan_service
        self._workspace_factory = workspace_factory

    def scan_repository_url(self, raw_url: str) -> RepositoryScanResponse:
        """Scan eligible files from one public GitHub URL in a temporary workspace."""
        repository_url = parse_public_github_repository_url(raw_url)
        try:
            with self._workspace_factory() as workspace:
                acquired = self._acquirer.acquire(repository_url, workspace)
                self._validate_acquired_repository(acquired.repository_path, workspace)
                report = self._limit_enforcer.enforce(acquired.repository_path)
                scanner = self._scan_service_factory(
                    workspace.workspace_path,
                    _index_limits_for(self._limit_enforcer.limits),
                )
                return scanner.scan(
                    workspace.repository_path.name,
                    allowed_relative_paths=[item.relative_path for item in report.eligible_files],
                )
        except (GitHubAcquisitionError, GitHubScanError, ScannerError):
            raise
        except Exception as error:
            raise GitHubScanError() from error

    @staticmethod
    def _validate_acquired_repository(
        repository_path: Path,
        workspace: TemporaryRepositoryWorkspace,
    ) -> None:
        """Require the acquirer result to be precisely the active repository child."""
        try:
            acquired_root = repository_path.resolve(strict=True)
            expected_root = workspace.repository_path.resolve(strict=True)
        except OSError as error:
            raise GitHubScanError() from error
        if acquired_root != expected_root:
            raise GitHubScanError()


def _build_scan_service(allowed_root: Path, limits: IndexLimits) -> _ScanExecutor:
    """Construct an isolated deterministic scanner for a temporary workspace."""
    return build_scan_service(allowed_root=allowed_root, limits=limits)


def _index_limits_for(repository_limits: RepositoryLimits) -> IndexLimits:
    """Keep the existing indexer at or below the acquisition bounds."""
    return IndexLimits(
        max_file_count=repository_limits.max_file_count,
        max_file_size_bytes=repository_limits.max_individual_file_bytes,
        max_total_bytes_read=repository_limits.max_inspected_bytes,
    )
