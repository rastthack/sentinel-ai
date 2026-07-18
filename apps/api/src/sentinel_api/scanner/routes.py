"""Thin FastAPI routes for static repository scans."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from sentinel_api.config import github_repository_limits
from sentinel_api.github.acquisition import RepositoryAcquirer
from sentinel_api.github.exceptions import (
    GitHubAcquisitionError,
    GitHubScanError,
    GitHubUrlError,
)
from sentinel_api.github.limits import RepositoryLimitEnforcer
from sentinel_api.github.service import GitHubScanService
from sentinel_api.scanner.exceptions import ScannerError
from sentinel_api.scanner.models import (
    GitHubRepositoryScanRequest,
    RepositoryScanRequest,
    RepositoryScanResponse,
)
from sentinel_api.scanner.service import ScanService, build_scan_service

router = APIRouter(prefix="/api/scans", tags=["scans"])


def get_scan_service() -> ScanService:
    """Build a request-scoped service from current server configuration."""
    return build_scan_service()


ScanServiceDependency = Annotated[ScanService, Depends(get_scan_service)]


def get_github_scan_service() -> GitHubScanService:
    """Build a request-scoped GitHub scan service with server-controlled bounds."""
    return GitHubScanService(
        acquirer=RepositoryAcquirer(clone_timeout_seconds=30.0),
        limit_enforcer=RepositoryLimitEnforcer(github_repository_limits()),
    )


GitHubScanServiceDependency = Annotated[GitHubScanService, Depends(get_github_scan_service)]


@router.post("/repository", response_model=RepositoryScanResponse)
def scan_repository(
    request: RepositoryScanRequest,
    service: ScanServiceDependency,
) -> RepositoryScanResponse:
    """Statically inspect one repository below the configured scan root."""
    return _scan_or_error(service, request.repository_path)


@router.get("/demo", response_model=RepositoryScanResponse)
def scan_demo(service: ScanServiceDependency) -> RepositoryScanResponse:
    """Statically inspect the bundled TaskFlow AI demo through the shared service."""
    return _scan_or_error(service, "demo/vulnerable-taskflow")


@router.post("/github", response_model=RepositoryScanResponse)
def scan_github_repository(
    request: GitHubRepositoryScanRequest,
    service: GitHubScanServiceDependency,
) -> RepositoryScanResponse:
    """Statically scan one validated public GitHub repository URL."""
    return _github_scan_or_error(service, request.github_url)


def _scan_or_error(service: ScanService, repository_path: str) -> RepositoryScanResponse:
    try:
        return service.scan(repository_path)
    except ScannerError as error:
        raise HTTPException(
            status_code=error.status_code,
            detail={"code": error.code, "message": error.public_message},
        ) from error


def _github_scan_or_error(
    service: GitHubScanService,
    github_url: str,
) -> RepositoryScanResponse:
    """Translate safe GitHub scan failures into the established API error shape."""
    try:
        return service.scan_repository_url(github_url)
    except GitHubUrlError as error:
        raise _github_http_error(error, 422) from error
    except GitHubAcquisitionError as error:
        raise _github_http_error(error, _github_status_code(error.code)) from error
    except GitHubScanError as error:
        raise _github_http_error(error, 500) from error
    except ScannerError as error:
        raise HTTPException(
            status_code=error.status_code,
            detail={"code": error.code, "message": error.public_message},
        ) from error


def _github_status_code(code: str) -> int:
    """Return a stable HTTP status for each sanitized GitHub domain failure."""
    return {
        "github_repository_unavailable": 502,
        "github_clone_timed_out": 504,
        "github_repository_too_large": 413,
        "github_repository_too_many_files": 413,
        "github_repository_invalid_layout": 422,
    }.get(code, 502)


def _github_http_error(
    error: GitHubAcquisitionError | GitHubScanError | GitHubUrlError,
    status_code: int,
) -> HTTPException:
    """Build the project-standard public error response without diagnostics."""
    return HTTPException(
        status_code=status_code,
        detail={"code": error.code, "message": error.public_message},
    )
