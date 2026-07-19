"""Thin FastAPI routes for static repository scans."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError

from sentinel_api.config import github_clone_timeout_seconds, github_repository_limits
from sentinel_api.github.acquisition import RepositoryAcquirer
from sentinel_api.github.exceptions import (
    GitHubAcquisitionError,
    GitHubScanError,
    GitHubUrlError,
)
from sentinel_api.github.limits import RepositoryLimitEnforcer
from sentinel_api.github.service import GitHubScanService
from sentinel_api.reviewer.evidence import build_security_evidence_package
from sentinel_api.reviewer.review_models import AIReviewerResponse
from sentinel_api.reviewer.service import ReviewerService
from sentinel_api.scanner.exceptions import ScannerError
from sentinel_api.scanner.models import (
    GitHubRepositoryScanRequest,
    RepositoryScanRequest,
    RepositoryScanResponse,
)
from sentinel_api.scanner.scan_store import CompletedScanStore
from sentinel_api.scanner.service import ScanService, build_scan_service

router = APIRouter(prefix="/api/scans", tags=["scans"])
_completed_scan_store = CompletedScanStore()


def get_scan_service() -> ScanService:
    """Build a request-scoped service from current server configuration."""
    return build_scan_service()


ScanServiceDependency = Annotated[ScanService, Depends(get_scan_service)]


def get_completed_scan_store() -> CompletedScanStore:
    """Return application-owned completed scan state for follow-up review."""
    return _completed_scan_store


CompletedScanStoreDependency = Annotated[
    CompletedScanStore, Depends(get_completed_scan_store)
]


def get_reviewer_service() -> ReviewerService:
    """Build the optional reviewer using server-side configuration only."""
    return ReviewerService()


ReviewerServiceDependency = Annotated[ReviewerService, Depends(get_reviewer_service)]


def get_github_scan_service() -> GitHubScanService:
    """Build a request-scoped GitHub scan service with server-controlled bounds."""
    return GitHubScanService(
        acquirer=RepositoryAcquirer(clone_timeout_seconds=github_clone_timeout_seconds()),
        limit_enforcer=RepositoryLimitEnforcer(github_repository_limits()),
    )


GitHubScanServiceDependency = Annotated[GitHubScanService, Depends(get_github_scan_service)]


@router.post("/repository", response_model=RepositoryScanResponse)
def scan_repository(
    request: RepositoryScanRequest,
    service: ScanServiceDependency,
    store: CompletedScanStoreDependency,
) -> RepositoryScanResponse:
    """Statically inspect one repository below the configured scan root."""
    return store.save(_scan_or_error(service, request.repository_path))


@router.get("/demo", response_model=RepositoryScanResponse)
def scan_demo(
    service: ScanServiceDependency,
    store: CompletedScanStoreDependency,
) -> RepositoryScanResponse:
    """Statically inspect the bundled TaskFlow AI demo through the shared service."""
    return store.save(_scan_or_error(service, "demo/vulnerable-taskflow"))


@router.get("/demo/multirule", response_model=RepositoryScanResponse)
def scan_multirule_demo(
    service: ScanServiceDependency,
    store: CompletedScanStoreDependency,
) -> RepositoryScanResponse:
    """Statically inspect the controlled multi-rule fixture through the shared service."""
    return store.save(_scan_or_error(service, "demo/vulnerable-multirule"))


@router.post("/github", response_model=RepositoryScanResponse)
async def scan_github_repository(
    request: Request,
    service: GitHubScanServiceDependency,
    store: CompletedScanStoreDependency,
) -> RepositoryScanResponse:
    """Statically scan one validated public GitHub repository URL."""
    try:
        payload: object = await request.json()
        scan_request = GitHubRepositoryScanRequest.model_validate(payload)
    except (ValueError, ValidationError):
        raise _github_http_error(GitHubUrlError(), 422) from None
    return store.save(_github_scan_or_error(service, scan_request.github_url))


@router.post("/{scan_id}/review", response_model=AIReviewerResponse)
def review_scan(
    scan_id: str,
    store: CompletedScanStoreDependency,
    reviewer_service: ReviewerServiceDependency,
) -> AIReviewerResponse:
    """Return a bounded, non-authoritative review of one completed scan."""
    scan = store.get(scan_id)
    if scan is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "scan_not_found", "message": "The requested scan does not exist."},
        )
    if not scan.findings:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "review_evidence_unavailable",
                "message": "The scan has no reviewable deterministic findings.",
            },
        )

    evidence = build_security_evidence_package(scan)
    try:
        response = reviewer_service.review(evidence)
        return AIReviewerResponse.from_evidence(response.model_dump(), evidence)
    except Exception:
        raise HTTPException(
            status_code=502,
            detail={
                "code": "reviewer_unavailable",
                "message": "The optional reviewer is currently unavailable.",
            },
        ) from None


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
