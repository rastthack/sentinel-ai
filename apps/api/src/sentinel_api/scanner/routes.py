"""Thin FastAPI routes for static repository scans."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from sentinel_api.scanner.exceptions import ScannerError
from sentinel_api.scanner.models import RepositoryScanRequest, RepositoryScanResponse
from sentinel_api.scanner.service import ScanService, build_scan_service

router = APIRouter(prefix="/api/scans", tags=["scans"])


def get_scan_service() -> ScanService:
    """Build a request-scoped service from current server configuration."""
    return build_scan_service()


ScanServiceDependency = Annotated[ScanService, Depends(get_scan_service)]


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


def _scan_or_error(service: ScanService, repository_path: str) -> RepositoryScanResponse:
    try:
        return service.scan(repository_path)
    except ScannerError as error:
        raise HTTPException(
            status_code=error.status_code,
            detail={"code": error.code, "message": error.public_message},
        ) from error
