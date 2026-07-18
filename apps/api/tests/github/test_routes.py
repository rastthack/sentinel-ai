"""FastAPI tests for the public GitHub repository scan endpoint."""

import asyncio
import json
from collections.abc import Callable, Generator
from pathlib import Path

import httpx
import pytest

from sentinel_api.github.exceptions import (
    GitHubCloneTimedOutError,
    GitHubRepositoryInvalidLayoutError,
    GitHubRepositoryTooLargeError,
    GitHubRepositoryTooManyFilesError,
    GitHubRepositoryUnavailableError,
    GitHubScanError,
    GitHubUrlError,
)
from sentinel_api.main import app
from sentinel_api.scanner.models import RepositoryScanResponse
from sentinel_api.scanner.routes import get_github_scan_service
from sentinel_api.scanner.service import build_scan_service

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


class RecordingGitHubScanService:
    """A no-network endpoint double with controlled success or failure behavior."""

    def __init__(
        self,
        response: RepositoryScanResponse | None = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.calls: list[str] = []

    def scan_repository_url(self, github_url: str) -> RepositoryScanResponse:
        self.calls.append(github_url)
        if self.error is not None:
            raise self.error
        assert self.response is not None
        return self.response


async def api_request(github_url: str) -> httpx.Response:
    """Call the local ASGI application without a network listener."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/api/scans/github", json={"github_url": github_url})


@pytest.fixture
def override_github_service() -> Generator[Callable[[RecordingGitHubScanService], None]]:
    """Override the request-scoped GitHub dependency and restore the application."""

    def override(service: RecordingGitHubScanService) -> None:
        app.dependency_overrides[get_github_scan_service] = lambda: service

    yield override
    app.dependency_overrides.pop(get_github_scan_service, None)


def test_github_scan_returns_existing_response_schema(
    monkeypatch: pytest.MonkeyPatch,
    override_github_service: Callable[[RecordingGitHubScanService], None],
) -> None:
    monkeypatch.setenv("SENTINEL_SCAN_ROOT", str(REPOSITORY_ROOT))
    expected = build_scan_service(REPOSITORY_ROOT).scan("demo/vulnerable-taskflow")
    service = RecordingGitHubScanService(response=expected)
    override_github_service(service)

    response = asyncio.run(api_request("https://github.com/owner/repository"))
    payload = response.json()
    serialized = json.dumps(payload)

    assert response.status_code == 200
    assert RepositoryScanResponse.model_validate(payload) == expected
    assert service.calls == ["https://github.com/owner/repository"]
    assert str(REPOSITORY_ROOT) not in serialized
    assert "/private/" not in serialized


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_code"),
    [
        (GitHubUrlError(), 422, "github_url_invalid"),
        (GitHubRepositoryUnavailableError(), 502, "github_repository_unavailable"),
        (GitHubCloneTimedOutError(), 504, "github_clone_timed_out"),
        (GitHubRepositoryTooLargeError(), 413, "github_repository_too_large"),
        (GitHubRepositoryTooManyFilesError(), 413, "github_repository_too_many_files"),
        (GitHubRepositoryInvalidLayoutError(), 422, "github_repository_invalid_layout"),
        (GitHubScanError(), 500, "github_scan_failed"),
    ],
)
def test_github_scan_maps_safe_domain_errors(
    override_github_service: Callable[[RecordingGitHubScanService], None],
    error: Exception,
    expected_status: int,
    expected_code: str,
) -> None:
    service = RecordingGitHubScanService(error=error)
    override_github_service(service)

    response = asyncio.run(api_request("https://github.com/owner/repository"))

    assert response.status_code == expected_status
    assert response.json()["detail"] == {"code": expected_code, "message": str(error)}
    assert service.calls == ["https://github.com/owner/repository"]


def test_github_scan_rejects_local_path_without_exposing_it(
    override_github_service: Callable[[RecordingGitHubScanService], None],
) -> None:
    local_path = "/private/example/repository"
    service = RecordingGitHubScanService(error=GitHubUrlError())
    override_github_service(service)

    response = asyncio.run(api_request(local_path))

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "github_url_invalid"
    assert local_path not in response.text
    assert service.calls == [local_path]
