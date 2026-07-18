"""FastAPI tests for bounded, non-authoritative scan reviews."""

import asyncio
import json
from collections.abc import Generator
from pathlib import Path

import httpx
import pytest

from sentinel_api.config import AISettings
from sentinel_api.main import app
from sentinel_api.reviewer.demo import DemoReviewer
from sentinel_api.reviewer.models import SecurityEvidencePackage
from sentinel_api.reviewer.review_models import AIReviewerResponse
from sentinel_api.reviewer.service import ReviewerService
from sentinel_api.scanner.models import RepositoryScanResponse
from sentinel_api.scanner.routes import (
    get_completed_scan_store,
    get_reviewer_service,
    get_scan_service,
)
from sentinel_api.scanner.scan_store import CompletedScanStore
from sentinel_api.scanner.service import build_scan_service

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


class FailingReviewerService:
    """Review service double that simulates a private provider failure."""

    def review(self, evidence: SecurityEvidencePackage) -> AIReviewerResponse:
        raise RuntimeError("provider failure at /private/sentinel/credentials")


class StaticScanService:
    """Controlled completed-scan producer for scan-to-review API coverage."""

    def __init__(self, response: RepositoryScanResponse) -> None:
        self.response = response

    def scan(self, repository_path: str) -> RepositoryScanResponse:
        assert repository_path == "demo/vulnerable-taskflow"
        return self.response


async def review_request(scan_id: str) -> httpx.Response:
    """Call the local ASGI application without a network listener."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post(f"/api/scans/{scan_id}/review")


async def demo_scan_request() -> httpx.Response:
    """Run the demo scan through the local ASGI application."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get("/api/scans/demo")


@pytest.fixture
def completed_scan() -> RepositoryScanResponse:
    """Create the controlled TaskFlow response used by review route tests."""
    return build_scan_service(REPOSITORY_ROOT).scan("demo/vulnerable-taskflow")


@pytest.fixture
def review_store() -> Generator[CompletedScanStore]:
    """Give each test isolated application-memory completed scan state."""
    store = CompletedScanStore()
    app.dependency_overrides[get_completed_scan_store] = lambda: store
    yield store
    app.dependency_overrides.pop(get_completed_scan_store, None)


@pytest.fixture
def demo_reviewer() -> Generator[ReviewerService]:
    """Use the no-key reviewer path without reading environment configuration."""
    service = ReviewerService(
        settings=AISettings(
            enabled=False,
            api_key=None,
            model="gpt-5.6-sol",
            timeout_seconds=20.0,
            max_retries=2,
            cache_path=REPOSITORY_ROOT / ".test-review-cache.json",
        )
    )
    app.dependency_overrides[get_reviewer_service] = lambda: service
    yield service
    app.dependency_overrides.pop(get_reviewer_service, None)


def test_review_returns_valid_deterministic_demo_response(
    completed_scan: RepositoryScanResponse,
    review_store: CompletedScanStore,
    demo_reviewer: ReviewerService,
) -> None:
    review_store.save(completed_scan)

    response = asyncio.run(review_request(completed_scan.scan_id))
    payload = response.json()

    assert response.status_code == 200
    reviewed = AIReviewerResponse.model_validate(
        payload,
        context={
            "deterministic_finding_ids": frozenset(
                finding.finding_id for finding in completed_scan.findings
            )
        },
    )
    assert reviewed.model == DemoReviewer.model_name
    assert [item.finding_id for item in reviewed.prioritized_findings] == [
        finding.finding_id for finding in completed_scan.findings
    ]
    assert str(REPOSITORY_ROOT) not in json.dumps(payload)


def test_review_loads_a_completed_demo_scan_from_the_api(
    completed_scan: RepositoryScanResponse,
    review_store: CompletedScanStore,
    demo_reviewer: ReviewerService,
) -> None:
    app.dependency_overrides[get_scan_service] = lambda: StaticScanService(completed_scan)
    try:
        scan_response = asyncio.run(demo_scan_request())
        review_response = asyncio.run(review_request(scan_response.json()["scan_id"]))
    finally:
        app.dependency_overrides.pop(get_scan_service, None)

    assert scan_response.status_code == 200
    assert review_store.get(completed_scan.scan_id) is completed_scan
    assert review_response.status_code == 200


def test_review_returns_404_for_unknown_scan(
    review_store: CompletedScanStore,
    demo_reviewer: ReviewerService,
) -> None:
    response = asyncio.run(review_request("missing-scan"))

    assert response.status_code == 404
    assert response.json()["detail"] == {
        "code": "scan_not_found",
        "message": "The requested scan does not exist.",
    }


def test_review_returns_409_when_scan_has_no_findings(
    completed_scan: RepositoryScanResponse,
    review_store: CompletedScanStore,
    demo_reviewer: ReviewerService,
) -> None:
    empty_scan = completed_scan.model_copy(update={"findings": []})
    review_store.save(empty_scan)

    response = asyncio.run(review_request(empty_scan.scan_id))

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "review_evidence_unavailable"


def test_reviewer_failure_is_sanitized_and_does_not_mutate_scan(
    completed_scan: RepositoryScanResponse,
    review_store: CompletedScanStore,
) -> None:
    snapshot = completed_scan.model_dump(mode="json")
    review_store.save(completed_scan)
    app.dependency_overrides[get_reviewer_service] = lambda: FailingReviewerService()
    try:
        response = asyncio.run(review_request(completed_scan.scan_id))
    finally:
        app.dependency_overrides.pop(get_reviewer_service, None)

    assert response.status_code == 502
    assert response.json()["detail"] == {
        "code": "reviewer_unavailable",
        "message": "The optional reviewer is currently unavailable.",
    }
    assert "/private/sentinel/credentials" not in response.text
    assert review_store.get(completed_scan.scan_id) is completed_scan
    assert completed_scan.model_dump(mode="json") == snapshot


def test_no_key_selects_demo_reviewer() -> None:
    service = ReviewerService(
        settings=AISettings(
            enabled=True,
            api_key=None,
            model="gpt-5.6-sol",
            timeout_seconds=20.0,
            max_retries=2,
            cache_path=REPOSITORY_ROOT / ".test-review-cache.json",
        )
    )

    assert isinstance(service.reviewer, DemoReviewer)
