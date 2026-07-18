"""Deterministic reviewer engine and provider-selection tests."""

from pathlib import Path

import pytest

from sentinel_api.config import AISettings
from sentinel_api.reviewer.demo import DemoReviewer
from sentinel_api.reviewer.evidence import build_security_evidence_package
from sentinel_api.reviewer.models import SecurityEvidencePackage
from sentinel_api.reviewer.openai_provider import OpenAIReviewer
from sentinel_api.reviewer.review_models import ConfidenceLevel, ReviewerStatus
from sentinel_api.reviewer.service import ReviewerService
from sentinel_api.scanner.service import build_scan_service

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture(scope="module")
def evidence() -> SecurityEvidencePackage:
    scan = build_scan_service(REPOSITORY_ROOT, ai_enabled=False).scan("demo/vulnerable-taskflow")
    return build_security_evidence_package(scan)


def _settings(*, enabled: bool, api_key: str | None) -> AISettings:
    return AISettings(
        enabled=enabled,
        api_key=api_key,
        model="configured-reviewer-model",
        timeout_seconds=20.0,
        max_retries=0,
        cache_path=Path("/tmp/reviewer-cache.json"),
    )


def test_demo_reviewer_generates_non_authoritative_explanations(
    evidence: SecurityEvidencePackage,
) -> None:
    response = DemoReviewer().review(evidence)

    assert response.status is ReviewerStatus.COMPLETE
    assert response.executive_summary is not None
    assert response.executive_summary.overall_risk is ConfidenceLevel.HIGH
    assert {item.finding_id for item in response.prioritized_findings} == {
        item.finding_id for item in evidence.findings
    }
    finding = response.prioritized_findings[0]
    assert finding.root_cause
    assert finding.attack_scenario
    assert finding.business_impact
    assert finding.secure_recommendation
    assert finding.patch_proposals[0].is_authoritative is False
    assert "Deterministic scanner findings remain the authoritative" in response.limitations[0]


def test_demo_reviewer_handles_empty_deterministic_evidence(
    evidence: SecurityEvidencePackage,
) -> None:
    empty_evidence = evidence.model_copy(update={"findings": []})

    response = DemoReviewer().review(empty_evidence)

    assert response.status is ReviewerStatus.COMPLETE
    assert response.prioritized_findings == []
    assert response.executive_summary is not None
    assert response.executive_summary.overall_risk is ConfidenceLevel.LOW


def test_demo_reviewer_text_is_deterministic(evidence: SecurityEvidencePackage) -> None:
    first = DemoReviewer().review(evidence).model_dump(mode="json")
    second = DemoReviewer().review(evidence).model_dump(mode="json")
    first.pop("generated_at")
    second.pop("generated_at")

    assert first == second


def test_service_uses_demo_by_default_and_openai_placeholder_when_configured(
    evidence: SecurityEvidencePackage,
) -> None:
    demo_service = ReviewerService(settings=_settings(enabled=False, api_key=None))
    configured_service = ReviewerService(
        settings=_settings(enabled=True, api_key="server-only-key")
    )

    assert isinstance(demo_service.reviewer, DemoReviewer)
    assert demo_service.review(evidence).status is ReviewerStatus.COMPLETE
    assert isinstance(configured_service.reviewer, OpenAIReviewer)
    response = configured_service.review(evidence)
    assert response.status is ReviewerStatus.UNAVAILABLE
    assert response.prioritized_findings == []
    assert response.model == "configured-reviewer-model"


def test_openai_placeholder_never_imports_or_calls_a_provider(
    evidence: SecurityEvidencePackage,
) -> None:
    response = OpenAIReviewer("placeholder-model").review(evidence)

    assert response.status is ReviewerStatus.UNAVAILABLE
    assert response.model == "placeholder-model"
    assert "not implemented" in response.limitations[0]
