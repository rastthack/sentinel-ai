"""Provider-neutral AI reviewer response model tests."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sentinel_api.reviewer.models import (
    EvidenceFinding,
    EvidenceRepository,
    EvidenceSummary,
    EvidenceTruncation,
    SecurityEvidencePackage,
)
from sentinel_api.reviewer.review_models import (
    AIReviewerResponse,
    ConfidenceLevel,
    EvidenceReference,
    ExecutiveSummary,
    PatchProposal,
    PrioritizedFinding,
    ReviewerMode,
    ReviewerStatus,
)

FINDING_ID = "AUTH-BOLA-D1D193AD3E"


def _evidence() -> SecurityEvidencePackage:
    return SecurityEvidencePackage(
        scan_id="scan-1",
        repository=EvidenceRepository(name="taskflow", relative_path="demo/taskflow"),
        summary=EvidenceSummary(
            primary_language="TypeScript",
            frameworks=["Express"],
            route_count=1,
            protected_route_count=1,
            prisma_model_count=1,
            mapped_route_count=1,
            finding_count=1,
            high_finding_count=1,
        ),
        findings=[
            EvidenceFinding(
                finding_id=FINDING_ID,
                rule_id="AUTH-BOLA",
                title="Potential BOLA / IDOR",
                category="authorization",
                severity="high",
                confidence=0.9,
                route_id="route:GET:/api/projects/:id",
                method="GET",
                path="/api/projects/:id",
                model="Project",
                operation="read_one",
                ownership_candidate="ownerId",
                source_file="src/routes/projects.ts",
                line_number=1,
                description="Missing ownership filter.",
                evidence_references=["Selector uses a request parameter."],
                recommendation="Add owner scope.",
                cwe=["CWE-639"],
                owasp=["API1:2023"],
                risk_score=82,
            )
        ],
        routes=[],
        authentication=[],
        prisma_ownership=[],
        route_model_mappings=[],
        warnings=[],
        source_excerpts=[],
        total_evidence_characters=0,
        truncation=EvidenceTruncation(truncated=False, reasons=[]),
    )


def _payload(finding_id: str = FINDING_ID) -> dict[str, object]:
    return {
        "status": "complete",
        "mode": "security_review",
        "model": "reviewer-model",
        "executive_summary": {
            "overall_risk": "high",
            "summary": "The deterministic finding needs prompt remediation.",
            "key_takeaways": ["Scope lookups to the authenticated owner."],
        },
        "prioritized_findings": [
            {
                "finding_id": finding_id,
                "priority": 90,
                "confidence": "high",
                "rationale": "The endpoint reads an object by client-supplied ID.",
                "root_cause": "The selector has no ownership constraint.",
                "attack_scenario": "An attacker substitutes another identifier.",
                "business_impact": "Another user's data may be exposed.",
                "secure_recommendation": "Scope the selector to the authenticated owner.",
                "evidence_references": [
                    {
                        "finding_id": finding_id,
                        "source_file": "src/routes/projects.ts",
                        "line_number": 21,
                        "description": "The ORM selector lacks ownerId.",
                    }
                ],
                "patch_proposals": [
                    {
                        "language": "TypeScript",
                        "description": "Add an owner filter.",
                        "before": "findUnique({ where: { id } })",
                        "after": "findFirst({ where: { id, ownerId: user.id } })",
                        "warning": "Review and test this proposal before applying it.",
                        "is_authoritative": False,
                    }
                ],
            }
        ],
        "limitations": ["This response does not change deterministic findings."],
        "generated_at": datetime(2026, 7, 18, tzinfo=UTC).isoformat(),
    }


def test_valid_response_is_bound_to_deterministic_evidence() -> None:
    response = AIReviewerResponse.from_evidence(_payload(), _evidence())

    assert response.status is ReviewerStatus.COMPLETE
    assert response.mode is ReviewerMode.SECURITY_REVIEW
    assert response.prioritized_findings[0].confidence is ConfidenceLevel.HIGH
    assert response.prioritized_findings[0].patch_proposals[0].is_authoritative is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "invented"),
        ("mode", "invent_findings"),
    ],
)
def test_rejects_invalid_response_enums(field: str, value: str) -> None:
    payload = _payload()
    payload[field] = value
    with pytest.raises(ValidationError):
        AIReviewerResponse.from_evidence(payload, _evidence())

    invalid_confidence = _payload()
    prioritized = invalid_confidence["prioritized_findings"]
    assert isinstance(prioritized, list)
    prioritized[0]["confidence"] = "certain"
    with pytest.raises(ValidationError):
        AIReviewerResponse.from_evidence(invalid_confidence, _evidence())


def test_rejects_missing_required_fields() -> None:
    missing_summary = _payload()
    del missing_summary["executive_summary"]
    with pytest.raises(ValidationError):
        AIReviewerResponse.from_evidence(missing_summary, _evidence())


def test_rejects_new_finding_ids_mismatched_evidence_and_authoritative_patches() -> None:
    with pytest.raises(ValidationError, match="non-deterministic"):
        AIReviewerResponse.from_evidence(_payload("AUTH-NEW"), _evidence())

    mismatched = _payload()
    finding = mismatched["prioritized_findings"]
    assert isinstance(finding, list)
    reference = finding[0]["evidence_references"]
    assert isinstance(reference, list)
    reference[0]["finding_id"] = "AUTH-OTHER"
    with pytest.raises(ValidationError, match="must match"):
        AIReviewerResponse.from_evidence(mismatched, _evidence())

    authoritative = _payload()
    prioritized = authoritative["prioritized_findings"]
    assert isinstance(prioritized, list)
    proposals = prioritized[0]["patch_proposals"]
    assert isinstance(proposals, list)
    proposals[0]["is_authoritative"] = True
    with pytest.raises(ValidationError):
        AIReviewerResponse.from_evidence(authoritative, _evidence())


def test_serialization_and_schema_are_stable() -> None:
    response = AIReviewerResponse.from_evidence(_payload(), _evidence())
    serialized = response.model_dump(mode="json")
    schema = AIReviewerResponse.model_json_schema()

    assert serialized["status"] == "complete"
    assert serialized["prioritized_findings"][0]["finding_id"] == FINDING_ID
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {
        "status",
        "mode",
        "model",
        "executive_summary",
        "prioritized_findings",
        "limitations",
        "generated_at",
    }


def test_direct_validation_requires_deterministic_id_context_and_safe_reference_paths() -> None:
    with pytest.raises(ValidationError, match="Deterministic finding IDs"):
        AIReviewerResponse.model_validate(_payload())

    unsafe_path = _payload()
    prioritized = unsafe_path["prioritized_findings"]
    assert isinstance(prioritized, list)
    references = prioritized[0]["evidence_references"]
    assert isinstance(references, list)
    references[0]["source_file"] = "/private/repository.ts"
    with pytest.raises(ValidationError, match="relative paths"):
        AIReviewerResponse.from_evidence(unsafe_path, _evidence())


def test_component_models_are_strict_and_frozen() -> None:
    summary = ExecutiveSummary(
        overall_risk=ConfidenceLevel.MEDIUM,
        summary="Evidence is limited.",
        key_takeaways=["Review deterministic evidence."],
    )
    proposal = PatchProposal(
        language="TypeScript",
        description="Filter by owner.",
        before="before",
        after="after",
        warning="Human review required.",
    )
    prioritized = PrioritizedFinding(
        finding_id=FINDING_ID,
        priority=1,
        confidence=ConfidenceLevel.LOW,
        rationale="Limited confidence.",
        root_cause="The evidence is incomplete.",
        attack_scenario="An attacker may test identifiers.",
        business_impact="Data isolation may weaken.",
        secure_recommendation="Review ownership constraints.",
        evidence_references=[
            EvidenceReference(
                finding_id=FINDING_ID,
                source_file="src/routes/projects.ts",
                line_number=1,
                description="Evidence.",
            )
        ],
    )

    assert summary.overall_risk is ConfidenceLevel.MEDIUM
    assert proposal.is_authoritative is False
    assert prioritized.patch_proposals == []
    with pytest.raises(ValidationError):
        ExecutiveSummary.model_validate({"overall_risk": "medium", "summary": "x", "extra": True})
