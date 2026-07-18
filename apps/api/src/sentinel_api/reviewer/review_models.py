"""Provider-neutral, non-authoritative AI reviewer response models."""

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from pathlib import PurePath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

from sentinel_api.reviewer.models import SecurityEvidencePackage


class ReviewerStatus(StrEnum):
    """Availability state of an optional reviewer provider response."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"


class ReviewerMode(StrEnum):
    """The bounded reviewer task requested from a provider."""

    SECURITY_REVIEW = "security_review"
    PRIORITIZATION = "prioritization"
    REMEDIATION = "remediation"


class ConfidenceLevel(StrEnum):
    """Qualitative confidence assigned by a non-authoritative reviewer."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ExecutiveSummary(BaseModel):
    """Concise, non-authoritative summary of deterministic evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    overall_risk: ConfidenceLevel
    summary: str = Field(min_length=1, max_length=2_000)
    key_takeaways: list[str] = Field(min_length=1, max_length=10)


class EvidenceReference(BaseModel):
    """One source location supporting an explanation of an existing finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Field(min_length=1, max_length=256)
    source_file: str = Field(min_length=1, max_length=1_024)
    line_number: int = Field(ge=1)
    description: str = Field(min_length=1, max_length=1_000)

    @field_validator("source_file")
    @classmethod
    def source_file_must_be_safe_relative_path(cls, value: str) -> str:
        """Prevent provider output from introducing an absolute filesystem path."""
        path = PurePath(value)
        if value.startswith(("/", "\\")) or ":" in path.parts[0] or ".." in path.parts:
            raise ValueError("Evidence source files must be relative paths")
        return path.as_posix()


class PatchProposal(BaseModel):
    """A review-required patch suggestion that is never an authoritative change."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    language: str = Field(min_length=1, max_length=64)
    description: str = Field(min_length=1, max_length=2_000)
    before: str = Field(min_length=1, max_length=8_000)
    after: str = Field(min_length=1, max_length=8_000)
    warning: str = Field(min_length=1, max_length=1_000)
    is_authoritative: Literal[False] = False


class PrioritizedFinding(BaseModel):
    """An AI prioritization or explanation tied to one deterministic finding ID."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Field(min_length=1, max_length=256)
    priority: int = Field(ge=1, le=100)
    confidence: ConfidenceLevel
    rationale: str = Field(min_length=1, max_length=3_000)
    root_cause: str = Field(min_length=1, max_length=2_000)
    attack_scenario: str = Field(min_length=1, max_length=2_000)
    business_impact: str = Field(min_length=1, max_length=2_000)
    secure_recommendation: str = Field(min_length=1, max_length=2_000)
    evidence_references: list[EvidenceReference] = Field(min_length=1, max_length=20)
    patch_proposals: list[PatchProposal] = Field(default_factory=list, max_length=5)

    @model_validator(mode="after")
    def evidence_references_must_match_finding(self) -> "PrioritizedFinding":
        """Keep every provider explanation attached to its declared finding."""
        if any(reference.finding_id != self.finding_id for reference in self.evidence_references):
            raise ValueError("Evidence references must match the prioritized finding ID")
        return self


class AIReviewerResponse(BaseModel):
    """Provider output that can explain, but never alter, deterministic findings."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: ReviewerStatus
    mode: ReviewerMode
    model: str | None = Field(default=None, max_length=256)
    executive_summary: ExecutiveSummary | None
    prioritized_findings: list[PrioritizedFinding] = Field(max_length=20)
    limitations: list[str] = Field(max_length=20)
    generated_at: datetime

    @field_validator("prioritized_findings")
    @classmethod
    def finding_ids_must_be_deterministic(
        cls,
        findings: list[PrioritizedFinding],
        info: ValidationInfo,
    ) -> list[PrioritizedFinding]:
        """Require the caller to provide authoritative allowed IDs as validation context."""
        allowed_ids = (info.context or {}).get("deterministic_finding_ids")
        if not isinstance(allowed_ids, frozenset) or not all(
            isinstance(finding_id, str) for finding_id in allowed_ids
        ):
            raise ValueError("Deterministic finding IDs are required for reviewer validation")
        unexpected_ids = sorted(
            {finding.finding_id for finding in findings}.difference(allowed_ids)
        )
        if unexpected_ids:
            raise ValueError("Reviewer output referenced a non-deterministic finding ID")
        return findings

    @field_validator("generated_at")
    @classmethod
    def generated_at_must_include_timezone(cls, value: datetime) -> datetime:
        """Ensure an externally visible reviewer timestamp is unambiguous."""
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("generated_at must include a timezone")
        return value

    @classmethod
    def from_evidence(
        cls,
        response: Mapping[str, Any],
        evidence: SecurityEvidencePackage,
    ) -> "AIReviewerResponse":
        """Validate provider output against the 9A deterministic evidence package."""
        return cls.model_validate(
            response,
            context={
                "deterministic_finding_ids": frozenset(
                    finding.finding_id for finding in evidence.findings
                )
            },
        )
