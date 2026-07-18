"""Strict, bounded public models for deterministic reviewer evidence."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class EvidenceRepository(BaseModel):
    """Safe repository identity without filesystem location details."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    relative_path: str


class EvidenceSummary(BaseModel):
    """Small deterministic scan summary for reviewer context."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    primary_language: str | None
    frameworks: list[str]
    route_count: int = Field(ge=0)
    protected_route_count: int = Field(ge=0)
    prisma_model_count: int = Field(ge=0)
    mapped_route_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    high_finding_count: int = Field(ge=0)


class EvidenceFinding(BaseModel):
    """An unchanged deterministic finding with bounded textual evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    rule_id: str
    title: str
    severity: str
    confidence: float = Field(ge=0, le=1)
    route_id: str
    method: str
    path: str
    model: str | None
    operation: str
    ownership_candidate: str | None
    source_file: str
    line_number: int = Field(ge=1)
    description: str
    evidence_references: list[str]
    recommendation: str
    cwe: list[str]
    owasp: list[str]
    risk_score: int = Field(ge=0, le=100)


class EvidenceRoute(BaseModel):
    """Route and authentication facts, never source content."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    route_id: str
    method: str
    path: str
    source_file: str
    line_number: int = Field(ge=1)
    authentication_required: bool | Literal["unknown"]
    authentication_mechanism: str | None
    authentication_evidence: list[str]


class AuthenticationEvidence(BaseModel):
    """Authentication discovery facts and their deterministic references."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    mechanism: str
    source_file: str
    line_number: int = Field(ge=1)
    evidence_references: list[str]


class PrismaOwnershipEvidence(BaseModel):
    """A possible ownership field without an AI-derived conclusion."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model: str
    field: str
    candidate_type: str
    confidence: float = Field(ge=0, le=1)
    source_file: str | None
    evidence_references: list[str]


class EvidenceRouteModelMapping(BaseModel):
    """A deterministic association between a route and a data model operation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    route_id: str
    model: str
    operation: str
    confidence: float = Field(ge=0, le=1)
    source_file: str
    evidence_references: list[str]


class SourceExcerpt(BaseModel):
    """Redacted untrusted source text retained solely as reviewer evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    relative_path: str
    content: str
    truncated: bool


class EvidenceTruncation(BaseModel):
    """Explicit deterministic evidence-budget outcomes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    truncated: bool
    reasons: list[str]


class SecurityEvidencePackage(BaseModel):
    """Bounded deterministic facts for a future optional reviewer layer."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    scan_id: str
    repository: EvidenceRepository
    summary: EvidenceSummary
    findings: list[EvidenceFinding] = Field(max_length=20)
    routes: list[EvidenceRoute]
    authentication: list[AuthenticationEvidence]
    prisma_ownership: list[PrismaOwnershipEvidence]
    route_model_mappings: list[EvidenceRouteModelMapping]
    warnings: list[str]
    source_excerpts: list[SourceExcerpt] = Field(max_length=30)
    total_evidence_characters: int = Field(ge=0, le=40_000)
    truncation: EvidenceTruncation
