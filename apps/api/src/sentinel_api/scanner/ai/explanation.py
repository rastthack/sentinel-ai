"""Public structured models for AI explanations and response state."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from sentinel_api.scanner.ai.remediation import PatchProposal, RemediationPlan
from sentinel_api.scanner.ai.verification import VerificationChecklist


class SecurityExplanation(BaseModel):
    """Plain-text explanation of one authoritative deterministic finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    summary: str = Field(min_length=1, max_length=500)
    technical_explanation: str = Field(min_length=1, max_length=2_000)
    business_impact: str = Field(min_length=1, max_length=1_500)
    why_detected: str = Field(min_length=1, max_length=1_500)
    confidence_reasoning: str = Field(min_length=1, max_length=1_000)
    false_positive_notes: str = Field(min_length=1, max_length=1_000)


class AIFindingResult(BaseModel):
    """Complete GPT enrichment associated with an unchanged finding ID."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    explanation: SecurityExplanation
    root_cause: str = Field(min_length=1, max_length=500)
    remediation: RemediationPlan
    patch: PatchProposal
    verification: VerificationChecklist
    cached: bool


class AIError(BaseModel):
    """Sanitized per-finding or provider failure."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str | None
    code: str
    message: str


class AIAnalysis(BaseModel):
    """Optional AI layer status returned without changing deterministic findings."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: Literal["disabled", "complete", "partial", "unavailable"]
    provider: str | None
    model: str | None
    results: list[AIFindingResult]
    errors: list[AIError]
