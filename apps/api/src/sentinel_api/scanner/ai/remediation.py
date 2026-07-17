"""Structured remediation and review-required patch proposal models."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RemediationPlan(BaseModel):
    """Minimal secure-remediation strategy for one finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    priority: Literal["low", "medium", "high", "critical"]
    strategy: Literal[
        "ownership_filter",
        "ownership_check",
        "membership_check",
        "authorization_middleware",
        "authentication_required",
    ]
    steps: list[str] = Field(min_length=1, max_length=8)


class PatchProposal(BaseModel):
    """Diff-style proposal that must remain unapplied until human review."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    language: Literal["typescript", "javascript", "python"]
    source_file: str
    diff: str = Field(min_length=1, max_length=8_000)
    review_required: Literal[True]
    safety_notes: list[str] = Field(min_length=1, max_length=6)
