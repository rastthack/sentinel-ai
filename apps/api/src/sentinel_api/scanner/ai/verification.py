"""Structured verification checklist models."""

from pydantic import BaseModel, ConfigDict, Field


class VerificationItem(BaseModel):
    """One reviewable remediation verification step."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    check: str = Field(min_length=1, max_length=300)
    required: bool


class VerificationChecklist(BaseModel):
    """Checklist for human review and a later controlled scanner rerun."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    items: list[VerificationItem] = Field(min_length=1, max_length=10)
