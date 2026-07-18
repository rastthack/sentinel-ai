"""Common metadata contract for deterministic static rules."""

from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from sentinel_api.scanner.analysis.models import AuthorizationFinding
from sentinel_api.scanner.models import IndexResult

RuleCategory = Literal[
    "secrets",
    "cors",
    "jwt",
    "rate_limiting",
    "redirect",
    "filesystem",
    "command_execution",
    "file_upload",
]


class RuleDefinition(BaseModel):
    """Public, stable metadata describing a conservative rule family member."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    title: str
    category: RuleCategory
    severity: Literal["medium", "high", "critical"]
    cwe: list[str] = Field(min_length=1)
    owasp_mapping: list[str] = Field(min_length=1)
    supported_languages: list[str] = Field(min_length=1)
    supported_frameworks: list[str] = Field(min_length=1)
    limitations: str


class SecurityRule(Protocol):
    """One deterministic rule that emits only structurally evidenced findings."""

    definition: RuleDefinition

    def analyze(self, index: IndexResult) -> list[AuthorizationFinding]:
        """Return bounded public findings without executing scanned code."""
