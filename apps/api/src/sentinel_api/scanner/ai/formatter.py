"""Strict structured-output contract and model-response safety validation."""

import re

from pydantic import BaseModel, ConfigDict, model_validator

from sentinel_api.scanner.ai.explanation import SecurityExplanation
from sentinel_api.scanner.ai.remediation import PatchProposal, RemediationPlan
from sentinel_api.scanner.ai.verification import VerificationChecklist

_MARKDOWN_OR_HTML = re.compile(
    r"```|^#{1,6}\s|\*\*|\[[^]]+]\([^)]+\)|<\/?[A-Za-z][^>]*>",
    re.MULTILINE,
)
_DESTRUCTIVE = re.compile(
    r"\brm\s+-rf\b|\bdrop\s+(?:table|database)\b|\btruncate\s+table\b|"
    r"\bdelete\s+from\b|\bchild_process\b|\bsubprocess\b|\bos\.system\b",
    re.IGNORECASE,
)
_SECURITY_REMOVAL = re.compile(
    r"authenticat|authoriz|middleware|validat|csrf|helmet|permission|role",
    re.IGNORECASE,
)


class AIModelOutput(BaseModel):
    """Single structured model response for explanation and remediation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    explanation: SecurityExplanation
    root_cause: str
    remediation: RemediationPlan
    patch: PatchProposal
    verification: VerificationChecklist

    @model_validator(mode="after")
    def validate_safe_output(self) -> "AIModelOutput":
        """Reject formatting and patch behavior outside the product contract."""
        validate_model_output(self)
        return self


def validate_model_output(output: AIModelOutput) -> None:
    """Validate plain text and a minimal review-required unified diff."""
    natural_text = [
        output.explanation.summary,
        output.explanation.technical_explanation,
        output.explanation.business_impact,
        output.explanation.why_detected,
        output.explanation.confidence_reasoning,
        output.explanation.false_positive_notes,
        output.root_cause,
        *output.remediation.steps,
        *output.patch.safety_notes,
        *(item.check for item in output.verification.items),
    ]
    if any(_MARKDOWN_OR_HTML.search(value) for value in natural_text):
        raise ValueError("AI natural-language output must be plain text")
    if any(_DESTRUCTIVE.search(value) for value in [*natural_text, output.patch.diff]):
        raise ValueError("AI output contains a destructive operation")
    _validate_patch(output.patch)


def _validate_patch(patch: PatchProposal) -> None:
    if patch.source_file.startswith(("/", "\\")) or ".." in patch.source_file.split("/"):
        raise ValueError("AI patch source must be a safe relative path")
    lines = patch.diff.splitlines()
    expected_old = f"--- a/{patch.source_file}"
    expected_new = f"+++ b/{patch.source_file}"
    if expected_old not in lines or expected_new not in lines:
        raise ValueError("AI patch must target only the declared relative source file")
    if not any(line.startswith("@@") for line in lines):
        raise ValueError("AI patch must include a unified diff hunk")
    if not any(line.startswith("+") and not line.startswith("+++") for line in lines):
        raise ValueError("AI patch must add an authorization control")
    removed_lines = [
        line[1:]
        for line in lines
        if line.startswith("-") and not line.startswith("---")
    ]
    if any(_SECURITY_REMOVAL.search(line) for line in removed_lines):
        raise ValueError("AI patch may not remove authentication or security controls")
