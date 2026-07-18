"""Placeholder for a future configured OpenAI reviewer integration."""

from datetime import UTC, datetime

from sentinel_api.reviewer.models import SecurityEvidencePackage
from sentinel_api.reviewer.review_models import AIReviewerResponse, ReviewerMode, ReviewerStatus


class OpenAIReviewer:
    """Return a safe placeholder response without importing or calling an OpenAI SDK."""

    def __init__(self, model_name: str) -> None:
        self.model_name = model_name

    def review(self, evidence: SecurityEvidencePackage) -> AIReviewerResponse:
        """Report unavailable until a future provider integration is explicitly implemented."""
        return AIReviewerResponse.from_evidence(
            {
                "status": ReviewerStatus.UNAVAILABLE,
                "mode": ReviewerMode.SECURITY_REVIEW,
                "model": self.model_name,
                "executive_summary": None,
                "prioritized_findings": [],
                "limitations": [
                    "OpenAI reviewer integration is not implemented in this milestone.",
                    "Deterministic scanner findings remain the authoritative security record.",
                ],
                "generated_at": datetime.now(UTC),
            },
            evidence,
        )
