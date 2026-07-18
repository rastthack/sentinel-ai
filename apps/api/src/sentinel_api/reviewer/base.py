"""Provider-neutral reviewer interface."""

from typing import Protocol

from sentinel_api.reviewer.models import SecurityEvidencePackage
from sentinel_api.reviewer.review_models import AIReviewerResponse


class SecurityReviewer(Protocol):
    """Explain bounded deterministic evidence without creating findings."""

    def review(self, evidence: SecurityEvidencePackage) -> AIReviewerResponse:
        """Return a non-authoritative response tied only to evidence finding IDs."""
