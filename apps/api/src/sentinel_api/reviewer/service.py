"""Selection service for optional reviewer implementations."""

from sentinel_api.config import AISettings, ai_settings
from sentinel_api.reviewer.base import SecurityReviewer
from sentinel_api.reviewer.demo import DemoReviewer
from sentinel_api.reviewer.models import SecurityEvidencePackage
from sentinel_api.reviewer.openai_provider import OpenAIReviewer
from sentinel_api.reviewer.review_models import AIReviewerResponse


class ReviewerService:
    """Select a configured placeholder provider or the deterministic demo reviewer."""

    def __init__(
        self,
        reviewer: SecurityReviewer | None = None,
        settings: AISettings | None = None,
    ) -> None:
        configured_settings = settings or ai_settings()
        self.reviewer = reviewer or _select_reviewer(configured_settings)

    def review(self, evidence: SecurityEvidencePackage) -> AIReviewerResponse:
        """Return optional reviewer text without changing deterministic evidence."""
        return self.reviewer.review(evidence)


def _select_reviewer(settings: AISettings) -> SecurityReviewer:
    if settings.enabled and settings.api_key is not None:
        return OpenAIReviewer(settings.model)
    return DemoReviewer()
