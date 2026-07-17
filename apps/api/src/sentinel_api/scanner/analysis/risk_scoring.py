"""Transparent deterministic authorization risk scoring."""

from sentinel_api.scanner.analysis.models import (
    RiskScore,
    RiskScoreComponent,
    Severity,
)
from sentinel_api.scanner.discovery.models import MappingOperation


class RiskScorer:
    """Build explainable scores with operation-sensitive adjustments."""

    def bola(self, operation: MappingOperation) -> RiskScore:
        """Score a fully evidenced object-level authorization gap."""
        components = [
            RiskScoreComponent(name="authenticated_object_route", points=12),
            RiskScoreComponent(name="single_object_operation", points=12),
            RiskScoreComponent(name="client_identifier_reaches_selector", points=20),
            RiskScoreComponent(name="model_has_ownership_candidate", points=14),
            RiskScoreComponent(name="missing_ownership_query_filter", points=10),
            RiskScoreComponent(name="missing_post_fetch_control", points=9),
            RiskScoreComponent(name="missing_authorization_middleware", points=5),
        ]
        if operation == "update":
            components.append(RiskScoreComponent(name="write_operation", points=8))
        elif operation == "delete":
            components.append(RiskScoreComponent(name="destructive_operation", points=10))
        return self.from_components(components)

    def missing_authentication(self, operation: MappingOperation) -> RiskScore:
        """Score a conservatively detected unauthenticated sensitive operation."""
        points = 25 if operation in {"update", "delete"} else 15
        return self.from_components(
            [
                RiskScoreComponent(name="sensitive_operation", points=points),
                RiskScoreComponent(name="authentication_missing", points=35),
                RiskScoreComponent(name="direct_model_access", points=15),
            ]
        )

    @staticmethod
    def from_components(components: list[RiskScoreComponent]) -> RiskScore:
        """Sum components and apply stable severity boundaries."""
        score = min(100, sum(component.points for component in components))
        return RiskScore(
            score=score,
            severity=severity_for_score(score),
            components=components,
        )


def severity_for_score(score: int) -> Severity:
    """Map an integer risk score to the documented severity bands."""
    if score <= 24:
        return "informational"
    if score <= 44:
        return "low"
    if score <= 64:
        return "medium"
    if score <= 84:
        return "high"
    return "critical"
