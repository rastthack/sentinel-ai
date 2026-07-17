"""Conservative missing-authentication candidate detection."""

from dataclasses import dataclass

from sentinel_api.scanner.discovery.models import (
    DiscoveredRoute,
    OwnershipCandidate,
    RouteModelMapping,
)

_PUBLIC_PATH_MARKERS = ("/health", "/login", "/register", "/signup")


@dataclass(frozen=True, slots=True)
class MissingAuthenticationCandidate:
    """Internal candidate for unauthenticated sensitive model access."""

    route: DiscoveredRoute
    mapping: RouteModelMapping
    confidence: float


class MissingAuthenticationDetector:
    """Require direct sensitive model access and an objectively public route."""

    def detect(
        self,
        routes: list[DiscoveredRoute],
        mappings: list[RouteModelMapping],
        ownership_candidates: list[OwnershipCandidate],
    ) -> list[MissingAuthenticationCandidate]:
        """Return high-evidence candidates while excluding public lifecycle routes."""
        owned_models = {candidate.model for candidate in ownership_candidates}
        routes_by_id = {route.route_id: route for route in routes}
        candidates: list[MissingAuthenticationCandidate] = []
        for mapping in mappings:
            route = routes_by_id[mapping.route_id]
            if route.authentication_required is not False or mapping.confidence < 0.9:
                continue
            if any(marker in route.path.casefold() for marker in _PUBLIC_PATH_MARKERS):
                continue
            mutation = mapping.operation in {"create", "update", "delete"}
            owned_object_read = mapping.operation == "read_one" and mapping.model in owned_models
            if mutation or owned_object_read:
                candidates.append(
                    MissingAuthenticationCandidate(
                        route=route,
                        mapping=mapping,
                        confidence=round(min(route.confidence, mapping.confidence), 2),
                    )
                )
        return sorted(candidates, key=lambda item: (item.route.path, item.mapping.model))
