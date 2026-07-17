"""Conservative deterministic BOLA/IDOR candidate detection."""

from dataclasses import dataclass

from sentinel_api.scanner.analysis.models import HandlerContext, ResourceIdentifier
from sentinel_api.scanner.discovery.models import (
    DiscoveredRoute,
    OwnershipCandidate,
    RouteModelMapping,
)


@dataclass(frozen=True, slots=True)
class BolaCandidate:
    """Fully evidenced internal BOLA candidate before finding construction."""

    route: DiscoveredRoute
    context: HandlerContext
    mapping: RouteModelMapping
    identifier: ResourceIdentifier
    ownership: OwnershipCandidate
    confidence: float


class BolaDetector:
    """Apply explicit false-positive controls to object access routes."""

    def detect(
        self,
        routes: list[DiscoveredRoute],
        contexts: list[HandlerContext],
        mappings: list[RouteModelMapping],
        ownership_candidates: list[OwnershipCandidate],
    ) -> list[BolaCandidate]:
        """Return candidates only when all strong deterministic conditions hold."""
        contexts_by_id = {context.route_id: context for context in contexts}
        mappings_by_route: dict[str, list[RouteModelMapping]] = {}
        for mapping in mappings:
            mappings_by_route.setdefault(mapping.route_id, []).append(mapping)
        ownership_by_model: dict[str, list[OwnershipCandidate]] = {}
        for candidate in ownership_candidates:
            ownership_by_model.setdefault(candidate.model, []).append(candidate)

        candidates: dict[tuple[str, str], BolaCandidate] = {}
        for route in routes:
            context = contexts_by_id[route.route_id]
            if route.authentication_required is not True or not context.extraction_complete:
                continue
            if context.authorization_controls:
                continue
            for mapping in mappings_by_route.get(route.route_id, []):
                if mapping.operation not in {"read_one", "update", "delete"}:
                    continue
                if mapping.confidence < 0.9:
                    continue
                ownership = ownership_by_model.get(mapping.model, [])
                if not ownership:
                    continue
                identifier = next(
                    (
                        item
                        for item in context.resource_identifiers
                        if item.used_in_orm_selector
                        and item.associated_model == mapping.model
                        and item.confidence >= 0.9
                        and _looks_like_object_identifier(
                            item.parameter_name,
                            item.selector_field,
                        )
                    ),
                    None,
                )
                if identifier is None:
                    continue
                selected = max(ownership, key=lambda item: item.confidence)
                confidence = round(
                    min(
                        route.confidence,
                        mapping.confidence,
                        identifier.confidence,
                        selected.confidence,
                    ),
                    2,
                )
                candidates[(route.route_id, mapping.model)] = BolaCandidate(
                    route=route,
                    context=context,
                    mapping=mapping,
                    identifier=identifier,
                    ownership=selected,
                    confidence=confidence,
                )
        return sorted(
            candidates.values(),
            key=lambda item: (item.route.path, item.mapping.model),
        )


def _looks_like_object_identifier(parameter: str, selector_field: str | None) -> bool:
    values = (parameter.casefold(), (selector_field or "").casefold())
    return any(value == "id" or value.endswith("id") for value in values)
