"""Conservative missing-authentication detector tests."""

from sentinel_api.scanner.analysis.missing_auth_detector import MissingAuthenticationDetector
from sentinel_api.scanner.discovery.models import (
    DiscoveredRoute,
    OwnershipCandidate,
    RouteModelMapping,
)


def _public_route(path: str) -> DiscoveredRoute:
    return DiscoveredRoute(
        route_id=f"route:POST:{path}",
        method="POST",
        path=path,
        local_path=path,
        mounted_path="/",
        source_file="src/routes.ts",
        line_number=1,
        handler="anonymous",
        inline_handler=True,
        middlewares=[],
        router_name="app",
        authentication_required=False,
        authentication_middleware=[],
        authentication_mechanism=None,
        authentication_evidence=["No authentication applies"],
        confidence=0.98,
        evidence=["Test route"],
    )


def _mapping(route: DiscoveredRoute, operation: str = "update") -> RouteModelMapping:
    return RouteModelMapping.model_validate(
        {
            "route_id": route.route_id,
            "model": "Project",
            "operation": operation,
            "confidence": 0.99,
            "evidence": ["Direct Prisma call"],
            "source_file": route.source_file,
        }
    )


def test_public_sensitive_mutation_is_detected() -> None:
    route = _public_route("/api/projects/:id")

    candidates = MissingAuthenticationDetector().detect([route], [_mapping(route)], [])

    assert len(candidates) == 1


def test_login_is_suppressed_as_intentionally_public() -> None:
    route = _public_route("/api/login")

    candidates = MissingAuthenticationDetector().detect([route], [_mapping(route)], [])

    assert candidates == []


def test_public_owned_object_read_requires_ownership_evidence() -> None:
    route = _public_route("/api/projects/:id")
    read_mapping = _mapping(route, "read_one")
    ownership = OwnershipCandidate(
        model="Project",
        field="ownerId",
        candidate_type="direct_owner",
        confidence=0.98,
        evidence=["Owner relation"],
    )

    without_ownership = MissingAuthenticationDetector().detect(
        [route], [read_mapping], []
    )
    with_ownership = MissingAuthenticationDetector().detect(
        [route], [read_mapping], [ownership]
    )

    assert without_ownership == []
    assert len(with_ownership) == 1
