"""Route-to-Prisma-model mapping tests."""

from sentinel_api.scanner.discovery.models import (
    DiscoveredRoute,
    PrismaDataModel,
    PrismaModel,
)
from sentinel_api.scanner.discovery.route_model_mapper import RouteModelMapper


def _route(path: str = "/api/projects") -> DiscoveredRoute:
    return DiscoveredRoute(
        route_id=f"route:GET:{path}",
        method="GET",
        path=path,
        local_path=path,
        mounted_path="/",
        source_file="src/routes.ts",
        line_number=1,
        handler="anonymous",
        inline_handler=True,
        middlewares=[],
        router_name="router",
        authentication_required=False,
        authentication_middleware=[],
        authentication_mechanism=None,
        authentication_evidence=[],
        confidence=0.98,
        evidence=["test route"],
    )


def _data_model() -> PrismaDataModel:
    return PrismaDataModel(
        provider="sqlite",
        generators=[],
        models=[
            PrismaModel(
                name="Project",
                source_file="prisma/schema.prisma",
                primary_key=["id"],
                unique_fields=[],
                fields=[],
                model_attributes=[],
            )
        ],
        ownership_candidates=[],
    )


def test_direct_prisma_calls_map_all_supported_operations_and_deduplicate() -> None:
    route = _route()
    source = """
        await prisma.project.findMany({});
        await prisma.project.findMany({});
        await prisma.project.findUnique({});
        await prisma.project.create({});
        await prisma.project.update({});
        await prisma.project.delete({});
    """

    mappings, warnings = RouteModelMapper().map(
        [route], {route.route_id: source}, _data_model()
    )

    assert warnings == []
    assert [(item.model, item.operation) for item in mappings] == [
        ("Project", "create"),
        ("Project", "delete"),
        ("Project", "read_one"),
        ("Project", "read_many"),
        ("Project", "update"),
    ]


def test_direct_model_evidence_outweighs_a_different_path_noun() -> None:
    route = _route("/api/tasks")

    mappings, _ = RouteModelMapper().map(
        [route],
        {route.route_id: "await prisma.project.findUnique({});"},
        _data_model(),
    )

    assert [(item.model, item.operation) for item in mappings] == [
        ("Project", "read_one")
    ]


def test_route_noun_alone_is_not_treated_as_model_evidence() -> None:
    route = _route()

    mappings, warnings = RouteModelMapper().map(
        [route], {route.route_id: "return projects;"}, _data_model()
    )

    assert mappings == []
    assert warnings == []
