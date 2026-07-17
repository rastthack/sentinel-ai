"""Evidence-backed mapping from Express handlers to Prisma models."""

import re
from typing import Final

from sentinel_api.scanner.discovery.models import (
    DiscoveredRoute,
    MappingOperation,
    PrismaDataModel,
    RouteModelMapping,
)

_PRISMA_CALL: Final = re.compile(
    r"\bprisma\.([A-Za-z_]\w*)\."
    r"(findUnique|findFirst|findMany|count|create|createMany|upsert|"
    r"update|updateMany|delete|deleteMany)\s*\(",
    re.IGNORECASE,
)
_OPERATIONS: Final[dict[str, MappingOperation]] = {
    "findunique": "read_one",
    "findfirst": "read_one",
    "findmany": "read_many",
    "count": "read_many",
    "create": "create",
    "createmany": "create",
    "upsert": "create",
    "update": "update",
    "updatemany": "update",
    "delete": "delete",
    "deletemany": "delete",
}
_OPERATION_ORDER: Final[dict[MappingOperation, int]] = {
    "create": 0,
    "delete": 1,
    "read_one": 2,
    "read_many": 3,
    "update": 4,
    "unknown": 5,
}


class RouteModelMapper:
    """Associate routes only when handler source contains a direct Prisma call."""

    def map(
        self,
        routes: list[DiscoveredRoute],
        handler_sources: dict[str, str],
        data_model: PrismaDataModel,
    ) -> tuple[list[RouteModelMapping], list[str]]:
        """Return stable mappings and warnings for unsupported Prisma delegates."""
        models = {model.name.casefold(): model.name for model in data_model.models}
        mappings: dict[tuple[str, str, MappingOperation], RouteModelMapping] = {}
        warnings: set[str] = set()

        for route in routes:
            source = handler_sources.get(route.route_id, "")
            for match in _PRISMA_CALL.finditer(source):
                delegate, prisma_operation = match.groups()
                model = models.get(delegate.casefold())
                if model is None:
                    warnings.add(
                        f"Prisma delegate {delegate} used by {route.method} {route.path} "
                        "does not match a parsed model"
                    )
                    continue
                operation = _OPERATIONS[prisma_operation.casefold()]
                key = (route.route_id, model, operation)
                mappings[key] = RouteModelMapping(
                    route_id=route.route_id,
                    model=model,
                    operation=operation,
                    confidence=0.99,
                    evidence=[
                        f"Route handler directly calls prisma.{delegate}.{prisma_operation}"
                    ],
                    source_file=route.source_file,
                )

        return sorted(
            mappings.values(),
            key=lambda item: (
                item.route_id,
                item.model,
                _OPERATION_ORDER[item.operation],
            ),
        ), sorted(warnings)
