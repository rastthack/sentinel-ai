"""Static application-structure discovery components."""

from sentinel_api.scanner.discovery.authentication import AuthenticationDiscoverer
from sentinel_api.scanner.discovery.express_routes import ExpressRouteDiscoverer
from sentinel_api.scanner.discovery.prisma_schema import PrismaSchemaParser
from sentinel_api.scanner.discovery.route_model_mapper import RouteModelMapper

__all__ = [
    "AuthenticationDiscoverer",
    "ExpressRouteDiscoverer",
    "PrismaSchemaParser",
    "RouteModelMapper",
]
