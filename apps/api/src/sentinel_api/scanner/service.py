"""Shared repository scan orchestration for API and CLI callers."""

from pathlib import Path
from uuid import uuid4

from sentinel_api.scanner.discovery import (
    AuthenticationDiscoverer,
    ExpressRouteDiscoverer,
    PrismaSchemaParser,
    RouteModelMapper,
)
from sentinel_api.scanner.file_indexer import FileIndexer
from sentinel_api.scanner.framework_detector import (
    FrameworkDetector,
    detect_entrypoints,
    detect_languages,
)
from sentinel_api.scanner.models import (
    IndexLimits,
    RepositoryMetadata,
    RepositoryScanResponse,
    ScanSummary,
)
from sentinel_api.scanner.repository_loader import RepositoryLoader, configured_scan_root


class ScanService:
    """Coordinate safe loading, indexing, and deterministic detection."""

    def __init__(
        self,
        loader: RepositoryLoader,
        indexer: FileIndexer,
        detector: FrameworkDetector,
        route_discoverer: ExpressRouteDiscoverer,
        authentication_discoverer: AuthenticationDiscoverer,
        prisma_parser: PrismaSchemaParser,
        route_model_mapper: RouteModelMapper,
    ) -> None:
        self.loader = loader
        self.indexer = indexer
        self.detector = detector
        self.route_discoverer = route_discoverer
        self.authentication_discoverer = authentication_discoverer
        self.prisma_parser = prisma_parser
        self.route_model_mapper = route_model_mapper

    def scan(self, repository_path: str | Path) -> RepositoryScanResponse:
        """Return structured metadata for one allowed local repository."""
        repository = self.loader.load(repository_path)
        index = self.indexer.index(repository)
        languages = detect_languages(index.files)
        technologies = self.detector.detect(index)
        entrypoints = detect_entrypoints(index)
        express = self.route_discoverer.discover(index)
        routes, authentication = self.authentication_discoverer.discover(index, express)
        data_model, prisma_warnings = self.prisma_parser.parse(index)
        mappings, mapping_warnings = self.route_model_mapper.map(
            routes,
            express.handler_sources,
            data_model,
        )

        frameworks = [item.name for item in technologies if item.category == "framework"]
        package_managers = [
            item.name for item in technologies if item.category == "package_manager"
        ]
        orm = [item.name for item in technologies if item.category == "orm"]
        databases = [item.name for item in technologies if item.category == "database"]
        source_count = sum(item.category == "source" for item in index.files)
        configuration_count = sum(item.category == "configuration" for item in index.files)

        return RepositoryScanResponse(
            scan_id=str(uuid4()),
            repository=RepositoryMetadata(
                name=repository.name,
                relative_path=repository.relative_path,
            ),
            summary=ScanSummary(
                primary_language=languages[0].name if languages else None,
                frameworks=frameworks,
                package_manager=package_managers[0] if package_managers else None,
                orm=orm,
                databases=databases,
                source_file_count=source_count,
                configuration_file_count=configuration_count,
                ignored_file_count=index.ignored_file_count,
                route_count=len(routes),
                protected_route_count=authentication.protected_route_count,
                public_route_count=authentication.public_route_count,
                prisma_model_count=len(data_model.models),
                mapped_route_count=len({mapping.route_id for mapping in mappings}),
            ),
            languages=languages,
            technologies=technologies,
            entrypoints=entrypoints,
            files=index.files,
            routes=routes,
            authentication=authentication,
            data_model=data_model,
            route_model_mappings=mappings,
            warnings=[
                *index.warnings,
                *express.warnings,
                *prisma_warnings,
                *mapping_warnings,
            ],
        )


def build_scan_service(
    allowed_root: Path | None = None,
    limits: IndexLimits | None = None,
) -> ScanService:
    """Construct a scanner with explicit or environment-backed configuration."""
    return ScanService(
        loader=RepositoryLoader(allowed_root or configured_scan_root()),
        indexer=FileIndexer(limits),
        detector=FrameworkDetector(),
        route_discoverer=ExpressRouteDiscoverer(),
        authentication_discoverer=AuthenticationDiscoverer(),
        prisma_parser=PrismaSchemaParser(),
        route_model_mapper=RouteModelMapper(),
    )
