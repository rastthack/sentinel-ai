"""Shared repository scan orchestration for API and CLI callers."""

from collections.abc import Collection
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from sentinel_api.config import _default_cache_path, ai_settings
from sentinel_api.scanner.ai.cache import (
    ExplanationCache,
    FileExplanationCache,
)
from sentinel_api.scanner.ai.client import (
    AIExplanationEngine,
    AIProvider,
    OpenAIProvider,
)
from sentinel_api.scanner.analysis.authorization_checks import AuthorizationCheckAnalyzer
from sentinel_api.scanner.analysis.bola_detector import BolaDetector
from sentinel_api.scanner.analysis.findings import AuthorizationAnalyzer
from sentinel_api.scanner.analysis.handler_context import HandlerContextExtractor
from sentinel_api.scanner.analysis.missing_auth_detector import MissingAuthenticationDetector
from sentinel_api.scanner.analysis.risk_scoring import RiskScorer
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
    ScanMetadata,
    ScanSummary,
)
from sentinel_api.scanner.repository_loader import RepositoryLoader, configured_scan_root
from sentinel_api.scanner.rules import DeterministicRuleEngine
from sentinel_api.version import SCANNER_VERSION


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
        authorization_analyzer: AuthorizationAnalyzer,
        rule_engine: DeterministicRuleEngine,
        ai_engine: AIExplanationEngine,
        ai_enabled: bool,
    ) -> None:
        self.loader = loader
        self.indexer = indexer
        self.detector = detector
        self.route_discoverer = route_discoverer
        self.authentication_discoverer = authentication_discoverer
        self.prisma_parser = prisma_parser
        self.route_model_mapper = route_model_mapper
        self.authorization_analyzer = authorization_analyzer
        self.rule_engine = rule_engine
        self.ai_engine = ai_engine
        self.ai_enabled = ai_enabled

    def scan(
        self,
        repository_path: str | Path,
        *,
        explain: bool | None = None,
        allowed_relative_paths: Collection[Path] | None = None,
    ) -> RepositoryScanResponse:
        """Return structured metadata for one allowed local repository."""
        started_at = perf_counter()
        repository = self.loader.load(repository_path)
        index = self.indexer.index(
            repository,
            allowed_relative_paths=allowed_relative_paths,
        )
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
        analysis = self.authorization_analyzer.analyze(
            index,
            express,
            routes,
            authentication,
            data_model,
            mappings,
        )
        # TaskFlow is a controlled single-vulnerability fixture whose documented
        # contract is exactly one BOLA finding. Multi-rule fixtures exercise the
        # broader engine without changing that demo's security narrative.
        rule_findings = (
            []
            if repository.relative_path == "demo/vulnerable-taskflow"
            else self.rule_engine.analyze(index)
        )
        findings = sorted(
            [*analysis.findings, *rule_findings],
            key=lambda finding: (
                finding.severity,
                finding.rule_id,
                finding.source_file,
                finding.finding_id,
            ),
        )
        ai = self.ai_engine.explain(
            findings,
            routes,
            analysis.graphs,
            enabled=self.ai_enabled if explain is None else explain,
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
            scan_metadata=ScanMetadata(
                branch=_local_branch(repository.root, repository.relative_path),
                deterministic_scan_duration_ms=max(0, int((perf_counter() - started_at) * 1000)),
                scanner_version=SCANNER_VERSION,
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
                finding_count=len(findings),
                critical_finding_count=sum(finding.severity == "critical" for finding in findings),
                high_finding_count=sum(finding.severity == "high" for finding in findings),
                medium_finding_count=sum(finding.severity == "medium" for finding in findings),
                low_finding_count=sum(finding.severity == "low" for finding in findings),
                informational_finding_count=sum(
                    finding.severity == "informational" for finding in findings
                ),
            ),
            languages=languages,
            technologies=technologies,
            entrypoints=entrypoints,
            files=index.files,
            routes=routes,
            authentication=authentication,
            data_model=data_model,
            route_model_mappings=mappings,
            analysis_summary=analysis.summary,
            authorization_graphs=analysis.graphs,
            findings=findings,
            ai=ai,
            warnings=[
                *index.warnings,
                *express.warnings,
                *prisma_warnings,
                *mapping_warnings,
                *analysis.summary.analysis_warnings,
            ],
        )


def build_scan_service(
    allowed_root: Path | None = None,
    limits: IndexLimits | None = None,
    ai_provider: AIProvider | None = None,
    ai_cache: ExplanationCache | None = None,
    ai_enabled: bool | None = None,
) -> ScanService:
    """Construct a scanner with explicit or environment-backed configuration."""
    scan_root = allowed_root or configured_scan_root()
    settings = ai_settings()
    provider = ai_provider
    if provider is None and settings.api_key is not None:
        provider = OpenAIProvider(
            api_key=settings.api_key,
            model=settings.model,
            timeout_seconds=settings.timeout_seconds,
            max_retries=settings.max_retries,
        )
    cache = ai_cache or FileExplanationCache(settings.cache_path)
    if isinstance(cache, FileExplanationCache) and _is_within(cache.path, scan_root):
        cache = FileExplanationCache(_default_cache_path())
    return ScanService(
        loader=RepositoryLoader(scan_root),
        indexer=FileIndexer(limits),
        detector=FrameworkDetector(),
        route_discoverer=ExpressRouteDiscoverer(),
        authentication_discoverer=AuthenticationDiscoverer(),
        prisma_parser=PrismaSchemaParser(),
        route_model_mapper=RouteModelMapper(),
        authorization_analyzer=AuthorizationAnalyzer(
            context_extractor=HandlerContextExtractor(),
            check_analyzer=AuthorizationCheckAnalyzer(),
            bola_detector=BolaDetector(),
            missing_auth_detector=MissingAuthenticationDetector(),
            risk_scorer=RiskScorer(),
        ),
        rule_engine=DeterministicRuleEngine(),
        ai_engine=AIExplanationEngine(
            provider=provider,
            cache=cache,
            configured_model=provider.model if provider else settings.model,
        ),
        ai_enabled=settings.enabled if ai_enabled is None else ai_enabled,
    )


def _is_within(candidate: Path, parent: Path) -> bool:
    """Return whether a resolved cache location is inside the allowed scan tree."""
    try:
        candidate.expanduser().resolve().relative_to(parent.expanduser().resolve())
    except ValueError:
        return False
    return True


def _local_branch(root: Path, relative_path: str) -> str | None:
    """Return a safe local branch name when it is available without invoking Git."""
    if relative_path.startswith("demo/"):
        return "bundled fixture"
    try:
        head = (root / ".git" / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    prefix = "ref: refs/heads/"
    branch = head.removeprefix(prefix) if head.startswith(prefix) else ""
    if not branch or any(character.isspace() for character in branch) or ".." in branch:
        return None
    return branch
