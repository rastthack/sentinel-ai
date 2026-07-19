"""Deterministic conversion of a scan response into bounded untrusted evidence."""

import re
from collections.abc import Mapping
from pathlib import PurePath

from sentinel_api.reviewer.models import (
    AuthenticationEvidence,
    EvidenceFinding,
    EvidenceRepository,
    EvidenceRoute,
    EvidenceRouteModelMapping,
    EvidenceSummary,
    EvidenceTruncation,
    PrismaOwnershipEvidence,
    SecurityEvidencePackage,
    SourceExcerpt,
)
from sentinel_api.scanner.analysis.models import AuthorizationFinding
from sentinel_api.scanner.models import RepositoryScanResponse
from sentinel_api.scanner.redaction import redact_sensitive_text

MAX_FINDINGS = 20
MAX_REFERENCED_FILES = 30
MAX_EXCERPT_CHARACTERS = 2_000
MAX_EVIDENCE_CHARACTERS = 40_000

_SOURCE_CATEGORIES = frozenset({"source", "configuration"})
_LOCK_FILES = frozenset(
    {"package-lock.json", "pnpm-lock.yaml", "poetry.lock", "yarn.lock", "pipfile.lock"}
)
_ABSOLUTE_PATH = re.compile(r"(?<![\w:])(?:[A-Za-z]:[\\/]|/(?!api(?:/|$)))[^\s\"']+")


def build_security_evidence_package(
    scan: RepositoryScanResponse,
    source_contents: Mapping[str, str] | None = None,
) -> SecurityEvidencePackage:
    """Build a bounded package without mutating deterministic scan data.

    ``source_contents`` is an internal, caller-owned mapping such as
    ``IndexResult.contents``. Its text is untrusted data, never instructions.
    """
    budget = _EvidenceBudget()
    selected_findings = sorted(
        scan.findings,
        key=lambda finding: (
            -_severity_rank(finding.severity),
            -finding.risk_score,
            finding.finding_id,
        ),
    )[:MAX_FINDINGS]
    if len(scan.findings) > MAX_FINDINGS:
        budget.truncate("finding_limit")

    model_sources = {model.name: model.source_file for model in scan.data_model.models}
    findings = [_finding_evidence(finding, budget) for finding in selected_findings]
    routes = [
        _route_evidence(route, budget)
        for route in sorted(scan.routes, key=lambda route: route.route_id)
        if _safe_path(route.source_file) is not None
    ]
    authentication = [
        _authentication_evidence(item, budget)
        for item in sorted(
            scan.authentication.authentication_middleware, key=lambda item: item.name
        )
        if _safe_path(item.source_file) is not None
    ]
    ownership = [
        _ownership_evidence(item, model_sources.get(item.model), budget)
        for item in sorted(
            scan.data_model.ownership_candidates, key=lambda item: (item.model, item.field)
        )
    ]
    mappings = [
        _mapping_evidence(item, budget)
        for item in sorted(
            scan.route_model_mappings,
            key=lambda item: (item.route_id, item.model, item.operation, item.source_file),
        )
        if _safe_path(item.source_file) is not None
    ]
    excerpts = _source_excerpts(
        scan,
        source_contents or {},
        selected_findings,
        budget,
    )

    return SecurityEvidencePackage(
        scan_id=budget.text(scan.scan_id),
        repository=EvidenceRepository(
            name=budget.text(scan.repository.name),
            relative_path=_safe_path(scan.repository.relative_path) or "[redacted-path]",
        ),
        summary=EvidenceSummary(
            primary_language=_optional_text(scan.summary.primary_language, budget),
            frameworks=[budget.text(item) for item in sorted(scan.summary.frameworks)],
            route_count=scan.summary.route_count,
            protected_route_count=scan.summary.protected_route_count,
            prisma_model_count=scan.summary.prisma_model_count,
            mapped_route_count=scan.summary.mapped_route_count,
            finding_count=scan.summary.finding_count,
            high_finding_count=scan.summary.high_finding_count,
        ),
        findings=findings,
        routes=routes,
        authentication=authentication,
        prisma_ownership=ownership,
        route_model_mappings=mappings,
        warnings=[budget.text(warning) for warning in sorted(scan.warnings)],
        source_excerpts=excerpts,
        total_evidence_characters=budget.used,
        truncation=EvidenceTruncation(
            truncated=bool(budget.reasons), reasons=sorted(budget.reasons)
        ),
    )


def _finding_evidence(finding: object, budget: "_EvidenceBudget") -> EvidenceFinding:
    from sentinel_api.scanner.analysis.models import AuthorizationFinding

    assert isinstance(finding, AuthorizationFinding)
    return EvidenceFinding(
        finding_id=budget.text(finding.finding_id),
        rule_id=budget.text(finding.rule_id),
        title=budget.text(finding.title),
        category=finding.category,
        severity=finding.severity,
        confidence=finding.confidence,
        route_id=budget.text(finding.route_id),
        method=_optional_text(finding.method, budget),
        path=_optional_literal(finding.path, budget),
        model=_optional_text(finding.model, budget),
        operation=finding.operation,
        ownership_candidate=_optional_text(finding.ownership_candidate, budget),
        source_file=_safe_path(finding.source_file) or "[redacted-path]",
        line_number=finding.line_number,
        description=budget.text(finding.description),
        evidence_references=[budget.text(item) for item in finding.evidence],
        recommendation=budget.text(finding.recommendation),
        cwe=[budget.text(item) for item in finding.cwe],
        owasp=[budget.text(item) for item in finding.owasp],
        risk_score=finding.risk_score,
    )


def _route_evidence(route: object, budget: "_EvidenceBudget") -> EvidenceRoute:
    from sentinel_api.scanner.discovery.models import DiscoveredRoute

    assert isinstance(route, DiscoveredRoute)
    return EvidenceRoute(
        route_id=budget.text(route.route_id),
        method=route.method,
        path=budget.literal(route.path),
        source_file=_safe_path(route.source_file) or "[redacted-path]",
        line_number=route.line_number,
        authentication_required=route.authentication_required,
        authentication_mechanism=route.authentication_mechanism,
        authentication_evidence=[budget.text(item) for item in route.authentication_evidence],
    )


def _authentication_evidence(item: object, budget: "_EvidenceBudget") -> AuthenticationEvidence:
    from sentinel_api.scanner.discovery.models import AuthenticationMiddleware

    assert isinstance(item, AuthenticationMiddleware)
    return AuthenticationEvidence(
        name=budget.text(item.name),
        mechanism=item.mechanism,
        source_file=_safe_path(item.source_file) or "[redacted-path]",
        line_number=item.line_number,
        evidence_references=[budget.text(value) for value in item.evidence],
    )


def _ownership_evidence(
    item: object,
    source_file: str | None,
    budget: "_EvidenceBudget",
) -> PrismaOwnershipEvidence:
    from sentinel_api.scanner.discovery.models import OwnershipCandidate

    assert isinstance(item, OwnershipCandidate)
    return PrismaOwnershipEvidence(
        model=budget.text(item.model),
        field=budget.text(item.field),
        candidate_type=item.candidate_type,
        confidence=item.confidence,
        source_file=_safe_path(source_file) if source_file else None,
        evidence_references=[budget.text(value) for value in item.evidence],
    )


def _mapping_evidence(item: object, budget: "_EvidenceBudget") -> EvidenceRouteModelMapping:
    from sentinel_api.scanner.discovery.models import RouteModelMapping

    assert isinstance(item, RouteModelMapping)
    return EvidenceRouteModelMapping(
        route_id=budget.text(item.route_id),
        model=budget.text(item.model),
        operation=item.operation,
        confidence=item.confidence,
        source_file=_safe_path(item.source_file) or "[redacted-path]",
        evidence_references=[budget.text(value) for value in item.evidence],
    )


def _source_excerpts(
    scan: RepositoryScanResponse,
    source_contents: Mapping[str, str],
    findings: list[AuthorizationFinding],
    budget: "_EvidenceBudget",
) -> list[SourceExcerpt]:
    eligible = {
        file.relative_path
        for file in scan.files
        if file.content_inspected
        and file.category in _SOURCE_CATEGORIES
        and _safe_path(file.relative_path) is not None
        and not _excluded_path(file.relative_path)
    }
    finding_sources = [
        finding.source_file for finding in findings if _safe_path(finding.source_file) in eligible
    ]
    references = (
        {route.source_file for route in scan.routes}
        | {item.source_file for item in scan.authentication.authentication_middleware}
        | {model.source_file for model in scan.data_model.models}
        | {mapping.source_file for mapping in scan.route_model_mappings}
    )
    ordered_paths = list(dict.fromkeys(sorted(finding_sources))) + sorted(
        path for path in references if path not in finding_sources
    )
    allowed_paths = [path for path in ordered_paths if path in eligible][:MAX_REFERENCED_FILES]
    if len([path for path in ordered_paths if path in eligible]) > MAX_REFERENCED_FILES:
        budget.truncate("referenced_file_limit")

    excerpts: list[SourceExcerpt] = []
    for path in allowed_paths:
        content = source_contents.get(path)
        if not isinstance(content, str):
            continue
        excerpt, truncated = _excerpt(content, budget)
        excerpts.append(SourceExcerpt(relative_path=path, content=excerpt, truncated=truncated))
    return excerpts


def _excerpt(value: str, budget: "_EvidenceBudget") -> tuple[str, bool]:
    redacted = _ABSOLUTE_PATH.sub("[redacted-path]", _redact(value))
    limited, budget_truncated = budget.excerpt_text(redacted)
    truncated = len(redacted) > MAX_EXCERPT_CHARACTERS or budget_truncated
    if len(redacted) > MAX_EXCERPT_CHARACTERS:
        budget.truncate("excerpt_character_limit")
    return limited, truncated


def _redact(value: str) -> str:
    """Redact common credentials while retaining untrusted text as literal evidence."""
    return redact_sensitive_text(value)


def _safe_path(value: str | None) -> str | None:
    if not value or value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", value):
        return None
    path = PurePath(value)
    if ".." in path.parts or ".git" in path.parts or any(not part for part in path.parts):
        return None
    normalized = path.as_posix()
    return None if _excluded_path(normalized) else normalized


def _excluded_path(path: str) -> bool:
    name = PurePath(path).name.casefold()
    return name in _LOCK_FILES or name == ".env" or name.startswith(".env.")


def _optional_text(value: str | None, budget: "_EvidenceBudget") -> str | None:
    return budget.text(value) if value is not None else None


def _optional_literal(value: str | None, budget: "_EvidenceBudget") -> str | None:
    return budget.literal(value) if value is not None else None


def _severity_rank(value: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}.get(value, 0)


class _EvidenceBudget:
    """One deterministic character budget shared by all package text fields."""

    def __init__(self) -> None:
        self.used = 0
        self.reasons: set[str] = set()

    def text(self, value: str) -> str:
        sanitized = _ABSOLUTE_PATH.sub("[redacted-path]", _redact(value))
        maximum = min(len(sanitized), MAX_EVIDENCE_CHARACTERS - self.used)
        truncated = len(sanitized) > maximum
        if truncated:
            self.truncate("evidence_character_limit")
        result = sanitized[:maximum]
        self.used += len(result)
        return result

    def literal(self, value: str) -> str:
        """Retain a structured route value while applying the shared character limit."""
        maximum = min(len(value), MAX_EVIDENCE_CHARACTERS - self.used)
        if len(value) > maximum:
            self.truncate("evidence_character_limit")
        result = value[:maximum]
        self.used += len(result)
        return result

    def excerpt_text(self, value: str) -> tuple[str, bool]:
        maximum = min(MAX_EXCERPT_CHARACTERS, MAX_EVIDENCE_CHARACTERS - self.used)
        truncated = len(value) > maximum
        if truncated:
            self.truncate("evidence_character_limit")
        result = value[:maximum]
        self.used += len(result)
        return result, truncated

    def truncate(self, reason: str) -> None:
        self.reasons.add(reason)
