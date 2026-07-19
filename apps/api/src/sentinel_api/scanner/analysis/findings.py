"""Authorization-analysis orchestration, findings, and explainable graphs."""

import hashlib
from dataclasses import dataclass

from sentinel_api.scanner.analysis.authorization_checks import AuthorizationCheckAnalyzer
from sentinel_api.scanner.analysis.bola_detector import BolaCandidate, BolaDetector
from sentinel_api.scanner.analysis.handler_context import HandlerContextExtractor
from sentinel_api.scanner.analysis.missing_auth_detector import (
    MissingAuthenticationCandidate,
    MissingAuthenticationDetector,
)
from sentinel_api.scanner.analysis.models import (
    AnalysisSummary,
    AuthorizationFinding,
    AuthorizationGraph,
    AuthorizationGraphEdge,
    AuthorizationGraphNode,
    GraphDecision,
    HandlerContext,
    Severity,
)
from sentinel_api.scanner.analysis.risk_scoring import RiskScorer
from sentinel_api.scanner.discovery.models import (
    AuthenticationDiscovery,
    DiscoveredRoute,
    ExpressDiscoveryResult,
    PrismaDataModel,
    RouteModelMapping,
)
from sentinel_api.scanner.models import IndexResult

_SEVERITY_ORDER: dict[Severity, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}


@dataclass(frozen=True, slots=True)
class AuthorizationAnalysisResult:
    """Complete internal result returned to the shared scan service."""

    contexts: list[HandlerContext]
    graphs: list[AuthorizationGraph]
    findings: list[AuthorizationFinding]
    summary: AnalysisSummary


class AuthorizationAnalyzer:
    """Coordinate context, controls, detectors, scoring, and graph output."""

    def __init__(
        self,
        context_extractor: HandlerContextExtractor,
        check_analyzer: AuthorizationCheckAnalyzer,
        bola_detector: BolaDetector,
        missing_auth_detector: MissingAuthenticationDetector,
        risk_scorer: RiskScorer,
    ) -> None:
        self.context_extractor = context_extractor
        self.check_analyzer = check_analyzer
        self.bola_detector = bola_detector
        self.missing_auth_detector = missing_auth_detector
        self.risk_scorer = risk_scorer

    def analyze(
        self,
        index: IndexResult,
        express: ExpressDiscoveryResult,
        routes: list[DiscoveredRoute],
        authentication: AuthenticationDiscovery,
        data_model: PrismaDataModel,
        mappings: list[RouteModelMapping],
    ) -> AuthorizationAnalysisResult:
        """Run deterministic static authorization analysis for all routes."""
        contexts = self.context_extractor.extract(
            routes,
            express.handler_sources,
            index,
            data_model,
        )
        contexts = self.check_analyzer.analyze(
            routes,
            contexts,
            express.handler_sources,
            data_model,
            authentication,
        )
        bola = self.bola_detector.detect(
            routes,
            contexts,
            mappings,
            data_model.ownership_candidates,
        )
        missing_auth = self.missing_auth_detector.detect(
            routes,
            mappings,
            data_model.ownership_candidates,
        )
        findings = [self._bola_finding(candidate) for candidate in bola]
        findings.extend(self._missing_auth_finding(candidate) for candidate in missing_auth)
        findings.sort(key=_finding_sort_key)
        graphs = self._graphs(
            routes,
            contexts,
            mappings,
            data_model,
            bola,
        )
        warnings = sorted({warning for context in contexts for warning in context.warnings})
        ownership_control_types = {
            "ownership_query_filter",
            "ownership_post_fetch_comparison",
            "membership_query_filter",
            "membership_post_fetch_check",
        }
        return AuthorizationAnalysisResult(
            contexts=contexts,
            graphs=graphs,
            findings=findings,
            summary=AnalysisSummary(
                routes_analyzed=len(routes),
                routes_with_resource_identifiers=sum(
                    bool(context.resource_identifiers) for context in contexts
                ),
                routes_with_ownership_controls=sum(
                    any(
                        control.control_type in ownership_control_types
                        for control in context.authorization_controls
                    )
                    for context in contexts
                ),
                potential_bola_count=len(bola),
                missing_authentication_count=len(missing_auth),
                analysis_warnings=warnings,
            ),
        )

    def _bola_finding(self, candidate: BolaCandidate) -> AuthorizationFinding:
        risk = self.risk_scorer.bola(candidate.mapping.operation)
        ownership = f"{candidate.ownership.model}.{candidate.ownership.field}"
        evidence = _unique(
            [
                "Route requires recognized authentication",
                (
                    f"Client-controlled {candidate.identifier.parameter_source} parameter "
                    f"{candidate.identifier.parameter_name} reaches a direct ORM selector"
                ),
                f"Route directly maps to {candidate.mapping.model}.{candidate.mapping.operation}",
                f"Model contains ownership candidate {ownership}",
                "No ownership query filter was found in the relevant handler",
                "No ownership or membership comparison was found after retrieval",
                "No recognized authorization middleware applies to the route",
            ]
        )
        return AuthorizationFinding(
            finding_id=_stable_finding_id(
                "AUTH-BOLA",
                candidate.route.method,
                candidate.route.path,
                candidate.mapping.model,
                candidate.route.source_file,
            ),
            rule_id="AUTH-BOLA",
            title="Potential BOLA / IDOR",
            category="authorization",
            severity=risk.severity,
            confidence=candidate.confidence,
            status="open",
            route_id=candidate.route.route_id,
            method=candidate.route.method,
            path=candidate.route.path,
            model=candidate.mapping.model,
            operation=candidate.mapping.operation,
            ownership_candidate=candidate.ownership.field,
            source_file=candidate.route.source_file,
            line_number=candidate.route.line_number,
            description=(
                f"The authenticated route retrieves a {candidate.mapping.model} using a "
                "client-controlled identifier without a deterministic ownership, membership, "
                "or equivalent authorization control."
            ),
            evidence=evidence,
            recommendation=(
                "Scope the database query to the authenticated user or perform an explicit "
                "ownership or membership check before returning the resource."
            ),
            cwe=["CWE-639"],
            owasp=["OWASP API1:2023 Broken Object Level Authorization"],
            risk_score=risk.score,
            risk_components=risk.components,
        )

    def _missing_auth_finding(
        self,
        candidate: MissingAuthenticationCandidate,
    ) -> AuthorizationFinding:
        risk = self.risk_scorer.missing_authentication(candidate.mapping.operation)
        return AuthorizationFinding(
            finding_id=_stable_finding_id(
                "AUTH-MISSING",
                candidate.route.method,
                candidate.route.path,
                candidate.mapping.model,
                candidate.route.source_file,
            ),
            rule_id="AUTH-MISSING",
            title="Potential Missing Authentication",
            category="authentication",
            severity=risk.severity,
            confidence=candidate.confidence,
            status="open",
            route_id=candidate.route.route_id,
            method=candidate.route.method,
            path=candidate.route.path,
            model=candidate.mapping.model,
            operation=candidate.mapping.operation,
            ownership_candidate=None,
            source_file=candidate.route.source_file,
            line_number=candidate.route.line_number,
            description=(
                "A public route performs a sensitive direct model operation without recognized "
                "authentication."
            ),
            evidence=[
                "Route is classified as public",
                f"Route directly maps to {candidate.mapping.model}.{candidate.mapping.operation}",
            ],
            recommendation="Require authentication before the sensitive model operation.",
            cwe=["CWE-306"],
            owasp=["OWASP API2:2023 Broken Authentication"],
            risk_score=risk.score,
            risk_components=risk.components,
        )

    @staticmethod
    def _graphs(
        routes: list[DiscoveredRoute],
        contexts: list[HandlerContext],
        mappings: list[RouteModelMapping],
        data_model: PrismaDataModel,
        bola: list[BolaCandidate],
    ) -> list[AuthorizationGraph]:
        contexts_by_id = {context.route_id: context for context in contexts}
        mappings_by_route: dict[str, list[RouteModelMapping]] = {}
        for mapping in mappings:
            mappings_by_route.setdefault(mapping.route_id, []).append(mapping)
        ownership_by_model: dict[str, list[str]] = {}
        for candidate in data_model.ownership_candidates:
            ownership_by_model.setdefault(candidate.model, []).append(candidate.field)
        bola_keys = {(candidate.route.route_id, candidate.mapping.model) for candidate in bola}
        graphs = [
            _route_graph(
                route,
                contexts_by_id[route.route_id],
                mappings_by_route.get(route.route_id, []),
                ownership_by_model,
                bola_keys,
            )
            for route in routes
        ]
        return sorted(graphs, key=lambda item: item.route_id)


def _route_graph(
    route: DiscoveredRoute,
    context: HandlerContext,
    mappings: list[RouteModelMapping],
    ownership_by_model: dict[str, list[str]],
    bola_keys: set[tuple[str, str]],
) -> AuthorizationGraph:
    nodes = [
        AuthorizationGraphNode(
            node_id=f"{route.route_id}:route",
            type="route",
            value=f"{route.method} {route.path}",
        )
    ]
    edges: list[AuthorizationGraphEdge] = []
    route_node = nodes[0].node_id
    for middleware in route.authentication_middleware:
        node_id = f"{route.route_id}:authentication:{middleware}"
        nodes.append(
            AuthorizationGraphNode(node_id=node_id, type="authentication", value=middleware)
        )
        edges.append(
            AuthorizationGraphEdge(
                source=route_node,
                target=node_id,
                relationship="protected_by",
            )
        )
    if context.authenticated_identity:
        node_id = f"{route.route_id}:identity"
        nodes.append(
            AuthorizationGraphNode(
                node_id=node_id,
                type="identity",
                value=context.authenticated_identity.expression,
            )
        )
        for middleware in route.authentication_middleware:
            edges.append(
                AuthorizationGraphEdge(
                    source=f"{route.route_id}:authentication:{middleware}",
                    target=node_id,
                    relationship="establishes",
                )
            )
    for index, identifier in enumerate(context.resource_identifiers):
        node_id = f"{route.route_id}:identifier:{index}"
        nodes.append(
            AuthorizationGraphNode(
                node_id=node_id,
                type="resource_identifier",
                value=identifier.expression,
            )
        )
        edges.append(
            AuthorizationGraphEdge(
                source=route_node,
                target=node_id,
                relationship="accepts",
            )
        )
    for index, mapping in enumerate(mappings):
        operation_node = f"{route.route_id}:operation:{index}"
        model_node = f"{route.route_id}:model:{mapping.model}"
        nodes.extend(
            [
                AuthorizationGraphNode(
                    node_id=operation_node,
                    type="orm_operation",
                    value=mapping.operation,
                ),
                AuthorizationGraphNode(
                    node_id=model_node,
                    type="model",
                    value=mapping.model,
                ),
            ]
        )
        edges.extend(
            [
                AuthorizationGraphEdge(
                    source=route_node,
                    target=operation_node,
                    relationship="performs",
                ),
                AuthorizationGraphEdge(
                    source=operation_node,
                    target=model_node,
                    relationship="accesses",
                ),
            ]
        )
        for field in sorted(ownership_by_model.get(mapping.model, [])):
            owner_node = f"{route.route_id}:ownership:{mapping.model}:{field}"
            nodes.append(
                AuthorizationGraphNode(
                    node_id=owner_node,
                    type="ownership_candidate",
                    value=f"{mapping.model}.{field}",
                )
            )
        for identifier_index, identifier in enumerate(context.resource_identifiers):
            if identifier.associated_model == mapping.model:
                edges.append(
                    AuthorizationGraphEdge(
                        source=f"{route.route_id}:identifier:{identifier_index}",
                        target=model_node,
                        relationship="selects",
                    )
                )
            edges.append(
                AuthorizationGraphEdge(
                    source=model_node,
                    target=owner_node,
                    relationship="may_be_owned_by",
                )
            )
    for index, control in enumerate(context.authorization_controls):
        node_id = f"{route.route_id}:control:{index}"
        nodes.append(
            AuthorizationGraphNode(
                node_id=node_id,
                type="authorization_control",
                value=control.control_type,
            )
        )
        edges.append(
            AuthorizationGraphEdge(
                source=route_node,
                target=node_id,
                relationship="controlled_by",
            )
        )
    potential_bola = any((route.route_id, mapping.model) in bola_keys for mapping in mappings)
    decision: GraphDecision
    if potential_bola:
        decision = "potential_bola"
        missing_node = f"{route.route_id}:control:missing"
        nodes.append(
            AuthorizationGraphNode(
                node_id=missing_node,
                type="authorization_control",
                value="missing",
            )
        )
        edges.append(
            AuthorizationGraphEdge(
                source=route_node,
                target=missing_node,
                relationship="lacks",
            )
        )
    elif context.authorization_controls:
        decision = "controlled"
    elif context.resource_identifiers and mappings:
        decision = "inconclusive"
    else:
        decision = "not_applicable"
    return AuthorizationGraph(
        route_id=route.route_id,
        nodes=_deduplicate_nodes(nodes),
        edges=sorted(edges, key=lambda item: (item.source, item.target, item.relationship)),
        decision=decision,
    )


def _deduplicate_nodes(nodes: list[AuthorizationGraphNode]) -> list[AuthorizationGraphNode]:
    unique = {node.node_id: node for node in nodes}
    return sorted(unique.values(), key=lambda item: item.node_id)


def _stable_finding_id(
    rule_id: str,
    method: str,
    path: str,
    model: str,
    source_file: str,
) -> str:
    fingerprint = "|".join((rule_id, method, path, model, source_file))
    digest = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:10].upper()
    return f"{rule_id}-{digest}"


def _finding_sort_key(finding: AuthorizationFinding) -> tuple[int, str, str, str, str]:
    return (
        _SEVERITY_ORDER[finding.severity],
        finding.rule_id,
        finding.path or "",
        finding.model or "",
        finding.finding_id,
    )


def _unique(evidence: list[str]) -> list[str]:
    return list(dict.fromkeys(evidence))
