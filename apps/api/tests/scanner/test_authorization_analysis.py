"""Handler-context, authorization-control, and BOLA decision tests."""

from sentinel_api.scanner.analysis.authorization_checks import AuthorizationCheckAnalyzer
from sentinel_api.scanner.analysis.bola_detector import BolaDetector
from sentinel_api.scanner.analysis.findings import (
    AuthorizationAnalysisResult,
    AuthorizationAnalyzer,
)
from sentinel_api.scanner.analysis.handler_context import HandlerContextExtractor
from sentinel_api.scanner.analysis.missing_auth_detector import MissingAuthenticationDetector
from sentinel_api.scanner.analysis.risk_scoring import RiskScorer
from sentinel_api.scanner.discovery.models import (
    AuthenticationDiscovery,
    DiscoveredRoute,
    ExpressDiscoveryResult,
    MiddlewareDiscovery,
    OwnershipCandidate,
    PrismaDataModel,
    PrismaField,
    PrismaModel,
    RouteModelMapping,
)
from sentinel_api.scanner.models import IndexResult


def _route(
    path: str = "/api/projects/:id",
    *,
    middlewares: list[str] | None = None,
) -> DiscoveredRoute:
    return DiscoveredRoute(
        route_id=f"route:GET:{path}",
        method="GET",
        path=path,
        local_path="/:id" if ":id" in path else "/",
        mounted_path="/api/projects",
        source_file="src/routes/projects.ts",
        line_number=10,
        handler="anonymous",
        inline_handler=True,
        middlewares=["authenticate", *(middlewares or [])],
        router_name="router",
        authentication_required=True,
        authentication_middleware=["authenticate"],
        authentication_mechanism="bearer_token",
        authentication_evidence=["Authentication middleware applies"],
        confidence=0.98,
        evidence=["Test route declaration"],
    )


def _field(name: str, *, relation: str | None = None) -> PrismaField:
    return PrismaField(
        name=name,
        type="String",
        is_optional=False,
        is_list=False,
        is_primary_key=name == "id",
        is_unique=False,
        is_foreign_key=relation is not None,
        is_relation_field=False,
        relation_model=relation,
        is_enum=False,
        default=None,
        attributes=[],
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
                fields=[_field("id"), _field("ownerId", relation="User")],
                model_attributes=[],
            ),
            PrismaModel(
                name="ProjectMember",
                source_file="prisma/schema.prisma",
                primary_key=["id"],
                unique_fields=[],
                fields=[
                    _field("id"),
                    _field("projectId", relation="Project"),
                    _field("userId", relation="User"),
                ],
                model_attributes=[],
            ),
        ],
        ownership_candidates=[
            OwnershipCandidate(
                model="Project",
                field="ownerId",
                candidate_type="direct_owner",
                confidence=0.98,
                evidence=["Direct User ownership relation"],
            ),
            OwnershipCandidate(
                model="ProjectMember",
                field="userId",
                candidate_type="user_reference",
                confidence=0.93,
                evidence=["User membership relation"],
            ),
        ],
    )


def _authentication(
    authorization_middleware: str | None = None,
) -> AuthenticationDiscovery:
    middleware = []
    if authorization_middleware:
        middleware.append(
            MiddlewareDiscovery(
                name=authorization_middleware,
                category="authorization",
                source_file="src/middleware/authorize.ts",
                line_number=1,
                confidence=0.95,
                evidence=["Enforces a permission and rejects with HTTP 403"],
            )
        )
    return AuthenticationDiscovery(
        mechanisms=[],
        middleware=middleware,
        authentication_middleware=[],
        protected_route_count=1,
        public_route_count=0,
        unknown_route_count=0,
    )


def _analyze(
    source: str,
    *,
    route: DiscoveredRoute | None = None,
    mapping_confidence: float = 0.99,
    authorization_middleware: str | None = None,
) -> AuthorizationAnalysisResult:
    selected_route = route or _route()
    express = ExpressDiscoveryResult(
        routes=[selected_route],
        handler_sources={selected_route.route_id: source},
    )
    index = IndexResult(
        contents={
            "src/routes/projects.ts": source,
            "src/middleware/auth.ts": "request.authUser = user;",
        }
    )
    mapping = RouteModelMapping(
        route_id=selected_route.route_id,
        model="Project",
        operation="read_one",
        confidence=mapping_confidence,
        evidence=["Direct prisma.project.findUnique call"],
        source_file=selected_route.source_file,
    )
    analyzer = AuthorizationAnalyzer(
        context_extractor=HandlerContextExtractor(),
        check_analyzer=AuthorizationCheckAnalyzer(),
        bola_detector=BolaDetector(),
        missing_auth_detector=MissingAuthenticationDetector(),
        risk_scorer=RiskScorer(),
    )
    return analyzer.analyze(
        index,
        express,
        [selected_route],
        _authentication(authorization_middleware),
        _data_model(),
        [mapping],
    )


VULNERABLE_HANDLER = """
async (request, response) => {
  const projectId = request.params.id;
  const project = await prisma.project.findUnique({ where: { id: projectId } });
  response.json({ project });
}
"""


def test_handler_context_extracts_parameter_identity_and_orm_selector() -> None:
    result = _analyze(VULNERABLE_HANDLER)
    context = result.contexts[0]

    assert context.route_parameters == ["id"]
    assert context.authenticated_identity is not None
    assert context.authenticated_identity.expression == "request.authUser.id"
    assert context.model_calls[0].model == "Project"
    assert context.model_calls[0].selector_fields == ["id"]
    assert context.model_calls[0].selector_sources == ["request.params.id"]
    assert context.resource_identifiers[0].used_in_orm_selector
    assert context.resource_identifiers[0].selector_field == "id"


def test_authenticated_object_lookup_without_control_produces_one_finding() -> None:
    result = _analyze(VULNERABLE_HANDLER)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "AUTH-BOLA"
    assert result.graphs[0].decision == "potential_bola"


def test_secure_query_scope_suppresses_bola() -> None:
    result = _analyze(
        """
        async (req, res) => {
          const project = await prisma.project.findFirst({
            where: { id: req.params.id, ownerId: req.user.id }
          });
          res.json({ project });
        }
        """
    )

    assert result.findings == []
    assert result.contexts[0].authorization_controls[0].control_type == (
        "ownership_query_filter"
    )


def test_secure_post_fetch_owner_comparison_suppresses_bola() -> None:
    result = _analyze(
        """
        async (req, res) => {
          const project = await prisma.project.findUnique({ where: { id: req.params.id } });
          if (project.ownerId !== req.user.id) {
            return res.status(403).json({ error: "Forbidden" });
          }
          res.json({ project });
        }
        """
    )

    assert result.findings == []
    context = result.contexts[0]
    assert context.authorization_controls[0].control_type == (
        "ownership_post_fetch_comparison"
    )
    assert context.rejection_status_codes == [403]
    assert context.resource_access_before_authorization is True


def test_secure_membership_query_suppresses_bola() -> None:
    result = _analyze(
        """
        async (req, res) => {
          const project = await prisma.project.findUnique({ where: { id: req.params.id } });
          const membership = await prisma.projectMember.findFirst({
            where: { projectId: req.params.id, userId: req.user.id }
          });
          res.json({ project, membership });
        }
        """
    )

    assert result.findings == []
    assert any(
        control.control_type == "membership_query_filter"
        for control in result.contexts[0].authorization_controls
    )


def test_authorization_middleware_and_role_checks_are_controls() -> None:
    route = _route(middlewares=["requireProjectRole"])
    result = _analyze(
        """
        async (req, res) => {
          const project = await prisma.project.findUnique({ where: { id: req.params.id } });
          if (req.user.role !== "ADMIN") return res.status(403).json({});
          res.json({ project });
        }
        """,
        route=route,
        authorization_middleware="requireProjectRole",
    )

    assert result.findings == []
    assert {control.control_type for control in result.contexts[0].authorization_controls} == {
        "authorization_middleware",
        "role_check",
    }


def test_unrelated_equality_is_not_an_authorization_control() -> None:
    result = _analyze(
        """
        async (req, res) => {
          const project = await prisma.project.findUnique({ where: { id: req.params.id } });
          if (project.status === req.query.status) return res.status(403).json({});
          res.json({ project });
        }
        """
    )

    assert result.contexts[0].authorization_controls == []
    assert len(result.findings) == 1


def test_list_no_identifier_and_weak_mapping_do_not_produce_findings() -> None:
    list_result = _analyze(
        "async (req, res) => prisma.project.findMany({})",
        route=_route("/api/projects"),
    )
    weak_result = _analyze(VULNERABLE_HANDLER, mapping_confidence=0.5)
    non_identifier_result = _analyze(
        """
        async (req, res) => {
          const project = await prisma.project.findUnique({
            where: { status: req.query.status }
          });
          res.json({ project });
        }
        """
    )

    assert list_result.findings == []
    assert weak_result.findings == []
    assert non_identifier_result.findings == []


def test_duplicate_direct_calls_do_not_duplicate_findings() -> None:
    result = _analyze(
        VULNERABLE_HANDLER
        + "\nasync () => prisma.project.findUnique({ where: { id: request.params.id } });"
    )

    assert len(result.findings) == 1


def test_different_routes_receive_different_stable_finding_ids() -> None:
    first = _analyze(VULNERABLE_HANDLER)
    second = _analyze(
        VULNERABLE_HANDLER.replace("params.id", "params.projectId"),
        route=_route("/api/projects/:projectId"),
    )

    assert first.findings[0].finding_id != second.findings[0].finding_id


def test_graph_and_finding_order_are_deterministic() -> None:
    first = _analyze(VULNERABLE_HANDLER)
    second = _analyze(VULNERABLE_HANDLER)

    assert first.graphs == second.graphs
    assert first.findings == second.findings
