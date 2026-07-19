"""Strict public models for deterministic authorization analysis."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MappingOperation = Literal["read_one", "read_many", "create", "update", "delete", "unknown"]
IdentifierSource = Literal["path", "query", "body"]
ControlType = Literal[
    "ownership_query_filter",
    "ownership_post_fetch_comparison",
    "membership_query_filter",
    "membership_post_fetch_check",
    "role_check",
    "authorization_middleware",
    "unknown_custom_control",
]
Severity = Literal["informational", "low", "medium", "high", "critical"]
FindingStatus = Literal["open"]
GraphNodeType = Literal[
    "route",
    "authentication",
    "identity",
    "resource_identifier",
    "orm_operation",
    "model",
    "ownership_candidate",
    "authorization_control",
]
GraphDecision = Literal["potential_bola", "controlled", "not_applicable", "inconclusive"]


class ModelCallSignal(BaseModel):
    """Security-relevant metadata from one direct Prisma handler call."""

    model_config = ConfigDict(frozen=True)

    model: str
    operation: str
    normalized_operation: MappingOperation
    selector_fields: list[str]
    selector_sources: list[str]
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(min_length=1)


class ResourceIdentifier(BaseModel):
    """Client-controlled identifier and its observed selector flow."""

    model_config = ConfigDict(frozen=True)

    parameter_name: str
    parameter_source: IdentifierSource
    expression: str
    used_in_orm_selector: bool
    associated_model: str | None
    selector_field: str | None
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(min_length=1)


class AuthenticatedIdentity(BaseModel):
    """Expression representing the identity established by route authentication."""

    model_config = ConfigDict(frozen=True)

    authentication_middleware: list[str]
    expression: str
    user_model: str | None
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(min_length=1)


class AuthorizationControl(BaseModel):
    """Concrete ownership, membership, role, or middleware control."""

    model_config = ConfigDict(frozen=True)

    control_type: ControlType
    model: str | None
    field: str | None
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(min_length=1)


class HandlerContext(BaseModel):
    """Structured security signals extracted from a single route handler."""

    model_config = ConfigDict(frozen=True)

    route_id: str
    route_parameters: list[str]
    query_parameters: list[str]
    body_fields: list[str]
    authenticated_user_references: list[str]
    authenticated_identity: AuthenticatedIdentity | None
    model_calls: list[ModelCallSignal]
    resource_identifiers: list[ResourceIdentifier]
    authorization_controls: list[AuthorizationControl]
    rejection_status_codes: list[int]
    resource_access_before_authorization: bool | None
    extraction_complete: bool
    warnings: list[str]


class RiskScoreComponent(BaseModel):
    """One explainable contribution to deterministic risk."""

    model_config = ConfigDict(frozen=True)

    name: str
    points: int = Field(ge=0)


class RiskScore(BaseModel):
    """Deterministic risk score separate from confidence."""

    model_config = ConfigDict(frozen=True)

    score: int = Field(ge=0, le=100)
    severity: Severity
    components: list[RiskScoreComponent]


class AuthorizationFinding(BaseModel):
    """Public static authorization finding without payload or source content."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    rule_id: str
    title: str
    category: Literal[
        "authorization",
        "authentication",
        "secrets",
        "cors",
        "jwt",
        "rate_limiting",
        "redirect",
        "filesystem",
        "command_execution",
        "file_upload",
    ]
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    status: FindingStatus
    route_id: str
    method: str | None
    path: str | None
    model: str | None
    operation: MappingOperation
    ownership_candidate: str | None
    source_file: str
    line_number: int = Field(ge=1)
    description: str
    evidence: list[str] = Field(min_length=1)
    recommendation: str
    cwe: list[str]
    owasp: list[str]
    risk_score: int = Field(ge=0, le=100)
    risk_components: list[RiskScoreComponent]


class AuthorizationGraphNode(BaseModel):
    """Stable node in a route authorization graph."""

    model_config = ConfigDict(frozen=True)

    node_id: str
    type: GraphNodeType
    value: str


class AuthorizationGraphEdge(BaseModel):
    """Stable directed relationship between graph nodes."""

    model_config = ConfigDict(frozen=True)

    source: str
    target: str
    relationship: str


class AuthorizationGraph(BaseModel):
    """Explainable authorization path for one discovered route."""

    model_config = ConfigDict(frozen=True)

    route_id: str
    nodes: list[AuthorizationGraphNode]
    edges: list[AuthorizationGraphEdge]
    decision: GraphDecision


class AnalysisSummary(BaseModel):
    """Counts and warnings from deterministic authorization analysis."""

    model_config = ConfigDict(frozen=True)

    routes_analyzed: int = Field(ge=0)
    routes_with_resource_identifiers: int = Field(ge=0)
    routes_with_ownership_controls: int = Field(ge=0)
    potential_bola_count: int = Field(ge=0)
    missing_authentication_count: int = Field(ge=0)
    analysis_warnings: list[str]
