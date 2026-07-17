"""Strict public models and typed internal records for structure discovery."""

from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
AuthenticationRequirement = bool | Literal["unknown"]
MiddlewareCategory = Literal[
    "authentication",
    "authorization",
    "validation",
    "error",
    "unknown",
]
AuthenticationMechanismName = Literal[
    "bearer_token",
    "jwt",
    "session",
    "cookie",
    "api_key",
    "custom_token",
    "unknown_custom",
]
MappingOperation = Literal["read_one", "read_many", "create", "update", "delete", "unknown"]
OwnershipCandidateType = Literal[
    "direct_owner",
    "user_reference",
    "member_reference",
    "account_scope",
    "organization_scope",
    "tenant_scope",
    "workspace_scope",
    "team_scope",
]


class DiscoveredRoute(BaseModel):
    """Normalized Express route with middleware and authentication metadata."""

    model_config = ConfigDict(frozen=True)

    route_id: str
    method: HttpMethod
    path: str
    local_path: str
    mounted_path: str
    source_file: str
    line_number: int = Field(ge=1)
    handler: str
    inline_handler: bool
    middlewares: list[str]
    router_name: str
    authentication_required: AuthenticationRequirement
    authentication_middleware: list[str]
    authentication_mechanism: AuthenticationMechanismName | None
    authentication_evidence: list[str]
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(min_length=1)


class MiddlewareDiscovery(BaseModel):
    """One middleware observed in an Express application."""

    model_config = ConfigDict(frozen=True)

    name: str
    category: MiddlewareCategory
    source_file: str
    line_number: int = Field(ge=1)
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(min_length=1)


class AuthenticationMiddleware(BaseModel):
    """Middleware whose source provides deterministic authentication evidence."""

    model_config = ConfigDict(frozen=True)

    name: str
    source_file: str
    line_number: int = Field(ge=1)
    mechanism: AuthenticationMechanismName
    reads_authentication_data: bool
    resolves_user: bool
    attaches_user: bool
    rejects_unauthenticated: bool
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(min_length=1)


class AuthenticationMechanism(BaseModel):
    """Authentication mechanism summarized across matching middleware."""

    model_config = ConfigDict(frozen=True)

    name: AuthenticationMechanismName
    middleware: list[str]
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(min_length=1)


class AuthenticationDiscovery(BaseModel):
    """Repository authentication components and route coverage counts."""

    model_config = ConfigDict(frozen=True)

    mechanisms: list[AuthenticationMechanism]
    middleware: list[MiddlewareDiscovery]
    authentication_middleware: list[AuthenticationMiddleware]
    protected_route_count: int = Field(ge=0)
    public_route_count: int = Field(ge=0)
    unknown_route_count: int = Field(ge=0)


class PrismaGenerator(BaseModel):
    """Prisma generator block metadata."""

    model_config = ConfigDict(frozen=True)

    name: str
    provider: str | None
    output: str | None


class PrismaField(BaseModel):
    """Supported Prisma field syntax normalized for consumers."""

    model_config = ConfigDict(frozen=True)

    name: str
    type: str
    is_optional: bool
    is_list: bool
    is_primary_key: bool
    is_unique: bool
    is_foreign_key: bool
    is_relation_field: bool
    relation_model: str | None
    is_enum: bool
    default: str | None
    attributes: list[str]


class PrismaModel(BaseModel):
    """One focused Prisma model parse result."""

    model_config = ConfigDict(frozen=True)

    name: str
    source_file: str
    primary_key: list[str]
    unique_fields: list[str]
    fields: list[PrismaField]
    model_attributes: list[str]


class OwnershipCandidate(BaseModel):
    """Possible owner or tenancy field without a security conclusion."""

    model_config = ConfigDict(frozen=True)

    model: str
    field: str
    candidate_type: OwnershipCandidateType
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(min_length=1)


class PrismaDataModel(BaseModel):
    """Focused Prisma datasource, generator, model, and ownership metadata."""

    model_config = ConfigDict(frozen=True)

    provider: str | None
    generators: list[PrismaGenerator]
    models: list[PrismaModel]
    ownership_candidates: list[OwnershipCandidate]


class RouteModelMapping(BaseModel):
    """Evidence-backed association between a route and Prisma operation."""

    model_config = ConfigDict(frozen=True)

    route_id: str
    model: str
    operation: MappingOperation
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(min_length=1)
    source_file: str


@dataclass(frozen=True, slots=True)
class RawRoute:
    """Internal route declaration before mount and auth resolution."""

    router_key: str
    router_name: str
    method: HttpMethod
    local_path: str
    source_file: str
    line_number: int
    handler: str
    handler_source: str
    inline_handler: bool
    direct_middlewares: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MiddlewareUse:
    """Internal router-level middleware registration."""

    router_key: str
    name: str
    source_file: str
    line_number: int


@dataclass(frozen=True, slots=True)
class RouterMount:
    """Internal parent-to-child router mount edge."""

    parent_key: str
    child_key: str
    base_path: str
    source_file: str
    line_number: int
    middlewares: tuple[str, ...] = ()


@dataclass(slots=True)
class ExpressDiscoveryResult:
    """Public routes plus internal handler source needed for model mapping."""

    routes: list[DiscoveredRoute] = field(default_factory=list)
    handler_sources: dict[str, str] = field(default_factory=dict)
    middleware_uses: list[MiddlewareUse] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
