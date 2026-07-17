"""Deterministic extraction of security-relevant Express handler signals."""

import re
from dataclasses import dataclass
from typing import Final

from sentinel_api.scanner.analysis.models import (
    AuthenticatedIdentity,
    HandlerContext,
    IdentifierSource,
    ModelCallSignal,
    ResourceIdentifier,
)
from sentinel_api.scanner.discovery.express_routes import (
    _extract_parenthesized,
    _matching_delimiter,
)
from sentinel_api.scanner.discovery.models import (
    DiscoveredRoute,
    MappingOperation,
    PrismaDataModel,
)
from sentinel_api.scanner.models import IndexResult

_PRISMA_CALL: Final = re.compile(
    r"\bprisma\.([A-Za-z_]\w*)\."
    r"(findUnique|findFirst|findMany|count|create|createMany|upsert|"
    r"update|updateMany|delete|deleteMany)\s*\(",
    re.IGNORECASE,
)
_NORMALIZED_OPERATIONS: Final[dict[str, MappingOperation]] = {
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
_REQUEST_VALUE: Final = re.compile(
    r"\b(?:req|request)\.(params|query|body)\.([A-Za-z_$][\w$]*)"
)
_BRACKET_REQUEST_VALUE: Final = re.compile(
    r"\b(?:req|request)\.(params|query|body)\[['\"]([A-Za-z_$][\w$]*)['\"]]"
)
_IDENTITY_REFERENCE: Final = re.compile(
    r"\b(?:(?:req|request)\.(?:authUser|user|currentUser)|"
    r"res\.locals\.user)\.(?:id|userId)\b"
)
_ALIAS: Final = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)"
)
_OBJECT_FIELD: Final = re.compile(r"\b([A-Za-z_$][\w$]*)\s*:\s*([^,}\n]+)")
_STATUS_CODE: Final = re.compile(r"\.(?:status|sendStatus)\s*\(\s*(401|403)\s*\)")


@dataclass(frozen=True, slots=True)
class _RequestReference:
    source: IdentifierSource
    name: str
    expression: str


class HandlerContextExtractor:
    """Extract bounded structured signals from route-local handler text."""

    def extract(
        self,
        routes: list[DiscoveredRoute],
        handler_sources: dict[str, str],
        index: IndexResult,
        data_model: PrismaDataModel,
    ) -> list[HandlerContext]:
        """Return one deterministic context per discovered route."""
        models = {model.name.casefold(): model.name for model in data_model.models}
        default_identity = self._authenticated_identity_expression(index)
        return [
            self._route_context(
                route,
                handler_sources.get(route.route_id, ""),
                models,
                default_identity,
            )
            for route in routes
        ]

    def _route_context(
        self,
        route: DiscoveredRoute,
        source: str,
        models: dict[str, str],
        default_identity: str | None,
    ) -> HandlerContext:
        aliases = self._aliases(source)
        request_references = self._request_references(source)
        identity_references = sorted(set(_IDENTITY_REFERENCE.findall(source)))
        calls = self._model_calls(source, models, aliases)
        identifiers = self._resource_identifiers(
            route,
            request_references,
            aliases,
            calls,
        )
        identity_expression = identity_references[0] if identity_references else default_identity
        identity = None
        if route.authentication_required is True and identity_expression is not None:
            identity = AuthenticatedIdentity(
                authentication_middleware=route.authentication_middleware,
                expression=identity_expression,
                user_model="User" if "user" in identity_expression.casefold() else None,
                confidence=0.96 if identity_references else 0.88,
                evidence=[
                    "Authenticated identity is attached by recognized middleware"
                ],
            )
        warnings: list[str] = []
        extraction_complete = route.inline_handler and bool(source)
        if not extraction_complete:
            warnings.append(
                "Named or unavailable handler body was not resolved for "
                f"{route.method} {route.path}"
            )
        return HandlerContext(
            route_id=route.route_id,
            route_parameters=sorted(
                segment[1:] for segment in route.path.split("/") if segment.startswith(":")
            ),
            query_parameters=sorted(
                {item.name for item in request_references if item.source == "query"}
            ),
            body_fields=sorted(
                {item.name for item in request_references if item.source == "body"}
            ),
            authenticated_user_references=identity_references,
            authenticated_identity=identity,
            model_calls=calls,
            resource_identifiers=identifiers,
            authorization_controls=[],
            rejection_status_codes=sorted(
                {int(match.group(1)) for match in _STATUS_CODE.finditer(source)}
            ),
            resource_access_before_authorization=None,
            extraction_complete=extraction_complete,
            warnings=warnings,
        )

    @staticmethod
    def _aliases(source: str) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for match in _ALIAS.finditer(source):
            aliases[match.group(1)] = match.group(2).strip()
        return aliases

    @staticmethod
    def _request_references(source: str) -> list[_RequestReference]:
        references: dict[tuple[IdentifierSource, str], _RequestReference] = {}
        for match in _REQUEST_VALUE.finditer(source):
            source_name, name = match.groups()
            parameter_source = _identifier_source(source_name)
            references[(parameter_source, name)] = _RequestReference(
                source=parameter_source,
                name=name,
                expression=match.group(0),
            )
        for match in _BRACKET_REQUEST_VALUE.finditer(source):
            source_name, name = match.groups()
            parameter_source = _identifier_source(source_name)
            references[(parameter_source, name)] = _RequestReference(
                source=parameter_source,
                name=name,
                expression=match.group(0),
            )
        return sorted(references.values(), key=lambda item: (item.source, item.name))

    @staticmethod
    def _model_calls(
        source: str,
        models: dict[str, str],
        aliases: dict[str, str],
    ) -> list[ModelCallSignal]:
        calls: list[ModelCallSignal] = []
        for match in _PRISMA_CALL.finditer(source):
            delegate, operation = match.groups()
            model = models.get(delegate.casefold())
            extracted = _extract_parenthesized(source, match.end() - 1)
            if model is None or extracted is None:
                continue
            arguments, _ = extracted
            where = _named_object(arguments, "where")
            selectors: list[tuple[str, str]] = []
            if where is not None:
                selectors = [
                    (field, _resolve_alias(value.strip(), aliases))
                    for field, value in _OBJECT_FIELD.findall(where)
                ]
            selector_pairs = sorted(set(selectors))
            calls.append(
                ModelCallSignal(
                    model=model,
                    operation=operation,
                    normalized_operation=_NORMALIZED_OPERATIONS[operation.casefold()],
                    selector_fields=[field for field, _ in selector_pairs],
                    selector_sources=[value for _, value in selector_pairs],
                    confidence=0.98,
                    evidence=[f"Handler directly calls prisma.{delegate}.{operation}"],
                )
            )
        return calls

    @staticmethod
    def _resource_identifiers(
        route: DiscoveredRoute,
        references: list[_RequestReference],
        aliases: dict[str, str],
        calls: list[ModelCallSignal],
    ) -> list[ResourceIdentifier]:
        route_parameters = {
            segment[1:] for segment in route.path.split("/") if segment.startswith(":")
        }
        candidates = [
            item
            for item in references
            if item.source != "path" or item.name in route_parameters
        ]
        identifiers: list[ResourceIdentifier] = []
        for reference in candidates:
            matched_model: str | None = None
            matched_field: str | None = None
            for call in calls:
                if any(
                    _same_expression(source, reference.expression, aliases)
                    for source in call.selector_sources
                ):
                    matched_model = call.model
                    matched_field = _selector_field_for_reference(
                        call,
                        reference.expression,
                        aliases,
                    )
                    break
            used = matched_model is not None
            identifiers.append(
                ResourceIdentifier(
                    parameter_name=reference.name,
                    parameter_source=reference.source,
                    expression=reference.expression,
                    used_in_orm_selector=used,
                    associated_model=matched_model,
                    selector_field=matched_field,
                    confidence=0.98 if used else 0.8,
                    evidence=[
                        "Client-controlled request value reaches an ORM selector"
                        if used
                        else "Client-controlled request value is referenced by the handler"
                    ],
                )
            )
        return identifiers

    @staticmethod
    def _authenticated_identity_expression(index: IndexResult) -> str | None:
        assignment = re.compile(
            r"\b((?:req|request)\.(?:authUser|user|currentUser)|"
            r"res\.locals\.user)\s*="
        )
        for path, content in sorted(index.contents.items()):
            if not path.endswith((".js", ".jsx", ".ts", ".tsx")):
                continue
            match = assignment.search(content)
            if match:
                return f"{match.group(1)}.id"
        return None


def _identifier_source(value: str) -> IdentifierSource:
    if value == "params":
        return "path"
    if value == "query":
        return "query"
    return "body"


def _named_object(content: str, name: str) -> str | None:
    match = re.search(rf"\b{re.escape(name)}\s*:\s*\{{", content)
    if match is None:
        return None
    opening = content.find("{", match.start(), match.end())
    closing = _matching_delimiter(content, opening, "{", "}")
    if closing is None:
        return None
    return content[opening + 1 : closing]


def _resolve_alias(expression: str, aliases: dict[str, str]) -> str:
    value = expression.strip()
    visited: set[str] = set()
    while re.fullmatch(r"[A-Za-z_$][\w$]*", value) and value in aliases and value not in visited:
        visited.add(value)
        value = aliases[value].strip()
    return value


def _same_expression(value: str, expected: str, aliases: dict[str, str]) -> bool:
    return _resolve_alias(value, aliases).replace(" ", "") == expected.replace(" ", "")


def _selector_field_for_reference(
    call: ModelCallSignal,
    expression: str,
    aliases: dict[str, str],
) -> str | None:
    for field, source in zip(call.selector_fields, call.selector_sources, strict=False):
        if _same_expression(source, expression, aliases):
            return field
    return call.selector_fields[0] if len(call.selector_fields) == 1 else None
