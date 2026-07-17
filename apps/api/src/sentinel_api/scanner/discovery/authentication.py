"""Evidence-based authentication and middleware classification."""

import re
from collections import defaultdict
from dataclasses import dataclass

from sentinel_api.scanner.discovery.express_routes import (
    _line_number,
    _mask_non_code,
    _matching_delimiter,
)
from sentinel_api.scanner.discovery.models import (
    AuthenticationDiscovery,
    AuthenticationMechanism,
    AuthenticationMechanismName,
    AuthenticationMiddleware,
    DiscoveredRoute,
    ExpressDiscoveryResult,
    MiddlewareCategory,
    MiddlewareDiscovery,
)
from sentinel_api.scanner.models import IndexResult

_FUNCTION_PATTERN = re.compile(
    r"\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)"
    r"(?:\s*:\s*[^\{]+)?\s*\{"
)
_CONST_FUNCTION_PATTERN = re.compile(
    r"\b(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*"
    r"(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*"
    r"(?:(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*)?\{"
)
_KNOWN_NON_AUTH = frozenset({"express.json", "express.urlencoded", "helmet"})


@dataclass(frozen=True, slots=True)
class _FunctionSource:
    name: str
    source_file: str
    line_number: int
    body: str


class AuthenticationDiscoverer:
    """Classify authentication only from concrete source behavior."""

    def discover(
        self,
        index: IndexResult,
        express: ExpressDiscoveryResult,
    ) -> tuple[list[DiscoveredRoute], AuthenticationDiscovery]:
        """Return routes with auth metadata and an application auth summary."""
        functions = self._functions(index)
        auth_components = [
            component
            for function in functions.values()
            if (component := self._authentication_component(function)) is not None
        ]
        auth_by_name = {component.name: component for component in auth_components}
        middleware = self._middleware_components(express, functions, auth_by_name)

        classified_routes = [self._classify_route(route, auth_by_name) for route in express.routes]
        mechanisms = self._mechanisms(auth_components)
        return classified_routes, AuthenticationDiscovery(
            mechanisms=mechanisms,
            middleware=middleware,
            authentication_middleware=sorted(
                auth_components, key=lambda item: (item.name, item.source_file)
            ),
            protected_route_count=sum(
                route.authentication_required is True for route in classified_routes
            ),
            public_route_count=sum(
                route.authentication_required is False for route in classified_routes
            ),
            unknown_route_count=sum(
                route.authentication_required == "unknown" for route in classified_routes
            ),
        )

    @staticmethod
    def _functions(index: IndexResult) -> dict[str, _FunctionSource]:
        functions: dict[str, _FunctionSource] = {}
        for source_file, content in sorted(index.contents.items()):
            if not source_file.endswith((".js", ".jsx", ".ts", ".tsx")):
                continue
            masked = _mask_non_code(content)
            for pattern in (_FUNCTION_PATTERN, _CONST_FUNCTION_PATTERN):
                for match in pattern.finditer(masked):
                    brace_index = masked.find("{", match.start(), match.end())
                    closing = _matching_delimiter(content, brace_index, "{", "}")
                    if closing is None:
                        continue
                    name = match.group(1)
                    functions.setdefault(
                        name,
                        _FunctionSource(
                            name=name,
                            source_file=source_file,
                            line_number=_line_number(content, match.start()),
                            body=content[brace_index + 1 : closing],
                        ),
                    )
        return functions

    @staticmethod
    def _authentication_component(
        function: _FunctionSource,
    ) -> AuthenticationMiddleware | None:
        body = function.body
        folded = body.casefold()
        reads_authorization = (
            ".header(\"authorization\")" in folded
            or ".header('authorization')" in folded
            or "headers.authorization" in folded
            or "headers[\"authorization\"]" in folded
            or "headers['authorization']" in folded
        )
        reads_cookie = ".cookies" in folded or ".cookie(" in folded
        reads_session = ".session" in folded
        reads_api_key = "x-api-key" in folded or "api_key" in folded or "apikey" in folded
        reads_authentication = reads_authorization or reads_cookie or reads_session or reads_api_key
        bearer = reads_authorization and "bearer" in folded
        jwt = "jwt.verify" in folded or "jsonwebtoken" in folded or "verifytoken" in folded
        resolves_user = bool(
            re.search(r"\b(?:prisma\.)?user\.(?:findunique|findfirst|findone)\s*\(", folded)
            or re.search(r"\b(?:get|find|load|resolve)user\s*\(", folded)
        )
        attaches_user = bool(
            re.search(r"\b(?:request|req)\.(?:authuser|user|currentuser)\s*=", folded)
        )
        rejects = bool(
            re.search(r"\.(?:status|sendstatus)\s*\(\s*401\s*\)", folded)
            or "unauthorized" in folded
        )
        custom_token = "token" in folded and resolves_user
        if not reads_authentication or not (rejects or resolves_user or attaches_user):
            return None

        mechanism: AuthenticationMechanismName
        if jwt:
            mechanism = "jwt"
        elif bearer:
            mechanism = "bearer_token"
        elif reads_session:
            mechanism = "session"
        elif reads_cookie:
            mechanism = "cookie"
        elif reads_api_key:
            mechanism = "api_key"
        elif custom_token:
            mechanism = "custom_token"
        else:
            mechanism = "unknown_custom"

        evidence: list[str] = []
        if reads_authorization:
            evidence.append("Reads the Authorization request header")
        elif reads_session:
            evidence.append("Reads authentication data from the request session")
        elif reads_cookie:
            evidence.append("Reads authentication data from request cookies")
        elif reads_api_key:
            evidence.append("Reads an API key from the request")
        if bearer:
            evidence.append("Requires a Bearer token scheme")
        if jwt:
            evidence.append("Verifies a JWT token")
        if resolves_user:
            evidence.append("Resolves a user from authentication data")
        if attaches_user:
            evidence.append("Attaches authenticated user information to the request")
        if rejects:
            evidence.append("Returns HTTP 401 when authentication fails")
        confidence = min(0.99, 0.72 + 0.06 * len(evidence))
        return AuthenticationMiddleware(
            name=function.name,
            source_file=function.source_file,
            line_number=function.line_number,
            mechanism=mechanism,
            reads_authentication_data=reads_authentication,
            resolves_user=resolves_user,
            attaches_user=attaches_user,
            rejects_unauthenticated=rejects,
            confidence=round(confidence, 2),
            evidence=evidence,
        )

    @staticmethod
    def _middleware_components(
        express: ExpressDiscoveryResult,
        functions: dict[str, _FunctionSource],
        auth_by_name: dict[str, AuthenticationMiddleware],
    ) -> list[MiddlewareDiscovery]:
        applications: dict[str, tuple[str, int]] = {}
        for use in express.middleware_uses:
            applications.setdefault(use.name, (use.source_file, use.line_number))
        for route in express.routes:
            for name in route.middlewares:
                applications.setdefault(name, (route.source_file, route.line_number))

        discovered: list[MiddlewareDiscovery] = []
        for name, (fallback_file, fallback_line) in sorted(applications.items()):
            function = functions.get(name)
            category: MiddlewareCategory = "unknown"
            evidence = ["Applied through an Express middleware registration"]
            confidence = 0.65
            if name in auth_by_name:
                category = "authentication"
                evidence = list(auth_by_name[name].evidence)
                confidence = auth_by_name[name].confidence
            elif function is not None:
                folded = function.body.casefold()
                if "errorrequesthandler" in folded or re.search(
                    r"\.(?:status|sendstatus)\s*\(\s*5\d\d\s*\)", folded
                ):
                    category, confidence = "error", 0.85
                    evidence.append("Middleware source handles server error responses")
                elif "safeparse" in folded or re.search(
                    r"\.(?:status|sendstatus)\s*\(\s*(?:400|422)\s*\)", folded
                ):
                    category, confidence = "validation", 0.8
                    evidence.append(
                        "Middleware source validates input and rejects invalid requests"
                    )
                elif re.search(r"\.(?:status|sendstatus)\s*\(\s*403\s*\)", folded) and any(
                    marker in folded for marker in ("permission", "role", "policy")
                ):
                    category, confidence = "authorization", 0.88
                    evidence.append("Middleware enforces permissions and returns HTTP 403")
            source_file = function.source_file if function else fallback_file
            line_number = function.line_number if function else fallback_line
            discovered.append(
                MiddlewareDiscovery(
                    name=name,
                    category=category,
                    source_file=source_file,
                    line_number=line_number,
                    confidence=confidence,
                    evidence=evidence,
                )
            )
        return discovered

    @staticmethod
    def _classify_route(
        route: DiscoveredRoute,
        auth_by_name: dict[str, AuthenticationMiddleware],
    ) -> DiscoveredRoute:
        middleware_names = list(dict.fromkeys(route.middlewares))
        matched = [auth_by_name[name] for name in middleware_names if name in auth_by_name]
        if matched:
            mechanisms = sorted({component.mechanism for component in matched})
            evidence = [
                f"Authentication middleware {component.name} applies to this route"
                for component in matched
            ]
            return route.model_copy(
                update={
                    "middlewares": middleware_names,
                    "authentication_required": True,
                    "authentication_middleware": [component.name for component in matched],
                    "authentication_mechanism": mechanisms[0],
                    "authentication_evidence": evidence,
                }
            )
        unknown = [name for name in middleware_names if name not in _KNOWN_NON_AUTH]
        if unknown:
            return route.model_copy(
                update={
                    "middlewares": middleware_names,
                    "authentication_required": "unknown",
                    "authentication_evidence": [
                        "Applied custom middleware lacks deterministic authentication evidence"
                    ],
                }
            )
        return route.model_copy(
            update={
                "middlewares": middleware_names,
                "authentication_required": False,
                "authentication_evidence": [
                    "No recognized authentication middleware applies before this route"
                ],
            }
        )

    @staticmethod
    def _mechanisms(
        components: list[AuthenticationMiddleware],
    ) -> list[AuthenticationMechanism]:
        grouped: dict[
            AuthenticationMechanismName, list[AuthenticationMiddleware]
        ] = defaultdict(list)
        for component in components:
            grouped[component.mechanism].append(component)
        return [
            AuthenticationMechanism(
                name=mechanism,
                middleware=sorted(component.name for component in matching),
                confidence=max(component.confidence for component in matching),
                evidence=sorted(
                    {
                        evidence
                        for component in matching
                        for evidence in component.evidence
                    }
                ),
            )
            for mechanism, matching in sorted(grouped.items())
        ]
