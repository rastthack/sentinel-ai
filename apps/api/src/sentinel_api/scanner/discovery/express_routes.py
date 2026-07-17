"""Focused static Express route and router-mount discovery."""

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Final, cast

from sentinel_api.scanner.discovery.models import (
    DiscoveredRoute,
    ExpressDiscoveryResult,
    HttpMethod,
    MiddlewareUse,
    RawRoute,
    RouterMount,
)
from sentinel_api.scanner.models import IndexResult

_ROUTE_METHODS: Final = {"get", "post", "put", "patch", "delete"}
_CALL_PATTERN = re.compile(r"\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|use)\s*\(")
_ROUTER_DECLARATION = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:express\.)?Router\s*\("
)
_APP_DECLARATION = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*express\s*\("
)
_EXPORTED_CONST = re.compile(r"\bexport\s+const\s+([A-Za-z_$][\w$]*)\b")
_EXPORTED_FUNCTION = re.compile(
    r"\bexport\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)"
    r"(?:\s*:\s*[^\{]+)?\s*\{"
)


@dataclass(frozen=True, slots=True)
class _RouterDeclaration:
    key: str
    name: str
    source_file: str
    position: int
    is_app: bool


@dataclass(frozen=True, slots=True)
class _FunctionRange:
    name: str
    start: int
    end: int


class ExpressRouteDiscoverer:
    """Build normalized Express routes from statically parsed call expressions."""

    def discover(self, index: IndexResult) -> ExpressDiscoveryResult:
        """Discover route declarations, router mounts, and middleware order."""
        source_contents = {
            path: content
            for path, content in index.contents.items()
            if path.endswith((".js", ".jsx", ".ts", ".tsx"))
        }
        declarations: dict[str, _RouterDeclaration] = {}
        local_symbols: dict[str, dict[str, str]] = defaultdict(dict)
        aliases: dict[str, list[str]] = defaultdict(list)
        app_keys: set[str] = set()

        for source_file, content in sorted(source_contents.items()):
            masked = _mask_non_code(content)
            functions = _function_ranges(content, masked)
            exported_consts = {match.group(1) for match in _EXPORTED_CONST.finditer(masked)}
            for pattern, is_app in ((_ROUTER_DECLARATION, False), (_APP_DECLARATION, True)):
                for match in pattern.finditer(masked):
                    name = match.group(1)
                    key = f"{source_file}::{name}"
                    declaration = _RouterDeclaration(
                        key=key,
                        name=name,
                        source_file=source_file,
                        position=match.start(),
                        is_app=is_app,
                    )
                    declarations[key] = declaration
                    local_symbols[source_file][name] = key
                    if is_app:
                        app_keys.add(key)
                    if name in exported_consts:
                        aliases[name].append(key)
                    for function in functions:
                        if function.start <= match.start() <= function.end:
                            aliases[function.name].append(key)

        raw_routes: list[RawRoute] = []
        middleware_uses: list[MiddlewareUse] = []
        mounts: list[RouterMount] = []
        warnings: list[str] = []
        for source_file, content in sorted(source_contents.items()):
            masked = _mask_non_code(content)
            for match in _CALL_PATTERN.finditer(masked):
                variable, method = match.group(1), match.group(2)
                parent_key = local_symbols[source_file].get(variable)
                if parent_key is None:
                    continue
                open_index = match.end() - 1
                extracted = _extract_parenthesized(content, open_index)
                if extracted is None:
                    warnings.append(
                        "Unsupported Express call syntax at "
                        f"{source_file}:{_line_number(content, match.start())}"
                    )
                    continue
                argument_text, _ = extracted
                arguments = _split_arguments(argument_text)
                line_number = _line_number(content, match.start())
                if method in _ROUTE_METHODS:
                    route = self._parse_route(
                        parent_key,
                        variable,
                        method,
                        arguments,
                        source_file,
                        line_number,
                    )
                    if route is None:
                        warnings.append(
                            "Express route with a non-literal path was skipped at "
                            f"{source_file}:{line_number}"
                        )
                    else:
                        raw_routes.append(route)
                else:
                    mount = self._parse_use(
                        parent_key,
                        arguments,
                        source_file,
                        line_number,
                        local_symbols,
                        aliases,
                    )
                    if mount is not None:
                        mounts.append(mount)
                    else:
                        start = 1 if arguments and _string_literal(arguments[0]) is not None else 0
                        for argument in arguments[start:]:
                            name = _callable_name(argument)
                            if name:
                                middleware_uses.append(
                                    MiddlewareUse(
                                        router_key=parent_key,
                                        name=name,
                                        source_file=source_file,
                                        line_number=line_number,
                                    )
                                )

        return self._resolve_routes(
            raw_routes,
            middleware_uses,
            mounts,
            app_keys,
            warnings,
        )

    @staticmethod
    def _parse_route(
        router_key: str,
        router_name: str,
        method: str,
        arguments: list[str],
        source_file: str,
        line_number: int,
    ) -> RawRoute | None:
        if len(arguments) < 2:
            return None
        local_path = _string_literal(arguments[0])
        if local_path is None:
            return None
        handler_source = arguments[-1].strip()
        inline_handler = _is_inline_handler(handler_source)
        handler = "anonymous" if inline_handler else (_callable_name(handler_source) or "unknown")
        middlewares = tuple(
            name
            for argument in arguments[1:-1]
            if (name := _callable_name(argument)) is not None
        )
        return RawRoute(
            router_key=router_key,
            router_name=router_name,
            method=cast(HttpMethod, method.upper()),
            local_path=normalize_route_path(local_path),
            source_file=source_file,
            line_number=line_number,
            handler=handler,
            handler_source=handler_source,
            inline_handler=inline_handler,
            direct_middlewares=middlewares,
        )

    @staticmethod
    def _parse_use(
        parent_key: str,
        arguments: list[str],
        source_file: str,
        line_number: int,
        local_symbols: dict[str, dict[str, str]],
        aliases: dict[str, list[str]],
    ) -> RouterMount | None:
        if not arguments:
            return None
        literal_path = _string_literal(arguments[0])
        base_path = literal_path or "/"
        start = 1 if literal_path is not None else 0
        candidates = arguments[start:]
        child_index: int | None = None
        child_key: str | None = None
        for index in range(len(candidates) - 1, -1, -1):
            symbol = _callable_name(candidates[index])
            if symbol is None:
                continue
            local_key = local_symbols[source_file].get(symbol)
            alias_keys = aliases.get(symbol, [])
            resolved = local_key or (alias_keys[0] if len(alias_keys) == 1 else None)
            if resolved is not None:
                child_index = index
                child_key = resolved
                break
        if child_key is None or child_index is None:
            return None
        middleware = tuple(
            name
            for argument in candidates[:child_index]
            if (name := _callable_name(argument)) is not None
        )
        return RouterMount(
            parent_key=parent_key,
            child_key=child_key,
            base_path=normalize_route_path(base_path),
            source_file=source_file,
            line_number=line_number,
            middlewares=middleware,
        )

    @staticmethod
    def _resolve_routes(
        raw_routes: list[RawRoute],
        middleware_uses: list[MiddlewareUse],
        mounts: list[RouterMount],
        app_keys: set[str],
        warnings: list[str],
    ) -> ExpressDiscoveryResult:
        routes_by_router: dict[str, list[RawRoute]] = defaultdict(list)
        middleware_by_router: dict[str, list[MiddlewareUse]] = defaultdict(list)
        mounts_by_parent: dict[str, list[RouterMount]] = defaultdict(list)
        for route in raw_routes:
            routes_by_router[route.router_key].append(route)
        for middleware in middleware_uses:
            middleware_by_router[middleware.router_key].append(middleware)
        for mount in mounts:
            mounts_by_parent[mount.parent_key].append(mount)

        contexts: dict[str, list[tuple[str, tuple[str, ...], tuple[str, ...]]]] = defaultdict(list)

        def visit(
            router_key: str,
            base_path: str,
            inherited: tuple[str, ...],
            mount_evidence: tuple[str, ...],
            visited: frozenset[str],
        ) -> None:
            if router_key in visited:
                warnings.append("A cyclic Express router mount was skipped")
                return
            contexts[router_key].append((base_path, inherited, mount_evidence))
            next_visited = visited | {router_key}
            for mount in sorted(
                mounts_by_parent[router_key], key=lambda item: (item.line_number, item.child_key)
            ):
                prior = tuple(
                    item.name
                    for item in sorted(
                        middleware_by_router[router_key], key=lambda item: item.line_number
                    )
                    if item.line_number < mount.line_number
                )
                child_base = join_route_paths(base_path, mount.base_path)
                evidence = (
                    *mount_evidence,
                    f"{mount.source_file}:{mount.line_number} mounts router at {mount.base_path}",
                )
                visit(
                    mount.child_key,
                    child_base,
                    inherited + prior + mount.middlewares,
                    evidence,
                    next_visited,
                )

        for app_key in sorted(app_keys):
            visit(app_key, "/", (), (), frozenset())
        for router_key in sorted(routes_by_router):
            if router_key not in contexts:
                contexts[router_key].append(("/", (), ()))

        discovered: dict[str, DiscoveredRoute] = {}
        handler_sources: dict[str, str] = {}
        for router_key, router_routes in sorted(routes_by_router.items()):
            for base_path, inherited, mount_evidence in contexts[router_key]:
                for route in sorted(router_routes, key=lambda item: item.line_number):
                    local_middlewares = tuple(
                        item.name
                        for item in sorted(
                            middleware_by_router[router_key], key=lambda item: item.line_number
                        )
                        if item.line_number < route.line_number
                    )
                    final_path = join_route_paths(base_path, route.local_path)
                    route_id = f"route:{route.method}:{final_path}"
                    evidence = [
                        f"{route.source_file}:{route.line_number} declares "
                        f"{route.router_name}.{route.method.casefold()} "
                        f"at {route.local_path}"
                    ]
                    evidence.extend(mount_evidence)
                    candidate = DiscoveredRoute(
                        route_id=route_id,
                        method=route.method,
                        path=final_path,
                        local_path=route.local_path,
                        mounted_path=normalize_route_path(base_path),
                        source_file=route.source_file,
                        line_number=route.line_number,
                        handler=route.handler,
                        inline_handler=route.inline_handler,
                        middlewares=list(inherited + local_middlewares + route.direct_middlewares),
                        router_name=route.router_name,
                        authentication_required="unknown",
                        authentication_middleware=[],
                        authentication_mechanism=None,
                        authentication_evidence=[],
                        confidence=0.98 if mount_evidence or base_path == "/" else 0.9,
                        evidence=evidence,
                    )
                    existing = discovered.get(route_id)
                    if existing is None or candidate.confidence > existing.confidence:
                        discovered[route_id] = candidate
                        handler_sources[route_id] = route.handler_source
        return ExpressDiscoveryResult(
            routes=sorted(
                discovered.values(),
                key=lambda item: (item.path, item.method, item.source_file, item.line_number),
            ),
            handler_sources=handler_sources,
            middleware_uses=middleware_uses,
            warnings=warnings,
        )


def normalize_route_path(path: str) -> str:
    """Normalize an Express route while preserving parameter segments."""
    without_query = path.split("?", maxsplit=1)[0].strip()
    segments = [segment for segment in without_query.split("/") if segment]
    normalized = "/" + "/".join(segments)
    return normalized if normalized != "" else "/"


def join_route_paths(base_path: str, local_path: str) -> str:
    """Join normalized mount and local route paths."""
    if normalize_route_path(local_path) == "/":
        return normalize_route_path(base_path)
    if normalize_route_path(base_path) == "/":
        return normalize_route_path(local_path)
    return normalize_route_path(f"{base_path}/{local_path}")


def _mask_non_code(content: str) -> str:
    characters = list(content)
    index = 0
    state = "code"
    quote = ""
    while index < len(characters):
        current = characters[index]
        following = characters[index + 1] if index + 1 < len(characters) else ""
        if state == "code":
            if current in {'"', "'", "`"}:
                state, quote = "string", current
                characters[index] = " "
            elif current == "/" and following == "/":
                state = "line_comment"
                characters[index] = characters[index + 1] = " "
                index += 1
            elif current == "/" and following == "*":
                state = "block_comment"
                characters[index] = characters[index + 1] = " "
                index += 1
        elif state == "string":
            if current == "\\":
                characters[index] = " "
                if index + 1 < len(characters):
                    characters[index + 1] = " "
                    index += 1
            elif current == quote:
                characters[index] = " "
                state = "code"
            elif current != "\n":
                characters[index] = " "
        elif state == "line_comment":
            if current == "\n":
                state = "code"
            else:
                characters[index] = " "
        elif state == "block_comment":
            if current == "*" and following == "/":
                characters[index] = characters[index + 1] = " "
                index += 1
                state = "code"
            elif current != "\n":
                characters[index] = " "
        index += 1
    return "".join(characters)


def _function_ranges(content: str, masked: str) -> list[_FunctionRange]:
    ranges: list[_FunctionRange] = []
    for match in _EXPORTED_FUNCTION.finditer(masked):
        brace_index = masked.find("{", match.start(), match.end())
        end = _matching_delimiter(content, brace_index, "{", "}")
        if end is not None:
            ranges.append(_FunctionRange(name=match.group(1), start=brace_index, end=end))
    return ranges


def _extract_parenthesized(content: str, opening_index: int) -> tuple[str, int] | None:
    closing = _matching_delimiter(content, opening_index, "(", ")")
    if closing is None:
        return None
    return content[opening_index + 1 : closing], closing


def _matching_delimiter(
    content: str,
    opening_index: int,
    opening: str,
    closing: str,
) -> int | None:
    depth = 0
    index = opening_index
    state = "code"
    quote = ""
    while index < len(content):
        current = content[index]
        following = content[index + 1] if index + 1 < len(content) else ""
        if state == "code":
            if current in {'"', "'", "`"}:
                state, quote = "string", current
            elif current == "/" and following == "/":
                state = "line_comment"
                index += 1
            elif current == "/" and following == "*":
                state = "block_comment"
                index += 1
            elif current == opening:
                depth += 1
            elif current == closing:
                depth -= 1
                if depth == 0:
                    return index
        elif state == "string":
            if current == "\\":
                index += 1
            elif current == quote:
                state = "code"
        elif state == "line_comment" and current == "\n":
            state = "code"
        elif state == "block_comment" and current == "*" and following == "/":
            state = "code"
            index += 1
        index += 1
    return None


def _split_arguments(arguments: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0}
    pairs = {")": "(", "]": "[", "}": "{"}
    state = "code"
    quote = ""
    index = 0
    while index < len(arguments):
        current = arguments[index]
        following = arguments[index + 1] if index + 1 < len(arguments) else ""
        if state == "code":
            if current in {'"', "'", "`"}:
                state, quote = "string", current
            elif current == "/" and following == "/":
                state = "line_comment"
                index += 1
            elif current == "/" and following == "*":
                state = "block_comment"
                index += 1
            elif current in depths:
                depths[current] += 1
            elif current in pairs:
                depths[pairs[current]] -= 1
            elif current == "," and all(depth == 0 for depth in depths.values()):
                parts.append(arguments[start:index].strip())
                start = index + 1
        elif state == "string":
            if current == "\\":
                index += 1
            elif current == quote:
                state = "code"
        elif state == "line_comment" and current == "\n":
            state = "code"
        elif state == "block_comment" and current == "*" and following == "/":
            state = "code"
            index += 1
        index += 1
    final = arguments[start:].strip()
    if final:
        parts.append(final)
    return parts


def _string_literal(argument: str) -> str | None:
    stripped = argument.strip()
    if len(stripped) >= 2 and stripped[0] in {'"', "'", "`"} and stripped[-1] == stripped[0]:
        value = stripped[1:-1]
        return None if "${" in value else value
    return None


def _callable_name(argument: str) -> str | None:
    stripped = argument.strip()
    match = re.match(r"^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)", stripped)
    return match.group(1) if match else None


def _is_inline_handler(argument: str) -> bool:
    stripped = argument.strip()
    return "=>" in stripped or stripped.startswith(("function", "async function", "async ("))


def _line_number(content: str, position: int) -> int:
    return content.count("\n", 0, position) + 1
