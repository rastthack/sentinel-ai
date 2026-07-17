"""Concrete ownership, membership, role, and middleware control detection."""

import re

from sentinel_api.scanner.analysis.models import AuthorizationControl, HandlerContext
from sentinel_api.scanner.discovery.express_routes import _mask_non_code
from sentinel_api.scanner.discovery.models import (
    AuthenticationDiscovery,
    DiscoveredRoute,
    PrismaDataModel,
)


class AuthorizationCheckAnalyzer:
    """Enrich handler contexts using only deterministic authorization evidence."""

    def analyze(
        self,
        routes: list[DiscoveredRoute],
        contexts: list[HandlerContext],
        handler_sources: dict[str, str],
        data_model: PrismaDataModel,
        authentication: AuthenticationDiscovery,
    ) -> list[HandlerContext]:
        """Return contexts with normalized authorization controls."""
        routes_by_id = {route.route_id: route for route in routes}
        authorization_middleware = {
            item.name for item in authentication.middleware if item.category == "authorization"
        }
        candidates_by_model: dict[str, list[str]] = {}
        for candidate in data_model.ownership_candidates:
            candidates_by_model.setdefault(candidate.model, []).append(candidate.field)

        enriched: list[HandlerContext] = []
        for context in contexts:
            route = routes_by_id[context.route_id]
            source = handler_sources.get(context.route_id, "")
            controls = self._controls(
                route,
                context,
                source,
                candidates_by_model,
                authorization_middleware,
            )
            access_before = self._access_before_authorization(source, controls)
            enriched.append(
                context.model_copy(
                    update={
                        "authorization_controls": controls,
                        "resource_access_before_authorization": access_before,
                    }
                )
            )
        return enriched

    def _controls(
        self,
        route: DiscoveredRoute,
        context: HandlerContext,
        source: str,
        candidates_by_model: dict[str, list[str]],
        authorization_middleware: set[str],
    ) -> list[AuthorizationControl]:
        controls: dict[tuple[str, str | None, str | None], AuthorizationControl] = {}
        identity = (
            context.authenticated_identity.expression
            if context.authenticated_identity
            else None
        )

        for call in context.model_calls:
            for field in candidates_by_model.get(call.model, []):
                if field in call.selector_fields and self._call_field_uses_identity(
                    call.selector_fields,
                    call.selector_sources,
                    field,
                    identity,
                ):
                    self._add(
                        controls,
                        AuthorizationControl(
                            control_type="ownership_query_filter",
                            model=call.model,
                            field=field,
                            confidence=0.98,
                            evidence=[
                                f"ORM selector scopes {call.model} by ownership field {field}"
                            ],
                        ),
                    )

        project_identifier = any(
            identifier.used_in_orm_selector for identifier in context.resource_identifiers
        )
        for call in context.model_calls:
            if call.model.casefold().endswith("member") and identity is not None:
                has_user = self._call_field_uses_identity(
                    call.selector_fields,
                    call.selector_sources,
                    "userId",
                    identity,
                )
                has_resource = "projectId" in call.selector_fields and project_identifier
                if has_user and has_resource:
                    self._add(
                        controls,
                        AuthorizationControl(
                            control_type="membership_query_filter",
                            model=call.model,
                            field="userId",
                            confidence=0.97,
                            evidence=[
                                "Membership lookup combines the resource identifier "
                                "and authenticated user"
                            ],
                        ),
                    )

        masked = _mask_non_code(source)
        if identity is not None:
            for model, fields in candidates_by_model.items():
                for field in fields:
                    if self._has_ownership_comparison(masked, field, identity):
                        self._add(
                            controls,
                            AuthorizationControl(
                                control_type="ownership_post_fetch_comparison",
                                model=model,
                                field=field,
                                confidence=0.97,
                                evidence=[
                                    f"Handler compares fetched {field} with the "
                                    "authenticated identity"
                                ],
                            ),
                        )
            if (
                ".some(" in masked
                and "userid" in masked.casefold()
                and self._contains_identity(masked, identity)
            ):
                self._add(
                    controls,
                    AuthorizationControl(
                        control_type="membership_post_fetch_check",
                        model=None,
                        field="userId",
                        confidence=0.92,
                        evidence=[
                            "Handler checks resource membership against the "
                            "authenticated identity"
                        ],
                    ),
                )

        if 403 in context.rejection_status_codes and re.search(
            r"\b(?:role|permission|policy)\b", masked, re.IGNORECASE
        ):
            self._add(
                controls,
                AuthorizationControl(
                    control_type="role_check",
                    model=None,
                    field=None,
                    confidence=0.9,
                    evidence=["Handler enforces a role or permission and can reject with HTTP 403"],
                ),
            )

        for middleware in route.middlewares:
            if middleware in authorization_middleware:
                self._add(
                    controls,
                    AuthorizationControl(
                        control_type="authorization_middleware",
                        model=None,
                        field=None,
                        confidence=0.95,
                        evidence=[f"Recognized authorization middleware {middleware} applies"],
                    ),
                )
        return sorted(
            controls.values(),
            key=lambda item: (item.control_type, item.model or "", item.field or ""),
        )

    @staticmethod
    def _call_field_uses_identity(
        fields: list[str],
        sources: list[str],
        expected_field: str,
        identity: str | None,
    ) -> bool:
        if identity is None:
            return False
        normalized_identity = identity.replace(" ", "").casefold()
        return any(
            field == expected_field
            and (
                normalized_identity in source.replace(" ", "").casefold()
                or _identity_object_expression(identity) in source.replace(" ", "").casefold()
            )
            for field, source in zip(fields, sources, strict=False)
        )

    @staticmethod
    def _has_ownership_comparison(source: str, field: str, identity: str) -> bool:
        field_expression = rf"[A-Za-z_$][\w$]*\.{re.escape(field)}"
        identity_expression = re.escape(identity)
        operator = r"(?:===|!==|==|!=)"
        return bool(
            re.search(
                rf"(?:{field_expression}\s*{operator}\s*{identity_expression}|"
                rf"{identity_expression}\s*{operator}\s*{field_expression})",
                source,
            )
        )

    @staticmethod
    def _contains_identity(source: str, identity: str) -> bool:
        return identity.replace(" ", "").casefold() in source.replace(" ", "").casefold()

    @staticmethod
    def _add(
        controls: dict[tuple[str, str | None, str | None], AuthorizationControl],
        control: AuthorizationControl,
    ) -> None:
        key = (control.control_type, control.model, control.field)
        controls[key] = control

    @staticmethod
    def _access_before_authorization(
        source: str,
        controls: list[AuthorizationControl],
    ) -> bool | None:
        if not source or not controls:
            return None
        if any(control.control_type.endswith("query_filter") for control in controls):
            return False
        prisma_position = source.casefold().find("prisma.")
        folded = source.casefold()
        rejection_position = min(
            (
                position
                for code in (".status(403)", ".sendstatus(403)")
                if (position := folded.find(code)) >= 0
            ),
            default=-1,
        )
        if prisma_position >= 0 and rejection_position >= 0:
            return prisma_position < rejection_position
        return None


def _identity_object_expression(identity: str) -> str:
    return identity.rsplit(".", maxsplit=1)[0].replace(" ", "").casefold()
