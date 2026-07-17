"""Provider abstraction and graceful AI explanation orchestration."""

from typing import Literal, Protocol

from openai import OpenAI, OpenAIError

from sentinel_api.scanner.ai.cache import ExplanationCache
from sentinel_api.scanner.ai.explanation import (
    AIAnalysis,
    AIError,
    AIFindingResult,
)
from sentinel_api.scanner.ai.formatter import AIModelOutput
from sentinel_api.scanner.ai.prompts import PromptRequest, build_prompt
from sentinel_api.scanner.analysis.models import (
    AuthorizationFinding,
    AuthorizationGraph,
)
from sentinel_api.scanner.discovery.models import DiscoveredRoute


class AIProviderError(Exception):
    """Safe provider error without upstream response or credential details."""


class AIProvider(Protocol):
    """Provider-neutral structured generation contract."""

    @property
    def name(self) -> str:
        """Return a stable provider name."""
        ...

    @property
    def model(self) -> str:
        """Return the configured model identifier."""
        ...

    def generate(self, prompt: PromptRequest) -> AIModelOutput:
        """Generate one validated structured explanation."""
        ...


class OpenAIProvider:
    """OpenAI GPT-5.6 structured-output provider."""

    def __init__(
        self,
        api_key: str,
        model: str,
        timeout_seconds: float,
        max_retries: int,
    ) -> None:
        self._model = model
        self._client = OpenAI(
            api_key=api_key,
            timeout=timeout_seconds,
            max_retries=max_retries,
        )

    @property
    def name(self) -> str:
        return "openai"

    @property
    def model(self) -> str:
        return self._model

    def generate(self, prompt: PromptRequest) -> AIModelOutput:
        """Call GPT with no tools and parse its strict Pydantic response."""
        try:
            completion = self._client.chat.completions.parse(
                model=self._model,
                messages=[
                    {"role": "system", "content": prompt.system},
                    {"role": "user", "content": prompt.user},
                ],
                response_format=AIModelOutput,
                reasoning_effort="none",
                temperature=0.0,
                max_completion_tokens=1_800,
            )
            message = completion.choices[0].message
            if message.refusal:
                raise AIProviderError("The model declined the structured explanation request")
            if message.parsed is None:
                raise AIProviderError("The model returned no structured explanation")
            return message.parsed
        except AIProviderError:
            raise
        except (OpenAIError, ValueError, IndexError) as error:
            raise AIProviderError("The OpenAI explanation request failed safely") from error


class AIExplanationEngine:
    """Enrich existing findings without changing or creating findings."""

    def __init__(
        self,
        provider: AIProvider | None,
        cache: ExplanationCache,
        configured_model: str,
    ) -> None:
        self.provider = provider
        self.cache = cache
        self.configured_model = configured_model

    def explain(
        self,
        findings: list[AuthorizationFinding],
        routes: list[DiscoveredRoute],
        graphs: list[AuthorizationGraph],
        *,
        enabled: bool,
    ) -> AIAnalysis:
        """Return cached/generated enrichment or a sanitized graceful state."""
        if not enabled:
            return AIAnalysis(
                status="disabled",
                provider=self.provider.name if self.provider else None,
                model=self.configured_model,
                results=[],
                errors=[],
            )
        if self.provider is None:
            return AIAnalysis(
                status="unavailable",
                provider="openai",
                model=self.configured_model,
                results=[],
                errors=[
                    AIError(
                        finding_id=None,
                        code="provider_unavailable",
                        message=(
                            "AI explanation is unavailable; deterministic scan results "
                            "remain valid."
                        ),
                    )
                ],
            )

        routes_by_id = {route.route_id: route for route in routes}
        graphs_by_id = {graph.route_id: graph for graph in graphs}
        results: list[AIFindingResult] = []
        errors: list[AIError] = []
        for finding in findings:
            route = routes_by_id.get(finding.route_id)
            graph = graphs_by_id.get(finding.route_id)
            if route is None or graph is None:
                errors.append(
                    AIError(
                        finding_id=finding.finding_id,
                        code="context_unavailable",
                        message=(
                            "Structured finding context is incomplete; AI explanation was skipped."
                        ),
                    )
                )
                continue
            prompt = build_prompt(finding, route, graph, self.provider.model)
            try:
                output = self.cache.get(finding.finding_id, prompt.prompt_hash)
                cached = output is not None
            except OSError:
                output = None
                cached = False
                errors.append(_cache_error(finding.finding_id, "cache_read_failed"))
            try:
                if output is None:
                    output = self.provider.generate(prompt)
                    if output.patch.source_file != finding.source_file:
                        raise ValueError("AI patch targeted an unexpected source file")
                    try:
                        self.cache.set(finding.finding_id, prompt.prompt_hash, output)
                    except OSError:
                        errors.append(_cache_error(finding.finding_id, "cache_write_failed"))
                results.append(
                    AIFindingResult(
                        finding_id=finding.finding_id,
                        explanation=output.explanation,
                        root_cause=output.root_cause,
                        remediation=output.remediation,
                        patch=output.patch,
                        verification=output.verification,
                        cached=cached,
                    )
                )
            except (AIProviderError, ValueError):
                errors.append(
                    AIError(
                        finding_id=finding.finding_id,
                        code="explanation_failed",
                        message=(
                            "AI explanation failed safely; the deterministic finding is unchanged."
                        ),
                    )
                )
        status: Literal["complete", "partial", "unavailable"]
        status = "complete" if not errors else "partial" if results else "unavailable"
        return AIAnalysis(
            status=status,
            provider=self.provider.name,
            model=self.provider.model,
            results=sorted(results, key=lambda item: item.finding_id),
            errors=sorted(errors, key=lambda item: item.finding_id or ""),
        )


def _cache_error(finding_id: str, code: str) -> AIError:
    """Return a safe cache warning without filesystem details."""
    return AIError(
        finding_id=finding_id,
        code=code,
        message="AI cache was unavailable; deterministic findings and AI output remain available.",
    )
