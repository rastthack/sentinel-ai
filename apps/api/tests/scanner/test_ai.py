"""Offline coverage for optional AI explanations and their safety boundary."""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from sentinel_api.scanner.ai.cache import FileExplanationCache, MemoryExplanationCache
from sentinel_api.scanner.ai.client import AIExplanationEngine, AIProviderError
from sentinel_api.scanner.ai.formatter import AIModelOutput
from sentinel_api.scanner.ai.prompts import build_prompt
from sentinel_api.scanner.analysis.models import AuthorizationFinding, AuthorizationGraph
from sentinel_api.scanner.discovery.models import DiscoveredRoute
from sentinel_api.scanner.service import build_scan_service

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


def valid_output(source_file: str = "src/routes/projects.ts") -> AIModelOutput:
    return AIModelOutput.model_validate(
        {
            "explanation": {
                "summary": (
                    "The project lookup accepts an identifier without an ownership condition."
                ),
                "technical_explanation": (
                    "The query selects a project by id after authentication but does not "
                    "scope it to the authenticated user."
                ),
                "business_impact": "A signed-in user can read another customer's project data.",
                "why_detected": (
                    "The deterministic finding records an identifier lookup and missing "
                    "ownership condition."
                ),
                "confidence_reasoning": "The route and data access evidence are both present.",
                "false_positive_notes": (
                    "Review custom Prisma middleware before applying the proposed change."
                ),
            },
            "root_cause": (
                "The project query is not constrained by the authenticated owner identifier."
            ),
            "remediation": {
                "priority": "high",
                "strategy": "ownership_filter",
                "steps": ["Add the owner identifier to the project lookup filter."],
            },
            "patch": {
                "language": "typescript",
                "source_file": source_file,
                "diff": (
                    f"--- a/{source_file}\n+++ b/{source_file}\n@@ -20,3 +20,6 @@\n"
                    "-      where: { id: request.params.id },\n+"
                    "+      where: {\n+"
                    "+        id: request.params.id,\n+"
                    "+        ownerId: request.authUser.id,\n+"
                    "+      },"
                ),
                "review_required": True,
                "safety_notes": ["Review the patch before applying it to any repository."],
            },
            "verification": {
                "items": [
                    {
                        "check": "Confirm a user cannot read another user's project.",
                        "required": True,
                    }
                ]
            },
        }
    )


class FakeProvider:
    name = "fake"
    model = "configured-test-model"

    def __init__(self, output: AIModelOutput | None = None, fail: bool = False) -> None:
        self.output = output or valid_output()
        self.fail = fail
        self.calls = 0

    def generate(self, _prompt: object) -> AIModelOutput:
        self.calls += 1
        if self.fail:
            raise AIProviderError("offline test failure")
        return self.output


class FailingCache:
    def get(self, _finding_id: str, _prompt_hash: str) -> None:
        raise OSError("offline cache unavailable")

    def set(self, _finding_id: str, _prompt_hash: str, _output: AIModelOutput) -> None:
        raise OSError("offline cache unavailable")


def _context() -> tuple[AuthorizationFinding, list[DiscoveredRoute], list[AuthorizationGraph]]:
    response = build_scan_service(REPOSITORY_ROOT, ai_enabled=False).scan(
        "demo/vulnerable-taskflow"
    )
    return response.findings[0], response.routes, response.authorization_graphs


def test_prompt_is_deterministic_and_excludes_source_and_absolute_path() -> None:
    finding, routes, graphs = _context()
    route = next(item for item in routes if item.route_id == finding.route_id)
    graph = next(item for item in graphs if item.route_id == finding.route_id)
    first = build_prompt(finding, route, graph, "any-configured-model")
    second = build_prompt(finding, route, graph, "any-configured-model")

    assert first.prompt_hash == second.prompt_hash
    assert finding.finding_id in first.user
    assert str(REPOSITORY_ROOT) not in first.user
    assert "INTENTIONALLY VULNERABLE" not in first.user
    assert "user-a-demo-token" not in first.user


def test_engine_caches_validated_output_without_changing_finding() -> None:
    finding, routes, graphs = _context()
    provider = FakeProvider()
    engine = AIExplanationEngine(provider, MemoryExplanationCache(), "fallback-model")

    first = engine.explain([finding], routes, graphs, enabled=True)
    second = engine.explain([finding], routes, graphs, enabled=True)

    assert first.status == "complete"
    assert second.results[0].cached is True
    assert provider.calls == 1
    assert first.results[0].finding_id == finding.finding_id


def test_engine_is_graceful_when_provider_fails() -> None:
    finding, routes, graphs = _context()
    result = AIExplanationEngine(
        FakeProvider(fail=True), MemoryExplanationCache(), "fallback"
    ).explain([finding], routes, graphs, enabled=True)

    assert result.status == "unavailable"
    assert result.results == []
    assert result.errors[0].code == "explanation_failed"


def test_disabled_engine_does_not_call_provider() -> None:
    finding, routes, graphs = _context()
    provider = FakeProvider()
    result = AIExplanationEngine(provider, MemoryExplanationCache(), "fallback").explain(
        [finding], routes, graphs, enabled=False
    )

    assert result.status == "disabled"
    assert provider.calls == 0


def test_cache_failure_preserves_a_generated_result() -> None:
    finding, routes, graphs = _context()
    result = AIExplanationEngine(FakeProvider(), FailingCache(), "fallback").explain(
        [finding], routes, graphs, enabled=True
    )

    assert result.status == "partial"
    assert len(result.results) == 1
    assert {error.code for error in result.errors} == {"cache_read_failed", "cache_write_failed"}


def test_file_cache_is_outside_and_never_writes_the_scan_target(tmp_path: Path) -> None:
    target = REPOSITORY_ROOT / "demo" / "vulnerable-taskflow"
    before = {
        path.relative_to(target): path.read_bytes() for path in target.rglob("*") if path.is_file()
    }
    provider = FakeProvider()
    service = build_scan_service(
        REPOSITORY_ROOT,
        ai_provider=provider,
        ai_cache=FileExplanationCache(tmp_path / "sentinel-owned" / "explanations.json"),
        ai_enabled=True,
    )

    response = service.scan("demo/vulnerable-taskflow")
    after = {
        path.relative_to(target): path.read_bytes() for path in target.rglob("*") if path.is_file()
    }

    assert response.ai.status == "complete"
    assert before == after
    assert (tmp_path / "sentinel-owned" / "explanations.json").is_file()


def test_configured_file_cache_inside_scan_root_is_replaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsafe_path = REPOSITORY_ROOT / ".sentinel-ai-cache.json"
    monkeypatch.setenv("SENTINEL_AI_CACHE_PATH", str(unsafe_path))
    service = build_scan_service(REPOSITORY_ROOT, ai_enabled=False)

    assert isinstance(service.ai_engine.cache, FileExplanationCache)
    assert service.ai_engine.cache.path != unsafe_path


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda value: value["explanation"].__setitem__("summary", "# heading"), "plain text"),
        (lambda value: value["patch"].__setitem__("source_file", "../escape.ts"), "safe relative"),
        (
            lambda value: value["patch"].__setitem__(
                "diff", "--- a/src/routes/projects.ts\n+++ b/src/routes/projects.ts\n+ safe"
            ),
            "unified diff hunk",
        ),
        (
            lambda value: value["patch"].__setitem__(
                "diff",
                (
                    "--- a/src/routes/projects.ts\n+++ b/src/routes/projects.ts\n"
                    "@@ -1 +1 @@\n- remove authentication\n+ code"
                ),
            ),
            "may not remove",
        ),
        (
            lambda value: value["patch"].__setitem__(
                "diff",
                (
                    "--- a/src/routes/projects.ts\n+++ b/src/routes/projects.ts\n"
                    "@@ -1 +1 @@\n+ rm -rf /"
                ),
            ),
            "destructive",
        ),
    ],
)
def test_formatter_rejects_unsafe_model_output(
    change: Callable[[dict[str, Any]], None], message: str
) -> None:
    value = valid_output().model_dump(mode="json")
    change(value)
    with pytest.raises(ValidationError, match=message):
        AIModelOutput.model_validate(value)


def test_formatter_rejects_fabricated_finding_identifier_field() -> None:
    value = valid_output().model_dump(mode="json")
    value["finding_id"] = "invented-finding"
    with pytest.raises(ValidationError):
        AIModelOutput.model_validate(value)
