"""Scanner API and bundled demo integration tests."""

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from sentinel_api.main import app
from sentinel_api.scanner.service import build_scan_service

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


async def api_request(
    method: str,
    path: str,
    json_body: dict[str, Any] | None = None,
) -> httpx.Response:
    """Call the FastAPI app without opening a network port."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, path, json=json_body)


def test_bundled_taskflow_scan_succeeds() -> None:
    response = build_scan_service(REPOSITORY_ROOT).scan("demo/vulnerable-taskflow")
    serialized = response.model_dump_json()

    assert response.repository.name == "vulnerable-taskflow"
    assert response.repository.relative_path == "demo/vulnerable-taskflow"
    assert response.summary.primary_language == "TypeScript"
    assert "Express" in response.summary.frameworks
    assert response.summary.package_manager == "npm"
    assert "Prisma" in response.summary.orm
    assert "SQLite" in response.summary.databases
    assert response.summary.route_count == 7
    assert response.summary.protected_route_count == 5
    assert response.summary.public_route_count == 2
    assert {route.path for route in response.routes} == {
        "/health",
        "/api/login",
        "/api/dashboard",
        "/api/projects",
        "/api/projects/:id",
        "/api/tasks",
        "/api/profile",
    }
    assert [mechanism.name for mechanism in response.authentication.mechanisms] == [
        "bearer_token"
    ]
    assert {model.name for model in response.data_model.models} == {
        "User",
        "Project",
        "ProjectMember",
        "Task",
    }
    assert any(
        candidate.model == "Project" and candidate.field == "ownerId"
        for candidate in response.data_model.ownership_candidates
    )
    assert any(
        mapping.route_id == "route:GET:/api/projects/:id"
        and mapping.model == "Project"
        and mapping.operation == "read_one"
        for mapping in response.route_model_mappings
    )
    assert {"src/app.ts", "src/server.ts"} <= {
        entrypoint.relative_path for entrypoint in response.entrypoints
    }
    assert str(REPOSITORY_ROOT) not in serialized
    assert "INTENTIONALLY VULNERABLE" not in serialized
    assert all("content" not in file.model_dump() for file in response.files)
    assert response.summary.finding_count == 1
    assert response.summary.high_finding_count == 1
    assert response.analysis_summary.potential_bola_count == 1
    assert len(response.findings) == 1
    finding = response.findings[0]
    assert finding.rule_id == "AUTH-BOLA"
    assert finding.title == "Potential BOLA / IDOR"
    assert finding.severity == "high"
    assert finding.confidence >= 0.9
    assert finding.path == "/api/projects/:id"
    assert finding.model == "Project"
    assert finding.operation == "read_one"
    assert finding.ownership_candidate == "ownerId"
    assert finding.risk_score == 82
    assert response.ai.status == "disabled"
    assert response.ai.results == []
    assert "user-a-demo-token" not in serialized


def test_bundled_finding_identifier_is_stable() -> None:
    service = build_scan_service(REPOSITORY_ROOT)

    first = service.scan("demo/vulnerable-taskflow")
    second = service.scan("demo/vulnerable-taskflow")

    assert first.findings[0].finding_id == second.findings[0].finding_id
    assert first.findings[0].finding_id.startswith("AUTH-BOLA-")
    assert [finding.path for finding in first.findings] == ["/api/projects/:id"]


def test_demo_api_response_is_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_SCAN_ROOT", str(REPOSITORY_ROOT))

    response = asyncio.run(api_request("GET", "/api/scans/demo"))
    payload = response.json()
    serialized = json.dumps(payload)

    assert response.status_code == 200
    assert payload["repository"]["relative_path"] == "demo/vulnerable-taskflow"
    assert payload["analysis_summary"]["potential_bola_count"] == 1
    assert payload["findings"][0]["rule_id"] == "AUTH-BOLA"
    assert payload["ai"]["status"] == "disabled"
    assert payload["ai"]["results"] == []
    assert len(payload["authorization_graphs"]) == 7
    assert str(REPOSITORY_ROOT) not in serialized
    assert "INTENTIONALLY VULNERABLE" not in serialized
    assert not any("content" in file for file in payload["files"])


def test_repository_post_scans_bundled_demo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_SCAN_ROOT", str(REPOSITORY_ROOT))

    response = asyncio.run(
        api_request(
            "POST",
            "/api/scans/repository",
            {"repository_path": "demo/vulnerable-taskflow"},
        )
    )

    assert response.status_code == 200
    assert response.json()["summary"]["frameworks"] == ["Express"]


def test_repository_api_rejects_path_traversal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_SCAN_ROOT", str(REPOSITORY_ROOT))

    response = asyncio.run(
        api_request(
            "POST",
            "/api/scans/repository",
            {"repository_path": "demo/../demo/vulnerable-taskflow"},
        )
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "unsafe_repository_path"
    assert str(REPOSITORY_ROOT) not in response.text
