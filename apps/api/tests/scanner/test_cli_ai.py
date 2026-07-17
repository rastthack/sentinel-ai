"""CLI coverage for optional explanation selection without network access."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

from pytest import CaptureFixture

from sentinel_api.scanner.cli import main
from sentinel_api.scanner.models import RepositoryScanResponse
from sentinel_api.scanner.service import ScanService, build_scan_service

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


class FakeService:
    def __init__(self, response: RepositoryScanResponse) -> None:
        self.response = response
        self.explain: bool | None = None

    def scan(
        self, _repository_path: Path, *, explain: bool | None = None
    ) -> RepositoryScanResponse:
        self.explain = explain
        return self.response


def _service_builder(service: FakeService) -> Callable[[Path | None], ScanService]:
    return cast(Callable[[Path | None], ScanService], lambda _root: service)


def test_cli_defaults_to_no_explanation_and_emits_safe_json(
    capsys: CaptureFixture[str],
) -> None:
    response = build_scan_service(REPOSITORY_ROOT, ai_enabled=False).scan(
        "demo/vulnerable-taskflow"
    )
    service = FakeService(response)

    exit_code = main(
        ["demo/vulnerable-taskflow"],
        service_builder=_service_builder(service),
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert service.explain is False
    assert payload["ai"]["status"] == "disabled"
    assert "user-a-demo-token" not in json.dumps(payload)


def test_cli_explain_flag_is_forwarded_to_the_service(capsys: CaptureFixture[str]) -> None:
    response = build_scan_service(REPOSITORY_ROOT, ai_enabled=False).scan(
        "demo/vulnerable-taskflow"
    )
    service = FakeService(response)

    exit_code = main(
        ["demo/vulnerable-taskflow", "--explain", "--format", "summary"],
        service_builder=_service_builder(service),
    )

    assert exit_code == 0
    assert service.explain is True
    assert "AI explanation: disabled" in capsys.readouterr().out
