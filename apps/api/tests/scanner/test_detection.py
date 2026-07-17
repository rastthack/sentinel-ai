"""Language, framework, data-layer, and entrypoint detection tests."""

import json
from pathlib import Path

from sentinel_api.scanner.service import build_scan_service


def test_typescript_express_npm_prisma_and_sqlite_are_detected(tmp_path: Path) -> None:
    repository = tmp_path / "taskflow"
    (repository / "src").mkdir(parents=True)
    (repository / "prisma").mkdir()
    (repository / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "@prisma/client": "7.8.0",
                    "express": "5.2.1",
                }
            }
        ),
        encoding="utf-8",
    )
    (repository / "package-lock.json").write_text("{}", encoding="utf-8")
    (repository / "src" / "server.ts").write_text(
        'import express from "express";\nexpress().listen(4000);', encoding="utf-8"
    )
    (repository / "src" / "app.ts").write_text("export const app = {};", encoding="utf-8")
    (repository / "prisma" / "schema.prisma").write_text(
        'datasource db {\n  provider = "sqlite"\n}\n', encoding="utf-8"
    )

    response = build_scan_service(tmp_path).scan("taskflow")
    technology_names = {technology.name for technology in response.technologies}
    entrypoints = {entrypoint.relative_path for entrypoint in response.entrypoints}

    assert response.summary.primary_language == "TypeScript"
    assert {"Express", "npm", "Prisma", "SQLite"} <= technology_names
    assert {"src/app.ts", "src/server.ts"} <= entrypoints
    assert all(technology.evidence for technology in response.technologies)


def test_generated_typescript_does_not_affect_language_counts(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / "generated").mkdir()
    (repository / "src" / "main.py").write_text("print('safe')", encoding="utf-8")
    for index in range(5):
        (repository / "generated" / f"client-{index}.ts").write_text(
            "export {};", encoding="utf-8"
        )

    response = build_scan_service(tmp_path).scan("repository")

    assert response.summary.primary_language == "Python"
    assert all(language.name != "TypeScript" for language in response.languages)
