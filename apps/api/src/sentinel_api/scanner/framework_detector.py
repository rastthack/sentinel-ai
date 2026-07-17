"""Deterministic language, technology, and entrypoint detection."""

import json
import tomllib
from collections import Counter
from collections.abc import Mapping
from typing import Any

from sentinel_api.scanner.models import (
    EntrypointDetection,
    IndexedFile,
    IndexResult,
    LanguageStat,
    TechnologyDetection,
)

LANGUAGES_BY_EXTENSION = {
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".py": "Python",
    ".json": "JSON",
    ".prisma": "Prisma",
    ".sql": "SQL",
    ".html": "HTML",
    ".css": "CSS",
}


def detect_languages(files: list[IndexedFile]) -> list[LanguageStat]:
    """Count supported languages without generated, secret, or ignored files."""
    counts: Counter[str] = Counter()
    for file in files:
        if file.category in {"generated", "sensitive", "binary", "database"}:
            continue
        if file.skip_reason is not None:
            continue
        language = LANGUAGES_BY_EXTENSION.get(file.extension)
        if language:
            counts[language] += 1
    total = sum(counts.values())
    return [
        LanguageStat(name=name, file_count=count, percentage=round(count / total * 100, 2))
        for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


class FrameworkDetector:
    """Detect supported technologies only when backed by static evidence."""

    def detect(self, index: IndexResult) -> list[TechnologyDetection]:
        """Return sorted evidence-backed technology detections."""
        package_data = self._package_json(
            index.contents.get("package.json"),
            index.warnings,
        )
        pyproject_data = self._pyproject(
            index.contents.get("pyproject.toml"),
            index.warnings,
        )
        dependencies = self._node_dependencies(package_data)
        python_dependencies = self._python_dependencies(pyproject_data, index.contents)
        file_paths = {item.relative_path for item in index.files}
        detections: list[TechnologyDetection] = []

        self._detect_node_frameworks(dependencies, index.contents, detections)
        self._detect_python_frameworks(python_dependencies, index.contents, detections)
        self._detect_package_managers(file_paths, pyproject_data, detections)
        self._detect_data_layers(dependencies, python_dependencies, index, detections)
        self._detect_databases(dependencies, python_dependencies, index, detections)
        return sorted(detections, key=lambda item: (item.category, item.name))

    @staticmethod
    def _detect_node_frameworks(
        dependencies: set[str],
        contents: Mapping[str, str],
        detections: list[TechnologyDetection],
    ) -> None:
        for dependency, name, import_markers in (
            ("express", "Express", ('from "express"', "from 'express'", 'require("express")')),
            ("next", "Next.js", ('from "next/', "from 'next/", 'from "next"', "from 'next'")),
        ):
            evidence: list[str] = []
            if dependency in dependencies:
                evidence.append(f"package.json dependency: {dependency}")
            import_path = _first_content_match(contents, import_markers)
            if import_path:
                evidence.append(f"{import_path} imports {dependency}")
            if evidence:
                detections.append(
                    TechnologyDetection(
                        name=name,
                        category="framework",
                        confidence=0.98 if len(evidence) > 1 else 0.9,
                        evidence=evidence,
                    )
                )

    @staticmethod
    def _detect_python_frameworks(
        dependencies: set[str],
        contents: Mapping[str, str],
        detections: list[TechnologyDetection],
    ) -> None:
        evidence: list[str] = []
        if "fastapi" in dependencies:
            evidence.append("Python dependency: fastapi")
        import_path = _first_content_match(contents, ("from fastapi", "import fastapi"))
        if import_path:
            evidence.append(f"{import_path} imports fastapi")
        if evidence:
            detections.append(
                TechnologyDetection(
                    name="FastAPI",
                    category="framework",
                    confidence=0.98 if len(evidence) > 1 else 0.9,
                    evidence=evidence,
                )
            )

    @staticmethod
    def _detect_package_managers(
        file_paths: set[str],
        pyproject_data: Mapping[str, Any],
        detections: list[TechnologyDetection],
    ) -> None:
        lock_evidence = (
            ("package-lock.json", "npm"),
            ("pnpm-lock.yaml", "pnpm"),
            ("yarn.lock", "yarn"),
        )
        for path, name in lock_evidence:
            if path in file_paths:
                detections.append(
                    TechnologyDetection(
                        name=name,
                        category="package_manager",
                        confidence=0.99,
                        evidence=[f"Repository contains {path}"],
                    )
                )
        tool_data = pyproject_data.get("tool", {})
        uses_poetry = "poetry.lock" in file_paths or (
            isinstance(tool_data, dict) and "poetry" in tool_data
        )
        if uses_poetry:
            evidence = (
                "Repository contains poetry.lock"
                if "poetry.lock" in file_paths
                else "pyproject.toml contains [tool.poetry]"
            )
            detections.append(
                TechnologyDetection(
                    name="Poetry", category="package_manager", confidence=0.98, evidence=[evidence]
                )
            )
        requirements = sorted(
            path
            for path in file_paths
            if path.startswith("requirements") and path.endswith(".txt")
        )
        if requirements:
            detections.append(
                TechnologyDetection(
                    name="pip",
                    category="package_manager",
                    confidence=0.9,
                    evidence=[f"Repository contains {requirements[0]}"],
                )
            )
        elif isinstance(pyproject_data.get("project"), dict) and not uses_poetry:
            detections.append(
                TechnologyDetection(
                    name="pip",
                    category="package_manager",
                    confidence=0.75,
                    evidence=["pyproject.toml contains standard [project] metadata"],
                )
            )

    @staticmethod
    def _detect_data_layers(
        node_dependencies: set[str],
        python_dependencies: set[str],
        index: IndexResult,
        detections: list[TechnologyDetection],
    ) -> None:
        paths = {item.relative_path for item in index.files}
        prisma_evidence: list[str] = []
        if "prisma" in node_dependencies or "@prisma/client" in node_dependencies:
            prisma_evidence.append("package.json dependency: Prisma")
        if "prisma/schema.prisma" in paths:
            prisma_evidence.append("Repository contains prisma/schema.prisma")
        if prisma_evidence:
            detections.append(
                TechnologyDetection(
                    name="Prisma",
                    category="orm",
                    confidence=0.99 if len(prisma_evidence) > 1 else 0.9,
                    evidence=prisma_evidence,
                )
            )

        sqlalchemy_evidence: list[str] = []
        if "sqlalchemy" in python_dependencies:
            sqlalchemy_evidence.append("Python dependency: sqlalchemy")
        sqlalchemy_path = _first_content_match(
            index.contents, ("from sqlalchemy", "import sqlalchemy")
        )
        if sqlalchemy_path:
            sqlalchemy_evidence.append(f"{sqlalchemy_path} imports sqlalchemy")
        if sqlalchemy_evidence:
            detections.append(
                TechnologyDetection(
                    name="SQLAlchemy",
                    category="orm",
                    confidence=0.98 if len(sqlalchemy_evidence) > 1 else 0.9,
                    evidence=sqlalchemy_evidence,
                )
            )

        supabase_evidence: list[str] = []
        if "@supabase/supabase-js" in node_dependencies or "supabase" in python_dependencies:
            supabase_evidence.append("Repository dependency: Supabase client")
        supabase_path = _first_content_match(
            index.contents, ("@supabase/supabase-js", "from supabase")
        )
        if supabase_path:
            supabase_evidence.append(f"{supabase_path} imports Supabase")
        if supabase_evidence:
            detections.append(
                TechnologyDetection(
                    name="Supabase",
                    category="orm",
                    confidence=0.95,
                    evidence=supabase_evidence,
                )
            )

    @staticmethod
    def _detect_databases(
        node_dependencies: set[str],
        python_dependencies: set[str],
        index: IndexResult,
        detections: list[TechnologyDetection],
    ) -> None:
        schema = index.contents.get("prisma/schema.prisma", "").casefold()
        database_evidence: dict[str, list[str]] = {"SQLite": [], "PostgreSQL": [], "MySQL": []}
        if 'provider = "sqlite"' in schema:
            database_evidence["SQLite"].append("prisma/schema.prisma provider: sqlite")
        if 'provider = "postgresql"' in schema or 'provider = "postgres"' in schema:
            database_evidence["PostgreSQL"].append("prisma/schema.prisma provider: postgresql")
        if 'provider = "mysql"' in schema:
            database_evidence["MySQL"].append("prisma/schema.prisma provider: mysql")
        if "better-sqlite3" in node_dependencies or "sqlite3" in node_dependencies:
            database_evidence["SQLite"].append("package.json contains a SQLite driver")
        if (
            "pg" in node_dependencies
            or "psycopg" in python_dependencies
            or "psycopg2" in python_dependencies
        ):
            database_evidence["PostgreSQL"].append(
                "Repository contains a PostgreSQL driver dependency"
            )
        if (
            "mysql" in node_dependencies
            or "mysql2" in node_dependencies
            or "pymysql" in python_dependencies
        ):
            database_evidence["MySQL"].append("Repository contains a MySQL driver dependency")
        for name, evidence in database_evidence.items():
            if evidence:
                detections.append(
                    TechnologyDetection(
                        name=name,
                        category="database",
                        confidence=0.98 if any("provider" in item for item in evidence) else 0.85,
                        evidence=evidence,
                    )
                )

    @staticmethod
    def _package_json(content: str | None, warnings: list[str]) -> Mapping[str, Any]:
        if not content:
            return {}
        try:
            parsed = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            warnings.append("package.json could not be parsed; related detections were skipped")
            return {}
        return parsed if isinstance(parsed, dict) else {}

    @staticmethod
    def _pyproject(content: str | None, warnings: list[str]) -> Mapping[str, Any]:
        if not content:
            return {}
        try:
            return tomllib.loads(content)
        except (tomllib.TOMLDecodeError, TypeError):
            warnings.append("pyproject.toml could not be parsed; related detections were skipped")
            return {}

    @staticmethod
    def _node_dependencies(package_data: Mapping[str, Any]) -> set[str]:
        dependencies: set[str] = set()
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            values = package_data.get(section, {})
            if isinstance(values, dict):
                dependencies.update(str(name).casefold() for name in values)
        return dependencies

    @staticmethod
    def _python_dependencies(
        pyproject_data: Mapping[str, Any], contents: Mapping[str, str]
    ) -> set[str]:
        dependencies: set[str] = set()
        project = pyproject_data.get("project", {})
        if isinstance(project, dict):
            raw_dependencies = project.get("dependencies", [])
            if isinstance(raw_dependencies, list):
                dependencies.update(_dependency_name(str(item)) for item in raw_dependencies)
        tool = pyproject_data.get("tool", {})
        if isinstance(tool, dict):
            poetry = tool.get("poetry", {})
            if isinstance(poetry, dict) and isinstance(poetry.get("dependencies"), dict):
                dependencies.update(str(name).casefold() for name in poetry["dependencies"])
        for path, content in contents.items():
            if path.startswith("requirements") and path.endswith(".txt"):
                dependencies.update(
                    _dependency_name(line)
                    for line in content.splitlines()
                    if line.strip() and not line.lstrip().startswith("#")
                )
        return dependencies


def detect_entrypoints(index: IndexResult) -> list[EntrypointDetection]:
    """Select conventional entrypoint files and Next.js application directories."""
    paths = {item.relative_path for item in index.files if item.skip_reason is None}
    candidates = {
        "src/server.ts": "Conventional TypeScript server entrypoint",
        "src/index.ts": "Conventional TypeScript application entrypoint",
        "src/app.ts": "Conventional TypeScript application composition entrypoint",
        "server.js": "Conventional JavaScript server entrypoint",
        "app.py": "Conventional Python application entrypoint",
        "main.py": "Conventional Python application entrypoint",
    }
    entrypoints = [
        EntrypointDetection(relative_path=path, confidence=0.95, evidence=[evidence])
        for path, evidence in candidates.items()
        if path in paths
    ]
    if any(path.startswith("app/") or "/app/" in path for path in paths):
        entrypoints.append(
            EntrypointDetection(
                relative_path="app/",
                confidence=0.9,
                evidence=["Repository contains a Next.js-style app directory"],
            )
        )
    elif any(path.startswith("pages/") or "/pages/" in path for path in paths):
        entrypoints.append(
            EntrypointDetection(
                relative_path="pages/",
                confidence=0.9,
                evidence=["Repository contains a Next.js-style pages directory"],
            )
        )
    return sorted(entrypoints, key=lambda item: item.relative_path)


def _first_content_match(contents: Mapping[str, str], markers: tuple[str, ...]) -> str | None:
    for path, content in sorted(contents.items()):
        if any(marker in content for marker in markers):
            return path
    return None


def _dependency_name(requirement: str) -> str:
    normalized = requirement.strip().casefold()
    for separator in ("[", "<", ">", "=", "!", "~", " "):
        normalized = normalized.split(separator, maxsplit=1)[0]
    return normalized.replace("_", "-")
