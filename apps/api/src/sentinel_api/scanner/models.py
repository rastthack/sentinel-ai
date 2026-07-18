"""Public response models and private scanner data structures."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from sentinel_api.scanner.ai.explanation import AIAnalysis
from sentinel_api.scanner.analysis.models import (
    AnalysisSummary,
    AuthorizationFinding,
    AuthorizationGraph,
)
from sentinel_api.scanner.discovery.models import (
    AuthenticationDiscovery,
    DiscoveredRoute,
    PrismaDataModel,
    RouteModelMapping,
)

FileCategory = Literal[
    "source",
    "configuration",
    "documentation",
    "sensitive",
    "database",
    "binary",
    "generated",
    "other",
]
TechnologyCategory = Literal["framework", "package_manager", "orm", "database"]


class RepositoryScanRequest(BaseModel):
    """Request to statically inspect a repository under the configured scan root."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    repository_path: str = Field(min_length=1, max_length=1_024)


class GitHubRepositoryScanRequest(BaseModel):
    """A public GitHub repository URL, with no local filesystem input."""

    model_config = ConfigDict(extra="forbid")

    github_url: str = Field(min_length=1, max_length=2_048)


class RepositoryMetadata(BaseModel):
    """Safe repository identity relative to the allowed scan root."""

    model_config = ConfigDict(frozen=True)

    name: str
    relative_path: str


class IndexedFile(BaseModel):
    """Metadata about one repository file, never its contents."""

    model_config = ConfigDict(frozen=True)

    relative_path: str
    extension: str
    category: FileCategory
    size_bytes: int = Field(ge=0)
    content_inspected: bool
    skip_reason: str | None = None


class LanguageStat(BaseModel):
    """Count of relevant, non-generated files for a language."""

    model_config = ConfigDict(frozen=True)

    name: str
    file_count: int = Field(ge=1)
    percentage: float = Field(ge=0, le=100)


class TechnologyDetection(BaseModel):
    """A technology claim backed by deterministic repository evidence."""

    model_config = ConfigDict(frozen=True)

    name: str
    category: TechnologyCategory
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(min_length=1)


class EntrypointDetection(BaseModel):
    """A likely application entrypoint and why it was selected."""

    model_config = ConfigDict(frozen=True)

    relative_path: str
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(min_length=1)


class ScanSummary(BaseModel):
    """Compact repository scan summary."""

    model_config = ConfigDict(frozen=True)

    primary_language: str | None
    frameworks: list[str]
    package_manager: str | None
    orm: list[str]
    databases: list[str]
    source_file_count: int = Field(ge=0)
    configuration_file_count: int = Field(ge=0)
    ignored_file_count: int = Field(ge=0)
    route_count: int = Field(ge=0)
    protected_route_count: int = Field(ge=0)
    public_route_count: int = Field(ge=0)
    prisma_model_count: int = Field(ge=0)
    mapped_route_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    critical_finding_count: int = Field(ge=0)
    high_finding_count: int = Field(ge=0)
    medium_finding_count: int = Field(ge=0)
    low_finding_count: int = Field(ge=0)
    informational_finding_count: int = Field(ge=0)


class RepositoryScanResponse(BaseModel):
    """Complete safe scan response without local paths or source contents."""

    model_config = ConfigDict(frozen=True)

    scan_id: str
    repository: RepositoryMetadata
    summary: ScanSummary
    languages: list[LanguageStat]
    technologies: list[TechnologyDetection]
    entrypoints: list[EntrypointDetection]
    files: list[IndexedFile]
    routes: list[DiscoveredRoute]
    authentication: AuthenticationDiscovery
    data_model: PrismaDataModel
    route_model_mappings: list[RouteModelMapping]
    analysis_summary: AnalysisSummary
    authorization_graphs: list[AuthorizationGraph]
    findings: list[AuthorizationFinding]
    ai: AIAnalysis
    warnings: list[str]


@dataclass(frozen=True, slots=True)
class LoadedRepository:
    """Validated internal repository path information."""

    root: Path
    allowed_root: Path
    name: str
    relative_path: str


@dataclass(frozen=True, slots=True)
class IndexLimits:
    """Resource budgets for a single static scan."""

    max_file_count: int = 5_000
    max_file_size_bytes: int = 1_000_000
    max_total_bytes_read: int = 10_000_000
    max_directory_depth: int = 20


@dataclass(slots=True)
class IndexResult:
    """Public file metadata plus private in-memory inspection text."""

    files: list[IndexedFile] = field(default_factory=list)
    contents: dict[str, str] = field(default_factory=dict)
    ignored_file_count: int = 0
    warnings: list[str] = field(default_factory=list)
