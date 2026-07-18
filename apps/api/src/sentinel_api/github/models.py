"""Typed public GitHub repository identity models."""

from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class GitHubRepositoryUrl(BaseModel):
    """Validated public HTTPS GitHub repository identity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    owner: str = Field(min_length=1)
    repository: str = Field(min_length=1)
    normalized_url: str
    display_name: str


@dataclass(frozen=True, slots=True)
class AcquiredRepository:
    """Internal repository checkout metadata; never serialize this publically."""

    repository_path: Path
    display_name: str
    normalized_url: str
