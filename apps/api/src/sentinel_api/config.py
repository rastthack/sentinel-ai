"""Runtime configuration with safe local-development defaults."""

import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel_api.github.limits import RepositoryLimits


def cors_origins() -> list[str]:
    """Return explicitly configured browser origins."""
    configured = os.getenv("CORS_ORIGINS", "http://localhost:3000")
    return [origin.strip() for origin in configured.split(",") if origin.strip()]


def github_workspace_parent() -> Path:
    """Return the server-configured parent for application-owned GitHub workspaces."""
    configured = os.getenv("SENTINEL_GITHUB_WORKSPACE_PARENT", "").strip()
    parent = Path(configured).expanduser() if configured else Path(tempfile.gettempdir())
    parent.mkdir(parents=True, exist_ok=True)
    return parent.resolve(strict=True)


def github_repository_limits() -> "RepositoryLimits":
    """Load positive server-controlled GitHub repository metadata limits."""
    from sentinel_api.github.limits import RepositoryLimits

    try:
        return RepositoryLimits(
            max_repository_bytes=_positive_environment_integer(
                "SENTINEL_GITHUB_MAX_REPOSITORY_BYTES", 50 * 1024 * 1024
            ),
            max_file_count=_positive_environment_integer("SENTINEL_GITHUB_MAX_FILE_COUNT", 5_000),
            max_individual_file_bytes=_positive_environment_integer(
                "SENTINEL_GITHUB_MAX_INDIVIDUAL_FILE_BYTES", 1 * 1024 * 1024
            ),
            max_inspected_bytes=_positive_environment_integer(
                "SENTINEL_GITHUB_MAX_INSPECTED_BYTES", 20 * 1024 * 1024
            ),
        )
    except ValueError as error:
        raise ValueError("Invalid GitHub repository limit configuration") from error


def github_clone_timeout_seconds() -> float:
    """Return a bounded server-side timeout for shallow public GitHub cloning."""
    configured = os.getenv("SENTINEL_GITHUB_CLONE_TIMEOUT_SECONDS")
    if configured is None:
        return 30.0
    try:
        value = float(configured)
    except ValueError as error:
        raise ValueError("Invalid GitHub clone timeout configuration") from error
    if not 10.0 <= value <= 120.0:
        raise ValueError("GitHub clone timeout must be between 10 and 120 seconds")
    return value


def _positive_environment_integer(name: str, default: int) -> int:
    """Read one positive integer from trusted server configuration."""
    value = os.getenv(name)
    if value is None:
        return default
    parsed = int(value)
    if parsed <= 0:
        raise ValueError("Limit must be positive")
    return parsed


@dataclass(frozen=True, slots=True)
class AISettings:
    """Server-only model configuration; API keys never enter public models."""

    enabled: bool
    api_key: str | None
    model: str
    timeout_seconds: float
    max_retries: int
    cache_path: Path


def ai_settings() -> AISettings:
    """Load bounded OpenAI settings from server environment variables."""
    api_key = os.getenv("OPENAI_API_KEY", "").strip() or None
    model = os.getenv("OPENAI_MODEL", "gpt-5.6-sol").strip() or "gpt-5.6-sol"
    enabled = os.getenv("SENTINEL_AI_ENABLED", "false").strip().casefold() == "true"
    configured_cache = os.getenv("SENTINEL_AI_CACHE_PATH", "").strip()
    cache_path = Path(configured_cache).expanduser() if configured_cache else _default_cache_path()
    return AISettings(
        enabled=enabled,
        api_key=api_key,
        model=model,
        timeout_seconds=20.0,
        max_retries=2,
        cache_path=cache_path,
    )


def _default_cache_path() -> Path:
    """Return an application-owned platform cache path, never a scan-root path."""
    if os.name == "nt":
        base = Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.getenv("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "sentinel-ai" / "ai-explanations.json"
