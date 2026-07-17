"""Runtime configuration with safe local-development defaults."""

import os
import sys
from dataclasses import dataclass
from pathlib import Path


def cors_origins() -> list[str]:
    """Return explicitly configured browser origins."""
    configured = os.getenv("CORS_ORIGINS", "http://localhost:3000")
    return [origin.strip() for origin in configured.split(",") if origin.strip()]


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
