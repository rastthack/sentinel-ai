"""Runtime configuration with safe local-development defaults."""

import os


def cors_origins() -> list[str]:
    """Return explicitly configured browser origins."""
    configured = os.getenv("CORS_ORIGINS", "http://localhost:3000")
    return [origin.strip() for origin in configured.split(",") if origin.strip()]
