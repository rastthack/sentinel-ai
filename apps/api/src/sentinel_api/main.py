"""FastAPI application entry point."""

from typing import Literal

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict

from sentinel_api.config import cors_origins

APP_VERSION = "0.1.0"


class HealthResponse(BaseModel):
    """Public service health response."""

    model_config = ConfigDict(frozen=True)

    service: Literal["sentinel-api"] = "sentinel-api"
    status: Literal["ok"] = "ok"
    version: str


app = FastAPI(
    title="Sentinel AI API",
    description="Evidence-driven security review API.",
    version=APP_VERSION,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(),
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["Accept", "Content-Type"],
)


@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    """Report that the API process is ready to accept requests."""
    return HealthResponse(version=APP_VERSION)
