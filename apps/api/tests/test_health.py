"""Health endpoint tests."""

import asyncio

import httpx

from sentinel_api.main import APP_VERSION, app


async def request_health() -> httpx.Response:
    """Request the endpoint directly through the ASGI transport."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get("/health")


def test_health_endpoint() -> None:
    """The service reports its stable public health contract."""
    response = asyncio.run(request_health())

    assert response.status_code == 200
    assert response.json() == {
        "service": "sentinel-api",
        "status": "ok",
        "version": APP_VERSION,
    }
