"""Tests for JWTBearer integration with FastAPI endpoints (main.py)."""

import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

# Add parent directory to path to import main
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
async def app():
    """Import and return the FastAPI app."""
    from tests.main import app as fastapi_app  # noqa: PLC0415

    return fastapi_app


@pytest.fixture
async def client(app):
    """Create an async test client for the FastAPI app."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


async def test_app_loads(client):
    """Sanity test to make the the app loads and the public endpoint works."""
    response = await client.get("/public")
    assert response.status_code == 200
    assert response.json() == {"message": "Public endpoint"}
