"""Tests for FastAPI JWT application endpoints."""

import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

# Add parent directory to path to import main
sys.path.insert(0, str(Path(__file__).parent.parent))

from main import app


@pytest.fixture
async def client():
    """Create an async test client for the FastAPI app."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


async def test_root(client):
    """Test public endpoint without authentication."""
    response = await client.get("/public")
    assert response.status_code == 200
    assert response.json() == {"message": "Public endpoint"}
