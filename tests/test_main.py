"""Tests for JWTBearer integration with FastAPI endpoints (main.py)."""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

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


async def test_protected_endpoint_no_token(client):
    """Test accessing protected endpoint without a token."""
    response = await client.get("/protected")
    assert response.status_code == 401  # Unauthorized


async def test_protected_endpoint_with_token(client):
    """Test accessing protected endpoint with a valid token."""
    headers = {"Authorization": "Bearer imatoken"}
    mock_payload = {
        "aud": "test-client",
        "preferred_username": "joebob",
        "given_name": "Robert",
        "family_name": "Landers",
        "email": "bob@yahoo.com",
        "disabled": False,
        "groups": ["user", "support", "admin"],
    }
    with patch("fastapi_security_jwt.auth.jwt.decode", return_value=mock_payload):
        from tests import main  # noqa: PLC0415

        key_cacher_stub = Mock()
        key_cacher_stub.fetch_key = AsyncMock(return_value={})
        main.bearer_scheme.key_cache = key_cacher_stub

        response = await client.get("/protected", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Protected endpoint"
    assert data["user"] == "joebob"
