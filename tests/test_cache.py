"""Tests for the caching module (cache.py)."""

from unittest.mock import MagicMock, patch

import jwt
import pytest
from httpx import AsyncClient, Response

from fastapi_security_jwt.cache import JWTKeyCache
from fastapi_security_jwt.errors import KeyFetchError


@pytest.fixture
def mock_jwks_response():
    """Dummy JWKS response data."""
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-1",
                "n": "xGOr-H7A...",
                "e": "AQAB",
                "alg": "RS256",
            },
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-2",
                "n": "yHPs-I8B...",
                "e": "AQAB",
                "alg": "RS256",
            },
        ]
    }


@pytest.fixture
def mock_oidc_config():
    """Dummy OIDC data."""
    return {
        "issuer": "https://example.com",
        "jwks_uri": "https://example.com/.well-known/jwks.json",
        "authorization_endpoint": "https://example.com/authorize",
    }


@pytest.fixture
def mock_token_header():
    """Dummy JWT header data."""
    return {"kid": "test-key-1", "alg": "RS256", "typ": "JWT"}


@pytest.fixture
def mock_token():
    """Generates a 'real' dummy token for decoding."""
    payload = {"sub": "arealboy"}
    headers = {"kid": "test-key-1"}

    return jwt.encode(payload, "!secret", algorithm="HS256", headers=headers)


@pytest.fixture
def cache():
    """JWTKeyCache singleton for testing."""
    return JWTKeyCache("localhost")


async def test_async_context(cache):
    """Test async client gets created at enter and closed on exit."""
    assert cache._client is None

    async with cache as self:
        assert self._client is not None

    assert cache._client is None


async def test_client_close_noop(cache):
    """Client should be set to None on close."""
    await cache.close()
    assert cache._client is None


async def test_key_fetch_caches(
    cache, mock_token, mock_token_header, mock_oidc_config, mock_jwks_response
):
    """Tests that a key can be retrieved and cached."""
    with patch.object(AsyncClient, "get") as mock_get:
        oidc_response = MagicMock(spec=Response)
        oidc_response.json.resturn_value = mock_oidc_config
        oidc_response.raise_for_status = MagicMock()

        jwks_response = MagicMock(spec=Response)
        jwks_response.json.return_value = mock_jwks_response
        jwks_response.for_status = MagicMock()

        mock_get.side_effect = [oidc_response, jwks_response]

        key = await cache.fetch_key(mock_token)
        assert key is not None
        assert "test-key-1" in cache


async def test_key_fetch_returns_early(cache, mock_token):
    """Intentionally not mocked so will fail if cache misses."""
    cache["test-key-1"] = "a key set"
    key = await cache.fetch_key(mock_token)
    assert isinstance(key, str)


async def test_key_fetch_failure(cache, mock_token):
    """Intentionally not mocked to cause failure."""
    with pytest.raises(KeyFetchError):
        await cache.fetch_key(mock_token)
