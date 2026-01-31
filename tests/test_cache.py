"""Tests for the caching module (cache.py)."""

from unittest.mock import AsyncMock, Mock

import jwt
import pytest
from httpx import AsyncClient, Response

from fastapi_security_jwt.cache import JWTKeyCache
from fastapi_security_jwt.errors import KeyFetchError, KeyNotFoundError


@pytest.fixture
def mock_jwks_response():
    """Dummy JWKS response data."""
    return {
        "keys": [
            {"kty": "oct", "kid": "test-key-1", "k": b"IXNlY3JldA=="},
            {"kty": "oct", "kid": "test-key-2", "k": b"IXNlY3JldA=="},
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
def mock_token_no_key():
    """Generates a 'real' dummy token for decoding that doesn't have a key."""
    payload = {"sub": "arealboy"}
    headers = {"kid": "test-key-3"}

    return jwt.encode(payload, "!secret", algorithm="HS256", headers=headers)


@pytest.fixture
def cache():
    """JWTKeyCache singleton for testing."""
    return JWTKeyCache(
        "localhost",
        cache_args={
            "lifespan": 300,
        },
    )


async def test_client_close(cache):
    """Test that that cache client can be closed."""
    cache._client = AsyncClient()
    await cache.close()
    assert cache._client is None


async def test_client_close_noop(cache):
    """Client should be set to None on close."""
    await cache.close()
    assert cache._client is None


async def test_key_fetch_caches(
    cache,
    mock_token,
    mock_oidc_config,
    mock_jwks_response,
):
    """Tests that a key can be retrieved and cached."""
    cache._client = AsyncMock(spec=AsyncClient)

    oidc_response = Mock(spec=Response)
    oidc_response.json.return_value = mock_oidc_config
    oidc_response.raise_for_status.return_value = None

    jwks_response = Mock(spec=Response)
    jwks_response.json.return_value = mock_jwks_response
    jwks_response.raise_for_status.return_value = None

    cache._client.get.side_effect = [oidc_response, jwks_response]

    key = await cache.fetch_key(mock_token)
    assert key is not None
    assert cache.get()["test-key-1"] == key


async def test_key_fetch_not_found(cache, mock_oidc_config, mock_jwks_response, mock_token_no_key):
    """Tests that none is returned instead of failing if the key is not found."""
    cache._client = AsyncMock(spec=AsyncClient)

    oidc_response = Mock(spec=Response)
    oidc_response.json.return_value = mock_oidc_config
    oidc_response.raise_for_status.return_value = None

    jwks_response = Mock(spec=Response)
    jwks_response.json.return_value = mock_jwks_response
    jwks_response.raise_for_status.return_value = None

    cache._client.get.side_effect = [oidc_response, jwks_response]

    with pytest.raises(KeyNotFoundError):
        await cache.fetch_key(mock_token_no_key)


async def test_key_fetch_retry(cache, mock_oidc_config, mock_jwks_response, mock_token_no_key):
    """Tests the fetch_key retry functionality."""
    cache.get = Mock()
    cache.get.return_value = {"test-key-2": "imarealboy"}
    cache._client = AsyncMock(spec=AsyncClient)

    oidc_response = Mock(spec=Response)
    oidc_response.json.return_value = mock_oidc_config
    oidc_response.raise_for_status.return_value = None

    jwks_response = Mock(spec=Response)
    jwks_response.json.return_value = mock_jwks_response
    jwks_response.raise_for_status.return_value = None

    cache._client.get.side_effect = [oidc_response, jwks_response]

    with pytest.raises(KeyNotFoundError):
        await cache.fetch_key(mock_token_no_key)
    assert cache.get.call_count == 2


async def test_key_fetch_returns_early(cache, mock_token):
    """Intentionally not mocked so will fail if cache misses."""
    mock_get = Mock()
    mock_get.return_value = {"test-key-1": "a key set"}
    cache.get = mock_get
    key = await cache.fetch_key(mock_token)
    assert isinstance(key, str)


async def test_key_fetch_failure(cache, mock_token):
    """Intentionally not mocked to cause failure."""
    with pytest.raises(KeyFetchError) as exc_info:
        await cache.fetch_key(mock_token)
    assert exc_info.value.args[0] == "Error while fetching key from JWKS endpoint"
