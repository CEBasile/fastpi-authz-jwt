"""Tests for FastAPI JWT authentication module (auth.py)."""

from unittest.mock import AsyncMock

import jwt
import pytest
from fastapi import HTTPException, Request
from fastapi.security import SecurityScopes
from starlette.exceptions import HTTPException as StarletteHTTPException

from fastapi_security_jwt import JWTBearer, TokenData
from fastapi_security_jwt.errors import KeyFetchError


@pytest.fixture
async def jwt_bearer():
    """Fixture to provide a JWTBearer instance."""
    return JWTBearer(
        openid_connect_url="http://localhost:8080/realms/default/.well-known/openid-configuration",
        scheme_name="TestJWTBearer",
        audience="test-client",
    )


def test_tokendata_scopes_alias():
    """Check scopes is aliased to groups."""
    token = TokenData(groups=["read", "write"])
    assert token.scopes == ["read", "write"]


async def test_decode_token_invalid(jwt_bearer: JWTBearer):
    """Test token decoding with invalid token."""
    invalid_token = "invalid.token.here"

    # Mock AsyncKeyFetcher to raise an error
    mock_cacher = AsyncMock()
    mock_cacher.fetch_key = AsyncMock(side_effect=KeyFetchError("Invalid token"))
    jwt_bearer.key_cache = mock_cacher

    # Build a minimal Request with Authorization header to invoke JWTBearer
    request = Request(
        scope={"type": "http", "headers": [(b"authorization", b"Bearer " + invalid_token.encode())]}
    )

    with pytest.raises(StarletteHTTPException) as exc_info:
        await jwt_bearer(request, SecurityScopes(scopes=[]))

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Could not validate credentials"


async def test_require_scopes_success(jwt_bearer: JWTBearer):
    """Test scope check via JWTBearer with valid scopes."""
    payload = {
        "aud": "test-client",
        "preferred_username": "testuser",
        "groups": ["admin", "users:read", "users:write"],
    }
    token = jwt.encode(payload, "!secret", algorithm="HS256")

    mock_cacher = AsyncMock()
    mock_cacher.fetch_key = AsyncMock(return_value={"key": "!secret", "algorithms": ["HS256"]})
    jwt_bearer.key_cache = mock_cacher

    request = Request(
        scope={"type": "http", "headers": [(b"authorization", b"Bearer " + token.encode())]}
    )
    security_scopes = SecurityScopes(scopes=["admin"])

    result = await jwt_bearer(request, security_scopes)
    assert result == TokenData(**payload)


async def test_require_scopes_multiple_required(jwt_bearer: JWTBearer):
    """Test scope check via JWTBearer with multiple required scopes."""
    payload = {
        "aud": "test-client",
        "preferred_username": "testuser",
        "groups": ["admin", "users:read", "users:write"],
    }
    token = jwt.encode(payload, "!secret", algorithm="HS256")

    mock_cacher = AsyncMock()
    mock_cacher.fetch_key = AsyncMock(return_value={"key": "!secret", "algorithms": ["HS256"]})
    jwt_bearer.key_cache = mock_cacher

    request = Request(
        scope={"type": "http", "headers": [(b"authorization", b"Bearer " + token.encode())]}
    )
    security_scopes = SecurityScopes(scopes=["admin", "users:read"])

    result = await jwt_bearer(request, security_scopes)
    assert result == TokenData(**payload)


async def test_require_scopes_missing_scope(jwt_bearer: JWTBearer):
    """Test JWTBearer raises when a required scope is missing."""
    payload = {"aud": "test-client", "preferred_username": "testuser", "groups": ["users:read"]}
    token = jwt.encode(payload, "!secret", algorithm="HS256")

    mock_cacher = AsyncMock()
    mock_cacher.fetch_key = AsyncMock(return_value={"key": "!secret", "algorithms": ["HS256"]})
    jwt_bearer.key_cache = mock_cacher

    request = Request(
        scope={"type": "http", "headers": [(b"authorization", b"Bearer " + token.encode())]}
    )
    security_scopes = SecurityScopes(scopes=["admin"])

    with pytest.raises(HTTPException) as exc_info:
        await jwt_bearer(request, security_scopes)

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Not enough permissions"


async def test_require_scopes_no_scopes_required(jwt_bearer: JWTBearer):
    """Test JWTBearer when no scopes are required (should pass)."""
    payload = {"aud": "test-client", "preferred_username": "testuser", "groups": []}
    token = jwt.encode(payload, "!secret", algorithm="HS256")

    mock_cacher = AsyncMock()
    mock_cacher.fetch_key = AsyncMock(return_value={"key": "!secret", "algorithms": ["HS256"]})
    jwt_bearer.key_cache = mock_cacher

    request = Request(
        scope={"type": "http", "headers": [(b"authorization", b"Bearer " + token.encode())]}
    )
    security_scopes = SecurityScopes(scopes=[])

    result = await jwt_bearer(request, security_scopes)
    assert result == TokenData(**payload)


async def test_missing_authorization_header_raises(jwt_bearer: JWTBearer):
    """Calling the dependency without an Authorization header should raise an exception."""
    request = Request(scope={"type": "http", "headers": []})

    with pytest.raises(StarletteHTTPException) as exc_info:
        await jwt_bearer(request, SecurityScopes(scopes=[]))

    assert exc_info.value.status_code == 401
    # ensure WWW-Authenticate header exists on the exception
    assert "WWW-Authenticate" in (exc_info.value.headers or {})
