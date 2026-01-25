"""Tests for FastAPI JWT authentication module (auth.py)."""

from typing import Any
from unittest.mock import AsyncMock, Mock

import jwt
import pytest
from fastapi import HTTPException, Request
from fastapi.security import SecurityScopes

from fastapi_security_jwt import JWTBearer, TokenData


@pytest.fixture
def jwt_bearer():
    """Fixture to provide a JWTBearer instance."""
    return JWTBearer(
        openid_connect_url="http://localhost:8080/realms/default/.well-known/openid-configuration",
        cache_args={
            "maxsize": 10,
            "ttl": 300,
        },
    )


@pytest.fixture
def mock_payload():
    """Fixure to provide mock payload data for token."""
    return {
        "preferred_username": "testuser",
        "groups": ["admin", "users:read", "users:write"],
    }


@pytest.fixture
def mock_token(mock_payload: dict[str, Any]):
    """Fixture to provide a 'valid' mock token."""
    return jwt.encode(mock_payload, "!secret", algorithm="HS256")


@pytest.fixture
def mock_request(mock_token):
    """Returns a request with a 'valid' token header."""
    request = Mock(spec=Request)
    request.headers = {"Authorization": f"Bearer {mock_token}"}
    return request


@pytest.fixture
def mock_fetch_key():
    """Fixture to provide a mocked result for fetch_key."""
    return AsyncMock(return_value={"key": "!secret", "algorithms": ["HS256"]})


@pytest.fixture
def jwt_bearer_fetch_key_replaced(jwt_bearer, mock_fetch_key):
    """Provides a JWTBearer instanced with fetch_key replaced by a mock."""
    mock_cacher = AsyncMock()
    mock_cacher.fetch_key = mock_fetch_key
    jwt_bearer.key_cache = mock_cacher

    return jwt_bearer


def test_tokendata_scopes_alias():
    """Check scopes is aliased to groups."""
    token = TokenData(groups=["read", "write"])
    assert token.scopes == ["read", "write"]


async def test_decode_token_invalid(jwt_bearer: JWTBearer):
    """Test token decoding with invalid token."""
    invalid_token = "invalid.token.here"

    request = Mock(spec=Request)
    request.headers = {"Authorization": f"Bearer {invalid_token}"}

    with pytest.raises(HTTPException) as exc_info:
        await jwt_bearer(request, SecurityScopes(scopes=[]))

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Could not validate credentials"


async def test_scopes_success(jwt_bearer_fetch_key_replaced, mock_request, mock_payload):
    """Test scope check via JWTBearer with valid scopes."""
    security_scopes = SecurityScopes(scopes=["admin"])

    result = await jwt_bearer_fetch_key_replaced(mock_request, security_scopes)
    assert result == TokenData(**mock_payload)


async def test_scopes_multiple_required(jwt_bearer_fetch_key_replaced, mock_token, mock_payload):
    """Test scope check via JWTBearer with multiple required scopes."""
    request = Mock(spec=Request)
    request.headers = {"Authorization": f"Bearer {mock_token}"}
    security_scopes = SecurityScopes(scopes=["admin", "users:read"])

    result = await jwt_bearer_fetch_key_replaced(request, security_scopes)
    assert result == TokenData(**mock_payload)


async def test_scopes_missing_scope(jwt_bearer_fetch_key_replaced, mock_request):
    """Test JWTBearer raises when a required scope is missing."""
    security_scopes = SecurityScopes(scopes=["admin", "hacker"])

    with pytest.raises(HTTPException) as exc_info:
        await jwt_bearer_fetch_key_replaced(mock_request, security_scopes)

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Not enough permissions"


async def test_scopes_no_scopes_required(jwt_bearer_fetch_key_replaced, mock_request, mock_payload):
    """Test JWTBearer when no scopes are required (should pass)."""
    security_scopes = SecurityScopes(scopes=[])

    result = await jwt_bearer_fetch_key_replaced(mock_request, security_scopes)
    assert result == TokenData(**mock_payload)


async def test_missing_authorization_header_raises(jwt_bearer):
    """Calling the dependency without an Authorization header should raise an exception."""
    request = Request(scope={"type": "http", "headers": []})

    with pytest.raises(HTTPException) as exc_info:
        await jwt_bearer(request, SecurityScopes(scopes=[]))

    assert exc_info.value.status_code == 401
    # ensure WWW-Authenticate header exists on the exception
    assert "WWW-Authenticate" in (exc_info.value.headers or {})
