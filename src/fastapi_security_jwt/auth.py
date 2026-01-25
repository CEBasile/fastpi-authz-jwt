"""FastAPI JWT scope validation utilities.

This module provides a small helper for validating OpenID Connect
JWTs and ensuring required scopes/groups are present.
"""

from typing import Any

import jwt
from fastapi import HTTPException, Request
from fastapi.security import OpenIdConnect, SecurityScopes
from fastapi.security.utils import get_authorization_scheme_param
from jwt import InvalidTokenError
from pydantic import BaseModel, ConfigDict

from .cache import JWTKeyCache
from .errors import KeyFetchError


class TokenData(BaseModel):
    """Parsed JWT claims used by the application."""

    model_config = ConfigDict(extra="allow")

    preferred_username: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    email: str | None = None
    groups: list[str] = []

    @property
    def username(self) -> str:
        """Return a sensible username for the token subject."""
        return self.preferred_username or self.email or "unknown"

    @property
    def scopes(self) -> list[str]:
        """Alias 'groups' as 'scopes' to support FastAPI's security model."""
        return self.groups


class JWTBearer(OpenIdConnect):
    """OpenID Connect security dependency that validates JWTs and required scopes.

    JWTBearer will fetch the signing key(s) asynchronously via AsyncKeyFetcher
    and validate the token using pyjwt. Missing or invalid tokens raise
    an HTTPException appropriate for FastAPI's security handling.

    """

    def __init__(
        self,
        *,
        openid_connect_url: str,
        oidc_args: dict[str, Any] | None = None,
        jwt_opts: dict[str, Any] | None = None,
        cache_args: dict[str, Any] | None = None,
    ) -> None:
        """Proccess initialization arguments.

        Args:
            openid_connect_url (str): URL to your OICD provider.
            client_id (str): this is you, your application's Client ID.
            oidc_args (dict): passed directly to OpenIdConnect()
            jwt_opts (dict): passed directly to jwt.decode()
            cache_args (dict): passed direclty to TTLCache()
        """
        self.oidc_url = openid_connect_url
        self.jwt_opts = jwt_opts or {}

        oidc_args = oidc_args or {}
        super().__init__(openIdConnectUrl=openid_connect_url, **oidc_args)

        cache_args = cache_args or {}
        self.key_cache: JWTKeyCache = JWTKeyCache(openid_connect_url, cache_args)

    def make_not_authenticated_error(  # type: ignore[override]
        self, code: int, detail: str, auth_value: str = "Bearer"
    ) -> HTTPException:
        """Build and return an HTTPException."""
        return HTTPException(
            status_code=code,
            detail=detail,
            headers={"WWW-Authenticate": auth_value},
        )

    async def __call__(self, request: Request, security_scopes: SecurityScopes) -> TokenData:  # type: ignore[override]
        """Validate the bearer token and ensure required scopes are present.

        Args:
            request (Request): incoming request
            security_scopes (SecurityScopes): scopes required by the dependency chain

        Returns:
            TokenData parsed from the validated JWT

        Raises:
            HTTPException with 401 or 403 when validation fails

        """
        authorization = request.headers.get("Authorization")
        scheme, token = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer" or not token:
            raise self.make_not_authenticated_error(401, "Not authenticated")

        try:
            key_entry = await self.key_cache.fetch_key(token)
            token_data = jwt.decode(jwt=token, **self.jwt_opts, **key_entry)
        except (InvalidTokenError, KeyFetchError) as e:
            raise self.make_not_authenticated_error(401, "Could not validate credentials") from e

        authenticate_value = (
            f'Bearer scope="{security_scopes.scope_str}"' if security_scopes.scopes else "Bearer"
        )

        groups = token_data.get("groups", [])
        for scope in security_scopes.scopes:
            if scope not in groups:
                raise self.make_not_authenticated_error(
                    403, "Not enough permissions", authenticate_value
                )

        return TokenData(**token_data)
