"""FastAPI JWT scope validation utilities.

This module provides a small helper for validating OpenID Connect
JWTs and ensuring required scopes/groups are present.
"""

from typing import Any

import jwt
from fastapi import HTTPException, Request, status
from fastapi.security import OpenIdConnect, SecurityScopes
from fastapi.security.utils import get_authorization_scheme_param
from jwt import InvalidTokenError
from pydantic import BaseModel, ConfigDict

from .cache import JWTKeyCache
from .errors import KeyFetchError


class TokenData(BaseModel):
    """Parsed JWT claims used by the application."""

    model_config = ConfigDict(extra="ignore")

    preferred_username: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    email: str | None = None
    disabled: bool = False
    groups: list[str] = []
    exp: int = 0
    iat: int = 0
    nbf: int = 0

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
        audience: str,
        jwt_opts: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Proccess initialization arguments.

        Args:
            openid_connect_url (str): URL of your OICD provider.
            audience (str): this is you, typically your Client ID.
            jwt_opts (dict): passed directly to jwt.decode()
            **kwargs: passed directly to underlying TTLCache
        """
        oicd_args: dict[str, Any] = {"scheme_name": None, "description": None, "auto_error": True}
        for opt in oicd_args:
            if opt in kwargs:
                oicd_args[opt] = kwargs.pop(opt)

        self.audience = audience
        self.jwt_opts = jwt_opts or {}
        self.key_cache: JWTKeyCache = JWTKeyCache(openid_connect_url, **kwargs)
        super().__init__(openIdConnectUrl=openid_connect_url, **oicd_args)

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
            raise self.make_not_authenticated_error()

        try:
            key_entry = await self.key_cache.fetch_key(token)
            token_data = jwt.decode(
                jwt=token, **key_entry, options=self.jwt_opts, audience=self.audience
            )
        except (InvalidTokenError, KeyFetchError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            ) from e

        authenticate_value = (
            f'Bearer scope="{security_scopes.scope_str}"' if security_scopes.scopes else "Bearer"
        )

        groups = token_data.get("groups", [])
        for scope in security_scopes.scopes:
            if scope not in groups:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not enough permissions",
                    headers={"WWW-Authenticate": authenticate_value},
                )

        return TokenData(**token_data)
