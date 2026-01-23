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
from pyjwt_key_fetcher.errors import JWTKeyFetcherError
from pyjwt_key_fetcher.fetcher import AsyncKeyFetcher


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
        self, *, openid_connect_url: str, jwt_opts: dict[str, Any] | None = None, **kwargs: Any
    ) -> None:
        """Proccess initialization arguments."""
        oicd_args: dict[str, Any] = {"scheme_name": None, "description": None, "auto_error": True}
        for opt in oicd_args:
            if opt in kwargs:
                oicd_args[opt] = kwargs.pop(opt)

        self.jwt_opts = jwt_opts or {}
        self.key_fetcher: AsyncKeyFetcher = AsyncKeyFetcher(**kwargs)
        super().__init__(openIdConnectUrl=openid_connect_url, **oicd_args)

    async def __call__(self, request: Request, security_scopes: SecurityScopes) -> TokenData:  # type: ignore[override]
        """Validate the bearer token and ensure required scopes are present.

        Args:
            request: incoming request
            security_scopes: scopes required by the dependency chain

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
            key_entry = await self.key_fetcher.get_key(token)
            token_data = jwt.decode(jwt=token, options=self.jwt_opts, **key_entry)
        except (InvalidTokenError, JWTKeyFetcherError) as e:
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
