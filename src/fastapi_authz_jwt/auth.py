"""
FastAPI JWT Scope Validation Module
"""

import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from pydantic import BaseModel, ConfigDict
from pyjwt_key_fetcher.fetcher import AsyncKeyFetcher

key_fetcher: AsyncKeyFetcher | None = None

# For integration with FastAPI's /docs endpoint
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="http://localhost:8080/realms/default/protocol/openid-connect/token",
    scopes={"openid": "OpenID", "profile": "Profile", "email": "Email", "groups": "Groups"},
)


class TokenData(BaseModel):
    """JWT token claims"""

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
        """Return preferred_username or email as username"""
        return self.preferred_username or self.email or "unknown"

    @property
    def scopes(self) -> list[str]:
        """Alias groups as scopes for clarity"""
        return self.groups


async def get_token(token: str = Security(oauth2_scheme)) -> str:
    """Extract token string from Authorization header"""
    return token


async def decode_token(token: str = Depends(get_token)) -> TokenData:
    """
    Decode and validate JWT token

    Args:
        token: JWT token string

    Returns:
        TokenData with validated claims

    Raises:
        HTTPException: If token is invalid
    """
    global key_fetcher
    if key_fetcher is None:
        key_fetcher = AsyncKeyFetcher()

    try:
        key_entry = await key_fetcher.get_key(token)
        payload = jwt.decode(jwt=token, options={"verify_aud": False}, **key_entry)
        return TokenData(**payload)
    except (jwt.InvalidTokenError, Exception):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


async def require_scopes(
    security_scopes: SecurityScopes,
    token_data: TokenData = Security(decode_token, scopes=[]),
) -> TokenData:
    """
    Validate that token has all required scopes

    SecurityScopes automatically aggregates scopes from the entire dependency chain,
    so if this is called from another Security() dependency with scopes, all scopes
    will be collected and validated here.

    Args:
        security_scopes: Required scopes
        token_data: Decoded token data

    Returns:
        TokenData if all scopes are present

    Raises:
        HTTPException: If any required scope is missing
    """
    authenticate_value = (
        f'Bearer scope="{security_scopes.scope_str}"' if security_scopes.scopes else "Bearer"
    )

    # Validate all required scopes are present in token
    for scope in security_scopes.scopes:
        if scope not in token_data.groups:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )

    return token_data
