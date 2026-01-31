"""Essentially recreating PyJWKClient but make it async."""

from httpx import AsyncClient
from jwt import PyJWK, PyJWKSet, get_unverified_header
from jwt.jwk_set_cache import JWKSetCache

from .errors import KeyFetchError, KeyNotFoundError


class JWTKeyCache(JWKSetCache):
    """Fetches keys from OICD endpoint automatically if they don't exist."""

    def __init__(self, openid_connect_url: str, cache_args: dict):
        """Initializes the cache and configures TTLCache.

        Args:
            openid_connect_url (str): URL of the OICD provider.
            cache_args (dict): passed directly to TTLCache.
        """
        self.base_url = openid_connect_url.rstrip("/")
        self._client: AsyncClient | None = None
        super().__init__(**cache_args)

    async def _create_client(self):
        if self._client is None:
            self._client = AsyncClient()

        return self._client

    async def close(self):
        """Closes async http client on loop exit. Maybe."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _fetch_oicd_config(self) -> dict:
        client = await self._create_client()

        response = await client.get(self.base_url)
        response.raise_for_status()

        return response.json()

    async def fetch_key(self, token: str) -> PyJWK:
        """Loads cache on first call from OICD endpoint and fetches key if not found.

        Args:
            token (str): The token to extract the kid from.

        Returns:
            A  PyJWK "key entry" if found in the JWKS.

        Raises:
            KeyFetchError: If anything fails while fetching the key.
            KeyNotFoundError: If the kid cannot be found inthe jwks.

        """
        kid = get_unverified_header(token)["kid"]
        if jwks := self.get():
            try:
                return jwks[kid]
            except KeyError:
                pass

        client = await self._create_client()

        try:
            config = await self._fetch_oicd_config()
            response = await client.get(config["jwks_uri"])
            response.raise_for_status()
        except Exception as e:
            raise KeyFetchError from e

        self.put(PyJWKSet(response.json().get("keys", [])))

        try:
            return self.get()[kid]  # type: ignore
        except KeyError as e:
            raise KeyNotFoundError from e
