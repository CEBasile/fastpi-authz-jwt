"""Essentially recreating PyJWKClient but make it async."""

from cachetools import TTLCache
from httpx import AsyncClient
from jwt import PyJWKSet, get_unverified_header

from .errors import KeyFetchError


class JWTKeyCache(TTLCache):
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

    async def fetch_key(self, token: str):
        """Loads cache on first call from OICD endpoint and fetches key if not found.

        Args:
            token (str): The token to extract the kid from.

        Returns:
            A "key entry" with the following structure:
            {
                "key": <certificate string>,
                "alg": <algorithm string>,
            }

        Raises:
            KeyFetchError: If anything fails while fetching the key.

        """
        client = await self._create_client()

        kid = get_unverified_header(token)["kid"]

        if kid in self:
            return self[kid]

        try:
            config = await self._fetch_oicd_config()
            response = await client.get(config["jwks_uri"])
            response.raise_for_status()

            for key in PyJWKSet(response.json().get("keys", [])).keys:
                self[key.key_id] = key
        except Exception as e:
            raise KeyFetchError from e

        return self[kid]
