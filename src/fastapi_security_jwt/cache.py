"""Essentially recreating PyJWKClient but make it async."""

from cachetools import TTLCache
from httpx import AsyncClient
from jwt import PyJWKSet, get_unverified_header

from .errors import KeyFetchError


class JWTKeyCache(TTLCache):
    """Fetches keys from OICD endpoint automatically if they don't exist."""

    def __init__(self, open_id_connect_url: str, max_size: int = 100, ttl: int = 300):
        """Initialize the cache and async HTTP client (later).

        Args:
            open_id_connect_url (str): URL of the OICD provider.
            max_size (int, optional): Maximum size of the cache. Defaults to 100.
            ttl (int, optional): Time-to-live for cache entries in seconds. Defaults to 300.
        """
        self.base_url = open_id_connect_url.rstrip("/")
        self._client: AsyncClient | None = None
        super().__init__(maxsize=max_size, ttl=ttl)

    # TODO: Add locking to prevent multiple fetches at once when used this way
    async def __aenter__(self):
        """Create the async client on context enter."""
        await self._create_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):  # pragma: no branch
        """Close the async client on context exist."""
        if self._client is not None:
            await self.close()

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

        # uri = f"{self.base_url}/.well-known/openid-configuration"
        response = await client.get(self.base_url)
        response.raise_for_status()

        return response.json()

    async def fetch_key(self, token: str):
        """Loads cache on first call from OICD endpoint and fetches key if not found.

        Apparently this is a massive security issue if you trust the tokens for their
        issue and algorithm. Will have to think about this more later.

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

        # Just load all the keys, not just the one asked for
        try:
            config = await self._fetch_oicd_config()
            response = await client.get(config["jwks_uri"])
            response.raise_for_status()

            for key in PyJWKSet(response.json().get("keys", [])).keys:
                self[key.key_id] = key
        except Exception as e:
            raise KeyFetchError from e

        # Potentially multiple keys here, add this logic later
        return self[kid]
