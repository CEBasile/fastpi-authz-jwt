"""TODO: Setup errors humans can understand."""


class KeyFetchError(Exception):
    """Raised when there is an error fetching a JWK from the JWKS endpoint."""

    def __init__(self, message: str = "Error while fetching key from JWKS endpoint"):
        """Initialize the error with a message."""
        self.message = message
        super().__init__(self.message)


class KeyNotFoundError(Exception):
    """Raised when the key id from the token cannot be found in the JWKS."""

    def __init__(self, message: str = "Key ID could not be found in the JWKS."):
        """Initialize the error with a message."""
        self.message = message
        super().__init__(self.message)
