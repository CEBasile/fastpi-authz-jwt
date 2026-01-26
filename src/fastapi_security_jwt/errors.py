"""TODO: Setup errors humans can understand."""


class KeyFetchError(Exception):
    """Raised when there is an error fetching a JWK from the JWKS endpoint."""

    def __init__(self, message: str = "Error while fetching key from JWKS endpoint"):
        """Initialize the error with a message."""
        self.message = message
        super().__init__(self.message)
