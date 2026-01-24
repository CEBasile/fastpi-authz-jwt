"""TODO: Setup errors humans can understand."""


class KeyFetchError(Exception):
    """Raised when there is an error fetching a JWK from the OICD endpoint."""

    def __init__(self, message: str = "Error fetching key from OICD endpoint"):
        """Initialize the error with a message."""
        self.message = message
        super().__init__(self.message)
