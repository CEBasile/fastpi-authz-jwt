"""Simple tests for custom exceptions (errors.py)."""

from fastapi_security_jwt.errors import KeyFetchError


def test_default_exception_message():
    """Test that the error message is set correctly."""
    error = KeyFetchError()
    assert error.message == "Error fetching key from OICD endpoint"
