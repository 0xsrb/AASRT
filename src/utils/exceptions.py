"""Custom exceptions for AASRT."""


class AASRTException(Exception):
    """Base exception for AASRT."""
    pass


class APIException(AASRTException):
    """Raised when API call fails."""

    def __init__(self, message: str, engine: str = None, status_code: int = None):
        self.engine = engine
        self.status_code = status_code
        super().__init__(message)


class RateLimitException(AASRTException):
    """Raised when rate limit is exceeded."""

    def __init__(self, message: str, engine: str = None, retry_after: int = None):
        self.engine = engine
        self.retry_after = retry_after
        super().__init__(message)


class ConfigurationException(AASRTException):
    """Raised when configuration is invalid."""
    pass


class ValidationException(AASRTException):
    """Raised when input validation fails."""
    pass


class AuthenticationException(AASRTException):
    """Raised when authentication fails."""

    def __init__(self, message: str, engine: str = None):
        self.engine = engine
        super().__init__(message)


class TimeoutException(AASRTException):
    """Raised when a request times out."""

    def __init__(self, message: str, engine: str = None, timeout: int = None):
        self.engine = engine
        self.timeout = timeout
        super().__init__(message)
