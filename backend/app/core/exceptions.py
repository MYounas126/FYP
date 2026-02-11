"""
Custom Exception Hierarchy for SentinelFlow

Provides structured exception handling across the application.
"""


class SentinelFlowError(Exception):
    """Base exception for all SentinelFlow errors."""
    
    def __init__(self, message: str = "An error occurred in SentinelFlow"):
        self.message = message
        super().__init__(self.message)


class ModelLoadError(SentinelFlowError):
    """Raised when ML model loading fails."""
    
    def __init__(self, message: str = "Failed to load ML model"):
        super().__init__(message)


class PredictionError(SentinelFlowError):
    """Raised when ML prediction fails."""
    
    def __init__(self, message: str = "ML prediction failed"):
        super().__init__(message)


class AuthenticationError(SentinelFlowError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message)


class ValidationError(SentinelFlowError):
    """Raised when input validation fails."""
    
    def __init__(self, message: str = "Input validation failed"):
        super().__init__(message)


class NetworkCaptureError(SentinelFlowError):
    """Raised when network capture operations fail."""
    
    def __init__(self, message: str = "Network capture operation failed"):
        super().__init__(message)


class ConfigurationError(SentinelFlowError):
    """Raised when configuration is invalid."""

    def __init__(self, message: str = "Configuration error"):
        super().__init__(message)


class FeatureExtractionError(SentinelFlowError):
    """Raised when feature extraction fails."""

    def __init__(self, message: str = "Feature extraction failed"):
        super().__init__(message)


class AuthorizationError(SentinelFlowError):
    """Raised when user lacks required permissions."""

    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(message)


class TokenError(AuthenticationError):
    """Raised when token validation fails."""

    def __init__(self, message: str = "Invalid or expired token"):
        super().__init__(message)


class IPValidationError(ValidationError):
    """Raised when IP address validation fails."""

    def __init__(self, ip: str):
        super().__init__(f"Invalid IP address: {ip}")


class BPFFilterError(ValidationError):
    """Raised when BPF filter validation fails."""

    def __init__(self, filter_str: str):
        super().__init__(f"Invalid BPF filter: {filter_str}")


class RateLimitError(SentinelFlowError):
    """Raised when rate limit is exceeded."""

    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(message)
