"""
Rate Limiting Configuration

Provides rate limiting for API endpoints to prevent abuse.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Global rate limiter instance
# Uses client IP address as the key for rate limiting
limiter = Limiter(key_func=get_remote_address)
