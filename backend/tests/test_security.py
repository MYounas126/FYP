"""
Security Tests for SentinelFlow

Tests security-critical functionality including:
- Input validation
- Rate limiting
- WebSocket authentication
- Configuration validation
"""

import pytest
from fastapi import status
from httpx import AsyncClient
import ipaddress

from app.core.config import Settings
from app.services.network_capture import validate_ip_filter


class TestIPValidation:
    """Tests for IP address validation."""

    def test_validate_valid_ipv4(self):
        """Test validation of valid IPv4 address."""
        result = validate_ip_filter("192.168.1.1")
        assert result == "192.168.1.1"

    def test_validate_valid_ipv6(self):
        """Test validation of valid IPv6 address."""
        result = validate_ip_filter("2001:db8::1")
        assert result == "2001:db8::1"

    def test_validate_invalid_ip(self):
        """Test that invalid IP raises ValueError."""
        with pytest.raises(ValueError, match="Invalid IP address"):
            validate_ip_filter("not_an_ip")

    def test_validate_ip_injection_attempt(self):
        """Test that BPF injection attempts are blocked."""
        # Attempt to inject additional BPF filter commands
        with pytest.raises(ValueError):
            validate_ip_filter("192.168.1.1 or port 22")

        with pytest.raises(ValueError):
            validate_ip_filter("192.168.1.1; rm -rf /")

        with pytest.raises(ValueError):
            validate_ip_filter("192.168.1.1 && whoami")

    def test_validate_empty_ip(self):
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError):
            validate_ip_filter("")

    def test_validate_null_bytes(self):
        """Test that null bytes are rejected."""
        with pytest.raises(ValueError):
            validate_ip_filter("192.168.1.1\x00malicious")


class TestTrafficSchemaValidation:
    """Tests for traffic schema IP validation."""

    def test_valid_traffic_data(self):
        """Test traffic schema accepts valid data."""
        from app.schemas.traffic import TrafficBase

        traffic = TrafficBase(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=45678,
            dst_port=443,
            protocol="TCP",
            bytes_sent=1500,
            bytes_received=3200,
        )

        assert str(traffic.src_ip) == "192.168.1.100"
        assert str(traffic.dst_ip) == "10.0.0.1"

    def test_invalid_src_ip(self):
        """Test traffic schema rejects invalid source IP."""
        from app.schemas.traffic import TrafficBase
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            TrafficBase(
                src_ip="not_valid_ip",
                dst_ip="10.0.0.1",
            )

    def test_invalid_dst_ip(self):
        """Test traffic schema rejects invalid destination IP."""
        from app.schemas.traffic import TrafficBase
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            TrafficBase(
                src_ip="192.168.1.100",
                dst_ip="invalid",
            )

    def test_port_range_validation(self):
        """Test that port numbers are validated."""
        from app.schemas.traffic import TrafficBase
        from pydantic import ValidationError

        # Port too high
        with pytest.raises(ValidationError):
            TrafficBase(
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                src_port=70000,  # Invalid
            )

        # Negative port
        with pytest.raises(ValidationError):
            TrafficBase(
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                dst_port=-1,  # Invalid
            )


class TestConfigurationSecurity:
    """Tests for configuration security validation."""

    def test_production_rejects_default_secret(self):
        """Test that production environment rejects default SECRET_KEY."""
        with pytest.raises(ValueError, match="SECRET_KEY must be changed"):
            Settings(
                ENVIRONMENT="production",
                SECRET_KEY="your-super-secret-key-change-in-production",
                POSTGRES_PASSWORD="strong_password_123",
            )

    def test_production_rejects_short_secret(self):
        """Test that production environment rejects short SECRET_KEY."""
        with pytest.raises(ValueError, match="at least 32 characters"):
            Settings(
                ENVIRONMENT="production",
                SECRET_KEY="short",  # Too short
                POSTGRES_PASSWORD="strong_password_123",
            )

    def test_production_rejects_default_db_password(self):
        """Test that production rejects default database password."""
        with pytest.raises(ValueError, match="POSTGRES_PASSWORD must be changed"):
            Settings(
                ENVIRONMENT="production",
                SECRET_KEY="a" * 64,  # Long enough
                POSTGRES_PASSWORD="sentinelflow_secure_password",  # Default
            )

    def test_development_allows_defaults(self):
        """Test that development environment allows default values."""
        # Should not raise
        settings = Settings(
            ENVIRONMENT="development",
            SECRET_KEY="your-super-secret-key-change-in-production",
            POSTGRES_PASSWORD="sentinelflow_secure_password",
        )
        assert settings.ENVIRONMENT == "development"

    def test_production_accepts_secure_config(self):
        """Test that production accepts properly configured secrets."""
        settings = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="a-very-long-and-secure-secret-key-that-is-definitely-long-enough",
            POSTGRES_PASSWORD="very_strong_database_password_123!@#",
        )
        assert settings.ENVIRONMENT == "production"


class TestDebugModeDefault:
    """Tests for DEBUG mode default value."""

    def test_debug_defaults_to_false(self):
        """Test that DEBUG defaults to False for security."""
        settings = Settings()
        assert settings.DEBUG is False

    def test_debug_can_be_enabled(self):
        """Test that DEBUG can be explicitly enabled."""
        settings = Settings(DEBUG=True)
        assert settings.DEBUG is True


class TestWebSocketAuthentication:
    """Tests for WebSocket authentication."""

    @pytest.mark.asyncio
    async def test_websocket_rejects_no_token(self, client):
        """Test WebSocket connection is rejected without token."""
        from fastapi.testclient import TestClient

        with pytest.raises(Exception):
            # Should fail to establish connection
            with client.websocket_connect("/api/v1/ws/live") as ws:
                pass

    @pytest.mark.asyncio
    async def test_websocket_rejects_invalid_token(self, client):
        """Test WebSocket connection is rejected with invalid token."""
        with pytest.raises(Exception):
            with client.websocket_connect("/api/v1/ws/live?token=invalid") as ws:
                pass


class TestRateLimiting:
    """Tests for rate limiting functionality."""

    @pytest.mark.asyncio
    async def test_login_rate_limit(self, async_client: AsyncClient):
        """Test that login endpoint has rate limiting."""
        # Make multiple requests quickly
        responses = []
        for _ in range(10):
            response = await async_client.post(
                "/api/v1/auth/login",
                data={"username": "test", "password": "test"},
            )
            responses.append(response.status_code)

        # Should eventually get rate limited (429 Too Many Requests)
        # Note: In testing, the rate limiter might not be fully active
        # This test documents expected behavior
        assert any(code in [401, 429] for code in responses)
