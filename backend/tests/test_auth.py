"""
Tests for Authentication Endpoints

Tests user registration, login, token refresh, and authorization.
"""

import pytest
from fastapi import status
from httpx import AsyncClient


class TestLogin:
    """Tests for login endpoint."""

    @pytest.mark.asyncio
    async def test_login_success(self, async_client: AsyncClient, test_user):
        """Test successful login returns tokens."""
        response = await async_client.post(
            "/api/v1/auth/login",
            data={"username": "testuser", "password": "testpassword123"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    @pytest.mark.asyncio
    async def test_login_invalid_password(self, async_client: AsyncClient, test_user):
        """Test login with invalid password returns 401."""
        response = await async_client.post(
            "/api/v1/auth/login",
            data={"username": "testuser", "password": "wrongpassword"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Incorrect username or password" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, async_client: AsyncClient):
        """Test login with nonexistent user returns 401."""
        response = await async_client.post(
            "/api/v1/auth/login",
            data={"username": "nonexistent", "password": "password123"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_login_inactive_user(self, async_client: AsyncClient, test_session):
        """Test login with inactive user returns 403."""
        from app.models.user import User
        from app.core.security import get_password_hash

        # Create inactive user
        inactive_user = User(
            email="inactive@example.com",
            username="inactiveuser",
            hashed_password=get_password_hash("password123"),
            full_name="Inactive User",
            role="observer",
            is_active=False,
        )
        test_session.add(inactive_user)
        await test_session.commit()

        response = await async_client.post(
            "/api/v1/auth/login",
            data={"username": "inactiveuser", "password": "password123"},
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestRegistration:
    """Tests for user registration endpoint."""

    @pytest.mark.asyncio
    async def test_register_success(self, async_client: AsyncClient):
        """Test successful user registration."""
        response = await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "username": "newuser",
                "password": "securepassword123",
                "full_name": "New User",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert data["username"] == "newuser"
        assert data["role"] == "observer"  # Always default role

    @pytest.mark.asyncio
    async def test_register_forces_observer_role(self, async_client: AsyncClient):
        """Test that registration always assigns observer role, even if admin requested."""
        response = await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": "hacker@example.com",
                "username": "hacker",
                "password": "password123",
                "full_name": "Hacker",
                "role": "admin",  # Attempting privilege escalation
            },
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # Role should be observer regardless of input
        assert data["role"] == "observer"

    @pytest.mark.asyncio
    async def test_register_duplicate_email(self, async_client: AsyncClient, test_user):
        """Test registration with duplicate email returns 400."""
        response = await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": "test@example.com",  # Already exists
                "username": "newusername",
                "password": "password123",
                "full_name": "New User",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Email already registered" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_register_duplicate_username(self, async_client: AsyncClient, test_user):
        """Test registration with duplicate username returns 400."""
        response = await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": "different@example.com",
                "username": "testuser",  # Already exists
                "password": "password123",
                "full_name": "New User",
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Username already taken" in response.json()["detail"]


class TestCurrentUser:
    """Tests for current user endpoint."""

    @pytest.mark.asyncio
    async def test_get_current_user_authenticated(
        self, async_client: AsyncClient, test_user, auth_headers
    ):
        """Test getting current user with valid token."""
        response = await async_client.get("/api/v1/auth/me", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == "test@example.com"
        assert data["username"] == "testuser"

    @pytest.mark.asyncio
    async def test_get_current_user_no_token(self, async_client: AsyncClient):
        """Test getting current user without token returns 401."""
        response = await async_client.get("/api/v1/auth/me")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_get_current_user_invalid_token(self, async_client: AsyncClient):
        """Test getting current user with invalid token returns 401."""
        response = await async_client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid_token"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestTokenRefresh:
    """Tests for token refresh endpoint."""

    @pytest.mark.asyncio
    async def test_refresh_token_success(self, async_client: AsyncClient, test_user):
        """Test refreshing tokens with valid refresh token."""
        from app.core.security import create_refresh_token

        refresh = create_refresh_token(subject=str(test_user.id))

        response = await async_client.post(
            "/api/v1/auth/refresh",
            params={"refresh_token": refresh},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data

    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, async_client: AsyncClient):
        """Test refreshing with invalid token returns 401."""
        response = await async_client.post(
            "/api/v1/auth/refresh",
            params={"refresh_token": "invalid_refresh_token"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
