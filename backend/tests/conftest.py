"""
Pytest Configuration and Fixtures for SentinelFlow Tests

Provides shared fixtures for testing the backend application.
"""

import asyncio
import pytest
import pytest_asyncio
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import create_application
from app.db.session import get_db
from app.models.user import User, Base
from app.core.security import get_password_hash, create_access_token
from app.services.ml_service import ml_service


# =============================================================================
# Database Fixtures
# =============================================================================

# Use in-memory SQLite for tests
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def test_engine():
    """Create a test database engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def test_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    async_session_maker = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session_maker() as session:
        yield session
        await session.rollback()


# =============================================================================
# Application Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def app(test_session) -> FastAPI:
    """Create a test FastAPI application instance."""
    application = create_application()

    # Override database dependency
    async def override_get_db():
        yield test_session

    application.dependency_overrides[get_db] = override_get_db

    return application


@pytest.fixture(scope="function")
def client(app) -> Generator[TestClient, None, None]:
    """Create a synchronous test client."""
    with TestClient(app) as test_client:
        yield test_client


@pytest_asyncio.fixture(scope="function")
async def async_client(app) -> AsyncGenerator[AsyncClient, None]:
    """Create an asynchronous test client."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


# =============================================================================
# User Fixtures
# =============================================================================

@pytest_asyncio.fixture(scope="function")
async def test_user(test_session) -> User:
    """Create a test user."""
    user = User(
        email="test@example.com",
        username="testuser",
        hashed_password=get_password_hash("testpassword123"),
        full_name="Test User",
        role="observer",
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)
    return user


@pytest_asyncio.fixture(scope="function")
async def test_admin(test_session) -> User:
    """Create a test admin user."""
    admin = User(
        email="admin@example.com",
        username="testadmin",
        hashed_password=get_password_hash("adminpassword123"),
        full_name="Test Admin",
        role="admin",
        is_active=True,
    )
    test_session.add(admin)
    await test_session.commit()
    await test_session.refresh(admin)
    return admin


@pytest.fixture(scope="function")
def user_token(test_user) -> str:
    """Create an access token for the test user."""
    return create_access_token(
        subject=str(test_user.id),
        additional_claims={"role": test_user.role.value}
    )


@pytest.fixture(scope="function")
def admin_token(test_admin) -> str:
    """Create an access token for the test admin."""
    return create_access_token(
        subject=str(test_admin.id),
        additional_claims={"role": test_admin.role.value}
    )


@pytest.fixture(scope="function")
def auth_headers(user_token) -> dict:
    """Create authorization headers for test user."""
    return {"Authorization": f"Bearer {user_token}"}


@pytest.fixture(scope="function")
def admin_auth_headers(admin_token) -> dict:
    """Create authorization headers for test admin."""
    return {"Authorization": f"Bearer {admin_token}"}


# =============================================================================
# ML Service Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def mock_ml_service():
    """Mock the ML service for testing."""
    with patch.object(ml_service, '_loaded', True):
        with patch.object(ml_service, 'models', {'anomaly': MagicMock(), 'classifier': MagicMock()}):
            with patch.object(ml_service, 'predict', new_callable=AsyncMock) as mock_predict:
                mock_predict.return_value = {
                    "is_anomaly": False,
                    "anomaly_score": 0.1,
                    "attack_category": None,
                    "mitre_tactic": None,
                    "mitre_technique": None,
                    "confidence": 0.0,
                }
                yield mock_predict


# =============================================================================
# Redis Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def mock_redis():
    """Mock Redis service for testing."""
    mock = MagicMock()
    mock.publish = AsyncMock()
    mock.subscribe = AsyncMock()
    mock.get = AsyncMock(return_value=None)
    mock.set = AsyncMock(return_value=True)
    return mock


# =============================================================================
# Sample Data Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def sample_traffic_data() -> dict:
    """Sample traffic data for testing."""
    return {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 45678,
        "dst_port": 443,
        "protocol": "TCP",
        "bytes_sent": 1500,
        "bytes_received": 3200,
        "packets_sent": 10,
        "packets_received": 15,
        "duration": 2.5,
    }


@pytest.fixture(scope="function")
def sample_alert_data() -> dict:
    """Sample alert data for testing."""
    return {
        "severity": "high",
        "attack_category": "DoS",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499",
        "confidence": 0.92,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
    }
