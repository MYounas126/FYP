"""
Database session management.

Provides async SQLAlchemy session for database operations.
"""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
from loguru import logger

from app.core.config import settings

# Create async engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

# Session factory
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# Base class for models
Base = declarative_base()


async def init_db() -> None:
    """
    Initialize database connection.
    Creates tables if they don't exist (for development).
    """
    try:
        async with engine.begin() as conn:
            # In production, use Alembic migrations instead
            # await conn.run_sync(Base.metadata.create_all)
            pass
        logger.info("Database connection established")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise


async def close_db() -> None:
    """Close database connection pool."""
    await engine.dispose()
    logger.info("Database connection closed")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for getting database session.

    Yields:
        AsyncSession: Database session

    Usage:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
