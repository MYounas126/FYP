"""
SentinelFlow - Main Application Entry Point

This module initializes the FastAPI application with all routes,
middleware, and event handlers.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse, JSONResponse
from loguru import logger
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import setup_logging
from app.core.rate_limit import limiter
from app.db.session import init_db, close_db
from app.services.redis_service import redis_manager
from app.services.ml_service import ml_service


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """
    Application lifespan manager.
    Handles startup and shutdown events.
    """
    # Startup
    logger.info("Starting SentinelFlow...")
    setup_logging()

    # Initialize database
    await init_db()
    logger.info("Database initialized")

    # Initialize Redis
    await redis_manager.connect()
    logger.info("Redis connected")

    # Load ML models
    await ml_service.load_models()
    logger.info("ML models loaded")

    logger.info(f"SentinelFlow v{settings.VERSION} started successfully")

    yield

    # Shutdown
    logger.info("Shutting down SentinelFlow...")
    await redis_manager.disconnect()
    await close_db()
    logger.info("SentinelFlow shutdown complete")


def create_application() -> FastAPI:
    """
    Application factory function.
    Creates and configures the FastAPI application.
    """
    app = FastAPI(
        title=settings.PROJECT_NAME,
        description="ML-Powered Network Intrusion Detection System",
        version=settings.VERSION,
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        openapi_url="/openapi.json" if settings.DEBUG else None,
        default_response_class=ORJSONResponse,
        lifespan=lifespan,
    )

    # Add rate limiter state and exception handler
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API router
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    # Health check endpoint
    @app.get("/health", tags=["Health"])
    async def health_check():
        """Health check endpoint for Docker and load balancers."""
        return {
            "status": "healthy",
            "version": settings.VERSION,
            "service": "sentinelflow-backend"
        }

    # Root endpoint
    @app.get("/", tags=["Root"])
    async def root():
        """Root endpoint with API information."""
        return {
            "name": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "docs": "/docs",
            "health": "/health"
        }

    return app


# Create application instance
app = create_application()
