"""
Logging configuration using Loguru.

Provides structured logging with different outputs for development
and production environments.
"""

import sys
from pathlib import Path

from loguru import logger

from app.core.config import settings


def setup_logging() -> None:
    """
    Configure application logging.

    Sets up Loguru with appropriate handlers based on environment.
    """
    # Remove default handler
    logger.remove()

    # Log format
    log_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level>"
    )

    # Console handler
    logger.add(
        sys.stdout,
        format=log_format,
        level=settings.LOG_LEVEL,
        colorize=True,
        backtrace=True,
        diagnose=settings.DEBUG,
    )

    # File handler (only in non-debug mode)
    if not settings.DEBUG:
        log_path = Path("/app/logs")
        log_path.mkdir(parents=True, exist_ok=True)

        # General log file
        logger.add(
            log_path / "sentinelflow.log",
            format=log_format,
            level="INFO",
            rotation="10 MB",
            retention="7 days",
            compression="gz",
        )

        # Error log file
        logger.add(
            log_path / "errors.log",
            format=log_format,
            level="ERROR",
            rotation="10 MB",
            retention="30 days",
            compression="gz",
        )

    logger.info(f"Logging configured: level={settings.LOG_LEVEL}")
