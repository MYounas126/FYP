"""
Application Configuration

Centralized configuration management using Pydantic Settings.
All configuration is loaded from environment variables.
"""

from functools import lru_cache
from typing import List

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # ==========================================================================
    # General
    # ==========================================================================
    PROJECT_NAME: str = "SentinelFlow"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False  # SECURITY: Default to False, explicit opt-in required
    LOG_LEVEL: str = "INFO"

    # ==========================================================================
    # API
    # ==========================================================================
    API_V1_PREFIX: str = "/api/v1"
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000

    # ==========================================================================
    # Security
    # ==========================================================================
    SECRET_KEY: str = "your-super-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ==========================================================================
    # CORS
    # ==========================================================================
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.strip("[]").replace('"', '').split(",")]
        return v

    # ==========================================================================
    # Database
    # ==========================================================================
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "sentinelflow"
    POSTGRES_PASSWORD: str = "sentinelflow_secure_password"
    POSTGRES_DB: str = "sentinelflow"

    @property
    def DATABASE_URL(self) -> str:
        return f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    @property
    def DATABASE_URL_SYNC(self) -> str:
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    # ==========================================================================
    # Redis
    # ==========================================================================
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""

    @property
    def REDIS_URL(self) -> str:
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/0"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"

    # ==========================================================================
    # Email (SMTP)
    # ==========================================================================
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "noreply@sentinelflow.local"
    SMTP_TLS: bool = True

    # ==========================================================================
    # ML Configuration
    # ==========================================================================
    ML_MODEL_PATH: str = "/app/ml/models"
    ML_BATCH_SIZE: int = 32
    ML_INFERENCE_DEVICE: str = "cuda"  # cuda or cpu
    ANOMALY_THRESHOLD: float = 0.7
    ALERT_THRESHOLD: float = 0.85

    # ==========================================================================
    # Network Capture
    # ==========================================================================
    CAPTURE_INTERFACE: str = "eth0"
    CAPTURE_BUFFER_SIZE: int = 65536
    CAPTURE_TIMEOUT: int = 1

    # ==========================================================================
    # Production Security Validation
    # ==========================================================================
    @model_validator(mode='after')
    def validate_production_secrets(self) -> 'Settings':
        """
        Validate that default secrets are not used in production.
        This prevents accidental deployment with insecure defaults.
        """
        if self.ENVIRONMENT == "production":
            # Check SECRET_KEY
            insecure_key_patterns = [
                "change-in-production",
                "your-super-secret",
                "changeme",
                "secret",
            ]
            for pattern in insecure_key_patterns:
                if pattern in self.SECRET_KEY.lower():
                    raise ValueError(
                        f"SECRET_KEY must be changed in production. "
                        f"Found insecure pattern: '{pattern}'"
                    )
            
            # Check SECRET_KEY minimum length
            if len(self.SECRET_KEY) < 32:
                raise ValueError(
                    "SECRET_KEY must be at least 32 characters in production"
                )
            
            # Check database password
            insecure_passwords = [
                "sentinelflow_secure_password",
                "password",
                "postgres",
                "admin",
            ]
            if self.POSTGRES_PASSWORD.lower() in insecure_passwords:
                raise ValueError(
                    f"POSTGRES_PASSWORD must be changed in production. "
                    f"Current value is a known insecure default."
                )
        
        return self


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Global settings instance
settings = get_settings()
