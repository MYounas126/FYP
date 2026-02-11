"""ML Model registry for tracking trained models."""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any

from sqlalchemy import String, Boolean, DateTime, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class MLModel(Base):
    """
    ML Model registry.

    Tracks trained models for versioning and deployment.

    Attributes:
        id: Unique identifier (UUID)
        name: Model name
        version: Model version (semantic versioning)
        model_type: Type of model (xgboost, isolation_forest, lstm, etc.)
        file_path: Path to model file
        metrics: Model performance metrics
        is_active: Whether this model is currently deployed
        trained_at: When model was trained
        dataset_info: Information about training dataset
    """

    __tablename__ = "ml_models"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    version: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )
    model_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )
    file_path: Mapped[str] = mapped_column(
        String(500),
        nullable=False
    )
    metrics: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=False
    )
    trained_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    dataset_info: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow
    )

    def __repr__(self) -> str:
        return f"<MLModel(name={self.name}, version={self.version}, active={self.is_active})>"
