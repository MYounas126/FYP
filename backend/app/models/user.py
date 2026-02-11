"""User model for authentication and authorization."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Boolean, DateTime, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
import enum

from app.db.session import Base


class UserRole(str, enum.Enum):
    """User roles for RBAC."""
    ADMIN = "admin"
    OBSERVER = "observer"


class User(Base):
    """
    User model for authentication.

    Attributes:
        id: Unique identifier (UUID)
        email: User email (unique)
        username: Username (unique)
        hashed_password: Bcrypt hashed password
        full_name: User's full name
        role: User role (admin or observer)
        is_active: Whether user account is active
        is_verified: Whether email is verified
        created_at: Account creation timestamp
        updated_at: Last update timestamp
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    username: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    full_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True
    )
    role: Mapped[UserRole] = mapped_column(
        SQLEnum(UserRole),
        default=UserRole.OBSERVER
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username={self.username}, role={self.role})>"
