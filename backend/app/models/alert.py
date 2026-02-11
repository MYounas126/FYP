"""Alert model for security incidents."""

import uuid
from datetime import datetime
from typing import Optional
import enum

from sqlalchemy import String, Float, Integer, DateTime, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class AlertSeverity(str, enum.Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    """Alert status for workflow."""
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Alert(Base):
    """
    Security alert model.

    Represents a detected security incident that requires attention.

    Attributes:
        id: Unique identifier (UUID)
        timestamp: When the alert was created
        severity: Alert severity level
        title: Short alert title
        description: Detailed description
        src_ip: Source IP involved
        dst_ip: Destination IP involved
        src_port: Source port
        dst_port: Destination port
        attack_category: Type of attack detected
        mitre_tactic: MITRE ATT&CK tactic
        mitre_technique: MITRE ATT&CK technique
        anomaly_score: ML anomaly score
        confidence: Prediction confidence
        traffic_id: Reference to network traffic
        status: Alert workflow status
        assigned_to: User assigned to investigate
        resolved_at: When alert was resolved
        resolved_by: User who resolved
        notes: Investigation notes
    """

    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        index=True
    )
    severity: Mapped[AlertSeverity] = mapped_column(
        SQLEnum(AlertSeverity),
        nullable=False,
        index=True
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )
    src_ip: Mapped[Optional[str]] = mapped_column(
        INET,
        nullable=True
    )
    dst_ip: Mapped[Optional[str]] = mapped_column(
        INET,
        nullable=True
    )
    src_port: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True
    )
    dst_port: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True
    )
    attack_category: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True
    )
    mitre_tactic: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True
    )
    mitre_technique: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True
    )
    anomaly_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True
    )
    confidence: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True
    )
    traffic_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True
    )
    status: Mapped[AlertStatus] = mapped_column(
        SQLEnum(AlertStatus),
        default=AlertStatus.NEW,
        index=True
    )
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    resolved_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True
    )
    notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
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
        return f"<Alert(id={self.id}, severity={self.severity}, status={self.status})>"
