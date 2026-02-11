"""Network traffic model for storing flow data."""

from datetime import datetime
from typing import Optional, Dict, Any

from sqlalchemy import String, Boolean, Float, Integer, BigInteger, DateTime, JSON
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class NetworkTraffic(Base):
    """
    Network traffic flow model.

    Stores individual network flows with ML predictions.
    Uses TimescaleDB hypertable for time-series optimization.

    Attributes:
        id: Auto-incrementing ID
        timestamp: Flow timestamp
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source port
        dst_port: Destination port
        protocol: Protocol (TCP, UDP, ICMP, etc.)
        bytes_sent: Bytes sent in flow
        bytes_received: Bytes received in flow
        packets_sent: Packets sent
        packets_received: Packets received
        duration: Flow duration in seconds
        flags: TCP flags if applicable
        flow_features: JSON of extracted ML features
        is_anomaly: Whether flow is classified as anomaly
        anomaly_score: ML anomaly score (-1 to 1)
        attack_category: Predicted attack category
        mitre_tactic: MITRE ATT&CK tactic
        mitre_technique: MITRE ATT&CK technique
        confidence: Prediction confidence
    """

    __tablename__ = "network_traffic"

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        primary_key=True,
        nullable=False,
        index=True
    )
    src_ip: Mapped[str] = mapped_column(
        INET,
        nullable=False,
        index=True
    )
    dst_ip: Mapped[str] = mapped_column(
        INET,
        nullable=False,
        index=True
    )
    src_port: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True
    )
    dst_port: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True
    )
    protocol: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True
    )
    bytes_sent: Mapped[int] = mapped_column(
        BigInteger,
        default=0
    )
    bytes_received: Mapped[int] = mapped_column(
        BigInteger,
        default=0
    )
    packets_sent: Mapped[int] = mapped_column(
        Integer,
        default=0
    )
    packets_received: Mapped[int] = mapped_column(
        Integer,
        default=0
    )
    duration: Mapped[float] = mapped_column(
        Float,
        default=0.0
    )
    flags: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True
    )

    # ML Features (stored as JSON for flexibility)
    flow_features: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True
    )

    # ML Predictions
    is_anomaly: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        index=True
    )
    anomaly_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True
    )
    attack_category: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        index=True
    )
    mitre_tactic: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True
    )
    mitre_technique: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True
    )
    confidence: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True
    )

    def __repr__(self) -> str:
        return f"<NetworkTraffic(id={self.id}, src={self.src_ip}, dst={self.dst_ip}, anomaly={self.is_anomaly})>"
