"""Alert schemas for API validation."""

from datetime import datetime
from typing import Optional, Dict, Any, List
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict

from app.models.alert import AlertSeverity, AlertStatus


class AlertBase(BaseModel):
    """Base alert schema."""
    severity: AlertSeverity
    title: str = Field(..., max_length=255)
    description: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    dst_port: Optional[int] = Field(None, ge=0, le=65535)
    attack_category: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None


class AlertCreate(AlertBase):
    """Schema for creating an alert."""
    anomaly_score: Optional[float] = None
    confidence: Optional[float] = None
    traffic_id: Optional[int] = None


class AlertUpdate(BaseModel):
    """Schema for updating an alert."""
    status: Optional[AlertStatus] = None
    assigned_to: Optional[UUID] = None
    notes: Optional[str] = None


class AlertResponse(AlertBase):
    """Schema for alert response."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    timestamp: datetime
    anomaly_score: Optional[float] = None
    confidence: Optional[float] = None
    traffic_id: Optional[int] = None
    status: AlertStatus
    assigned_to: Optional[UUID] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[UUID] = None
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class AlertStats(BaseModel):
    """Alert statistics for dashboard."""
    total_alerts: int
    new_alerts: int
    investigating_alerts: int
    resolved_alerts: int
    false_positives: int
    severity_distribution: Dict[str, int]
    category_distribution: Dict[str, int]
    hourly_trend: List[Dict[str, Any]]


class AlertQuery(BaseModel):
    """Query parameters for alert search."""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    severity: Optional[AlertSeverity] = None
    status: Optional[AlertStatus] = None
    attack_category: Optional[str] = None
    assigned_to: Optional[UUID] = None
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)


class RealTimeAlert(BaseModel):
    """Schema for real-time alert WebSocket message."""
    type: str = "alert"
    data: AlertResponse
    timestamp: datetime = Field(default_factory=datetime.utcnow)
