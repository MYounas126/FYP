"""Network traffic schemas for API validation."""

from datetime import datetime
from typing import Optional, Dict, Any, List, Union

from pydantic import BaseModel, Field, ConfigDict, IPvAnyAddress, field_validator


class TrafficBase(BaseModel):
    """Base traffic schema with validated IP addresses."""
    src_ip: IPvAnyAddress  # Validates IPv4 and IPv6 addresses
    dst_ip: IPvAnyAddress  # Validates IPv4 and IPv6 addresses
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    dst_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = None
    bytes_sent: int = Field(default=0, ge=0)
    bytes_received: int = Field(default=0, ge=0)
    packets_sent: int = Field(default=0, ge=0)
    packets_received: int = Field(default=0, ge=0)
    duration: float = Field(default=0.0, ge=0.0)
    flags: Optional[str] = None


class TrafficCreate(TrafficBase):
    """Schema for creating traffic record."""
    timestamp: Optional[datetime] = None
    flow_features: Optional[Dict[str, Any]] = None


class TrafficResponse(TrafficBase):
    """Schema for traffic response."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    flow_features: Optional[Dict[str, Any]] = None
    is_anomaly: bool
    anomaly_score: Optional[float] = None
    attack_category: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    confidence: Optional[float] = None


class TrafficStats(BaseModel):
    """Traffic statistics for dashboard."""
    total_flows: int
    total_bytes: int
    total_packets: int
    anomaly_count: int
    anomaly_percentage: float
    top_sources: List[Dict[str, Any]]
    top_destinations: List[Dict[str, Any]]
    protocol_distribution: Dict[str, int]
    attack_categories: Dict[str, int]
    time_range: Dict[str, datetime]


class TrafficQuery(BaseModel):
    """Query parameters for traffic search."""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    src_ip: Optional[IPvAnyAddress] = None  # Validates IP if provided
    dst_ip: Optional[IPvAnyAddress] = None  # Validates IP if provided
    protocol: Optional[str] = None
    is_anomaly: Optional[bool] = None
    attack_category: Optional[str] = None
    min_anomaly_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)


class RealTimeTraffic(BaseModel):
    """Schema for real-time traffic WebSocket message."""
    type: str = "traffic"
    data: TrafficResponse
    timestamp: datetime = Field(default_factory=datetime.utcnow)
