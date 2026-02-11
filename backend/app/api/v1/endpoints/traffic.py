"""
Network traffic endpoints.

Endpoints for querying and managing network traffic data.
"""

from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from loguru import logger

from app.db.session import get_db
from app.models.traffic import NetworkTraffic
from app.models.user import User
from app.schemas.traffic import TrafficResponse, TrafficStats, TrafficQuery
from app.api.v1.endpoints.auth import get_current_user

router = APIRouter()


@router.get("/", response_model=List[TrafficResponse])
async def list_traffic(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    is_anomaly: Optional[bool] = None,
    attack_category: Optional[str] = None,
    min_anomaly_score: Optional[float] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> List[TrafficResponse]:
    """
    Query network traffic with filters.

    Args:
        start_time: Filter by start time
        end_time: Filter by end time
        src_ip: Filter by source IP
        dst_ip: Filter by destination IP
        protocol: Filter by protocol
        is_anomaly: Filter by anomaly status
        attack_category: Filter by attack category
        min_anomaly_score: Minimum anomaly score
        limit: Maximum records to return
        offset: Number of records to skip
        db: Database session
        current_user: Authenticated user

    Returns:
        List of network traffic records
    """
    query = select(NetworkTraffic)

    if start_time:
        query = query.where(NetworkTraffic.timestamp >= start_time)
    if end_time:
        query = query.where(NetworkTraffic.timestamp <= end_time)
    if src_ip:
        query = query.where(NetworkTraffic.src_ip == src_ip)
    if dst_ip:
        query = query.where(NetworkTraffic.dst_ip == dst_ip)
    if protocol:
        query = query.where(NetworkTraffic.protocol == protocol)
    if is_anomaly is not None:
        query = query.where(NetworkTraffic.is_anomaly == is_anomaly)
    if attack_category:
        query = query.where(NetworkTraffic.attack_category == attack_category)
    if min_anomaly_score is not None:
        query = query.where(NetworkTraffic.anomaly_score >= min_anomaly_score)

    query = query.order_by(desc(NetworkTraffic.timestamp)).offset(offset).limit(limit)

    result = await db.execute(query)
    traffic_records = result.scalars().all()

    return [TrafficResponse.model_validate(t) for t in traffic_records]


@router.get("/stats", response_model=TrafficStats)
async def get_traffic_stats(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> TrafficStats:
    """
    Get traffic statistics for dashboard.

    Args:
        start_time: Start of time range (default: last 24 hours)
        end_time: End of time range (default: now)
        db: Database session
        current_user: Authenticated user

    Returns:
        Traffic statistics
    """
    if not end_time:
        end_time = datetime.utcnow()
    if not start_time:
        start_time = end_time - timedelta(hours=24)

    # Total flows and bytes
    stats_query = select(
        func.count(NetworkTraffic.id).label("total_flows"),
        func.sum(NetworkTraffic.bytes_sent + NetworkTraffic.bytes_received).label("total_bytes"),
        func.sum(NetworkTraffic.packets_sent + NetworkTraffic.packets_received).label("total_packets"),
        func.count(NetworkTraffic.id).filter(NetworkTraffic.is_anomaly == True).label("anomaly_count")
    ).where(
        NetworkTraffic.timestamp.between(start_time, end_time)
    )

    result = await db.execute(stats_query)
    stats = result.one()

    total_flows = stats.total_flows or 0
    anomaly_count = stats.anomaly_count or 0
    anomaly_percentage = (anomaly_count / total_flows * 100) if total_flows > 0 else 0

    # Top sources
    top_sources_query = select(
        NetworkTraffic.src_ip,
        func.count(NetworkTraffic.id).label("count")
    ).where(
        NetworkTraffic.timestamp.between(start_time, end_time)
    ).group_by(
        NetworkTraffic.src_ip
    ).order_by(
        desc("count")
    ).limit(10)

    result = await db.execute(top_sources_query)
    top_sources = [{"ip": str(row.src_ip), "count": row.count} for row in result]

    # Top destinations
    top_dests_query = select(
        NetworkTraffic.dst_ip,
        func.count(NetworkTraffic.id).label("count")
    ).where(
        NetworkTraffic.timestamp.between(start_time, end_time)
    ).group_by(
        NetworkTraffic.dst_ip
    ).order_by(
        desc("count")
    ).limit(10)

    result = await db.execute(top_dests_query)
    top_destinations = [{"ip": str(row.dst_ip), "count": row.count} for row in result]

    # Protocol distribution
    protocol_query = select(
        NetworkTraffic.protocol,
        func.count(NetworkTraffic.id).label("count")
    ).where(
        NetworkTraffic.timestamp.between(start_time, end_time)
    ).group_by(
        NetworkTraffic.protocol
    )

    result = await db.execute(protocol_query)
    protocol_distribution = {row.protocol or "Unknown": row.count for row in result}

    # Attack categories
    category_query = select(
        NetworkTraffic.attack_category,
        func.count(NetworkTraffic.id).label("count")
    ).where(
        NetworkTraffic.timestamp.between(start_time, end_time),
        NetworkTraffic.attack_category.isnot(None)
    ).group_by(
        NetworkTraffic.attack_category
    )

    result = await db.execute(category_query)
    attack_categories = {row.attack_category: row.count for row in result}

    return TrafficStats(
        total_flows=total_flows,
        total_bytes=stats.total_bytes or 0,
        total_packets=stats.total_packets or 0,
        anomaly_count=anomaly_count,
        anomaly_percentage=round(anomaly_percentage, 2),
        top_sources=top_sources,
        top_destinations=top_destinations,
        protocol_distribution=protocol_distribution,
        attack_categories=attack_categories,
        time_range={"start": start_time, "end": end_time}
    )


@router.get("/anomalies", response_model=List[TrafficResponse])
async def get_anomalies(
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> List[TrafficResponse]:
    """
    Get recent anomalous traffic.

    Args:
        limit: Maximum records to return
        db: Database session
        current_user: Authenticated user

    Returns:
        List of anomalous traffic records
    """
    query = select(NetworkTraffic).where(
        NetworkTraffic.is_anomaly == True
    ).order_by(
        desc(NetworkTraffic.timestamp)
    ).limit(limit)

    result = await db.execute(query)
    anomalies = result.scalars().all()

    return [TrafficResponse.model_validate(t) for t in anomalies]
