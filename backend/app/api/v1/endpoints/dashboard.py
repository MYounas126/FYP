"""
Dashboard endpoints.

Aggregated data for the main dashboard view.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from loguru import logger

from app.db.session import get_db
from app.models.traffic import NetworkTraffic
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.user import User
from app.api.v1.endpoints.auth import get_current_user

router = APIRouter()


@router.get("/overview")
async def get_dashboard_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get dashboard overview with key metrics.

    Returns aggregated data for the last 24 hours including:
    - Traffic statistics
    - Alert counts by severity
    - System status

    Args:
        db: Database session
        current_user: Authenticated user

    Returns:
        Dashboard overview data
    """
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_hour = now - timedelta(hours=1)

    # Traffic stats (last 24h)
    traffic_query = select(
        func.count(NetworkTraffic.id).label("total_flows"),
        func.sum(NetworkTraffic.bytes_sent + NetworkTraffic.bytes_received).label("total_bytes"),
        func.count(NetworkTraffic.id).filter(NetworkTraffic.is_anomaly == True).label("anomalies")
    ).where(NetworkTraffic.timestamp >= last_24h)

    result = await db.execute(traffic_query)
    traffic_stats = result.one()

    # Traffic in last hour (for trend)
    hourly_query = select(
        func.count(NetworkTraffic.id).label("flows")
    ).where(NetworkTraffic.timestamp >= last_hour)

    result = await db.execute(hourly_query)
    hourly_traffic = result.scalar() or 0

    # Alert counts
    alert_query = select(
        func.count(Alert.id).label("total"),
        func.count(Alert.id).filter(Alert.severity == AlertSeverity.CRITICAL).label("critical"),
        func.count(Alert.id).filter(Alert.severity == AlertSeverity.HIGH).label("high"),
        func.count(Alert.id).filter(Alert.severity == AlertSeverity.MEDIUM).label("medium"),
        func.count(Alert.id).filter(Alert.severity == AlertSeverity.LOW).label("low"),
        func.count(Alert.id).filter(Alert.status == AlertStatus.NEW).label("unresolved")
    ).where(Alert.timestamp >= last_24h)

    result = await db.execute(alert_query)
    alert_stats = result.one()

    # Recent alerts
    recent_alerts_query = select(Alert).order_by(desc(Alert.timestamp)).limit(5)
    result = await db.execute(recent_alerts_query)
    recent_alerts = result.scalars().all()

    return {
        "traffic": {
            "total_flows_24h": traffic_stats.total_flows or 0,
            "total_bytes_24h": traffic_stats.total_bytes or 0,
            "anomalies_24h": traffic_stats.anomalies or 0,
            "flows_last_hour": hourly_traffic,
            "anomaly_rate": round(
                (traffic_stats.anomalies or 0) / max(traffic_stats.total_flows or 1, 1) * 100, 2
            )
        },
        "alerts": {
            "total_24h": alert_stats.total or 0,
            "critical": alert_stats.critical or 0,
            "high": alert_stats.high or 0,
            "medium": alert_stats.medium or 0,
            "low": alert_stats.low or 0,
            "unresolved": alert_stats.unresolved or 0
        },
        "recent_alerts": [
            {
                "id": str(a.id),
                "title": a.title,
                "severity": a.severity.value,
                "timestamp": a.timestamp.isoformat(),
                "status": a.status.value
            }
            for a in recent_alerts
        ],
        "system": {
            "status": "healthy",
            "last_updated": now.isoformat()
        }
    }


@router.get("/timeline")
async def get_timeline_data(
    hours: int = 24,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get timeline data for charts.

    Args:
        hours: Number of hours to look back
        db: Database session
        current_user: Authenticated user

    Returns:
        Hourly traffic and alert data
    """
    now = datetime.utcnow()
    start_time = now - timedelta(hours=hours)

    # Hourly traffic
    traffic_query = select(
        func.date_trunc('hour', NetworkTraffic.timestamp).label("hour"),
        func.count(NetworkTraffic.id).label("flows"),
        func.sum(NetworkTraffic.bytes_sent + NetworkTraffic.bytes_received).label("bytes"),
        func.count(NetworkTraffic.id).filter(NetworkTraffic.is_anomaly == True).label("anomalies")
    ).where(
        NetworkTraffic.timestamp >= start_time
    ).group_by("hour").order_by("hour")

    result = await db.execute(traffic_query)
    traffic_timeline = [
        {
            "timestamp": row.hour.isoformat(),
            "flows": row.flows,
            "bytes": row.bytes or 0,
            "anomalies": row.anomalies
        }
        for row in result
    ]

    # Hourly alerts
    alert_query = select(
        func.date_trunc('hour', Alert.timestamp).label("hour"),
        func.count(Alert.id).label("count"),
        Alert.severity
    ).where(
        Alert.timestamp >= start_time
    ).group_by("hour", Alert.severity).order_by("hour")

    result = await db.execute(alert_query)

    # Aggregate alerts by hour
    alert_timeline = {}
    for row in result:
        hour = row.hour.isoformat()
        if hour not in alert_timeline:
            alert_timeline[hour] = {
                "timestamp": hour,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        alert_timeline[hour][row.severity.value] = row.count

    return {
        "traffic": traffic_timeline,
        "alerts": list(alert_timeline.values())
    }


@router.get("/attack-distribution")
async def get_attack_distribution(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """
    Get attack category distribution for pie chart.

    Args:
        db: Database session
        current_user: Authenticated user

    Returns:
        Attack category counts
    """
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)

    query = select(
        Alert.attack_category,
        func.count(Alert.id).label("count")
    ).where(
        Alert.timestamp >= last_24h,
        Alert.attack_category.isnot(None)
    ).group_by(Alert.attack_category).order_by(desc("count"))

    result = await db.execute(query)

    return [
        {"category": row.attack_category, "count": row.count}
        for row in result
    ]
