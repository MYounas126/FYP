"""
Alert management endpoints.

Endpoints for viewing and managing security alerts.
"""

from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from loguru import logger

from app.db.session import get_db
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.user import User
from app.schemas.alert import AlertResponse, AlertUpdate, AlertStats, AlertCreate
from app.api.v1.endpoints.auth import get_current_user, get_current_admin_user

router = APIRouter()


@router.get("/", response_model=List[AlertResponse])
async def list_alerts(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    severity: Optional[AlertSeverity] = None,
    status: Optional[AlertStatus] = None,
    attack_category: Optional[str] = None,
    assigned_to: Optional[UUID] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> List[AlertResponse]:
    """
    Query alerts with filters.

    Args:
        start_time: Filter by start time
        end_time: Filter by end time
        severity: Filter by severity
        status: Filter by status
        attack_category: Filter by attack category
        assigned_to: Filter by assigned user
        limit: Maximum records to return
        offset: Number of records to skip
        db: Database session
        current_user: Authenticated user

    Returns:
        List of alerts
    """
    query = select(Alert)

    if start_time:
        query = query.where(Alert.timestamp >= start_time)
    if end_time:
        query = query.where(Alert.timestamp <= end_time)
    if severity:
        query = query.where(Alert.severity == severity)
    if status:
        query = query.where(Alert.status == status)
    if attack_category:
        query = query.where(Alert.attack_category == attack_category)
    if assigned_to:
        query = query.where(Alert.assigned_to == assigned_to)

    query = query.order_by(desc(Alert.timestamp)).offset(offset).limit(limit)

    result = await db.execute(query)
    alerts = result.scalars().all()

    return [AlertResponse.model_validate(a) for a in alerts]


@router.get("/stats", response_model=AlertStats)
async def get_alert_stats(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> AlertStats:
    """
    Get alert statistics for dashboard.

    Args:
        start_time: Start of time range
        end_time: End of time range
        db: Database session
        current_user: Authenticated user

    Returns:
        Alert statistics
    """
    if not end_time:
        end_time = datetime.utcnow()
    if not start_time:
        start_time = end_time - timedelta(hours=24)

    # Status counts
    status_query = select(
        func.count(Alert.id).label("total"),
        func.count(Alert.id).filter(Alert.status == AlertStatus.NEW).label("new"),
        func.count(Alert.id).filter(Alert.status == AlertStatus.INVESTIGATING).label("investigating"),
        func.count(Alert.id).filter(Alert.status == AlertStatus.RESOLVED).label("resolved"),
        func.count(Alert.id).filter(Alert.status == AlertStatus.FALSE_POSITIVE).label("false_positive")
    ).where(
        Alert.timestamp.between(start_time, end_time)
    )

    result = await db.execute(status_query)
    status_stats = result.one()

    # Severity distribution
    severity_query = select(
        Alert.severity,
        func.count(Alert.id).label("count")
    ).where(
        Alert.timestamp.between(start_time, end_time)
    ).group_by(Alert.severity)

    result = await db.execute(severity_query)
    severity_distribution = {row.severity.value: row.count for row in result}

    # Category distribution
    category_query = select(
        Alert.attack_category,
        func.count(Alert.id).label("count")
    ).where(
        Alert.timestamp.between(start_time, end_time),
        Alert.attack_category.isnot(None)
    ).group_by(Alert.attack_category)

    result = await db.execute(category_query)
    category_distribution = {row.attack_category: row.count for row in result}

    # Hourly trend
    hourly_query = select(
        func.date_trunc('hour', Alert.timestamp).label("hour"),
        func.count(Alert.id).label("count")
    ).where(
        Alert.timestamp.between(start_time, end_time)
    ).group_by("hour").order_by("hour")

    result = await db.execute(hourly_query)
    hourly_trend = [{"hour": row.hour.isoformat(), "count": row.count} for row in result]

    return AlertStats(
        total_alerts=status_stats.total or 0,
        new_alerts=status_stats.new or 0,
        investigating_alerts=status_stats.investigating or 0,
        resolved_alerts=status_stats.resolved or 0,
        false_positives=status_stats.false_positive or 0,
        severity_distribution=severity_distribution,
        category_distribution=category_distribution,
        hourly_trend=hourly_trend
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> AlertResponse:
    """
    Get alert by ID.

    Args:
        alert_id: Alert UUID
        db: Database session
        current_user: Authenticated user

    Returns:
        Alert details

    Raises:
        HTTPException: If alert not found
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )

    return AlertResponse.model_validate(alert)


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: UUID,
    alert_data: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> AlertResponse:
    """
    Update alert status or assignment.

    Args:
        alert_id: Alert UUID
        alert_data: Update data
        db: Database session
        current_user: Authenticated user

    Returns:
        Updated alert

    Raises:
        HTTPException: If alert not found
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )

    update_data = alert_data.model_dump(exclude_unset=True)

    # Track resolution
    if "status" in update_data and update_data["status"] in [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]:
        update_data["resolved_at"] = datetime.utcnow()
        update_data["resolved_by"] = current_user.id

    for field, value in update_data.items():
        setattr(alert, field, value)

    await db.commit()
    await db.refresh(alert)

    logger.info(f"Alert {alert_id} updated by {current_user.username}")

    return AlertResponse.model_validate(alert)


@router.post("/", response_model=AlertResponse)
async def create_alert(
    alert_data: AlertCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
) -> AlertResponse:
    """
    Create a manual alert (admin only).

    Args:
        alert_data: Alert data
        db: Database session
        current_user: Authenticated admin user

    Returns:
        Created alert
    """
    alert = Alert(**alert_data.model_dump())

    db.add(alert)
    await db.commit()
    await db.refresh(alert)

    logger.info(f"Manual alert created by {current_user.username}: {alert.title}")

    return AlertResponse.model_validate(alert)
