"""
API v1 Router

Aggregates all API endpoints under /api/v1 prefix.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import auth, users, traffic, alerts, dashboard, websocket

api_router = APIRouter()

# Authentication endpoints
api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"]
)

# User management endpoints
api_router.include_router(
    users.router,
    prefix="/users",
    tags=["Users"]
)

# Network traffic endpoints
api_router.include_router(
    traffic.router,
    prefix="/traffic",
    tags=["Traffic"]
)

# Alert endpoints
api_router.include_router(
    alerts.router,
    prefix="/alerts",
    tags=["Alerts"]
)

# Dashboard endpoints
api_router.include_router(
    dashboard.router,
    prefix="/dashboard",
    tags=["Dashboard"]
)

# WebSocket endpoints
api_router.include_router(
    websocket.router,
    prefix="/ws",
    tags=["WebSocket"]
)
