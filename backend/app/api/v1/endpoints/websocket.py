"""
WebSocket endpoints for real-time updates.

Provides real-time traffic and alert streaming to connected clients.
Requires JWT authentication via query parameter.
"""

import asyncio
from typing import Set, Optional
from datetime import datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query, status
from loguru import logger
import json

from app.services.redis_service import redis_manager
from app.core.security import verify_token
from app.core.config import settings

router = APIRouter()


async def validate_websocket_token(token: Optional[str]) -> Optional[str]:
    """
    Validate JWT token for WebSocket connections.

    Args:
        token: JWT access token from query parameter

    Returns:
        User ID if valid, None otherwise
    """
    if not token:
        return None

    user_id = verify_token(token, token_type="access")
    return user_id


class ConnectionManager:
    """
    WebSocket connection manager.

    Manages active connections and broadcasts messages to all connected clients.
    """

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict) -> None:
        """Broadcast a message to all connected clients."""
        if not self.active_connections:
            return

        message_json = json.dumps(message, default=str)
        disconnected = set()

        for connection in self.active_connections:
            try:
                await connection.send_text(message_json)
            except Exception as e:
                logger.warning(f"Failed to send message: {e}")
                disconnected.add(connection)

        # Clean up disconnected clients
        self.active_connections -= disconnected

    async def send_to_client(self, websocket: WebSocket, message: dict) -> None:
        """Send a message to a specific client."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Failed to send message to client: {e}")


# Global connection manager
manager = ConnectionManager()


@router.websocket("/live")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None)
):
    """
    Main WebSocket endpoint for real-time updates.

    Clients connect here to receive:
    - Real-time traffic data
    - Alert notifications
    - System status updates

    The connection listens to Redis pub/sub for events.

    Authentication:
        Requires a valid JWT token as query parameter: /ws/live?token=<jwt_token>
    """
    # Validate authentication
    user_id = await validate_websocket_token(token)
    if not user_id:
        logger.warning("WebSocket connection rejected: invalid or missing token")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket)
    logger.info(f"WebSocket authenticated for user: {user_id}")

    try:
        # Subscribe to Redis channels
        pubsub = await redis_manager.subscribe(
            "sentinelflow:traffic",
            "sentinelflow:alerts",
            "sentinelflow:system"
        )

        # Send initial connection confirmation
        await manager.send_to_client(websocket, {
            "type": "connection",
            "status": "connected",
            "user_id": user_id,
            "timestamp": datetime.utcnow().isoformat()
        })

        # Listen for messages
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    await manager.send_to_client(websocket, data)
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in Redis message: {message['data']}")

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info(f"Client disconnected from WebSocket (user: {user_id})")

    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


@router.websocket("/traffic")
async def traffic_websocket(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None)
):
    """
    WebSocket endpoint specifically for traffic data.

    Streams real-time network traffic events.

    Authentication:
        Requires a valid JWT token as query parameter: /ws/traffic?token=<jwt_token>
    """
    # Validate authentication
    user_id = await validate_websocket_token(token)
    if not user_id:
        logger.warning("Traffic WebSocket connection rejected: invalid or missing token")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket)

    try:
        pubsub = await redis_manager.subscribe("sentinelflow:traffic")

        await manager.send_to_client(websocket, {
            "type": "connection",
            "channel": "traffic",
            "status": "connected",
            "timestamp": datetime.utcnow().isoformat()
        })

        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    await manager.send_to_client(websocket, data)
                except json.JSONDecodeError:
                    pass

    except WebSocketDisconnect:
        manager.disconnect(websocket)

    except Exception as e:
        logger.error(f"Traffic WebSocket error: {e}")
        manager.disconnect(websocket)


@router.websocket("/alerts")
async def alerts_websocket(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None)
):
    """
    WebSocket endpoint specifically for alerts.

    Streams real-time security alert notifications.

    Authentication:
        Requires a valid JWT token as query parameter: /ws/alerts?token=<jwt_token>
    """
    # Validate authentication
    user_id = await validate_websocket_token(token)
    if not user_id:
        logger.warning("Alerts WebSocket connection rejected: invalid or missing token")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket)

    try:
        pubsub = await redis_manager.subscribe("sentinelflow:alerts")

        await manager.send_to_client(websocket, {
            "type": "connection",
            "channel": "alerts",
            "status": "connected",
            "timestamp": datetime.utcnow().isoformat()
        })

        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    await manager.send_to_client(websocket, data)
                except json.JSONDecodeError:
                    pass

    except WebSocketDisconnect:
        manager.disconnect(websocket)

    except Exception as e:
        logger.error(f"Alerts WebSocket error: {e}")
        manager.disconnect(websocket)


async def broadcast_traffic(traffic_data: dict) -> None:
    """
    Broadcast traffic data to all connected clients.

    Called by the traffic ingestion service.
    """
    await redis_manager.publish("sentinelflow:traffic", {
        "type": "traffic",
        "data": traffic_data,
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_alert(alert_data: dict) -> None:
    """
    Broadcast alert to all connected clients.

    Called by the alert service.
    """
    await redis_manager.publish("sentinelflow:alerts", {
        "type": "alert",
        "data": alert_data,
        "timestamp": datetime.utcnow().isoformat()
    })
