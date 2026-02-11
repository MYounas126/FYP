"""
Redis service for caching and pub/sub.

Provides connection management and utility functions for Redis operations.
"""

import json
from typing import Any, Optional, List

import redis.asyncio as redis
from loguru import logger

from app.core.config import settings


class RedisManager:
    """
    Redis connection manager.

    Handles connection lifecycle and provides utility methods for
    common Redis operations including pub/sub.
    """

    def __init__(self):
        self._client: Optional[redis.Redis] = None

    async def connect(self) -> None:
        """Establish connection to Redis."""
        try:
            self._client = redis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
            # Test connection
            await self._client.ping()
            logger.info(f"Connected to Redis at {settings.REDIS_HOST}:{settings.REDIS_PORT}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    async def disconnect(self) -> None:
        """Close Redis connection."""
        if self._client:
            await self._client.close()
            logger.info("Redis connection closed")

    @property
    def client(self) -> redis.Redis:
        """Get Redis client instance."""
        if self._client is None:
            raise RuntimeError("Redis not connected. Call connect() first.")
        return self._client

    # =========================================================================
    # Basic Operations
    # =========================================================================

    async def get(self, key: str) -> Optional[str]:
        """Get value by key."""
        return await self.client.get(key)

    async def set(
        self,
        key: str,
        value: Any,
        expire: Optional[int] = None
    ) -> bool:
        """
        Set key-value pair with optional expiration.

        Args:
            key: Redis key
            value: Value to store (will be JSON serialized if not string)
            expire: Expiration time in seconds

        Returns:
            True if successful
        """
        if not isinstance(value, str):
            value = json.dumps(value, default=str)

        return await self.client.set(key, value, ex=expire)

    async def delete(self, *keys: str) -> int:
        """Delete one or more keys."""
        return await self.client.delete(*keys)

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        return await self.client.exists(key) > 0

    # =========================================================================
    # JSON Operations
    # =========================================================================

    async def get_json(self, key: str) -> Optional[Any]:
        """Get and parse JSON value."""
        value = await self.get(key)
        if value:
            return json.loads(value)
        return None

    async def set_json(
        self,
        key: str,
        value: Any,
        expire: Optional[int] = None
    ) -> bool:
        """Set JSON value."""
        return await self.set(key, json.dumps(value, default=str), expire)

    # =========================================================================
    # Pub/Sub Operations
    # =========================================================================

    async def publish(self, channel: str, message: Any) -> int:
        """
        Publish message to channel.

        Args:
            channel: Channel name
            message: Message to publish (will be JSON serialized)

        Returns:
            Number of subscribers that received the message
        """
        if not isinstance(message, str):
            message = json.dumps(message, default=str)

        return await self.client.publish(channel, message)

    async def subscribe(self, *channels: str) -> redis.client.PubSub:
        """
        Subscribe to one or more channels.

        Args:
            channels: Channel names to subscribe to

        Returns:
            PubSub instance for listening to messages
        """
        pubsub = self.client.pubsub()
        await pubsub.subscribe(*channels)
        return pubsub

    # =========================================================================
    # List Operations (for queues)
    # =========================================================================

    async def lpush(self, key: str, *values: Any) -> int:
        """Push values to the head of a list."""
        serialized = [
            v if isinstance(v, str) else json.dumps(v, default=str)
            for v in values
        ]
        return await self.client.lpush(key, *serialized)

    async def rpop(self, key: str) -> Optional[str]:
        """Pop value from the tail of a list."""
        return await self.client.rpop(key)

    async def lrange(self, key: str, start: int, end: int) -> List[str]:
        """Get range of values from list."""
        return await self.client.lrange(key, start, end)

    async def llen(self, key: str) -> int:
        """Get length of list."""
        return await self.client.llen(key)

    # =========================================================================
    # Counter Operations
    # =========================================================================

    async def incr(self, key: str, amount: int = 1) -> int:
        """Increment counter."""
        return await self.client.incrby(key, amount)

    async def decr(self, key: str, amount: int = 1) -> int:
        """Decrement counter."""
        return await self.client.decrby(key, amount)

    # =========================================================================
    # Cache Utilities
    # =========================================================================

    async def cache_get_or_set(
        self,
        key: str,
        factory,
        expire: int = 300
    ) -> Any:
        """
        Get value from cache or set it using factory function.

        Args:
            key: Cache key
            factory: Async function to generate value if not cached
            expire: Cache expiration in seconds

        Returns:
            Cached or newly generated value
        """
        value = await self.get_json(key)
        if value is not None:
            return value

        value = await factory()
        await self.set_json(key, value, expire)
        return value


# Global Redis manager instance
redis_manager = RedisManager()
