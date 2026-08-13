"""Redis caching utilities"""
import json
from typing import Optional
import redis.asyncio as redis
from app.core.config import settings
import structlog

logger = structlog.get_logger(__name__)


class RedisCache:
    """Async Redis cache manager"""

    def __init__(self):
        self.client: Optional[redis.Redis] = None

    async def connect(self) -> None:
        """Initialize Redis connection"""
        try:
            self.client = redis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
            await self.client.ping()
            logger.info("redis_connected", url=settings.REDIS_URL)
        except Exception as e:
            logger.error("redis_connection_failed", error=str(e))
            self.client = None

    async def close(self) -> None:
        """Close Redis connection"""
        if self.client:
            await self.client.close()
            logger.info("redis_closed")

    async def get_cached(self, url_hash: str) -> Optional[dict]:
        """
        Retrieve cached analysis result.

        Args:
            url_hash: SHA256 hash of normalized URL

        Returns:
            Cached result dict or None
        """
        if not self.client:
            return None

        try:
            cached = await self.client.get(f"analysis:{url_hash}")
            if cached:
                return json.loads(cached)
        except Exception as e:
            logger.warning("cache_get_failed", url_hash=url_hash, error=str(e))

        return None

    async def set_cached(
        self, url_hash: str, result: dict, ttl: Optional[int] = None
    ) -> None:
        """
        Store analysis result in cache.

        Args:
            url_hash: SHA256 hash of normalized URL
            result: Analysis result dictionary
            ttl: Time to live in seconds (default: CACHE_TTL)
        """
        if not self.client:
            return

        try:
            ttl = ttl or settings.CACHE_TTL
            await self.client.setex(
                f"analysis:{url_hash}",
                ttl,
                json.dumps(result)
            )
        except Exception as e:
            logger.warning("cache_set_failed", url_hash=url_hash, error=str(e))

    async def is_healthy(self) -> bool:
        """Check if Redis connection is healthy"""
        if not self.client:
            return False

        try:
            await self.client.ping()
            return True
        except Exception:
            return False


cache = RedisCache()
