"""Redis clients: async for the API, sync for the worker."""

import redis as sync_redis
import redis.asyncio as async_redis

from app.core.config import settings

_async_client: async_redis.Redis | None = None
_sync_client: sync_redis.Redis | None = None


def get_async_redis() -> async_redis.Redis:
    global _async_client
    if _async_client is None:
        _async_client = async_redis.from_url(settings.redis_url, decode_responses=True)
    return _async_client


def get_sync_redis() -> sync_redis.Redis:
    global _sync_client
    if _sync_client is None:
        _sync_client = sync_redis.from_url(settings.redis_url, decode_responses=True)
    return _sync_client
