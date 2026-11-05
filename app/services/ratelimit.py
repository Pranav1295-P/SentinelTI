"""Fixed-window rate limit backed by Redis."""

from fastapi import HTTPException, status

from app.core.redis import get_async_redis


async def enforce_rate_limit(scope: str, identity: str, per_minute: int) -> None:
    client = get_async_redis()
    key = f"ratelimit:{scope}:{identity}"
    count = await client.incr(key)
    if count == 1:
        await client.expire(key, 60)
    if count > per_minute:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Try again in a minute.",
            headers={"Retry-After": "60"},
        )
