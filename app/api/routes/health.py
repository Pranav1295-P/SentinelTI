from fastapi import APIRouter, HTTPException, status
from sqlalchemy import text

from app.api.deps import SessionDep
from app.core.config import settings
from app.core.redis import get_async_redis

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.get("/ready")
async def ready(session: SessionDep) -> dict:
    try:
        await session.execute(text("SELECT 1"))
        await get_async_redis().ping()
    except Exception:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="Dependencies unavailable") from None
    return {
        "status": "ready",
        "llm": settings.llm_enabled,
        "virustotal": bool(settings.virustotal_api_key.get_secret_value()),
        "otx": bool(settings.otx_api_key.get_secret_value()),
        "graph_db": bool(settings.neo4j_uri),
    }
