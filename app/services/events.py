"""Live progress events, stored in one Redis stream per analysis.

A stream gives replay and tailing in one structure, so a browser that connects
late (or reconnects) sees every event in order with no gap.
"""

import json
from datetime import UTC, datetime
from typing import Any

from app.core.redis import get_sync_redis

STREAM_TTL_SECONDS = 24 * 3600
STREAM_MAX_LEN = 2000


def stream_key(analysis_id: str) -> str:
    return f"analysis:{analysis_id}:events"


def emit(analysis_id: str, event_type: str, agent: str | None = None, **data: Any) -> None:
    payload = {
        "type": event_type,
        "agent": agent,
        "ts": datetime.now(UTC).isoformat(),
        **data,
    }
    client = get_sync_redis()
    key = stream_key(analysis_id)
    client.xadd(key, {"data": json.dumps(payload, default=str)}, maxlen=STREAM_MAX_LEN)
    client.expire(key, STREAM_TTL_SECONDS)
