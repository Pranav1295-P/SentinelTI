import asyncio
import json
import logging
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, File, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import func, select

from app.api.deps import CurrentUser, OwnedAnalysis, SessionDep
from app.core.config import settings
from app.core.redis import get_async_redis
from app.models import Analysis, AnalysisStatus
from app.schemas.analysis import (
    AnalysisDetail,
    AnalysisList,
    AnalysisSummary,
    ChatRequest,
    ChatResponse,
    HashLookupRequest,
    HashLookupResponse,
)
from app.services.chat import answer_question
from app.services.events import stream_key
from app.services.ratelimit import enforce_rate_limit
from app.services.reputation import lookup_hash
from app.services.storage import EmptyUpload, UploadTooLarge, clean_filename, save_upload
from app.workers.tasks import run_analysis

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyses", tags=["analyses"])

STREAM_BLOCK_MS = 15_000


def _summary(row: Analysis) -> AnalysisSummary:
    summary = AnalysisSummary.model_validate(row)
    summary.signals = (row.result or {}).get("signals", [])
    return summary


@router.post("", response_model=AnalysisSummary, status_code=status.HTTP_202_ACCEPTED)
async def create_analysis(file: Annotated[UploadFile, File()], session: SessionDep, user: CurrentUser) -> AnalysisSummary:
    await enforce_rate_limit("upload", str(user.id), settings.upload_rate_per_minute)
    try:
        sha256, size = await save_upload(file)
    except UploadTooLarge:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, detail=f"File is larger than the {settings.max_upload_bytes // (1024 * 1024)} MB limit") from None
    except EmptyUpload:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="The file is empty") from None

    row = Analysis(owner_id=user.id, filename=clean_filename(file.filename), sha256=sha256, size_bytes=size)
    session.add(row)
    await session.commit()
    try:
        run_analysis.delay(str(row.id))
    except Exception:
        row.status = AnalysisStatus.failed.value
        row.error = "The job queue is unavailable."
        await session.commit()
        logger.exception("Could not queue analysis", extra={"analysis_id": str(row.id)})
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="The job queue is unavailable. Try again shortly.") from None
    return _summary(row)


@router.get("", response_model=AnalysisList)
async def list_analyses(
    session: SessionDep,
    user: CurrentUser,
    tone: Annotated[Literal["crit", "warn", "ok"] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AnalysisList:
    filters = [Analysis.owner_id == user.id]
    if tone:
        filters.append(Analysis.tone == tone)
    total = await session.scalar(select(func.count()).select_from(Analysis).where(*filters))
    rows = await session.scalars(select(Analysis).where(*filters).order_by(Analysis.created_at.desc()).limit(limit).offset(offset))
    return AnalysisList(items=[_summary(row) for row in rows], total=total or 0)


@router.post("/lookup", response_model=HashLookupResponse)
async def lookup(body: HashLookupRequest, session: SessionDep, user: CurrentUser) -> HashLookupResponse:
    await enforce_rate_limit("lookup", str(user.id), settings.chat_rate_per_minute)
    sha256 = body.sha256.lower()
    reputation = await asyncio.to_thread(lookup_hash, sha256)
    rows = await session.scalars(
        select(Analysis).where(Analysis.owner_id == user.id, Analysis.sha256 == sha256).order_by(Analysis.created_at.desc()).limit(10)
    )
    return HashLookupResponse(sha256=sha256, reputation=reputation, previous_analyses=[_summary(row) for row in rows])


@router.get("/{analysis_id}", response_model=AnalysisDetail)
async def get_analysis(row: OwnedAnalysis) -> AnalysisDetail:
    detail = AnalysisDetail.model_validate({
        **{field: getattr(row, field) for field in AnalysisSummary.model_fields if field != "signals"},
        "error": row.error, "result": row.result, "has_report": bool(row.report_path),
        "signals": (row.result or {}).get("signals", []),
    })
    return detail


@router.get("/{analysis_id}/graph")
async def get_graph(row: OwnedAnalysis) -> dict:
    if not row.graph:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="The graph is not ready yet")
    return row.graph


@router.get("/{analysis_id}/report.pdf")
async def get_report(row: OwnedAnalysis) -> FileResponse:
    if not row.report_path or not Path(row.report_path).is_file():
        raise HTTPException(status.HTTP_409_CONFLICT, detail="The report is not ready yet")
    stem = "".join(c if c.isalnum() or c in "-_." else "_" for c in row.filename)[:80]
    return FileResponse(row.report_path, media_type="application/pdf", filename=f"sentinelti-{stem}.pdf")


@router.post("/{analysis_id}/chat", response_model=ChatResponse)
async def chat(body: ChatRequest, row: OwnedAnalysis, user: CurrentUser) -> dict:
    await enforce_rate_limit("chat", str(user.id), settings.chat_rate_per_minute)
    if row.status != AnalysisStatus.completed.value:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="The analysis has not finished yet")
    return await answer_question(row, body.message)


@router.get("/{analysis_id}/events")
async def events(row: OwnedAnalysis, request: Request, session: SessionDep) -> StreamingResponse:
    """Server-sent events. Replays from the start (or Last-Event-ID), then follows live."""
    analysis_id = str(row.id)
    start = request.headers.get("last-event-id") or "0-0"
    if not all(part.isdigit() for part in start.split("-")):
        start = "0-0"
    finished_already = row.status in (AnalysisStatus.completed.value, AnalysisStatus.failed.value)
    await session.close()  # A long-lived stream must not hold a database connection.

    async def stream():
        client = get_async_redis()
        key = stream_key(analysis_id)
        cursor = start
        yield "retry: 3000\n\n"
        while not await request.is_disconnected():
            batches = await client.xread({key: cursor}, block=None if finished_already else STREAM_BLOCK_MS, count=100)
            if not batches:
                if finished_already:
                    yield "event: end\ndata: {}\n\n"
                    return
                yield ": keep-alive\n\n"
                continue
            for _, entries in batches:
                for entry_id, fields in entries:
                    cursor = entry_id
                    yield f"id: {entry_id}\ndata: {fields['data']}\n\n"
                    if json.loads(fields["data"])["type"] in ("analysis_completed", "analysis_failed"):
                        yield "event: end\ndata: {}\n\n"
                        return

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
