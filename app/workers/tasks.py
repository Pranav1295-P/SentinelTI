"""Celery job that runs the LangGraph pipeline for one analysis."""

import logging
import uuid
from datetime import UTC, datetime

from langgraph.checkpoint.postgres import PostgresSaver

from app.agents.graph import build_pipeline
from app.agents.llm import configure_tracing
from app.core.config import settings
from app.core.db import SyncSessionLocal
from app.models import Analysis, AnalysisStatus
from app.services.events import emit
from app.services.storage import quarantine_path
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

RESULT_KEYS = (
    "triage", "parsed", "yara", "iocs", "string_count", "decoded_strings", "capabilities", "hypotheses",
    "techniques", "notes", "reputation", "verification", "assessment", "narrative", "related", "warnings", "trace",
)


def llm_mode(state: dict) -> str:
    if not settings.llm_enabled:
        return "deterministic"
    return "degraded" if any("LLM unavailable" in w for w in state.get("warnings", [])) else "llm"


def agent_signals(state: dict) -> list[float]:
    """Per-agent strength from 0 to 1, drawn as the coloured strip in the analyses table."""
    triage = state.get("triage") or {}
    parsed = state.get("parsed") or {}
    capabilities = state.get("capabilities") or []
    risk = state["assessment"]["risk"]
    vt = ((state.get("reputation") or {}).get("virustotal") or {}).get("malicious") or 0
    first = 0.9 if triage.get("disguised") else 0.5 if triage.get("entropy", 0) >= 7.2 else 0.05
    second = min(1.0, len((state.get("yara") or {}).get("matches", [])) * 0.25
                 + sum(a["severity"] != "low" for a in parsed.get("anomalies", [])) * 0.15)
    third = min(1.0, sum(c["weight"] for c in capabilities if c["status"] == "proven") / 60)
    fourth = min(1.0, len(state.get("techniques") or []) * 0.15 + min(vt, 20) / 25)
    return [round(v, 2) for v in (first, second, third, fourth, risk / 100)]


def apply_result(row: Analysis, state: dict) -> None:
    assessment = state["assessment"]
    row.status = AnalysisStatus.completed.value
    row.verdict = assessment["verdict"]
    row.tone = assessment["tone"]
    row.risk = assessment["risk"]
    row.family = (state.get("family") or "")[:128] or None
    row.llm_mode = llm_mode(state)
    row.graph = state["graph"]
    row.report_path = state["report_path"]
    row.report_sha256 = state["report_sha256"]
    row.result = {
        **{key: state.get(key) for key in RESULT_KEYS},
        "facts": list(state["facts"].values()),
        "signals": agent_signals(state),
    }
    row.completed_at = datetime.now(UTC)


def run_pipeline(row: Analysis, checkpointer=None) -> dict:
    """Run the graph, resuming from a checkpoint when this job was handed over mid-run."""
    pipeline = build_pipeline(checkpointer)
    config = {"configurable": {"thread_id": str(row.id)}, "recursion_limit": 60}
    if checkpointer is not None and pipeline.get_state(config).next:
        return pipeline.invoke(None, config)
    return pipeline.invoke(
        {
            "analysis_id": str(row.id), "owner_id": str(row.owner_id), "filename": row.filename,
            "sample_path": str(quarantine_path(row.sha256)), "expected_sha256": row.sha256,
            "facts": {}, "warnings": [], "trace": [],
        },
        config,
    )


def _checkpoint_url() -> str:
    return settings.database_url_sync.replace("postgresql+psycopg://", "postgresql://")


@celery_app.task(name="analysis.run", bind=True, acks_late=True)
def run_analysis(self, analysis_id: str) -> str:
    configure_tracing()
    key = uuid.UUID(analysis_id)
    log = {"analysis_id": analysis_id}

    with SyncSessionLocal() as session:
        row = session.get(Analysis, key)
        if row is None or row.status == AnalysisStatus.completed.value:
            return "skipped"
        row.status = AnalysisStatus.running.value
        row.started_at = row.started_at or datetime.now(UTC)
        session.commit()
        emit(analysis_id, "analysis_started", filename=row.filename)
        logger.info("Analysis started", extra=log)

        try:
            with PostgresSaver.from_conn_string(_checkpoint_url()) as checkpointer:
                checkpointer.setup()
                state = run_pipeline(row, checkpointer)
            apply_result(row, state)
            session.commit()
            emit(analysis_id, "analysis_completed", verdict=row.verdict, tone=row.tone, risk=row.risk,
                 family=row.family, llm_mode=row.llm_mode)
            logger.info("Analysis completed", extra=log)
            return row.verdict
        except Exception:
            session.rollback()
            logger.exception("Analysis failed", extra=log)
            row = session.get(Analysis, key)
            row.status = AnalysisStatus.failed.value
            # Details stay in the logs; they can contain paths and file-derived text.
            row.error = "The analysis pipeline failed. See the worker logs."
            row.completed_at = datetime.now(UTC)
            session.commit()
            emit(analysis_id, "analysis_failed", error=row.error)
            return "failed"
