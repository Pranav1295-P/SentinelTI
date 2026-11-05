import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

JsonType = JSON().with_variant(JSONB(), "postgresql")


class AnalysisStatus(enum.StrEnum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class Analysis(Base):
    __tablename__ = "analyses"
    __table_args__ = (Index("ix_analyses_owner_created", "owner_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))

    # Display name only. The quarantined file is addressed by sha256, never by this.
    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger)

    status: Mapped[str] = mapped_column(String(16), default=AnalysisStatus.queued.value)
    error: Mapped[str | None] = mapped_column(Text)

    verdict: Mapped[str | None] = mapped_column(String(16))
    tone: Mapped[str | None] = mapped_column(String(8))
    risk: Mapped[int | None] = mapped_column(Integer)
    family: Mapped[str | None] = mapped_column(String(128))
    llm_mode: Mapped[str | None] = mapped_column(String(16))

    result: Mapped[dict[str, Any] | None] = mapped_column(JsonType)
    graph: Mapped[dict[str, Any] | None] = mapped_column(JsonType)
    report_path: Mapped[str | None] = mapped_column(String(512))
    report_sha256: Mapped[str | None] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
