import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AnalysisSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    filename: str
    sha256: str
    size_bytes: int
    status: str
    verdict: str | None
    tone: str | None
    risk: int | None
    family: str | None
    llm_mode: str | None
    created_at: datetime
    completed_at: datetime | None
    signals: list[float] = Field(default_factory=list)


class AnalysisDetail(AnalysisSummary):
    error: str | None
    result: dict[str, Any] | None
    has_report: bool


class AnalysisList(BaseModel):
    items: list[AnalysisSummary]
    total: int


class HashLookupRequest(BaseModel):
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class HashLookupResponse(BaseModel):
    sha256: str
    reputation: dict[str, Any]
    previous_analyses: list[AnalysisSummary]


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)


class ChatResponse(BaseModel):
    answer: str
    evidence_ids: list[str]
    mode: str
