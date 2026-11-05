"""Evidence contracts shared by the tools, the agents and the API.

Every claim the platform makes is a Fact (or cites Facts). This is what the deck
means by "structured evidence, not a vague LLM output".
"""

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high"]


class Fact(BaseModel):
    id: str
    agent: str
    tool: str
    kind: str
    title: str
    detail: str = ""
    severity: Severity = "info"
    # Exact text expected in the file. Agent 5 re-finds it in the raw bytes.
    literal: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    verified: bool | None = None


class Capability(BaseModel):
    id: str
    name: str
    status: Literal["proven", "partial"]
    confidence: float = Field(ge=0, le=1)
    weight: int = 0
    techniques: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    explanation: str = ""


class Technique(BaseModel):
    id: str
    name: str
    tactic: str
    confidence: float = Field(ge=0, le=1)
    capability_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class ThreatNote(BaseModel):
    id: str
    title: str
    source: str
    excerpt: str


# ---- Structured outputs requested from the LLM. Every item must cite evidence ids.


class Hypothesis(BaseModel):
    """An analyst-style hypothesis. Never affects the score; shown as unproven."""

    statement: str = Field(description="One sentence describing the suspected behaviour.")
    evidence_ids: list[str] = Field(description="Fact ids from the evidence that support it.")
    confidence: float = Field(ge=0, le=1)


class HypothesisList(BaseModel):
    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=8)


class NarrativePoint(BaseModel):
    text: str = Field(description="One plain-English sentence for the analyst.")
    evidence_ids: list[str] = Field(description="Fact ids that prove this sentence.")


class Narrative(BaseModel):
    summary: list[NarrativePoint] = Field(default_factory=list, max_length=10)
    recommended_actions: list[str] = Field(default_factory=list, max_length=6)
