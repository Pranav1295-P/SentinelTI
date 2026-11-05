"""Questions about a finished analysis, answered only from its stored evidence."""

import logging
import re

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from app.agents.llm import get_llm
from app.agents.prompts import AGENT_PROMPTS, untrusted
from app.models import Analysis

logger = logging.getLogger(__name__)


class _Answer(BaseModel):
    answer: str = Field(description="A direct answer in plain English.")
    evidence_ids: list[str] = Field(default_factory=list, description="Fact ids relied on.")


def _rule_answer(row: Analysis, question: str) -> tuple[str, list[str]]:
    result = row.result or {}
    assessment = result.get("assessment") or {}
    iocs = result.get("iocs") or {}
    triage = result.get("triage") or {}
    if re.search(r"ioc|indicator|url|\bip\b|domain|c2", question, re.I):
        items = [v for kind in ("urls", "ips", "domains") for v in iocs.get(kind, [])][:15]
        if not items:
            return "No network indicators were recovered from the strings.", []
        return "Indicators found: " + ", ".join(items), []
    if re.search(r"hash|sha|md5", question, re.I):
        return f"SHA-256 {triage.get('sha256')}, MD5 {triage.get('md5')}, ssdeep {triage.get('ssdeep') or 'n/a'}.", ["file:sha256"]
    if re.search(r"att&?ck|mitre|technique", question, re.I):
        techniques = result.get("techniques") or []
        return ("Mapped techniques: " + ", ".join(f"{t['id']} ({t['name']})" for t in techniques)) if techniques else "No ATT&CK techniques were mapped.", []
    if re.search(r"why|explain|reason|suspicious|malicious|verdict|score|risk", question, re.I):
        items = assessment.get("breakdown") or []
        if not items:
            return f"{row.filename} scored {row.risk}: no capability, packer, rule hit or disguise was proven.", []
        reasons = "; ".join(f"{i['reason']} (+{i['points']})" for i in items)
        return f"{row.filename} scored {row.risk} because: {reasons}.", [e for i in items for e in i["evidence_ids"]][:10]
    return ("Free-form answers need an LLM key, which is not configured yet. "
            "I can already explain the verdict, list indicators, show hashes or list ATT&CK techniques."), []


async def answer_question(row: Analysis, question: str) -> dict:
    llm = get_llm()
    if llm is None:
        answer, ids = _rule_answer(row, question)
        return {"answer": answer, "evidence_ids": ids, "mode": "rules"}

    result = row.result or {}
    facts = {f["id"]: f for f in result.get("facts", []) if f.get("verified")}
    evidence = {
        "file": row.filename, "verdict": row.verdict, "risk": row.risk, "family": row.family,
        "score_breakdown": (result.get("assessment") or {}).get("breakdown"),
        "capabilities": [{"name": c["name"], "status": c["status"], "evidence_ids": c["evidence_ids"]} for c in result.get("capabilities", [])],
        "techniques": [t["id"] for t in result.get("techniques", [])],
        "iocs": result.get("iocs"),
        "facts": [{"id": f["id"], "title": f["title"], "detail": f["detail"][:160]} for f in facts.values()][:150],
    }
    try:
        reply: _Answer = await llm.with_structured_output(_Answer).ainvoke([
            SystemMessage(AGENT_PROMPTS["chat"]),
            HumanMessage("Evidence for this analysis:\n" + untrusted(evidence, 20000)),
            HumanMessage(f"Analyst question: {question}"),
        ])
    except Exception:
        logger.warning("Chat LLM call failed", exc_info=True)
        answer, ids = _rule_answer(row, question)
        return {"answer": answer, "evidence_ids": ids, "mode": "rules"}
    return {"answer": reply.answer, "evidence_ids": [i for i in reply.evidence_ids if i in facts], "mode": "llm"}
