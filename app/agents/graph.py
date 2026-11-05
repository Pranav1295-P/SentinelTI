"""The five-agent pipeline as a LangGraph StateGraph.

    triage -> evidence -> behaviour -> context
           -> verify -> narrate <-> (retry on bad citations) -> publish

verify, narrate and publish together are Agent 5. The graph takes a checkpointer,
so a job handed to another worker resumes from the last finished agent.
"""

import logging
import operator
from pathlib import Path
from typing import Annotated, Any, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

from app.agents import tools as T
from app.agents.llm import get_llm
from app.agents.loop import AgentSpec, run_agent
from app.agents.prompts import AGENT_PROMPTS, untrusted
from app.agents.verify import verify_facts
from app.analysis import scoring
from app.reporting.evidence_graph import build_evidence_graph
from app.reporting.graph_store import sync_and_match
from app.reporting.pdf import render_pdf
from app.schemas.evidence import HypothesisList, Narrative
from app.services.events import emit

logger = logging.getLogger(__name__)
MAX_NARRATIVE_ATTEMPTS = 2
# Section facts are too noisy to list. Notes are general references, not evidence about this file.
NOT_CITABLE = {"section", "note"}

TRIAGE = AgentSpec("triage", "Triage Agent", (T.identify_file_type, T.compute_file_hashes, T.check_file_size),
                   required=("identify_file_type", "compute_file_hashes", "check_file_size"))
EVIDENCE = AgentSpec("evidence", "Evidence Agent",
                     (T.parse_binary_metadata, T.scan_yara_rules, T.extract_strings_and_iocs, T.decode_obfuscated_strings),
                     required=("parse_binary_metadata", "scan_yara_rules", "extract_strings_and_iocs"))
BEHAVIOUR = AgentSpec("behaviour", "Behaviour Hypothesis Agent", (T.correlate_capabilities, T.inspect_imports, T.search_strings),
                      required=("correlate_capabilities",))
CONTEXT_TOOLS = (T.map_attack_techniques, T.search_threat_notes, T.lookup_hash_reputation)


def _merge_facts(left: dict, right: dict) -> dict:
    return {**left, **right}


class AnalysisState(TypedDict, total=False):
    analysis_id: str
    owner_id: str
    sample_path: str
    filename: str
    expected_sha256: str

    facts: Annotated[dict[str, dict], _merge_facts]
    warnings: Annotated[list[str], operator.add]
    trace: Annotated[list[dict], operator.add]

    triage: dict[str, Any]
    parsed: dict[str, Any]
    yara: dict[str, Any]
    iocs: dict[str, Any]
    string_count: int
    decoded_strings: list[str]
    capabilities: list[dict]
    hypotheses: list[dict]
    techniques: list[dict]
    notes: list[dict]
    reputation: dict[str, Any]

    verification: dict[str, Any]
    assessment: dict[str, Any]
    family: str | None
    narrative: dict[str, Any]
    narrative_attempts: int
    narrative_feedback: str
    graph: dict[str, Any]
    related: list[dict]
    report_path: str
    report_sha256: str


def _ctx(state: AnalysisState) -> dict:
    return {
        "analysis_id": state["analysis_id"], "sample_path": state["sample_path"], "filename": state["filename"],
        "triage": state.get("triage"), "parsed": state.get("parsed"), "capabilities": state.get("capabilities", []),
    }


def _finish(state: AnalysisState, spec_id: str, name: str, run: dict, label: str, tone: str = "ok") -> dict:
    emit(state["analysis_id"], "agent_finished", spec_id, name=name, label=label, tone=tone)
    facts = {f["id"]: f for f in run["facts"]}
    return {
        "facts": facts,
        "warnings": run["warnings"],
        "trace": [{"agent": spec_id, "name": name, "lines": run["lines"], "label": label, "tone": tone}],
    }


def triage_node(state: AnalysisState) -> dict:
    brief = "Triage this sample.\n" + untrusted({"submitted_filename": state["filename"]})
    run = run_agent(TRIAGE, _ctx(state), brief)
    out = run["outputs"]
    triage = {**out["identify_file_type"], **out["compute_file_hashes"], **out["check_file_size"]}
    if triage["sha256"] != state["expected_sha256"]:
        raise ValueError("quarantined file does not match its recorded SHA-256")
    return {"triage": triage, **_finish(state, "triage", TRIAGE.name, run, "Validated")}


def evidence_node(state: AnalysisState) -> dict:
    triage = state["triage"]
    brief = "Extract structured evidence from this sample.\n" + untrusted({"type": triage["label"], "entropy": triage["entropy"]})
    run = run_agent(EVIDENCE, _ctx(state), brief)
    out = run["outputs"]
    strings = out["extract_strings_and_iocs"]
    parsed = out["parse_binary_metadata"]
    if parsed.get("error") and triage["is_executable"]:
        run["warnings"].append(f"Evidence Agent: {parsed['error']}")
    return {
        "parsed": parsed,
        "yara": out["scan_yara_rules"],
        "iocs": strings["iocs"],
        "string_count": strings["string_count"],
        "decoded_strings": out.get("decode_obfuscated_strings", {}).get("strings", []),
        **_finish(state, "evidence", EVIDENCE.name, run, "Evidence"),
    }


def _write_hypotheses(state: AnalysisState, capabilities: list[dict], facts: dict[str, dict]) -> tuple[list[dict], list[str]]:
    """Partial chains become hypotheses. The LLM may add more, if it cites real facts."""
    hypotheses = [
        {"statement": f"Possible {c['name'].lower()}: part of the evidence chain is missing.",
         "evidence_ids": c["evidence_ids"], "confidence": c["confidence"], "source": "rules"}
        for c in capabilities if c["status"] == "partial"
    ]
    llm = get_llm()
    if not llm:
        return hypotheses, []
    listing = [{"id": f["id"], "title": f["title"]} for f in facts.values() if f["kind"] not in NOT_CITABLE][:120]
    try:
        reply: HypothesisList = llm.with_structured_output(HypothesisList).invoke([
            SystemMessage(AGENT_PROMPTS["hypotheses"]),
            HumanMessage("Available evidence:\n" + untrusted({"facts": listing, "capabilities": [{"name": c["name"], "status": c["status"]} for c in capabilities]}, 12000)),
        ])
    except Exception as exc:
        logger.warning("Hypothesis call failed", exc_info=True)
        return hypotheses, [f"Behaviour Hypothesis Agent: LLM unavailable ({type(exc).__name__})"]
    for item in reply.hypotheses:
        cited = [i for i in item.evidence_ids if i in facts and facts[i]["kind"] not in NOT_CITABLE]
        if cited:  # A hypothesis with no real citation is discarded.
            hypotheses.append({"statement": item.statement, "evidence_ids": cited, "confidence": item.confidence, "source": "llm"})
    return hypotheses, []


def behaviour_node(state: AnalysisState) -> dict:
    run = run_agent(BEHAVIOUR, _ctx(state), "Correlate the evidence into capabilities.\n" + untrusted({
        "anomalies": [a["title"] for a in (state.get("parsed") or {}).get("anomalies", [])],
        "yara": [m["rule"] for m in (state.get("yara") or {}).get("matches", [])],
    }))
    capabilities = run["outputs"]["correlate_capabilities"]["capabilities"]
    facts = {**state["facts"], **{f["id"]: f for f in run["facts"]}}
    hypotheses, warnings = _write_hypotheses(state, capabilities, facts)
    run["warnings"].extend(warnings)
    for hypothesis in hypotheses:
        run["lines"].append(f"Unproven hypothesis: {hypothesis['statement']}")
        emit(state["analysis_id"], "tool_result", "behaviour", tool="hypothesis", line=f"Unproven hypothesis: {hypothesis['statement']}")
    proven = sum(c["status"] == "proven" for c in capabilities)
    tone = "crit" if proven > 2 else "warn" if proven else "ok"
    label = f"{proven} proven" if proven else "None proven"
    return {"capabilities": capabilities, "hypotheses": hypotheses, **_finish(state, "behaviour", BEHAVIOUR.name, run, label, tone)}


def context_node(state: AnalysisState) -> dict:
    capabilities = state.get("capabilities", [])
    proven = [c["name"] for c in capabilities if c["status"] == "proven"]
    # With nothing proven there is nothing to look up, and a search would only attach unrelated notes.
    tools = CONTEXT_TOOLS if proven else tuple(t for t in CONTEXT_TOOLS if t is not T.search_threat_notes)
    spec = AgentSpec("context", "Threat Context Agent", tools,
                     required=tuple(t.name for t in tools),
                     default_args={"search_threat_notes": {"query": " ".join(proven)[:200]}})
    run = run_agent(spec, _ctx(state), "Add threat context to these findings.\n" + untrusted({"proven_capabilities": proven}))
    out = run["outputs"]
    techniques = out["map_attack_techniques"]["techniques"]
    return {
        "techniques": techniques,
        "notes": out.get("search_threat_notes", {}).get("notes", []),
        "reputation": out["lookup_hash_reputation"],
        **_finish(state, "context", spec.name, run, "Mapped"),
    }


def verify_node(state: AnalysisState) -> dict:
    """Agent 5, step 1: check every fact once against the file, then score what survives."""
    emit(state["analysis_id"], "agent_started", "report", name="Explainability & PDF Agent")
    facts, capabilities, techniques, summary = verify_facts(state)
    verified_state = {**state, "facts": facts, "capabilities": capabilities}
    assessment = scoring.score(verified_state)
    family = scoring.attribute_family(verified_state)
    line = f"Verified {summary['verified']} of {summary['checked']} facts against the file"
    if summary["failed"]:
        line += f" · {summary['failed']} rejected"
    emit(state["analysis_id"], "tool_result", "report", tool="verify_facts", line=line)
    return {
        "facts": facts, "capabilities": capabilities, "techniques": techniques, "verification": summary,
        "assessment": assessment, "family": family, "narrative_attempts": 0,
        "trace": [{"agent": "report", "name": "Explainability & PDF Agent", "lines": [line], "label": "Report", "tone": "ok"}],
    }


def fallback_narrative(state: AnalysisState) -> dict:
    assessment = state["assessment"]
    points = [
        {"text": f"{item['reason']} (+{item['points']}).", "evidence_ids": item["evidence_ids"]}
        for item in assessment["breakdown"]
    ]
    if not points:
        points = [{"text": "Static analysis found no capability, packer, rule hit or disguise. This does not prove the file is safe.", "evidence_ids": ["file:type"]}]
    actions = {
        "Critical": ["Isolate any host that ran this file.", "Block the listed indicators.", "Search your fleet for this SHA-256."],
        "Malicious": ["Do not run this file outside an isolated lab.", "Block the listed indicators.", "Search your fleet for this SHA-256."],
        "Suspicious": ["Review the evidence before trusting this file.", "Run it only in an isolated sandbox."],
        "Clean": ["No action needed based on static evidence. Packed or dynamic behaviour would not be visible here."],
    }[assessment["verdict"]]
    return {"summary": points, "recommended_actions": actions, "source": "rules"}


def narrate_node(state: AnalysisState) -> dict:
    """Agent 5, step 2: explain the verdict. Uncited sentences are removed."""
    llm = get_llm()
    attempts = state.get("narrative_attempts", 0) + 1
    if not llm:
        return {"narrative": fallback_narrative(state), "narrative_attempts": attempts, "narrative_feedback": ""}

    facts = state["facts"]
    verified = [{"id": f["id"], "title": f["title"], "detail": f["detail"][:200]} for f in facts.values() if f.get("verified") and f["kind"] not in NOT_CITABLE][:120]
    payload = {
        "verdict": state["assessment"]["verdict"], "risk": state["assessment"]["risk"], "family": state.get("family"),
        "score_breakdown": state["assessment"]["breakdown"],
        "capabilities": [{"name": c["name"], "status": c["status"], "evidence_ids": c["evidence_ids"]} for c in state["capabilities"]],
        "techniques": [t["id"] for t in state.get("techniques", [])],
        "verified_facts": verified,
    }
    messages = [SystemMessage(AGENT_PROMPTS["narrative"]), HumanMessage("Explain this result.\n" + untrusted(payload, 16000))]
    if state.get("narrative_feedback"):
        messages.append(HumanMessage(state["narrative_feedback"]))
    try:
        reply: Narrative = llm.with_structured_output(Narrative).invoke(messages)
    except Exception as exc:
        logger.warning("Narrative call failed", exc_info=True)
        return {
            "narrative": fallback_narrative(state), "narrative_attempts": MAX_NARRATIVE_ATTEMPTS, "narrative_feedback": "",
            "warnings": [f"Explainability Agent: LLM unavailable ({type(exc).__name__}), used rule-based explanation"],
        }

    valid = {f["id"] for f in verified}
    kept, dropped = [], []
    for point in reply.summary:
        cited = [i for i in point.evidence_ids if i in valid]
        (kept if cited else dropped).append({"text": point.text, "evidence_ids": cited})

    feedback = ""
    if dropped and attempts < MAX_NARRATIVE_ATTEMPTS:
        feedback = "These sentences cited no verified fact id, so they were rejected. Rewrite them with real ids, or remove them:\n" + untrusted([d["text"] for d in dropped])
    narrative = {"summary": kept, "recommended_actions": reply.recommended_actions, "source": "llm"}
    if not kept:
        narrative = fallback_narrative(state)
    warnings = [f"Explainability Agent: removed {len(dropped)} uncited sentences"] if dropped and not feedback else []
    return {"narrative": narrative, "narrative_attempts": attempts, "narrative_feedback": feedback, "warnings": warnings}


def route_narrative(state: AnalysisState) -> str:
    return "narrate" if state.get("narrative_feedback") else "publish"


def publish_node(state: AnalysisState) -> dict:
    """Agent 5, step 3: graph evidence, graph-database matching and the PDF report."""
    analysis_id = state["analysis_id"]
    warnings: list[str] = []
    related, status = sync_and_match(state)
    if status == "error":
        warnings.append("Graph database unreachable; related samples were not matched")
    state = {**state, "related": related}
    graph = build_evidence_graph(state)
    emit(analysis_id, "tool_result", "report", tool="build_evidence_graph",
         line=f"Evidence graph: {len(graph['nodes'])} nodes, {len(graph['edges'])} links"
              + (f" · {len(related)} related samples" if related else ""))

    path, digest = render_pdf({**state, "graph": graph})
    emit(analysis_id, "tool_result", "report", tool="render_pdf", line="PDF report ready")
    assessment = state["assessment"]
    emit(analysis_id, "agent_finished", "report", name="Explainability & PDF Agent", label="Report", tone="ok")
    return {
        "graph": graph, "related": related, "report_path": str(Path(path)), "report_sha256": digest, "warnings": warnings,
        "trace": [{"agent": "report", "name": "Explainability & PDF Agent",
                   "lines": [f"Verdict {assessment['verdict']} · risk {assessment['risk']}"], "label": "Report", "tone": "ok"}],
    }


def build_pipeline(checkpointer=None):
    graph = StateGraph(AnalysisState)
    graph.add_node("triage", triage_node)
    graph.add_node("evidence", evidence_node)
    graph.add_node("behaviour", behaviour_node)
    graph.add_node("context", context_node)
    graph.add_node("verify", verify_node)
    graph.add_node("narrate", narrate_node)
    graph.add_node("publish", publish_node)
    graph.add_edge(START, "triage")
    graph.add_edge("triage", "evidence")
    graph.add_edge("evidence", "behaviour")
    graph.add_edge("behaviour", "context")
    graph.add_edge("context", "verify")
    graph.add_edge("verify", "narrate")
    graph.add_conditional_edges("narrate", route_narrative, {"narrate": "narrate", "publish": "publish"})
    graph.add_edge("publish", END)
    return graph.compile(checkpointer=checkpointer)
