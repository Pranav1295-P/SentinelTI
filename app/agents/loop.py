"""The workflow from the deck, as one reusable LangGraph subgraph:

    LLM agent -> chooses a tool -> Pydantic validates -> tool runs -> evidence collected -> repeat

The LLM chooses which tools to run and may investigate further, but it cannot skip
a required tool: anything it leaves out is forced before the agent finishes. With
no LLM configured, the same graph runs on the required tools alone.
"""

import logging
import operator
from dataclasses import dataclass, field
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from app.agents.llm import get_llm
from app.agents.prompts import AGENT_PROMPTS
from app.core.config import settings
from app.services.events import emit

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AgentSpec:
    id: str
    name: str
    tools: tuple[BaseTool, ...]
    required: tuple[str, ...]
    default_args: dict[str, dict] = field(default_factory=dict)


def _merge(left: dict, right: dict) -> dict:
    return {**left, **right}


class LoopState(TypedDict, total=False):
    messages: Annotated[list[AnyMessage], add_messages]
    ctx: dict[str, Any]
    outputs: Annotated[dict[str, Any], _merge]
    facts: Annotated[list[dict], operator.add]
    lines: Annotated[list[str], operator.add]
    warnings: Annotated[list[str], operator.add]
    attempted: Annotated[list[str], operator.add]
    rounds: int
    llm_done: bool


def build_loop(spec: AgentSpec):
    llm = get_llm()
    llm_with_tools = llm.bind_tools(list(spec.tools)) if llm else None
    # handle_tool_errors returns a validation failure to the LLM so it can correct itself.
    tool_node = ToolNode(list(spec.tools), handle_tool_errors=True)

    def plan(state: LoopState) -> dict:
        update: dict = {"rounds": state.get("rounds", 0) + 1}
        analysis_id = state["ctx"]["analysis_id"]

        if llm_with_tools and not state.get("llm_done") and state.get("rounds", 0) < settings.agent_max_tool_rounds:
            try:
                reply = llm_with_tools.invoke(state["messages"])
                if reply.tool_calls:
                    return {**update, "messages": [reply]}
                update["messages"] = [reply]
            except Exception as exc:
                logger.warning("LLM call failed", extra={"agent": spec.id, "analysis_id": analysis_id}, exc_info=True)
                update["warnings"] = [f"{spec.name}: LLM unavailable ({type(exc).__name__}), used required tools only"]
            update["llm_done"] = True

        # Nothing further from the LLM: run whatever required tools it did not reach.
        missing = [name for name in spec.required if name not in state.get("attempted", [])]
        if missing:
            calls = [
                {"name": name, "args": spec.default_args.get(name, {}), "id": f"forced-{spec.id}-{name}", "type": "tool_call"}
                for name in missing
            ]
            update["llm_done"] = True
            update["messages"] = update.get("messages", []) + [AIMessage(content="", tool_calls=calls)]
        return update

    def route_after_plan(state: LoopState) -> str:
        last = state["messages"][-1]
        return "tools" if isinstance(last, AIMessage) and last.tool_calls else END

    def collect(state: LoopState) -> dict:
        """Move evidence out of the new tool messages and into state, and report progress."""
        analysis_id = state["ctx"]["analysis_id"]
        outputs, facts, lines, attempted = {}, [], [], []
        for message in reversed(state["messages"]):
            if not isinstance(message, ToolMessage):
                break
            attempted.append(message.name)
            artifact = message.artifact if isinstance(message.artifact, dict) else None
            if message.status == "error" or artifact is None:
                # A rejected LLM call does not count as the required tool having run.
                if not message.tool_call_id.startswith("forced-"):
                    attempted.pop()
                emit(analysis_id, "tool_error", spec.id, tool=message.name)
                continue
            outputs[message.name] = artifact["output"]
            facts.extend({**f, "agent": spec.id} for f in artifact["facts"])
            lines.append(artifact["line"])
            emit(analysis_id, "tool_result", spec.id, tool=message.name, line=artifact["line"])
        return {"outputs": outputs, "facts": facts, "lines": lines, "attempted": attempted}

    def announce_tools(state: LoopState) -> dict:
        last = state["messages"][-1]
        for call in last.tool_calls:
            emit(state["ctx"]["analysis_id"], "tool_call", spec.id, tool=call["name"])
        return {}

    graph = StateGraph(LoopState)
    graph.add_node("plan", plan)
    graph.add_node("announce", announce_tools)
    graph.add_node("tools", tool_node)
    graph.add_node("collect", collect)
    graph.add_edge(START, "plan")
    graph.add_conditional_edges("plan", route_after_plan, {"tools": "announce", END: END})
    graph.add_edge("announce", "tools")
    graph.add_edge("tools", "collect")
    graph.add_edge("collect", "plan")
    return graph.compile()


def run_agent(spec: AgentSpec, ctx: dict, brief: str) -> dict:
    """Run one agent's loop. Returns its tool outputs, new facts, progress lines and warnings."""
    emit(ctx["analysis_id"], "agent_started", spec.id, name=spec.name)
    result = build_loop(spec).invoke(
        {
            "messages": [SystemMessage(AGENT_PROMPTS[spec.id]), HumanMessage(brief)],
            "ctx": ctx, "outputs": {}, "facts": [], "lines": [], "warnings": [], "attempted": [], "rounds": 0,
        },
        {"recursion_limit": 25 + 4 * settings.agent_max_tool_rounds + 4 * len(spec.required)},
    )
    return {k: result.get(k, []) for k in ("facts", "lines", "warnings")} | {"outputs": result.get("outputs", {})}
