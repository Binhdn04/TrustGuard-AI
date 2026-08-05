from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from src.agents.nodes.example_node import analyze_node, respond_node
from src.agents.nodes.explanation import explain_result, route_action
from src.agents.nodes.extraction import classify_input, extract_indicators
from src.agents.nodes.llm import (
    build_analyze_message_node,
    build_generate_response_node,
    build_plan_tools_node,
    build_review_assessment_node,
)
from src.agents.nodes.planning import plan_next_tool
from src.agents.nodes.risk import assess_risk
from src.agents.nodes.rules import build_rule_check_node
from src.agents.nodes.tools import build_scan_urls_node, build_verify_claims_node
from src.agents.state import LegacyAgentState, WorkflowState
from src.agents.tools.protocols import BlacklistRepository, ClaimRetriever, UrlScanner


async def _classify_node(state: WorkflowState) -> dict:
    return classify_input(state)


async def _extract_node(state: WorkflowState) -> dict:
    return extract_indicators(state)


async def _assess_node(state: WorkflowState) -> dict:
    return assess_risk(state)


async def _explain_node(state: WorkflowState) -> dict:
    return explain_result(state)


async def _action_node(state: WorkflowState) -> dict:
    return route_action(state)


def _route_after_rules(state: WorkflowState) -> str:
    has_scannable_url = bool(
        state.get("consent_to_scan_urls")
        and set(state.get("normalized_urls", [])) - set(state.get("blocked_urls", []))
    )
    return "plan" if has_scannable_url or state.get("claims") else "assess"


def _build_planning_loop_node(
    url_scanner: UrlScanner | None,
    claim_retriever: ClaimRetriever | None,
    blacklist: BlacklistRepository | None,
):
    scan_node = build_scan_urls_node(url_scanner, blacklist)
    claim_node = build_verify_claims_node(claim_retriever)

    async def planning_loop(state: WorkflowState) -> dict:
        """Execute the bounded plan/act/observe loop inside one graph node.

        Keeping the loop state-local avoids coupling checkpoints to adapter
        objects while retaining an explicit conditional branch in LangGraph.
        """
        working: WorkflowState = dict(state)
        while True:
            plan = plan_next_tool(working)
            working.update(plan)
            route = plan["next_tool"]
            if route == "assess":
                break
            calls_before = working.get("tool_calls_used", 0)
            update = await (scan_node(working) if route == "scan_url" else claim_node(working))
            working.update(update)
            if working.get("tool_calls_used", 0) <= calls_before:
                # Tool nodes normally advance the counter before doing I/O. If
                # that contract regresses, stop safely instead of spinning on
                # the same plan forever.
                limitations = list(working.get("limitations", []))
                limitations.append("Vòng lặp công cụ dừng vì không ghi nhận tiến độ.")
                working.update({
                    "next_tool": "assess",
                    "tool_target": "assessment",
                    "limitations": list(dict.fromkeys(limitations)),
                })
                break
        return {
            key: working[key]
            for key in (
                "next_tool", "tool_target", "tool_calls_used", "tool_attempts",
                "url_findings", "claim_findings", "evidence", "errors", "limitations",
            )
            if key in working
        }

    return planning_loop


def build_graph(
    *,
    url_scanner: UrlScanner | None = None,
    claim_retriever: ClaimRetriever | None = None,
    blacklist: BlacklistRepository | None = None,
    llm: Any | None = None,
):
    """Build the injectable LangGraph analysis workflow.

    Adapters are captured by node closures and are never serialized into state.
    This keeps provider SDKs outside orchestration and makes fixture runs offline.
    """
    graph = StateGraph(WorkflowState)
    graph.add_node("classify_input", _classify_node)
    graph.add_node("extract_indicators", _extract_node)
    graph.add_node("analyze_message", build_analyze_message_node(llm))
    graph.add_node("normalize_and_check_rules", build_rule_check_node(blacklist))
    graph.add_node("plan_tools", build_plan_tools_node(llm))
    graph.add_node("planning_loop", _build_planning_loop_node(url_scanner, claim_retriever, blacklist))
    graph.add_node("assess_risk", _assess_node)
    graph.add_node("review_assessment", build_review_assessment_node(llm))
    graph.add_node("explain_result", _explain_node)
    graph.add_node("route_action", _action_node)
    graph.add_node("generate_response", build_generate_response_node(llm))

    graph.set_entry_point("classify_input")
    graph.add_edge("classify_input", "extract_indicators")
    graph.add_edge("extract_indicators", "analyze_message")
    graph.add_edge("analyze_message", "normalize_and_check_rules")
    graph.add_edge("normalize_and_check_rules", "plan_tools")
    graph.add_conditional_edges(
        "plan_tools",
        _route_after_rules,
        {"plan": "planning_loop", "assess": "assess_risk"},
    )
    graph.add_edge("planning_loop", "assess_risk")
    graph.add_edge("assess_risk", "review_assessment")
    graph.add_edge("review_assessment", "explain_result")
    graph.add_edge("explain_result", "route_action")
    graph.add_edge("route_action", "generate_response")
    graph.add_edge("generate_response", END)
    return graph.compile()


def should_continue(state: LegacyAgentState) -> str:
    """Compatibility router used by the starter graph."""
    return END if state.get("error") else "respond"


def build_legacy_graph():
    """Retain the starter graph until the API owner migrates `/chat`."""
    graph = StateGraph(LegacyAgentState)
    graph.add_node("analyze", analyze_node)
    graph.add_node("respond", respond_node)
    graph.set_entry_point("analyze")
    graph.add_edge("analyze", "respond")
    graph.add_edge("respond", END)
    return graph.compile()


def build_openai_graph(**kwargs):
    """Build the production graph; remains offline when no API key is configured."""
    from src.agents.tools.integration import build_provider_adapters
    from src.config import get_settings
    from src.services.llm import get_llm

    settings = get_settings()
    llm = get_llm() if settings.openai_api_key else None
    for name, adapter in build_provider_adapters(settings).items():
        kwargs.setdefault(name, adapter)
    return build_graph(llm=llm, **kwargs)


# Preferred graph for Analysis service integration. In CI it degrades offline.
analysis_agent = build_openai_graph()
# Backward compatibility for the existing `/chat` endpoint and starter tests.
agent = build_legacy_graph()

__all__ = [
    "agent", "analysis_agent", "build_graph", "build_legacy_graph", "build_openai_graph",
]
