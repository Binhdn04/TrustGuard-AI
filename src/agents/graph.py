from __future__ import annotations

import asyncio
from datetime import UTC, datetime
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
from src.agents.nodes.planning import build_investigation_plan, plan_next_tool, transition_step
from src.agents.nodes.risk import assess_risk
from src.agents.nodes.rules import build_rule_check_node
from src.agents.nodes.tools import build_inspect_domains_node, build_scan_urls_node, build_verify_claims_node
from src.agents.state import LegacyAgentState, WorkflowState
from src.agents.tools.protocols import BlacklistRepository, ClaimRetriever, DomainIntelligence, UrlScanner
from src.models import InvestigationStepStatus, InvestigationTool


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


def _deadline_reached(state: WorkflowState) -> bool:
    deadline = state.get("deadline_at")
    return deadline is not None and datetime.now(UTC) >= deadline


def _ready_steps(state: WorkflowState):
    statuses = {step.step_id: step.status for step in state.get("investigation_plan", [])}
    return [
        step
        for step in state.get("investigation_plan", [])
        if step.status is InvestigationStepStatus.PENDING
        and all(statuses.get(dependency) is InvestigationStepStatus.COMPLETED for dependency in step.depends_on)
    ]


def _skip_pending(plan):
    for step in list(plan):
        if step.status is InvestigationStepStatus.PENDING:
            plan = transition_step(plan, step.step_id, InvestigationStepStatus.SKIPPED)
    return plan


def _merge_tool_result(working: WorkflowState, base: WorkflowState, update: dict) -> None:
    for key in ("url_findings", "domain_findings", "claim_findings", "evidence", "errors"):
        before = list(base.get(key, []))
        produced = list(update.get(key, before))[len(before) :]
        working[key] = list(working.get(key, [])) + produced  # type: ignore[literal-required]
    limitations = list(working.get("limitations", []))
    base_limitations = list(base.get("limitations", []))
    limitations.extend(list(update.get("limitations", base_limitations))[len(base_limitations) :])
    working["limitations"] = list(dict.fromkeys(limitations))
    attempts = dict(working.get("tool_attempts", {}))
    for key, value in update.get("tool_attempts", {}).items():
        attempts[key] = max(attempts.get(key, 0), value)
    working["tool_attempts"] = attempts
    used_delta = update.get("tool_calls_used", base.get("tool_calls_used", 0)) - base.get("tool_calls_used", 0)
    working["tool_calls_used"] = working.get("tool_calls_used", 0) + max(0, used_delta)


def _build_planning_loop_node(
    url_scanner: UrlScanner | None,
    claim_retriever: ClaimRetriever | None,
    blacklist: BlacklistRepository | None,
    domain_intelligence: DomainIntelligence | None = None,
):
    scan_node = build_scan_urls_node(url_scanner, blacklist)
    claim_node = build_verify_claims_node(claim_retriever)
    domain_node = build_inspect_domains_node(domain_intelligence)

    async def run_step(step, snapshot: WorkflowState) -> dict:
        unit = dict(snapshot)
        unit["tool_target"] = step.target
        if step.tool is InvestigationTool.URL_SCANNER:
            return await scan_node(unit)
        if step.tool is InvestigationTool.DOMAIN_INTELLIGENCE:
            return await domain_node(unit)
        if step.tool is InvestigationTool.CLAIM_RETRIEVER:
            return await claim_node(unit)
        return {}

    async def planning_loop(state: WorkflowState) -> dict:
        """Run bounded independent work in parallel after executor hard gates."""
        working: WorkflowState = dict(state)
        working["investigation_plan"] = build_investigation_plan(working)
        working.setdefault("tool_calls_used", 0)
        working.setdefault("tool_attempts", {})
        working.setdefault("max_tool_calls", 6)
        working.setdefault("max_tool_retries", 1)

        while True:
            decision = plan_next_tool(working)
            if decision.get("next_tool") == "assess":
                if "limitations" in decision:
                    working["limitations"] = decision["limitations"]
                    working["investigation_plan"] = _skip_pending(working["investigation_plan"])
                break
            if _deadline_reached(working):
                limitations = list(working.get("limitations", []))
                limitations.append("Đã hết thời gian dành cho việc gọi công cụ.")
                working["limitations"] = list(dict.fromkeys(limitations))
                working["investigation_plan"] = _skip_pending(working["investigation_plan"])
                break

            ready = _ready_steps(working)
            if not ready:
                limitations = list(working.get("limitations", []))
                limitations.append("Vòng lặp công cụ dừng vì không ghi nhận tiến độ.")
                working["limitations"] = list(dict.fromkeys(limitations))
                working["next_tool"] = "assess"
                break
            gated = []
            for step in ready:
                # Recheck immediately before a coroutine is created. URL/domain
                # work that fails this gate never reaches asyncio.gather.
                if step.tool in {InvestigationTool.URL_SCANNER, InvestigationTool.DOMAIN_INTELLIGENCE}:
                    if working.get("consent_to_scan_urls") is not True:
                        working["investigation_plan"] = transition_step(
                            working["investigation_plan"], step.step_id, InvestigationStepStatus.SKIPPED
                        )
                        continue
                    if step.tool is InvestigationTool.URL_SCANNER and step.target in working.get("blocked_urls", []):
                        working["investigation_plan"] = transition_step(
                            working["investigation_plan"], step.step_id, InvestigationStepStatus.SKIPPED
                        )
                        continue
                gated.append(step)

            remaining = working["max_tool_calls"] - working["tool_calls_used"]
            selected = gated[:remaining]
            if not selected:
                continue
            for step in selected:
                working["investigation_plan"] = transition_step(
                    working["investigation_plan"], step.step_id, InvestigationStepStatus.RUNNING
                )

            snapshot: WorkflowState = dict(working)
            results = await asyncio.gather(*(run_step(step, snapshot) for step in selected))
            for step, update in zip(selected, results, strict=True):
                base_error_count = len(snapshot.get("errors", []))
                _merge_tool_result(working, snapshot, update)
                new_errors = list(update.get("errors", []))[base_error_count:]
                attempt_key = {
                    InvestigationTool.URL_SCANNER: "scan_url",
                    InvestigationTool.DOMAIN_INTELLIGENCE: "domain_intelligence",
                    InvestigationTool.CLAIM_RETRIEVER: "verify_claim",
                }[step.tool]
                attempts = working.get("tool_attempts", {}).get(f"{attempt_key}:{step.target}", 0)
                can_retry = bool(new_errors and new_errors[-1].retryable and attempts <= working["max_tool_retries"])
                status = (
                    InvestigationStepStatus.PENDING
                    if can_retry
                    else InvestigationStepStatus.FAILED
                    if new_errors
                    else InvestigationStepStatus.COMPLETED
                )
                working["investigation_plan"] = transition_step(working["investigation_plan"], step.step_id, status)

        return {
            key: working[key]
            for key in (
                "next_tool",
                "tool_target",
                "tool_calls_used",
                "tool_attempts",
                "investigation_plan",
                "url_findings",
                "domain_findings",
                "claim_findings",
                "evidence",
                "errors",
                "limitations",
            )
            if key in working
        }

    return planning_loop


def build_graph(
    *,
    url_scanner: UrlScanner | None = None,
    domain_intelligence: DomainIntelligence | None = None,
    claim_retriever: ClaimRetriever | None = None,
    blacklist: BlacklistRepository | None = None,
    llm: Any | None = None,
):
    """Build the injectable v2 analysis workflow."""
    graph = StateGraph(WorkflowState)
    graph.add_node("classify_input", _classify_node)
    graph.add_node("extract_indicators", _extract_node)
    graph.add_node("analyze_message", build_analyze_message_node(llm))
    graph.add_node("normalize_and_check_rules", build_rule_check_node(blacklist))
    graph.add_node("plan_tools", build_plan_tools_node(llm))
    graph.add_node(
        "planning_loop",
        _build_planning_loop_node(url_scanner, claim_retriever, blacklist, domain_intelligence),
    )
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
    graph.add_edge("plan_tools", "planning_loop")
    graph.add_edge("planning_loop", "assess_risk")
    graph.add_edge("assess_risk", "review_assessment")
    graph.add_edge("review_assessment", "explain_result")
    graph.add_edge("explain_result", "route_action")
    graph.add_edge("route_action", "generate_response")
    graph.add_edge("generate_response", END)
    return graph.compile()


def should_continue(state: LegacyAgentState) -> str:
    return END if state.get("error") else "respond"


def build_legacy_graph():
    graph = StateGraph(LegacyAgentState)
    graph.add_node("analyze", analyze_node)
    graph.add_node("respond", respond_node)
    graph.set_entry_point("analyze")
    graph.add_edge("analyze", "respond")
    graph.add_edge("respond", END)
    return graph.compile()


def build_openai_graph(**kwargs):
    from src.agents.tools.integration import build_provider_adapters
    from src.config import get_settings
    from src.services.llm import get_llm

    settings = get_settings()
    llm = get_llm() if settings.openai_api_key else None
    owned_adapters = build_provider_adapters(settings)
    for name, adapter in owned_adapters.items():
        kwargs.setdefault(name, adapter)
    graph = build_graph(llm=llm, **kwargs)
    graph._owned_adapters = tuple(owned_adapters.values())
    return graph


async def close_graph_resources(graph) -> None:
    for adapter in getattr(graph, "_owned_adapters", ()):
        close = getattr(adapter, "aclose", None)
        if close is not None:
            await close()


analysis_agent = build_openai_graph()
agent = build_legacy_graph()

__all__ = [
    "agent",
    "analysis_agent",
    "build_graph",
    "build_legacy_graph",
    "build_openai_graph",
    "close_graph_resources",
]
