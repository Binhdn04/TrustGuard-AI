from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from langgraph.graph import END, StateGraph

from src.agents.chatbot import build_chatbot_node
from src.agents.contracts import LiveStepTransition
from src.agents.fact_check import ExtractedClaim, FactCheckOrchestrator, registrable_domain
from src.agents.nodes.explanation import explain_result, route_action
from src.agents.nodes.extraction import classify_input, extract_indicators
from src.agents.nodes.llm import (
    build_analyze_message_node,
    build_generate_response_node,
    build_plan_tools_node,
    build_review_assessment_node,
)
from src.agents.nodes.planning import build_investigation_plan, plan_next_tool, transition_step
from src.agents.nodes.provisional import build_provisional_warning
from src.agents.nodes.risk import assess_risk
from src.agents.nodes.rules import build_rule_check_node
from src.agents.nodes.tools import (
    build_inspect_domains_node,
    build_resolve_redirects_node,
    build_scan_urls_node,
    build_verify_claims_node,
)
from src.agents.seams import (
    CampaignDetector,
    ExplanationEngine,
    FunctionExplanationEngine,
    FunctionRiskEngine,
    NullCampaignDetector,
    NullProgressSink,
    NullProvisionalWarningSink,
    ProgressSink,
    ProvisionalWarningSink,
    RiskEngine,
)
from src.agents.state import LegacyAgentState, WorkflowState
from src.agents.tools.protocols import (
    BlacklistRepository,
    ClaimRetriever,
    DomainIntelligence,
    FactCheckCorpus,
    RedirectResolver,
    ToolExecutionLedger,
    UrlReputationCascade,
    UrlScanner,
)
from src.models import InvestigationStepStatus, InvestigationTool, ToolError


async def _classify_node(state: WorkflowState) -> dict:
    return classify_input(state)


async def _extract_node(state: WorkflowState) -> dict:
    return extract_indicators(state)


async def _action_node(state: WorkflowState) -> dict:
    return {
        **route_action(state),
        "active_warning": "final",
        "provisional_warning": None,
    }


def _deadline_reached(state: WorkflowState, clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> bool:
    deadline = state.get("deadline_at")
    return deadline is not None and clock() >= deadline


def _ready_steps(state: WorkflowState):
    statuses = {step.step_id: step.status for step in state.get("investigation_plan", [])}
    return [
        step
        for step in state.get("investigation_plan", [])
        if step.status is InvestigationStepStatus.PENDING
        and all(statuses.get(dependency) is InvestigationStepStatus.COMPLETED for dependency in step.depends_on)
    ]


def _merge_tool_result(working: WorkflowState, base: WorkflowState, update: dict) -> None:
    for key in ("url_findings", "domain_findings", "claim_findings", "evidence", "errors", "tool_usage_refs"):
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
    for key in ("tool_cost_used_usd", "tool_tokens_used"):
        delta = update.get(key, base.get(key, 0)) - base.get(key, 0)
        working[key] = working.get(key, 0) + max(0, delta)  # type: ignore[literal-required]


def _build_planning_loop_node(
    url_scanner: UrlScanner | None,
    claim_retriever: ClaimRetriever | None,
    blacklist: BlacklistRepository | None,
    domain_intelligence: DomainIntelligence | None = None,
    redirect_resolver: RedirectResolver | None = None,
    url_reputation: UrlReputationCascade | None = None,
    execution_ledger: ToolExecutionLedger | None = None,
    progress_sink: ProgressSink | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    fact_check_corpus: FactCheckCorpus | None = None,
    fact_check_orchestrator: FactCheckOrchestrator | None = None,
):
    progress_sink = progress_sink or NullProgressSink()
    scan_node = build_scan_urls_node(url_scanner, blacklist, url_reputation)
    claim_node = build_verify_claims_node(claim_retriever, fact_check_corpus)
    domain_node = build_inspect_domains_node(domain_intelligence)
    redirect_node = build_resolve_redirects_node(redirect_resolver)

    adapters = {
        InvestigationTool.URL_SCANNER: url_reputation or url_scanner,
        InvestigationTool.REDIRECT_RESOLVER: redirect_resolver,
        InvestigationTool.DOMAIN_INTELLIGENCE: domain_intelligence,
        InvestigationTool.CLAIM_RETRIEVER: fact_check_corpus or claim_retriever,
    }

    def provider_for(tool: InvestigationTool) -> str | None:
        if tool not in adapters:
            return None
        adapter = adapters[tool]
        if adapter is None:
            if tool is InvestigationTool.REDIRECT_RESOLVER:
                return None
            return "not-configured"
        return str(getattr(adapter, "provider", f"{type(adapter).__module__}.{type(adapter).__qualname__}"))

    async def run_step(step, snapshot: WorkflowState) -> dict:
        unit = dict(snapshot)
        unit["tool_target"] = step.target
        if step.tool is InvestigationTool.URL_SCANNER:
            return await scan_node(unit)
        if step.tool is InvestigationTool.REDIRECT_RESOLVER:
            return await redirect_node(unit)
        if step.tool is InvestigationTool.DOMAIN_INTELLIGENCE:
            return await domain_node(unit)
        if step.tool is InvestigationTool.CLAIM_RETRIEVER:
            return await claim_node(unit)
        return {}

    async def planning_loop(state: WorkflowState) -> dict:
        """Run bounded independent work in parallel after executor hard gates."""
        working: WorkflowState = dict(state)
        active_progress_sink = working.get("runtime_progress_sink") or progress_sink
        working["enable_redirect_resolution"] = redirect_resolver is not None
        working["investigation_plan"] = build_investigation_plan(working)
        if fact_check_orchestrator is not None:
            # The Wave 2 orchestrator owns all claims as one batch. Per-claim
            # compatibility steps must never trigger duplicate embedding calls.
            for step in list(working["investigation_plan"]):
                if step.tool is InvestigationTool.CLAIM_RETRIEVER and step.status is InvestigationStepStatus.PENDING:
                    working["investigation_plan"] = transition_step(
                        working["investigation_plan"], step.step_id, InvestigationStepStatus.SKIPPED
                    )
        working.setdefault("step_transitions", [])
        working.setdefault("tool_usage_refs", [])
        working.setdefault("tool_calls_used", 0)
        working.setdefault("tool_attempts", {})
        working.setdefault("max_tool_calls", 6)
        working.setdefault("max_tool_retries", 1)
        working.setdefault("tool_cost_used_usd", 0.0)
        working.setdefault("tool_tokens_used", 0)
        working.setdefault("max_tool_cost_usd", float("inf"))
        working.setdefault("max_tool_tokens", 2**31 - 1)

        async def record_transition(step, *, force: bool = False) -> None:
            transitions = list(working.get("step_transitions", []))
            if not force and transitions:
                previous = next((item for item in reversed(transitions) if item.step_id == step.step_id), None)
                if previous is not None and previous.status is step.status:
                    return
            transition = LiveStepTransition(
                step_id=step.step_id,
                tool=step.tool,
                target=step.target,
                reason_code=step.reason_code,
                depends_on=list(step.depends_on),
                status=step.status,
                occurred_at=clock(),
            )
            transitions.append(transition)
            working["step_transitions"] = transitions
            await active_progress_sink.emit(transition.model_copy(deep=True))

        async def set_step_status(step_id: str, status: InvestigationStepStatus) -> None:
            before = next(step for step in working["investigation_plan"] if step.step_id == step_id)
            working["investigation_plan"] = transition_step(working["investigation_plan"], step_id, status)
            after = next(step for step in working["investigation_plan"] if step.step_id == step_id)
            if after.status is not before.status:
                await record_transition(after)

        for step in working["investigation_plan"]:
            if not any(item.step_id == step.step_id for item in working["step_transitions"]):
                await record_transition(step, force=True)

        async def skip_pending() -> None:
            for step in list(working["investigation_plan"]):
                if step.status is InvestigationStepStatus.PENDING:
                    await set_step_status(step.step_id, InvestigationStepStatus.SKIPPED)

        while True:
            decision = plan_next_tool(working)
            if decision.get("next_tool") == "assess":
                if "limitations" in decision:
                    working["limitations"] = decision["limitations"]
                    await skip_pending()
                break
            if _deadline_reached(working, clock):
                limitations = list(working.get("limitations", []))
                limitations.append("Đã hết thời gian dành cho việc gọi công cụ.")
                working["limitations"] = list(dict.fromkeys(limitations))
                await skip_pending()
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
                if step.tool in {
                    InvestigationTool.URL_SCANNER,
                    InvestigationTool.REDIRECT_RESOLVER,
                    InvestigationTool.DOMAIN_INTELLIGENCE,
                }:
                    if step.tool is InvestigationTool.REDIRECT_RESOLVER and redirect_resolver is None:
                        gated.append(step)
                        continue
                    if working.get("consent_to_scan_urls") is not True:
                        await set_step_status(step.step_id, InvestigationStepStatus.SKIPPED)
                        continue
                    if step.tool in {
                        InvestigationTool.URL_SCANNER,
                        InvestigationTool.REDIRECT_RESOLVER,
                    } and step.target in working.get("blocked_urls", []):
                        await set_step_status(step.step_id, InvestigationStepStatus.SKIPPED)
                        continue
                gated.append(step)

            if (
                working["tool_cost_used_usd"] >= working["max_tool_cost_usd"]
                or working["tool_tokens_used"] >= working["max_tool_tokens"]
            ):
                limitations = list(working.get("limitations", []))
                limitations.append("Đã dùng hết ngân sách chi phí/token cho công cụ.")
                working["limitations"] = list(dict.fromkeys(limitations))
                await skip_pending()
                break
            remaining = working["max_tool_calls"] - working["tool_calls_used"]
            selected = []
            selected_providers: list[str] = []
            for step in gated[:remaining]:
                provider = provider_for(step.tool)
                if provider is None:
                    errors = list(working.get("errors", []))
                    errors.append(
                        ToolError(
                            tool=step.tool.value,
                            code="UNSUPPORTED_TOOL",
                            message="Investigation tool is not supported by this executor",
                            retryable=False,
                        )
                    )
                    working["errors"] = errors
                    await set_step_status(step.step_id, InvestigationStepStatus.FAILED)
                    continue
                analysis_id = working.get("analysis_id")
                if execution_ledger is not None and analysis_id:
                    try:
                        claimed = await execution_ledger.claim_tool_execution(
                            str(analysis_id), step.step_id, step.target, provider
                        )
                    except Exception:
                        errors = list(working.get("errors", []))
                        errors.append(
                            ToolError(
                                tool=step.tool.value,
                                code="EXECUTION_LEDGER_ERROR",
                                message="Tool execution could not be claimed",
                                retryable=True,
                            )
                        )
                        working["errors"] = errors
                        await set_step_status(step.step_id, InvestigationStepStatus.FAILED)
                        continue
                    if not claimed:
                        await set_step_status(step.step_id, InvestigationStepStatus.SKIPPED)
                        continue
                selected.append(step)
                selected_providers.append(provider)
            if not selected:
                limitations = list(working.get("limitations", []))
                limitations.append("Vòng lặp công cụ dừng vì không còn bước vượt qua policy gate.")
                working["limitations"] = list(dict.fromkeys(limitations))
                working["next_tool"] = "assess"
                break
            for step in selected:
                await set_step_status(step.step_id, InvestigationStepStatus.RUNNING)

            snapshot: WorkflowState = dict(working)
            timeout_at = None
            if working.get("deadline_at") is not None:
                remaining_seconds = max(0.0, (working["deadline_at"] - clock()).total_seconds())
                timeout_at = asyncio.get_running_loop().time() + remaining_seconds

            async def run_with_deadline(step):
                if timeout_at is None:
                    return await run_step(step, snapshot)
                try:
                    # All selected tools share one absolute deadline. Time
                    # spent scheduling sibling tasks cannot extend the budget.
                    async with asyncio.timeout_at(timeout_at):
                        return await run_step(step, snapshot)
                except TimeoutError:
                    return {
                        "errors": list(snapshot.get("errors", []))
                        + [
                            ToolError(
                                tool=step.tool.value,
                                code="PROVIDER_TIMEOUT",
                                message="Tool call exceeded the analysis deadline",
                                retryable=False,
                            )
                        ],
                        "limitations": list(snapshot.get("limitations", []))
                        + ["Đã hết thời gian dành cho việc gọi công cụ."],
                    }

            results = await asyncio.gather(*(run_with_deadline(step) for step in selected))
            for step, provider, update in zip(selected, selected_providers, results, strict=True):
                base_error_count = len(snapshot.get("errors", []))
                _merge_tool_result(working, snapshot, update)
                new_errors = list(update.get("errors", []))[base_error_count:]
                attempt_key = {
                    InvestigationTool.URL_SCANNER: "scan_url",
                    InvestigationTool.REDIRECT_RESOLVER: "resolve_redirect",
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
                await set_step_status(step.step_id, status)
                analysis_id = working.get("analysis_id")
                if execution_ledger is not None and analysis_id:
                    await execution_ledger.finish_tool_execution(
                        str(analysis_id),
                        step.step_id,
                        step.target,
                        provider,
                        "failed" if new_errors else "completed",
                    )

        return {
            key: working[key]
            for key in (
                "next_tool",
                "tool_target",
                "tool_calls_used",
                "tool_cost_used_usd",
                "tool_tokens_used",
                "tool_attempts",
                "investigation_plan",
                "url_findings",
                "domain_findings",
                "claim_findings",
                "evidence",
                "errors",
                "limitations",
                "step_transitions",
                "tool_usage_refs",
            )
            if key in working
        }

    return planning_loop


def build_graph(
    *,
    url_scanner: UrlScanner | None = None,
    url_reputation: UrlReputationCascade | None = None,
    redirect_resolver: RedirectResolver | None = None,
    domain_intelligence: DomainIntelligence | None = None,
    claim_retriever: ClaimRetriever | None = None,
    fact_check_corpus: FactCheckCorpus | None = None,
    fact_check_orchestrator: FactCheckOrchestrator | None = None,
    embedding_provider: Any | None = None,
    google_claim_search: Any | None = None,
    hybrid_corpus_retriever: Any | None = None,
    tavily_search: Any | None = None,
    tavily_extract: Any | None = None,
    evidence_comparator: Any | None = None,
    source_registry: Any | None = None,
    max_claim_concurrency: int = 3,
    provisional_tier_c_enabled: bool = True,
    fact_check_timeout_seconds: float | None = None,
    post_processing_reserve_seconds: float = 0.0,
    blacklist: BlacklistRepository | None = None,
    execution_ledger: ToolExecutionLedger | None = None,
    progress_sink: ProgressSink | None = None,
    provisional_warning_sink: ProvisionalWarningSink | None = None,
    risk_engine: RiskEngine | None = None,
    explanation_engine: ExplanationEngine | None = None,
    campaign_detector: CampaignDetector | None = None,
    progress_clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    llm: Any | None = None,
):
    """Build the injectable v2 analysis workflow."""
    graph = StateGraph(WorkflowState)
    wave2_parts = (
        embedding_provider,
        google_claim_search,
        hybrid_corpus_retriever,
        tavily_search,
        tavily_extract,
        evidence_comparator,
        source_registry,
    )
    if fact_check_orchestrator is None and any(item is not None for item in wave2_parts):
        fact_check_orchestrator = FactCheckOrchestrator(
            embedding_provider=embedding_provider,
            google_claim_search=google_claim_search,
            corpus_retriever=hybrid_corpus_retriever,
            tavily_search=tavily_search,
            tavily_extract=tavily_extract,
            comparator=evidence_comparator,
            source_registry=source_registry,
            max_claim_concurrency=max_claim_concurrency,
            provisional_tier_c_enabled=provisional_tier_c_enabled,
        )
    graph.add_node("classify_input", _classify_node)
    graph.add_node("extract_indicators", _extract_node)
    graph.add_node("analyze_message", build_analyze_message_node(llm))
    graph.add_node("normalize_and_check_rules", build_rule_check_node(blacklist))
    provisional_warning_sink = provisional_warning_sink or NullProvisionalWarningSink()

    async def provisional_warning(state: WorkflowState) -> dict:
        update = build_provisional_warning(state, progress_clock)
        warning = update.get("provisional_warning")
        if warning is not None:
            sink = state.get("runtime_provisional_sink") or provisional_warning_sink
            await sink.emit(warning.model_copy(deep=True))
        return update

    graph.add_node("provisional_warning", provisional_warning)
    graph.add_node("plan_tools", build_plan_tools_node(llm))
    if execution_ledger is None and hasattr(blacklist, "claim_tool_execution"):
        execution_ledger = blacklist  # type: ignore[assignment]
    graph.add_node(
        "planning_loop",
        _build_planning_loop_node(
            url_scanner,
            claim_retriever,
            blacklist,
            domain_intelligence,
            redirect_resolver,
            url_reputation,
            execution_ledger,
            progress_sink,
            progress_clock,
            fact_check_corpus,
            fact_check_orchestrator,
        ),
    )

    async def verify_fact_checks(state: WorkflowState) -> dict:
        if fact_check_orchestrator is None:
            return {}
        extracted = list(state.get("extracted_claims", []))
        known = {item.normalized_text for item in extracted}
        for raw_claim in state.get("claims", []):
            try:
                item = ExtractedClaim.from_text(raw_claim)
            except ValueError:
                continue
            if item.normalized_text not in known:
                known.add(item.normalized_text)
                extracted.append(item)
        deadline = state.get("deadline_at")
        timeout = (deadline - datetime.now(UTC)).total_seconds() if deadline is not None else None
        if timeout is not None:
            timeout = max(0.0, timeout - post_processing_reserve_seconds)
        if fact_check_timeout_seconds is not None:
            timeout = min(timeout, fact_check_timeout_seconds) if timeout is not None else fact_check_timeout_seconds
        if timeout is not None and timeout <= 0:
            return {
                "fact_check_timed_out": True,
                "limitations": [
                    *state.get("limitations", []),
                    "Fact-check trực tuyến vượt quá thời gian xử lý; các bước tổng hợp sau đó dùng logic deterministic.",
                ],
            }
        try:
            operation = fact_check_orchestrator.verify(extracted[:5])
            result = await asyncio.wait_for(operation, timeout=timeout) if timeout is not None else await operation
        except TimeoutError:
            return {
                "fact_check_timed_out": True,
                "limitations": [
                    *state.get("limitations", []),
                    "Fact-check trực tuyến vượt quá thời gian xử lý; các bước tổng hợp sau đó dùng logic deterministic.",
                ],
                "errors": [
                    *state.get("errors", []),
                    ToolError(
                        tool="fact_check",
                        code="PROVIDER_TIMEOUT",
                        message="Online fact-check deadline exceeded",
                        retryable=True,
                    ),
                ],
            }
        evidence = list(state.get("evidence", []))
        for finding in result.claim_findings:
            from src.models import Evidence, EvidenceType

            evidence.append(
                Evidence(
                    type=EvidenceType.FACT_CHECK,
                    source=finding.source,
                    title=finding.title,
                    url=finding.url,
                    finding=finding.finding,
                    stance=finding.stance,
                    observed_at=finding.observed_at,
                    source_tier=finding.source_tier,
                    policy_version=finding.policy_version,
                    provisional=finding.provisional,
                )
            )
        findings = list(result.claim_findings)
        provisional_findings = [item for item in findings if item.provisional]
        reviewed_findings = [item for item in findings if not item.provisional]
        if reviewed_findings:
            fact_check_basis, fact_check_confidence = "reviewed", 0.9
        elif provisional_findings:
            domains = {registrable_domain(item.url or "") for item in provisional_findings}
            domains.discard("")
            fact_check_basis = "provisional"
            fact_check_confidence = min(0.7, 0.5 + 0.05 * len(domains))
        else:
            fact_check_basis, fact_check_confidence = "inconclusive", None
        return {
            "extracted_claims": extracted[:5],
            "claim_findings": list(state.get("claim_findings", [])) + list(result.claim_findings),
            "examined_evidence": list(result.examined_evidence),
            "evidence": evidence,
            "limitations": list(dict.fromkeys([*state.get("limitations", []), *result.limitations])),
            "errors": [*state.get("errors", []), *result.errors],
            "tool_usage_refs": list(dict.fromkeys([*state.get("tool_usage_refs", []), *result.tool_usage_refs])),
            "embedding_status": result.embedding_status,
            "usage_records": list(result.usage_records),
            "claim_feature_vectors": list(result.claim_feature_vectors),
            "fact_check_basis": fact_check_basis,
            "fact_check_confidence": fact_check_confidence,
        }

    graph.add_node("verify_fact_checks", verify_fact_checks)
    risk_engine = risk_engine or FunctionRiskEngine(assess_risk)
    explanation_engine = explanation_engine or FunctionExplanationEngine(explain_result)
    campaign_detector = campaign_detector or NullCampaignDetector()

    async def detect_campaign(state: WorkflowState) -> dict:
        return await campaign_detector.detect(state)

    async def assess_with_engine(state: WorkflowState) -> dict:
        return risk_engine.assess(state)

    async def explain_with_engine(state: WorkflowState) -> dict:
        return explanation_engine.explain(state)

    graph.add_node("detect_campaign", detect_campaign)
    graph.add_node("assess_risk", assess_with_engine)
    graph.add_node("review_assessment", build_review_assessment_node(llm))
    graph.add_node("explain_result", explain_with_engine)
    graph.add_node("route_action", _action_node)
    graph.add_node("generate_response", build_generate_response_node(llm))

    graph.set_entry_point("classify_input")
    graph.add_edge("classify_input", "extract_indicators")
    graph.add_edge("extract_indicators", "normalize_and_check_rules")
    graph.add_edge("normalize_and_check_rules", "provisional_warning")
    graph.add_edge("provisional_warning", "analyze_message")
    graph.add_edge("analyze_message", "plan_tools")
    graph.add_edge("plan_tools", "planning_loop")
    graph.add_edge("planning_loop", "verify_fact_checks")
    graph.add_edge("verify_fact_checks", "detect_campaign")
    graph.add_edge("detect_campaign", "assess_risk")
    graph.add_edge("assess_risk", "review_assessment")
    graph.add_edge("review_assessment", "explain_result")
    graph.add_edge("explain_result", "route_action")
    graph.add_edge("route_action", "generate_response")
    graph.add_edge("generate_response", END)
    return graph.compile()


def build_legacy_graph():
    """Build the GPT chatbot retained on the compatibility `/chat` route."""
    return build_chatbot_graph()


def build_chatbot_graph(*, llm: Any | None = None):
    graph = StateGraph(LegacyAgentState)
    graph.add_node("chat", build_chatbot_node(llm))
    graph.set_entry_point("chat")
    graph.add_edge("chat", END)
    return graph.compile()


def build_openai_graph(**kwargs):
    from src.agents.tools.integration import build_provider_adapters
    from src.agents.tools.runtime import (
        OpenAIEvidenceComparator,
        PostgresHybridCorpusRetriever,
    )
    from src.config import get_settings
    from src.services.llm import get_llm

    settings = get_settings()
    llm = get_llm() if settings.openai_api_key else None
    source_registry = kwargs.get("source_registry")
    owned_adapters = build_provider_adapters(settings, source_registry)
    repository = kwargs.get("blacklist")
    if repository is not None and hasattr(repository, "search_fact_check_corpus"):
        kwargs.setdefault("hybrid_corpus_retriever", PostgresHybridCorpusRetriever(repository))
    if llm is not None:
        kwargs.setdefault("evidence_comparator", OpenAIEvidenceComparator(llm))
    graph_adapter_names = {
        "url_scanner",
        "url_reputation",
        "redirect_resolver",
        "domain_intelligence",
        "claim_retriever",
        "fact_check_corpus",
        "embedding_provider",
        "google_claim_search",
        "hybrid_corpus_retriever",
        "tavily_search",
        "tavily_extract",
        "evidence_comparator",
        "source_registry",
        "max_claim_concurrency",
        "provisional_tier_c_enabled",
        "fact_check_timeout_seconds",
        "post_processing_reserve_seconds",
    }
    for name, adapter in owned_adapters.items():
        if name in graph_adapter_names:
            kwargs.setdefault(name, adapter)
    kwargs.setdefault("max_claim_concurrency", settings.max_claim_concurrency)
    kwargs.setdefault("provisional_tier_c_enabled", settings.source_provisional_enabled)
    kwargs.setdefault("fact_check_timeout_seconds", settings.fact_check_timeout_seconds)
    kwargs.setdefault("post_processing_reserve_seconds", settings.post_processing_reserve_seconds)
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
    "build_graph",
    "build_chatbot_graph",
    "build_legacy_graph",
    "build_openai_graph",
    "close_graph_resources",
]
