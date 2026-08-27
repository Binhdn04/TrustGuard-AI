from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from time import monotonic
from typing import Any
from urllib.parse import urlsplit

from src.agents.nodes.planning import step_id_for
from src.agents.nodes.rules import build_rule_check_node
from src.agents.tools.domains import canonicalize_registrable_domain
from src.agents.tools.models import DnsResolutionEnvelope, NormalizedToolResult, ToolErrorCode, ToolResultStatus
from src.agents.tools.protocols import (
    BlacklistRepository,
    DnsEvidenceProvider,
    DomainFamiliarityProvider,
    RdapProvider,
    RedirectResolver,
    ToolExecutionLedger,
    UrlReputationCascade,
)
from src.models import (
    DomainFamiliarityClassificationV4,
    DomainFamiliarityDetailsV4,
    Evidence,
    InvestigationStepV4,
    SecurityContextV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityInvestigationStatusV4,
    SecurityInvestigationStepStatusV4,
    SecurityInvestigationToolV4,
    SecurityScenarioV4,
    SecurityScopeResponseV4,
    SecurityToolErrorV4,
    SecurityTriageCreateRequestV4,
)
from src.security_ai.contracts import AssistantOperation, PlanPriority, SecurityAssistantModel
from src.security_ai.runtime import SecurityAssistantRuntime

ToolEnvelope = NormalizedToolResult[Any] | DnsResolutionEnvelope
ExternalCall = Callable[[], Awaitable[ToolEnvelope]]

_LOCAL_SIGNAL_BY_TITLE = {
    "URL đích bị chặn bởi SSRF guard": "ssrf_blocked",
    "Tên miền quốc tế hóa cần thận trọng": "punycode_domain",
    "Đường dẫn quy trình tài khoản": "credential_path",
    "Tên miền có mẫu mạo danh khuyến mãi": "promotion_lure_domain",
}

_TRUST_TOOLS = {
    SecurityInvestigationToolV4.BRAND_MATCH,
    SecurityInvestigationToolV4.WHITELIST_LOOKUP,
}


def _requires_high_risk_reputation(context: SecurityContextV4) -> bool:
    """Escalate reputation checks for requests that can lose money or access."""
    workflow_coverage = any(
        {part.casefold() for part in urlsplit(value).path.replace("-", "/").replace("_", "/").split("/")}
        & {"login", "signin", "verify", "account"}
        for value in context.urls
    )
    return bool(
        context.credential_request
        or context.otp_request
        or context.payment_request
        or context.personal_information_request
        or workflow_coverage
    )


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _evidence_ref(kind: str, source: str, target: str | None, signal: str) -> str:
    digest = hashlib.sha256(f"{kind}\0{source}\0{target or ''}\0{signal}".encode()).hexdigest()[:16]
    return f"evidence:{digest}"


def _ledger_target_ref(target: str) -> str:
    """Keep raw URLs, query tokens, and user-controlled targets out of durable ledgers."""
    return f"target:{hashlib.sha256(target.encode()).hexdigest()[:24]}"


def _evidence(
    kind: SecurityEvidenceTypeV4,
    source: str,
    signal: str,
    description: str,
    observed_at: datetime,
    *,
    target: str | None = None,
    confidence: float | None = None,
    provenance_ref: str | None = None,
    domain_familiarity: DomainFamiliarityDetailsV4 | None = None,
) -> SecurityEvidenceV4:
    return SecurityEvidenceV4(
        evidence_ref=_evidence_ref(kind.value, source, target, signal),
        type=kind,
        source=source,
        target=target,
        signal=signal,
        description=description,
        observed_at=observed_at,
        confidence=confidence,
        provenance_ref=provenance_ref,
        domain_familiarity=domain_familiarity,
    )


def _step(
    tool: SecurityInvestigationToolV4,
    target: str,
    reason_code: str,
    *,
    depends_on: list[str] | None = None,
    status: SecurityInvestigationStepStatusV4 = SecurityInvestigationStepStatusV4.PENDING,
    status_reason: str | None = None,
) -> InvestigationStepV4:
    return InvestigationStepV4(
        step_id=step_id_for(tool.value, target),
        tool=tool,
        target=target,
        reason_code=reason_code,
        depends_on=depends_on or [],
        status=status,
        status_reason=status_reason,
    )


def build_policy_constrained_investigation_plan(
    context: SecurityContextV4,
    *,
    external_url_lookup: bool,
    domain_familiarity_enabled: bool = False,
) -> list[InvestigationStepV4]:
    """Create a safe plan exclusively from normalized SecurityContext targets."""
    plan: list[InvestigationStepV4] = []
    context_step = _step(
        SecurityInvestigationToolV4.SECURITY_CONTEXT_ANALYSIS,
        "message",
        "security_context_available",
        status=SecurityInvestigationStepStatusV4.COMPLETED,
        status_reason="local_analysis_completed",
    )
    plan.append(context_step)
    seen_domains: set[str] = set()
    seen_familiarity_domains: set[str] = set()
    for url in context.urls:
        local = _step(
            SecurityInvestigationToolV4.LOCAL_URL_RULES,
            url,
            "url_present",
            depends_on=[context_step.step_id],
        )
        plan.append(local)
        host = (urlsplit(url).hostname or "").casefold()
        blacklist = _step(
            SecurityInvestigationToolV4.BLACKLIST_LOOKUP,
            host,
            "url_domain_present",
            depends_on=[local.step_id],
        )
        if host not in seen_domains:
            plan.append(blacklist)
            seen_domains.add(host)
        external_status = (
            SecurityInvestigationStepStatusV4.PENDING
            if external_url_lookup
            else SecurityInvestigationStepStatusV4.SKIPPED
        )
        external_reason = None if external_url_lookup else "consent_required"
        plan.extend(
            [
                _step(
                    SecurityInvestigationToolV4.DNS,
                    url,
                    "dns_safety_evidence",
                    depends_on=[blacklist.step_id],
                    status=external_status,
                    status_reason=external_reason,
                ),
                _step(
                    SecurityInvestigationToolV4.REDIRECT_RESOLVER,
                    url,
                    "redirect_chain_needed",
                    depends_on=[blacklist.step_id],
                    status=external_status,
                    status_reason=external_reason,
                ),
                _step(
                    SecurityInvestigationToolV4.URL_REPUTATION,
                    url,
                    "url_reputation_needed",
                    depends_on=[blacklist.step_id],
                    status=external_status,
                    status_reason=external_reason,
                ),
            ]
        )
        if sum(1 for item in plan if item.tool is SecurityInvestigationToolV4.RDAP and item.target == host) == 0:
            plan.append(
                _step(
                    SecurityInvestigationToolV4.RDAP,
                    host,
                    "domain_registration_needed",
                    depends_on=[blacklist.step_id],
                    status=external_status,
                    status_reason=external_reason,
                )
            )
        if domain_familiarity_enabled:
            try:
                registrable = canonicalize_registrable_domain(host)
            except ValueError:
                registrable = None
            if registrable is not None and registrable not in seen_familiarity_domains:
                plan.append(
                    _step(
                        SecurityInvestigationToolV4.DOMAIN_FAMILIARITY,
                        registrable,
                        "domain_popularity_context",
                        depends_on=[blacklist.step_id],
                        status=external_status,
                        status_reason=external_reason,
                    )
                )
                seen_familiarity_domains.add(registrable)
    needs_trust_routing = bool(context.urls or context.claimed_entity) or context.scenario in {
        SecurityScenarioV4.RECRUITMENT,
        SecurityScenarioV4.PROMOTION_PRIZE,
        SecurityScenarioV4.ACCOUNT_VERIFICATION,
    }
    # Payment/OTP-only turns are assessed from structured context. They never
    # receive a fabricated URL/domain target merely to make a provider usable.
    if not context.urls and context.scenario in {SecurityScenarioV4.PAYMENT, SecurityScenarioV4.REFUND}:
        needs_trust_routing = False
    if needs_trust_routing:
        brand = _step(
            SecurityInvestigationToolV4.BRAND_MATCH,
            "message",
            "claimed_entity_or_alias_check",
            depends_on=[context_step.step_id],
        )
        plan.append(brand)
        for host in sorted({(urlsplit(url).hostname or "").casefold() for url in context.urls} - {""}):
            plan.append(
                _step(
                    SecurityInvestigationToolV4.WHITELIST_LOOKUP,
                    host,
                    "trust_indicator_lookup",
                    depends_on=[brand.step_id],
                )
            )
    return plan


def build_security_investigation_plan(
    context: SecurityContextV4,
    *,
    external_url_lookup: bool,
) -> list[InvestigationStepV4]:
    """Compatibility view of the original URL investigation plan.

    The v4 executor uses :func:`build_policy_constrained_investigation_plan`;
    callers of this established helper keep its pre-WP3 URL-tool contract.
    """
    return [
        step
        for step in build_policy_constrained_investigation_plan(
            context,
            external_url_lookup=external_url_lookup,
        )
        if step.tool not in _TRUST_TOOLS
    ]


def _planner_context(context: SecurityContextV4) -> dict[str, Any]:
    """Return policy fields only; prose and user-supplied entity text stay out of planning."""
    return {
        "scenario": context.scenario.value,
        "potential_threat": context.potential_threat.value,
        "requested_action": context.requested_action.value if context.requested_action else None,
        "has_urls": bool(context.urls),
        "has_claimed_entity": bool(context.claimed_entity),
        "credential_request": context.credential_request,
        "otp_request": context.otp_request,
        "payment_request": context.payment_request,
        "personal_information_request": context.personal_information_request,
        "urgency": context.urgency,
    }


def _candidate_payload(plan: list[InvestigationStepV4]) -> list[dict[str, Any]]:
    return [
        {
            "step_id": step.step_id,
            "tool": step.tool.value,
            "target": step.target,
            "reason_code": step.reason_code,
            "depends_on": step.depends_on,
            "mandatory": True,
        }
        for step in plan
        # Policy owns non-applicability and consent skips. The AI only sees
        # runnable candidates and therefore cannot rewrite those decisions.
        if step.status is not SecurityInvestigationStepStatusV4.SKIPPED
    ]


def apply_plan_priority(
    plan: list[InvestigationStepV4],
    priority: PlanPriority,
) -> list[InvestigationStepV4] | None:
    """Apply AI priority hints while policy retains dependency ordering."""
    by_id = {step.step_id: step for step in plan}
    supplied = set(priority.ordered_step_ids) | set(priority.skipped_step_ids) | set(priority.requested_step_ids)
    if not supplied <= by_id.keys():
        return None
    if priority.skipped_step_ids:
        return None

    # The model supplies priority hints, not an execution graph. Dedupe a
    # harmless repeated allowlisted candidate and let policy restore the
    # dependency-safe order deterministically.
    preferred_ids = list(dict.fromkeys([*priority.ordered_step_ids, *priority.requested_step_ids]))
    for step in plan:
        if step.step_id not in preferred_ids:
            preferred_ids.append(step.step_id)

    active = set(preferred_ids)
    if any(dependency not in active for step_id in active for dependency in by_id[step_id].depends_on):
        return None

    active_ids: list[str] = []
    remaining = set(preferred_ids)
    while remaining:
        ready = next(
            (
                step_id
                for step_id in preferred_ids
                if step_id in remaining and all(dependency in active_ids for dependency in by_id[step_id].depends_on)
            ),
            None,
        )
        if ready is None:
            # Defensive cycle/missing-dependency guard. The deterministic
            # candidate graph should never reach this branch.
            return None
        active_ids.append(ready)
        remaining.remove(ready)

    return [by_id[step_id] for step_id in active_ids]


class SecurityInvestigationService:
    def __init__(
        self,
        *,
        blacklist: BlacklistRepository | None = None,
        dns: DnsEvidenceProvider | None = None,
        redirect: RedirectResolver | None = None,
        rdap: RdapProvider | None = None,
        reputation: UrlReputationCascade | None = None,
        domain_familiarity: DomainFamiliarityProvider | None = None,
        domain_familiarity_enabled: bool = False,
        execution_ledger: ToolExecutionLedger | None = None,
        planning_enabled: bool = False,
        assistant_model: SecurityAssistantModel | None = None,
        runtime_factory: Callable[[], SecurityAssistantRuntime] = SecurityAssistantRuntime,
        max_external_calls: int = 8,
        max_retries: int = 1,
        deadline_seconds: float = 20.0,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if max_external_calls < 0 or max_retries < 0 or deadline_seconds <= 0:
            raise ValueError("investigation budgets must be non-negative and deadline must be positive")
        self._blacklist = blacklist
        self._dns = dns
        self._redirect = redirect
        self._rdap = rdap
        self._reputation = reputation
        self._domain_familiarity = domain_familiarity
        self._domain_familiarity_enabled = domain_familiarity_enabled
        self._execution_ledger = execution_ledger
        self._planning_enabled = planning_enabled
        self._assistant_model = assistant_model
        self._runtime_factory = runtime_factory
        self._max_external_calls = max_external_calls
        self._max_retries = max_retries
        self._deadline_seconds = deadline_seconds
        self._clock = clock

    async def investigate(
        self,
        request: SecurityTriageCreateRequestV4,
        scope: SecurityScopeResponseV4,
        *,
        runtime: SecurityAssistantRuntime | None = None,
    ) -> SecurityScopeResponseV4:
        context = scope.security_context
        if context is None:
            return scope
        plan = build_policy_constrained_investigation_plan(
            context,
            external_url_lookup=request.consent.external_url_lookup,
            domain_familiarity_enabled=self._domain_familiarity_enabled,
        )
        evidence = [self._context_evidence(context)]
        errors: list[SecurityToolErrorV4] = []
        limitations = list(scope.limitations)
        # A one-step plan has nothing for AI to rank or skip. Avoid spending a
        # provider call (and producing a misleading fallback limitation) for
        # context-only investigations.
        if self._planning_enabled and self._assistant_model is not None and len(plan) > 1:
            turn_runtime = runtime or self._runtime_factory()
            result = await turn_runtime.invoke(
                AssistantOperation.PRIORITIZE_PLAN,
                lambda: self._assistant_model.prioritize_plan(
                    _planner_context(context),
                    _candidate_payload(plan),
                ),
                PlanPriority,
            )
            prioritized = apply_plan_priority(plan, result.output) if result.output is not None else None
            if prioritized is None:
                limitations.append("AI planner không trả được plan hợp lệ; đã dùng deterministic plan.")
            else:
                plan = prioritized
        blocked_urls: set[str] = set()
        blacklisted_domains: set[str] = set()

        if context.urls:
            local_rule = build_rule_check_node(None)
            for url in context.urls:
                local_update = await local_rule(
                    {
                        "extracted_urls": [url],
                        "consent_to_scan_urls": request.consent.external_url_lookup,
                        "claims": [],
                        "evidence": [],
                        "limitations": [],
                    }
                )
                blocked_urls.update(local_update.get("blocked_urls", []))
                limitations.extend(local_update.get("limitations", []))
                for item in local_update.get("evidence", []):
                    evidence.append(self._local_evidence(item, [url]))
            for index, item in enumerate(plan):
                if item.tool is SecurityInvestigationToolV4.LOCAL_URL_RULES:
                    plan[index] = item.model_copy(
                        update={
                            "status": SecurityInvestigationStepStatusV4.COMPLETED,
                            "status_reason": "local_rules_completed",
                        }
                    )

        for index, item in enumerate(plan):
            if item.tool is not SecurityInvestigationToolV4.BLACKLIST_LOOKUP:
                continue
            if self._blacklist is None:
                plan[index] = item.model_copy(
                    update={"status": SecurityInvestigationStepStatusV4.SKIPPED, "status_reason": "not_configured"}
                )
                limitations.append("Không có blacklist repository được cấu hình.")
                continue
            try:
                entry = await self._blacklist.get(item.target)
            except Exception:
                plan[index] = item.model_copy(
                    update={"status": SecurityInvestigationStepStatusV4.FAILED, "status_reason": "repository_error"}
                )
                errors.append(
                    SecurityToolErrorV4(
                        tool=item.tool,
                        target=item.target,
                        code="REPOSITORY_ERROR",
                        message="Blacklist lookup failed.",
                        retryable=True,
                        provider="internal-blacklist",
                    )
                )
                limitations.append("Không thể kiểm tra internal blacklist.")
                continue
            plan[index] = item.model_copy(
                update={"status": SecurityInvestigationStepStatusV4.COMPLETED, "status_reason": "lookup_completed"}
            )
            if entry is not None and entry.active:
                blacklisted_domains.add(item.target)
                evidence.append(
                    _evidence(
                        SecurityEvidenceTypeV4.BLACKLIST,
                        entry.source,
                        "approved_blacklist_hit",
                        f"Tên miền {item.target} nằm trong blacklist đã được phê duyệt.",
                        entry.added_at,
                        target=item.target,
                        confidence=1.0,
                        provenance_ref=f"decision:{entry.decision_id}",
                    )
                )

        if context.urls and not request.consent.external_url_lookup:
            limitations.append("External URL/domain lookup bị bỏ qua vì chưa có consent.")

        turn_remaining = (
            runtime.execution_context.remaining_seconds
            if runtime is not None and runtime.execution_context is not None
            else self._deadline_seconds
        )
        deadline_at = monotonic() + min(self._deadline_seconds, turn_remaining)
        calls_used = 0
        for index, item in enumerate(plan):
            if item.status is not SecurityInvestigationStepStatusV4.PENDING:
                continue
            if item.tool in _TRUST_TOOLS:
                continue
            completed = {step.step_id: step.status for step in plan}
            if any(
                completed.get(dependency) is not SecurityInvestigationStepStatusV4.COMPLETED
                for dependency in item.depends_on
            ):
                plan[index] = item.model_copy(
                    update={
                        "status": SecurityInvestigationStepStatusV4.SKIPPED,
                        "status_reason": "dependency_unsatisfied",
                    }
                )
                continue
            if (
                item.tool
                in {
                    SecurityInvestigationToolV4.DNS,
                    SecurityInvestigationToolV4.REDIRECT_RESOLVER,
                    SecurityInvestigationToolV4.RDAP,
                    SecurityInvestigationToolV4.URL_REPUTATION,
                    SecurityInvestigationToolV4.DOMAIN_FAMILIARITY,
                }
                and not request.consent.external_url_lookup
            ):
                plan[index] = item.model_copy(
                    update={
                        "status": SecurityInvestigationStepStatusV4.SKIPPED,
                        "status_reason": "consent_required",
                    }
                )
                continue
            host = (urlsplit(item.target).hostname or item.target).casefold()
            related_url = (
                item.target
                if "://" in item.target
                else next(
                    (url for url in context.urls if (urlsplit(url).hostname or "").casefold() == host),
                    None,
                )
            )
            if (related_url is not None and related_url in blocked_urls) or host in blacklisted_domains:
                reason = "ssrf_short_circuit" if related_url in blocked_urls else "blacklist_short_circuit"
                plan[index] = item.model_copy(
                    update={"status": SecurityInvestigationStepStatusV4.SKIPPED, "status_reason": reason}
                )
                continue
            call = self._external_call(item, high_risk=_requires_high_risk_reputation(context))
            if call is None:
                plan[index] = item.model_copy(
                    update={"status": SecurityInvestigationStepStatusV4.SKIPPED, "status_reason": "not_configured"}
                )
                limitations.append(f"Tool {item.tool.value} chưa được cấu hình.")
                continue
            if calls_used >= self._max_external_calls:
                plan[index] = item.model_copy(
                    update={"status": SecurityInvestigationStepStatusV4.SKIPPED, "status_reason": "budget_exhausted"}
                )
                limitations.append("Đã dùng hết ngân sách gọi công cụ bên ngoài.")
                continue
            provider = self._provider_name(item)
            if self._execution_ledger is not None:
                try:
                    claim = getattr(self._execution_ledger, "claim_security_tool_execution", None)
                    claim = claim or getattr(self._execution_ledger, "claim_tool_execution")
                    claimed = await claim(
                        str(scope.analysis_id), item.step_id, _ledger_target_ref(item.target), provider
                    )
                except Exception:
                    plan[index] = item.model_copy(
                        update={"status": SecurityInvestigationStepStatusV4.FAILED, "status_reason": "ledger_error"}
                    )
                    errors.append(
                        SecurityToolErrorV4(
                            tool=item.tool,
                            target=item.target,
                            code="EXECUTION_LEDGER_ERROR",
                            message="Tool execution could not be claimed.",
                            retryable=True,
                            provider=provider,
                        )
                    )
                    limitations.append("Không thể ghi nhận tool execution vào ledger.")
                    continue
                if not claimed:
                    plan[index] = item.model_copy(
                        update={
                            "status": SecurityInvestigationStepStatusV4.SKIPPED,
                            "status_reason": "duplicate_execution",
                        }
                    )
                    continue
            envelope, used = await self._execute(call, item, deadline_at, self._max_external_calls - calls_used)
            calls_used += used
            await self._finish_ledger(scope, item, provider, envelope, errors, limitations)
            if envelope is None:
                plan[index] = item.model_copy(
                    update={"status": SecurityInvestigationStepStatusV4.SKIPPED, "status_reason": "deadline_exhausted"}
                )
                limitations.append("Đã hết thời gian dành cho investigation tools.")
                continue
            if envelope.error is not None:
                status_reason = "ssrf_blocked" if envelope.error.code is ToolErrorCode.SSRF_BLOCKED else "tool_failed"
                plan[index] = item.model_copy(
                    update={"status": SecurityInvestigationStepStatusV4.FAILED, "status_reason": status_reason}
                )
                errors.append(
                    SecurityToolErrorV4(
                        tool=item.tool,
                        target=item.target,
                        code=envelope.error.code.value,
                        message=envelope.error.message,
                        retryable=envelope.error.retryable,
                        provider=envelope.error.provider,
                    )
                )
                limitations.append(f"Tool {item.tool.value} không trả được kết quả sử dụng được.")
                if envelope.error.code is ToolErrorCode.SSRF_BLOCKED and related_url is not None:
                    blocked_urls.add(related_url)
                continue
            plan[index] = item.model_copy(
                update={"status": SecurityInvestigationStepStatusV4.COMPLETED, "status_reason": "tool_completed"}
            )
            observed_host = None
            if item.tool is SecurityInvestigationToolV4.DOMAIN_FAMILIARITY:
                for url in context.urls:
                    try:
                        if canonicalize_registrable_domain(url) == item.target:
                            observed_host = (urlsplit(url).hostname or item.target).casefold()
                            break
                    except ValueError:
                        continue
            produced, produced_limitations = self._provider_evidence(
                item,
                envelope,
                observed_host=observed_host,
            )
            evidence.extend(produced)
            limitations.extend(produced_limitations)

        for index, item in enumerate(plan):
            if item.status is SecurityInvestigationStepStatusV4.PENDING and item.tool not in _TRUST_TOOLS:
                plan[index] = item.model_copy(
                    update={
                        "status": SecurityInvestigationStepStatusV4.SKIPPED,
                        "status_reason": "policy_short_circuit",
                    }
                )

        evidence = list({item.evidence_ref: item for item in evidence}.values())
        limitations = _unique(limitations)
        status = (
            SecurityInvestigationStatusV4.PARTIAL
            if errors
            or any(
                item.status in {SecurityInvestigationStepStatusV4.FAILED, SecurityInvestigationStepStatusV4.SKIPPED}
                for item in plan
                if item.tool not in _TRUST_TOOLS
            )
            else SecurityInvestigationStatusV4.COMPLETED
        )
        payload = scope.model_dump()
        payload.update(
            next_step="RISK_ASSESSMENT",
            investigation_status=status,
            investigation_plan=plan,
            evidence=evidence,
            errors=errors,
            limitations=limitations,
            tool_calls_used=calls_used,
        )
        return SecurityScopeResponseV4.model_validate(payload)

    def _context_evidence(self, context: SecurityContextV4) -> SecurityEvidenceV4:
        signals = [context.scenario.value, context.potential_threat.value]
        if context.requested_action is not None:
            signals.append(context.requested_action.value)
        for name in ("credential_request", "otp_request", "payment_request", "personal_information_request"):
            if getattr(context, name):
                signals.append(name)
        signal = "+".join(signals)
        return _evidence(
            SecurityEvidenceTypeV4.SECURITY_CONTEXT,
            context.schema_version,
            signal,
            "Structured security context xác định các signal: " + ", ".join(signals) + ".",
            self._clock(),
            target="message",
        )

    def _local_evidence(self, item: Evidence, urls: list[str]) -> SecurityEvidenceV4:
        signal = _LOCAL_SIGNAL_BY_TITLE.get(item.title, "local_url_signal")
        target = item.url or (urls[0] if len(urls) == 1 else None)
        return _evidence(
            SecurityEvidenceTypeV4.LOCAL_URL_RULE,
            item.source,
            signal,
            item.finding,
            item.observed_at,
            target=target,
        )

    def _external_call(self, step: InvestigationStepV4, *, high_risk: bool) -> ExternalCall | None:
        if step.tool is SecurityInvestigationToolV4.DNS and self._dns is not None:
            return lambda: self._dns.resolve(step.target)
        if step.tool is SecurityInvestigationToolV4.REDIRECT_RESOLVER and self._redirect is not None:
            return lambda: self._redirect.resolve(step.target)
        if step.tool is SecurityInvestigationToolV4.RDAP and self._rdap is not None:
            return lambda: self._rdap.lookup(step.target)
        if step.tool is SecurityInvestigationToolV4.URL_REPUTATION and self._reputation is not None:
            return lambda: self._reputation.assess(step.target, high_risk=high_risk)
        if step.tool is SecurityInvestigationToolV4.DOMAIN_FAMILIARITY and self._domain_familiarity is not None:
            return lambda: self._domain_familiarity.lookup(step.target)
        return None

    def _provider_name(self, step: InvestigationStepV4) -> str:
        adapter = {
            SecurityInvestigationToolV4.DNS: self._dns,
            SecurityInvestigationToolV4.REDIRECT_RESOLVER: self._redirect,
            SecurityInvestigationToolV4.RDAP: self._rdap,
            SecurityInvestigationToolV4.URL_REPUTATION: self._reputation,
            SecurityInvestigationToolV4.DOMAIN_FAMILIARITY: self._domain_familiarity,
        }[step.tool]
        return str(getattr(adapter, "provider", adapter.__class__.__name__))

    async def _finish_ledger(
        self,
        scope: SecurityScopeResponseV4,
        step: InvestigationStepV4,
        provider: str,
        envelope: ToolEnvelope | None,
        errors: list[SecurityToolErrorV4],
        limitations: list[str],
    ) -> None:
        if self._execution_ledger is None:
            return
        status = "completed" if envelope is not None and envelope.error is None else "failed"
        try:
            finish = getattr(self._execution_ledger, "finish_security_tool_execution", None)
            finish = finish or getattr(self._execution_ledger, "finish_tool_execution")
            await finish(str(scope.analysis_id), step.step_id, _ledger_target_ref(step.target), provider, status)
        except Exception:
            errors.append(
                SecurityToolErrorV4(
                    tool=step.tool,
                    target=step.target,
                    code="EXECUTION_LEDGER_ERROR",
                    message="Tool execution result could not be recorded.",
                    retryable=True,
                    provider=provider,
                )
            )
            limitations.append("Không thể hoàn tất bản ghi tool execution trong ledger.")

    async def _execute(
        self,
        call: ExternalCall,
        step: InvestigationStepV4,
        deadline_at: float,
        budget_remaining: int,
    ) -> tuple[ToolEnvelope | None, int]:
        used = 0
        last: ToolEnvelope | None = None
        attempt_limit = 1 if step.tool is SecurityInvestigationToolV4.DOMAIN_FAMILIARITY else self._max_retries + 1
        for _attempt in range(min(attempt_limit, budget_remaining)):
            remaining = deadline_at - monotonic()
            if remaining <= 0:
                return None, used
            used += 1
            try:
                async with asyncio.timeout(remaining):
                    last = await call()
            except TimeoutError:
                return None, used
            except Exception:
                return self._exception_envelope(step), used
            if not (last.error and last.error.retryable):
                return last, used
        return last, used

    def _exception_envelope(self, step: InvestigationStepV4) -> ToolEnvelope:
        from src.agents.tools.models import (
            CacheMetadata,
            CacheStatus,
            DnsResolutionError,
            NormalizedToolError,
            ToolName,
            UsageMetadata,
        )

        cache = CacheMetadata(status=CacheStatus.BYPASS, bypass_reason="unexpected_adapter_error")
        usage = UsageMetadata(
            usage_ref=f"usage:exception:{step.step_id}",
            provider="unknown",
            provider_version="v1",
            operation=step.tool.value,
            attempts=1,
            network_calls=0,
            latency_ms=0,
            observed_at=self._clock(),
        )
        if step.tool is SecurityInvestigationToolV4.DNS:
            return DnsResolutionEnvelope(
                status=ToolResultStatus.FAILED,
                error=DnsResolutionError(
                    code=ToolErrorCode.PROVIDER_ERROR,
                    message="Tool adapter raised an unexpected error.",
                    retryable=False,
                ),
                cache=cache,
                usage=usage,
            )
        tool_name = {
            SecurityInvestigationToolV4.REDIRECT_RESOLVER: ToolName.REDIRECT_RESOLVER,
            SecurityInvestigationToolV4.RDAP: ToolName.RDAP,
            SecurityInvestigationToolV4.URL_REPUTATION: ToolName.URL_REPUTATION,
            SecurityInvestigationToolV4.DOMAIN_FAMILIARITY: ToolName.DOMAIN_FAMILIARITY,
        }[step.tool]
        return NormalizedToolResult(
            status=ToolResultStatus.FAILED,
            error=NormalizedToolError(
                tool=tool_name,
                code=ToolErrorCode.PROVIDER_ERROR,
                message="Tool adapter raised an unexpected error.",
                retryable=False,
            ),
            cache=cache,
            usage=usage,
        )

    def _provider_evidence(
        self,
        step: InvestigationStepV4,
        envelope: ToolEnvelope,
        *,
        observed_host: str | None = None,
    ) -> tuple[list[SecurityEvidenceV4], list[str]]:
        result = envelope.result
        if result is None:
            return [], []
        usage = envelope.usage
        provenance = usage.usage_ref
        if step.tool is SecurityInvestigationToolV4.DNS:
            return [
                _evidence(
                    SecurityEvidenceTypeV4.DNS,
                    usage.provider,
                    "public_dns_resolution",
                    f"DNS trả {result.address_count} địa chỉ public ({result.ipv4_count} IPv4, {result.ipv6_count} IPv6).",
                    result.observed_at,
                    target=result.domain,
                    provenance_ref=provenance,
                )
            ], []
        if step.tool is SecurityInvestigationToolV4.REDIRECT_RESOLVER:
            signal = "+".join(result.signals) if result.signals else result.status.value
            if result.status.value == "unresolved":
                # A guarded request can establish the final URL even when its
                # response is unusable (for example, a 404 or bot challenge).
                # ``UNRESOLVED`` here describes retrieval, not an unknown final
                # destination: ``final_url`` and ``redirect_chain`` are already
                # concrete. Do not project that availability limitation as the
                # much stronger and false user-facing redirect claim.
                signal = "redirect_resolution_inconclusive+" + signal
            return [
                _evidence(
                    SecurityEvidenceTypeV4.REDIRECT,
                    usage.provider,
                    signal,
                    "Chuỗi redirect đã được revalidate: " + " -> ".join(result.redirect_chain),
                    result.observed_at,
                    target=result.normalized_url,
                    provenance_ref=provenance,
                )
            ], []
        if step.tool is SecurityInvestigationToolV4.RDAP:
            details = [f"domain={result.domain}"]
            if result.registered_at is not None:
                details.append(f"registered_at={result.registered_at.isoformat()}")
            if result.registrar is not None:
                details.append(f"registrar={result.registrar}")
            signal = "+".join(result.signals) if result.signals else "registration_metadata"
            if "not_found" in result.signals:
                limitations = ["RDAP không tìm thấy registration record; kết quả này không chứng minh domain an toàn."]
            elif "service_unavailable" in result.signals:
                limitations = [
                    "Registry của hậu tố domain không công bố dịch vụ RDAP; thiếu dữ liệu này không chứng minh domain an toàn."
                ]
            elif "provider_unavailable" in result.signals:
                limitations = [
                    "Không lấy được dữ liệu đăng ký domain từ RDAP; thiếu dữ liệu này không chứng minh domain an toàn."
                ]
            else:
                limitations = []
            return [
                _evidence(
                    SecurityEvidenceTypeV4.RDAP,
                    usage.provider,
                    signal,
                    "; ".join(details),
                    result.observed_at,
                    target=result.domain,
                    provenance_ref=provenance,
                )
            ], limitations
        if step.tool is SecurityInvestigationToolV4.URL_REPUTATION:
            findings = result.findings
            matched = [finding for finding in findings if finding.matched]
            malicious_matches = [finding for finding in matched if finding.verdict.value == "malicious"]
            signal_parts = [result.verdict.value] if matched else ["provider_no_hit"]
            if result.provider_conflict:
                signal_parts.append("provider_conflict")
            if len({finding.provider for finding in malicious_matches}) > 1:
                signal_parts.append("corroborated_provider_hit")
            signal = "+".join(signal_parts)
            description = (
                f"Reputation policy {result.policy_version} trả verdict {result.verdict.value}; "
                f"matched providers={len(matched)}/{len(findings)}."
            )
            limitations = (
                ["URL reputation provider không ghi nhận hit; no-hit không được diễn giải là SAFE."]
                if not matched
                else []
            )
            return [
                _evidence(
                    SecurityEvidenceTypeV4.URL_REPUTATION,
                    usage.provider,
                    signal,
                    description,
                    usage.observed_at,
                    target=result.normalized_url,
                    provenance_ref=provenance,
                )
            ], limitations
        if step.tool is SecurityInvestigationToolV4.DOMAIN_FAMILIARITY:
            if not result.matched:
                return [], ["Không có dữ liệu familiarity cho domain; no-hit không phải tín hiệu unsafe."]
            rank = result.popularity_rank
            bucket = result.popularity_bucket
            if rank is not None and rank <= 100:
                signal = "popular_top_100"
            elif (rank is not None and rank <= 10_000) or (bucket is not None and bucket <= 10_000):
                signal = "popular_top_10000"
            else:
                signal = "ranked_domain"
            details = DomainFamiliarityDetailsV4(
                observed_host=observed_host or result.registrable_domain,
                registrable_domain=result.registrable_domain,
                classification=DomainFamiliarityClassificationV4.RANKED_DOMAIN,
                popularity_rank=rank,
                popularity_bucket=bucket,
                dataset_window_end=result.dataset_window_end,
            )
            return [
                _evidence(
                    SecurityEvidenceTypeV4.DOMAIN_FAMILIARITY,
                    usage.provider,
                    signal,
                    "Domain xuất hiện trong dữ liệu xếp hạng phổ biến; độ phổ biến không bảo chứng nội dung.",
                    result.observed_at,
                    target=result.registrable_domain,
                    confidence=0.8,
                    provenance_ref=provenance,
                    domain_familiarity=details,
                )
            ], []
        return [], []

    async def aclose(self) -> None:
        seen: set[int] = set()
        for adapter in (
            self._dns,
            self._redirect,
            self._rdap,
            self._reputation,
            self._domain_familiarity,
            self._blacklist,
            self._execution_ledger,
        ):
            if adapter is None or id(adapter) in seen:
                continue
            seen.add(id(adapter))
            close = getattr(adapter, "aclose", None) or getattr(adapter, "close", None)
            if close is not None:
                result = close()
                if hasattr(result, "__await__"):
                    await result


__all__ = [
    "SecurityInvestigationService",
    "apply_plan_priority",
    "build_policy_constrained_investigation_plan",
    "build_security_investigation_plan",
]
