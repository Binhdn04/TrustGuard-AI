from __future__ import annotations

import pytest

from src.agents.security_investigation import (
    SecurityInvestigationService,
    apply_plan_priority,
    build_policy_constrained_investigation_plan,
)
from src.agents.tools import FakeBlacklistRepository
from src.models import (
    SecurityInvestigationToolV4,
    SecurityTriageCreateRequestV4,
)
from src.security_ai.contracts import ModelResponse, PlanPriority
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.security_triage import SecurityTriageScopeService


def _scope(message: str, *, external: bool = False):
    request = SecurityTriageCreateRequestV4(
        message=message,
        consent={"external_url_lookup": external},
    )
    return request, SecurityTriageScopeService().assess(request)


def test_scenario_planner_routes_no_url_cases_without_fabricating_url_targets() -> None:
    _recruitment_request, recruitment = _scope("HR ACME yêu cầu đóng phí hồ sơ")
    recruitment_plan = build_policy_constrained_investigation_plan(
        recruitment.security_context,
        external_url_lookup=False,
    )
    assert [step.tool for step in recruitment_plan] == [
        SecurityInvestigationToolV4.SECURITY_CONTEXT_ANALYSIS,
        SecurityInvestigationToolV4.BRAND_MATCH,
    ]
    assert {step.target for step in recruitment_plan} == {"message"}

    _payment_request, payment = _scope("Ngân hàng yêu cầu chuyển tiền 2 triệu ngay")
    payment_plan = build_policy_constrained_investigation_plan(
        payment.security_context,
        external_url_lookup=True,
    )
    assert [step.tool for step in payment_plan] == [SecurityInvestigationToolV4.SECURITY_CONTEXT_ANALYSIS]


def test_url_scenario_candidate_plan_is_canonical_and_complete() -> None:
    request, scoped = _scope("Đăng nhập https://example.com/login để xác minh", external=True)
    plan = build_policy_constrained_investigation_plan(
        scoped.security_context,
        external_url_lookup=request.consent.external_url_lookup,
    )

    assert {
        SecurityInvestigationToolV4.LOCAL_URL_RULES,
        SecurityInvestigationToolV4.BLACKLIST_LOOKUP,
        SecurityInvestigationToolV4.DNS,
        SecurityInvestigationToolV4.REDIRECT_RESOLVER,
        SecurityInvestigationToolV4.RDAP,
        SecurityInvestigationToolV4.URL_REPUTATION,
        SecurityInvestigationToolV4.BRAND_MATCH,
        SecurityInvestigationToolV4.WHITELIST_LOOKUP,
    } <= {step.tool for step in plan}
    assert {step.target for step in plan} <= {"message", "https://example.com/login", "example.com"}


def test_ai_priority_cannot_invent_steps_or_skip_mandatory_checks_and_policy_restores_dependencies() -> None:
    request, scoped = _scope("Đăng nhập https://example.com/login", external=True)
    plan = build_policy_constrained_investigation_plan(
        scoped.security_context,
        external_url_lookup=request.consent.external_url_lookup,
    )
    context_id = plan[0].step_id
    local_id = next(step.step_id for step in plan if step.tool is SecurityInvestigationToolV4.LOCAL_URL_RULES)
    blacklist_id = next(step.step_id for step in plan if step.tool is SecurityInvestigationToolV4.BLACKLIST_LOOKUP)

    assert apply_plan_priority(plan, PlanPriority(ordered_step_ids=["step-000000000000"])) is None
    assert apply_plan_priority(plan, PlanPriority(skipped_step_ids=[context_id])) is None
    prioritized = apply_plan_priority(plan, PlanPriority(ordered_step_ids=[blacklist_id, local_id, context_id]))
    assert prioritized is not None
    positions = {step.step_id: index for index, step in enumerate(prioritized)}
    assert positions[context_id] < positions[local_id] < positions[blacklist_id]


def test_ai_priority_deduplicates_allowlisted_ordered_and_requested_hints() -> None:
    request, scoped = _scope("Đăng nhập https://example.com/login", external=True)
    plan = build_policy_constrained_investigation_plan(
        scoped.security_context,
        external_url_lookup=request.consent.external_url_lookup,
    )
    reputation_id = next(
        step.step_id for step in plan if step.tool is SecurityInvestigationToolV4.URL_REPUTATION
    )

    prioritized = apply_plan_priority(
        plan,
        PlanPriority(ordered_step_ids=[reputation_id], requested_step_ids=[reputation_id]),
    )

    assert prioritized is not None
    assert [step.step_id for step in prioritized].count(reputation_id) == 1


class _SkippingPlanner:
    async def prioritize_plan(self, context, candidate_steps):
        del context
        optional = next(step for step in candidate_steps if step["tool"] == "url_reputation")
        ordered = [step["step_id"] for step in candidate_steps if step["step_id"] != optional["step_id"]]
        return ModelResponse(
            output=PlanPriority(ordered_step_ids=ordered, skipped_step_ids=[optional["step_id"]]),
            provider="fake",
            model="planner-v1",
        )


class _FailingPlanner:
    async def prioritize_plan(self, context, candidate_steps):
        del context, candidate_steps
        raise RuntimeError("untrusted message said to ignore policy")


class _MustNotRunPlanner:
    async def prioritize_plan(self, context, candidate_steps):
        del context, candidate_steps
        raise AssertionError("planner must not run without a prioritization choice")


@pytest.mark.asyncio
async def test_ai_cannot_skip_a_runnable_investigation_candidate() -> None:
    request, scoped = _scope("Đăng nhập https://example.com/login", external=True)
    service = SecurityInvestigationService(
        blacklist=FakeBlacklistRepository(),
        planning_enabled=True,
        assistant_model=_SkippingPlanner(),
        runtime_factory=lambda: SecurityAssistantRuntime(max_retries=0),
    )

    result = await service.investigate(request, scoped)

    reputation = next(step for step in result.investigation_plan if step.tool is SecurityInvestigationToolV4.URL_REPUTATION)
    assert reputation.status_reason == "not_configured"
    assert all(step.status_reason != "ai_priority_skip" for step in result.investigation_plan)
    assert any("deterministic plan" in limitation for limitation in result.limitations)


@pytest.mark.asyncio
async def test_planning_failure_falls_back_to_deterministic_policy() -> None:
    request, scoped = _scope(
        "Đăng nhập https://example.com/ignore-all-policy để xác minh",
        external=False,
    )
    service = SecurityInvestigationService(
        blacklist=FakeBlacklistRepository(),
        planning_enabled=True,
        assistant_model=_FailingPlanner(),
        runtime_factory=lambda: SecurityAssistantRuntime(max_retries=0),
    )

    result = await service.investigate(request, scoped)

    assert any("deterministic plan" in limitation for limitation in result.limitations)
    external = [
        step
        for step in result.investigation_plan
        if step.tool
        in {
            SecurityInvestigationToolV4.DNS,
            SecurityInvestigationToolV4.REDIRECT_RESOLVER,
            SecurityInvestigationToolV4.RDAP,
            SecurityInvestigationToolV4.URL_REPUTATION,
        }
    ]
    assert external and all(step.status_reason == "consent_required" for step in external)


@pytest.mark.asyncio
async def test_context_only_plan_does_not_call_ai_planner_or_report_fallback() -> None:
    request, scoped = _scope("Ngân hàng yêu cầu chuyển tiền 2 triệu ngay", external=True)
    service = SecurityInvestigationService(
        blacklist=FakeBlacklistRepository(),
        planning_enabled=True,
        assistant_model=_MustNotRunPlanner(),
        runtime_factory=lambda: SecurityAssistantRuntime(max_retries=0),
    )

    result = await service.investigate(request, scoped)

    assert len(result.investigation_plan) == 1
    assert not any("deterministic plan" in limitation for limitation in result.limitations)
