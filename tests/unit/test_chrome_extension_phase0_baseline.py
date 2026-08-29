from __future__ import annotations

import pytest

from src.agents.security_investigation import build_security_investigation_plan
from src.evaluation.security_v4 import EXTERNAL_TOOLS, EvaluationExpected, SecurityEvaluationCase, evaluate_case
from src.models import (
    ScopeDecisionV4,
    SecurityExecutionModeV4,
    SecurityRiskV4,
    SecurityTriageCreateRequestV4,
)
from src.services.security_triage import SecurityTriageScopeService
from tests.fixture_loader import (
    ChromeExtensionBaselineFixture,
    ChromeExtensionPhase0Case,
    load_chrome_extension_phase0_fixtures,
)

FIXTURES = load_chrome_extension_phase0_fixtures()
HIGH_RISKS = {SecurityRiskV4.HIGH_RISK, SecurityRiskV4.MALICIOUS}


def _evaluation_case(case: ChromeExtensionPhase0Case) -> SecurityEvaluationCase:
    expected = case.expected
    return SecurityEvaluationCase(
        dataset_version=FIXTURES.schema_version,
        id=case.id,
        category=case.category,
        message=case.capture.value,
        consent=case.consent.model_dump(mode="json"),
        fixture_evidence=case.fixture_evidence,
        fixture_error=case.fixture_error,
        expected=EvaluationExpected(
            scope_decision=expected.scope_decision,
            threat_type=expected.threat_type,
            accepted_risks=[expected.risk] if expected.risk is not None else [],
            required_tools=expected.planned_tools,
            max_provider_calls=expected.planned_provider_calls,
            high_risk=expected.risk in HIGH_RISKS,
        ),
    )


def _stable_scope(request: SecurityTriageCreateRequestV4) -> dict:
    response = SecurityTriageScopeService().assess(request)
    return response.model_dump(
        mode="json",
        exclude={"analysis_id", "conversation_id", "created_at", "completed_at"},
    )


def test_phase0_fixture_contract_covers_capture_and_security_branches() -> None:
    assert FIXTURES.schema_version == "chrome-extension-phase0-v1"
    assert {case.capture.kind for case in FIXTURES.cases} == {"selection", "link"}
    assert {case.category for case in FIXTURES.cases} == {
        "in_scope",
        "out_of_scope",
        "need_more_info",
        "no_consent",
        "provider_error",
        "provider_no_hit",
    }
    assert all(set(case.capture.model_dump()) == {"kind", "value"} for case in FIXTURES.cases)


@pytest.mark.parametrize(
    "investigation_output",
    [
        {"planned_tools": ["security_context_analysis"]},
        {"planned_provider_calls": 1},
    ],
)
def test_phase0_terminal_baseline_rejects_investigation_output(investigation_output: dict) -> None:
    with pytest.raises(ValueError, match="terminal extension baseline cannot contain investigation output"):
        ChromeExtensionBaselineFixture.model_validate(
            {"scope_decision": "NEED_MORE_INFO", **investigation_output}
        )


@pytest.mark.parametrize("case", FIXTURES.cases, ids=lambda case: case.id)
def test_phase0_v4_risk_projection_and_tool_plan_are_characterized(case: ChromeExtensionPhase0Case) -> None:
    result = evaluate_case(_evaluation_case(case))
    expected = case.expected

    assert result.scope_decision is expected.scope_decision
    assert result.threat_type is expected.threat_type
    assert result.risk is expected.risk
    assert result.planned_tools == expected.planned_tools
    assert result.planned_provider_calls == expected.planned_provider_calls
    assert result.routing_pass is True
    assert result.scope_pass is True
    assert result.threat_pass is True
    assert result.risk_pass is True
    assert result.grounding_pass is True

    request = SecurityTriageCreateRequestV4(
        message=case.capture.value,
        consent=case.consent,
    )
    scoped = SecurityTriageScopeService().assess(request)
    plan = (
        build_security_investigation_plan(
            scoped.security_context,
            external_url_lookup=request.consent.external_url_lookup,
        )
        if scoped.security_context is not None and scoped.scope_decision is ScopeDecisionV4.IN_SCOPE
        else []
    )
    assert [
        {"tool": step.tool, "status": step.status, "target": step.target}
        for step in plan
    ] == [
        {"tool": step.tool, "status": step.status, "target": step.target}
        for step in expected.plan
    ]
    assert sum(step.tool in EXTERNAL_TOOLS and step.status.value == "pending" for step in plan) == (
        expected.planned_provider_calls
    )


@pytest.mark.parametrize(
    "case",
    FIXTURES.cases,
    ids=lambda case: case.id,
)
def test_phase0_inline_and_async_requests_have_identical_scope_semantics(
    case: ChromeExtensionPhase0Case,
) -> None:
    inline = SecurityTriageCreateRequestV4(
        message=case.capture.value,
        consent=case.consent,
        execution_mode=SecurityExecutionModeV4.INLINE,
    )
    asynchronous = SecurityTriageCreateRequestV4(
        message=case.capture.value,
        consent=case.consent,
        execution_mode=SecurityExecutionModeV4.ASYNC,
    )

    assert inline.message == asynchronous.message == case.capture.value
    assert inline.consent == asynchronous.consent == case.consent
    assert _stable_scope(inline) == _stable_scope(asynchronous)


def test_phase0_no_consent_and_provider_failures_never_become_safe() -> None:
    by_category = {case.category: evaluate_case(_evaluation_case(case)) for case in FIXTURES.cases}

    assert by_category["no_consent"].planned_provider_calls == 0
    assert by_category["provider_error"].risk is SecurityRiskV4.INSUFFICIENT_EVIDENCE
    assert by_category["provider_no_hit"].risk is SecurityRiskV4.INSUFFICIENT_EVIDENCE
    assert by_category["provider_error"].risk is not SecurityRiskV4.SAFE
    assert by_category["provider_no_hit"].risk is not SecurityRiskV4.SAFE
