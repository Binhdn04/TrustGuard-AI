from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from scripts.evaluate_security_langfuse import _trace_output
from src.evaluation.security_langfuse import (
    MetricStatus,
    SecurityAction,
    SecurityEvaluationCase,
    TraceOutput,
    aggregate_results,
    dataset_sha256,
    evaluate_case,
    load_security_evaluation_set,
    to_langfuse_item,
)

DATASET = "eval/test_cases.jsonl"


def _case(case_id: str) -> SecurityEvaluationCase:
    return next(item for item in load_security_evaluation_set(DATASET) if item.id == case_id)


def test_standardized_dataset_has_stable_complete_coverage() -> None:
    cases = load_security_evaluation_set(DATASET)

    assert len(cases) == 40
    assert len(dataset_sha256(cases)) == 64
    assert {case.metadata.polarity for case in cases} == {"unsafe", "benign", "abstain"}
    assert {case.metadata.split.value for case in cases} == {"dev", "test"}
    assert all(to_langfuse_item(case)["metadata"]["case_id"] == case.id for case in cases)


def test_dataset_rejects_literal_secret_values() -> None:
    payload = _case("case_006_viettel_otp_phone").model_dump(mode="json")
    payload["input"]["message"] = "OTP: 123456"

    with pytest.raises(ValidationError, match="literal secret"):
        SecurityEvaluationCase.model_validate(payload)


def test_security_decision_and_grounding_are_scored_with_diagnostics() -> None:
    case = _case("case_018_bank_otp_phone")
    output = TraceOutput(
        status="COMPLETED",
        scope="IN_SCOPE",
        risk="HIGH_RISK",
        threat_type="CREDENTIAL_AND_OTP_PHISHING",
        recommended_actions=["DO_NOT_SHARE_OTP", "REPORT_AND_BLOCK_SENDER"],
        tools_called=["security_context_analysis"],
        tool_calls_used=1,
        evidence_refs=["evidence:1"],
        explanation_evidence_refs=["evidence:1"],
        assistant_response={
            "summary": "Không cung cấp OTP.",
            "top_reasons": [{"text": "OTP là bí mật.", "evidence_refs": ["evidence:1"]}],
            "immediate_steps": [
                {"action": "DO_NOT_SHARE_OTP", "policy_ref": "policy:otp"},
                {"action": "REPORT_AND_BLOCK_SENDER", "policy_ref": "policy:report"},
            ],
        },
    )

    result = evaluate_case(case, output)
    metrics = {item.name: item for item in result.metrics}

    assert result.actual_action is SecurityAction.DO_NOT_PROCEED
    assert metrics["security_decision_accuracy"].value == 1
    assert metrics["task_completion"].value == 1
    assert metrics["tool_correctness"].value == 1
    assert metrics["faithfulness"].value == 1
    assert metrics["contextual_precision"].status is MetricStatus.UNAVAILABLE


def test_tool_and_faithfulness_failures_explain_why() -> None:
    case = _case("case_018_bank_otp_phone")
    output = TraceOutput(
        status="COMPLETED",
        scope="IN_SCOPE",
        risk="HIGH_RISK",
        recommended_actions=["DO_NOT_SHARE_OTP"],
        tools_called=["dns"],
        tool_calls_used=3,
        evidence_refs=["evidence:real"],
        assistant_response={
            "summary": "Cảnh báo.",
            "top_reasons": [{"text": "Không có nguồn.", "evidence_refs": ["evidence:invented"]}],
            "immediate_steps": [{"action": "DO_NOT_TRANSFER_MONEY", "policy_ref": "policy:x"}],
        },
    )

    result = evaluate_case(case, output)
    metrics = {item.name: item for item in result.metrics}

    assert "forbidden_or_unconsented_tool" in metrics["tool_correctness"].failure_codes
    assert metrics["faithfulness"].details["fabricated_refs"] == ["evidence:invented"]
    assert metrics["faithfulness"].details["unsupported_actions"] == ["DO_NOT_TRANSFER_MONEY"]


def test_redacted_historical_trace_marks_unavailable_metrics() -> None:
    result = evaluate_case(
        _case("case_040_paypal_urgent_login"),
        TraceOutput(status="COMPLETED", scope="IN_SCOPE", risk="SUSPICIOUS", tool_calls_used=2),
    )
    unavailable = {item.name for item in result.metrics if item.status is MetricStatus.UNAVAILABLE}

    assert unavailable == {"task_completion", "tool_correctness", "contextual_precision", "faithfulness"}
    assert next(item for item in result.metrics if item.name == "security_decision_accuracy").value == 1


def test_confusion_matrix_and_undefined_denominators() -> None:
    unsafe = evaluate_case(
        _case("case_018_bank_otp_phone"),
        TraceOutput(scope="IN_SCOPE", risk="SAFE", recommended_actions=["ALLOW_OPEN"]),
    )
    benign = evaluate_case(
        _case("case_020_bidv_official_check"),
        TraceOutput(scope="IN_SCOPE", risk="HIGH_RISK", recommended_actions=["DO_NOT_OPEN_LINK"]),
    )
    summary = aggregate_results([unsafe, benign])

    assert summary["confusion_matrix"] == {"tp": 0, "fp": 1, "fn": 1, "tn": 0}
    assert summary["false_positive_rate"] == 1.0
    assert summary["false_negative_rate"] == 1.0
    assert summary["latency_ms"]["p95"] is None


def test_saved_rows_are_json_serializable() -> None:
    result = evaluate_case(
        _case("case_020_bidv_official_check"),
        TraceOutput(scope="IN_SCOPE", risk="SAFE", recommended_actions=["ALLOW_OPEN"]),
    )

    assert json.loads(result.model_dump_json())["case_id"] == "case_020_bidv_official_check"


def test_trace_adapter_aggregates_child_generation_usage_and_cost() -> None:
    output = _trace_output(
        {
            "start_time": "2026-08-31T00:00:00+00:00",
            "end_time": "2026-08-31T00:00:02+00:00",
            "output": '{"scope":"IN_SCOPE","risk":"SAFE"}',
        },
        [
            {"usage_details": {"input": 10, "output": 4}, "cost_details": {"total": 0.001}},
            {"usage_details": {"input": 20, "output": 6}, "total_cost": 0.002},
        ],
    )

    assert output.latency_ms == 2000
    assert output.input_tokens == 30
    assert output.output_tokens == 10
    assert output.cost_usd == pytest.approx(0.003)
