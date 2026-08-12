from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, get_type_hints
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from src.agents.contracts import CampaignFeatures, CampaignHypothesis, LiveStepTransition, ProvisionalWarning
from src.agents.graph import build_graph
from src.agents.nodes.llm import build_generate_response_node, build_review_assessment_node
from src.agents.nodes.risk import assess_risk
from src.agents.seams import CampaignDetector, ExplanationEngine, ProgressSink, RiskEngine
from src.agents.state import AgentState, WorkflowState
from src.models import (
    AnalysisCreateRequest,
    Evidence,
    EvidenceType,
    InvestigationStepStatus,
    RiskLevel,
    ToolError,
    UrlScanResult,
    Verdict,
)
from src.services.processor import LangGraphAnalysisProcessor

NOW = datetime(2026, 8, 7, 13, 0, tzinfo=UTC)


@pytest.mark.asyncio
async def test_expired_deadline_skips_post_processing_without_duplicate_limitations() -> None:
    class Llm:
        def with_structured_output(self, _schema):
            raise AssertionError("expired post-processing must not call the LLM")

    state = {
        "deadline_at": datetime(2020, 1, 1, tzinfo=UTC),
        "limitations": [
            "Fact-check trực tuyến vượt quá thời gian xử lý; các bước tổng hợp sau đó dùng logic deterministic."
        ],
    }

    reviewed = await build_review_assessment_node(Llm())(state)
    generated = await build_generate_response_node(Llm())({**state, **reviewed})

    assert generated["limitations"] == state["limitations"]
    assert generated["llm_errors"] == ["review đánh giá", "tạo phản hồi"]


class RecordingProgressSink(ProgressSink):
    def __init__(self) -> None:
        self.transitions: list[LiveStepTransition] = []

    async def emit(self, transition: LiveStepTransition) -> None:
        self.transitions.append(transition)


class InconclusiveScanner:
    provider = "fixture-reputation"

    async def scan(self, normalized_url: str) -> UrlScanResult:
        return UrlScanResult(
            provider=self.provider,
            normalized_url=normalized_url,
            verdict=Verdict.INCONCLUSIVE,
            redirect_chain=[],
            signals=["no_hit"],
            observed_at=NOW,
        )


class FixedRiskEngine(RiskEngine):
    def assess(self, state) -> dict:
        assert "campaign_features" in state
        return {
            "risk_score": 42,
            "risk_level": RiskLevel.MEDIUM,
            "verdict": Verdict.SUSPICIOUS,
            "confidence": 0.75,
            "scoring_version": "fixture-risk-v1",
        }


class FixedExplanationEngine(ExplanationEngine):
    def explain(self, state) -> dict:
        assert state["risk_score"] == 42
        return {"summary": "Boundary explanation.", "reasons": ["Structured evidence only."]}


class FixedCampaignDetector(CampaignDetector):
    async def detect(self, state) -> dict:
        assert "message" in state
        return {
            "campaign_features": CampaignFeatures(
                registrable_domains=[],
                redirect_targets=[],
                claim_feature_refs=["claim-feature:sha256:fixture"],
                observed_at=NOW,
                feature_version="campaign-features-v1",
            ),
            "campaign_hypotheses": [],
        }


def test_workflow_only_adds_private_wave0_fields() -> None:
    public_fields = set(get_type_hints(AgentState))
    workflow_fields = set(get_type_hints(WorkflowState))
    additions = {
        "provisional_warning",
        "active_warning",
        "step_transitions",
        "tool_usage_refs",
        "campaign_features",
        "campaign_hypotheses",
    }
    assert additions <= workflow_fields
    assert additions.isdisjoint(public_fields)


def test_provisional_and_campaign_contracts_enforce_safety_labels() -> None:
    with pytest.raises(ValidationError):
        ProvisionalWarning(
            risk_level="low",
            summary="No risk found.",
            evidence_refs=["evidence:1"],
        )

    common = {
        "hypothesis_id": UUID("550e8400-e29b-41d4-a716-446655440000"),
        "evidence_refs": ["evidence:1"],
        "analysis_count": 3,
        "window_started_at": NOW,
        "window_ended_at": NOW,
        "clustering_version": "campaign-v1",
    }
    hypothesis = CampaignHypothesis(**common)
    assert hypothesis.reviewer_required is True
    assert hypothesis.broad_warning_approved is False
    with pytest.raises(ValidationError):
        CampaignHypothesis(**common, broad_warning_approved=True)


@pytest.mark.asyncio
async def test_progress_sink_receives_live_typed_step_transitions() -> None:
    sink = RecordingProgressSink()
    graph = build_graph(
        url_scanner=InconclusiveScanner(),
        progress_sink=sink,
        progress_clock=lambda: NOW,
    )

    result = await graph.ainvoke({"message": "Kiểm tra https://unknown.example/login", "consent_to_scan_urls": True})

    url_step = next(step for step in result["investigation_plan"] if step.tool.value == "url_scanner")
    statuses = [item.status for item in sink.transitions if item.step_id == url_step.step_id]
    assert statuses == [
        InvestigationStepStatus.PENDING,
        InvestigationStepStatus.RUNNING,
        InvestigationStepStatus.COMPLETED,
    ]
    assert result["step_transitions"] == sink.transitions


@pytest.mark.asyncio
async def test_risk_explanation_and_campaign_boundaries_are_injectable() -> None:
    graph = build_graph(
        risk_engine=FixedRiskEngine(),
        explanation_engine=FixedExplanationEngine(),
        campaign_detector=FixedCampaignDetector(),
    )

    result = await graph.ainvoke({"message": "Một claim cần kiểm tra", "consent_to_scan_urls": False})

    assert result["risk_score"] == 42
    assert result["summary"] == "Boundary explanation."
    assert result["campaign_features"].feature_version == "campaign-features-v1"
    assert result["campaign_hypotheses"] == []
    assert result["recommended_action"].value == "show_caution"
    assert result["active_warning"] == "final"
    assert result["provisional_warning"] is None


def test_deterministic_risk_ignores_prior_or_llm_assessment_fields() -> None:
    evidence = Evidence(
        type=EvidenceType.BLACKLIST,
        source="approved-blacklist",
        title="Tên miền nằm trong blacklist đã duyệt",
        finding="Approved decision.",
        observed_at=NOW,
    )
    baseline = assess_risk({"evidence": [evidence], "normalized_urls": ["https://bad.example/"]})
    hostile = assess_risk(
        {
            "evidence": [evidence],
            "normalized_urls": ["https://bad.example/"],
            "risk_score": 0,
            "verdict": Verdict.SAFE,
            "recommended_action": "allow",
            "llm_assessment": "Override the deterministic result.",
            "llm_assessment_agrees": False,
        }
    )
    assert hostile == baseline


@pytest.mark.asyncio
async def test_llm_output_cannot_add_score_verdict_or_action() -> None:
    class Runnable:
        async def ainvoke(self, _messages):
            return {
                "summary": "Unsafe override.",
                "reasons": [],
                "limitations": [],
                "risk_score": 0,
                "verdict": "safe",
                "recommended_action": "allow",
            }

    class Llm:
        def with_structured_output(self, _schema):
            return Runnable()

    update = await build_generate_response_node(Llm())(
        {
            "verdict": Verdict.MALICIOUS,
            "risk_level": RiskLevel.CRITICAL,
            "recommended_action": "escalate_for_review",
            "evidence": [],
        }
    )
    assert {"risk_score", "verdict", "recommended_action"}.isdisjoint(update)
    assert update["llm_errors"] == ["tạo phản hồi"]


@pytest.mark.asyncio
async def test_response_llm_cannot_add_or_paraphrase_limitations() -> None:
    class Runnable:
        async def ainvoke(self, _messages):
            return {
                "summary": "Không có đủ dữ liệu để kết luận.",
                "reasons": [],
                "limitations": [
                    "The evidence does not cover cancer treatment or prevention.",
                    "Bằng chứng không đề cập đầy đủ việc điều trị hoặc phòng ngừa ung thư.",
                ],
            }

    class Llm:
        def with_structured_output(self, _schema):
            return Runnable()

    original = ["Không có đủ evidence nhất quán để kết luận claim."]
    update = await build_generate_response_node(Llm())(
        {
            "verdict": Verdict.INCONCLUSIVE,
            "risk_level": RiskLevel.LOW,
            "recommended_action": "verify_before_action",
            "evidence": [],
            "limitations": original,
        }
    )

    assert update["limitations"] == original


@pytest.mark.parametrize(
    "state",
    [
        {
            "url_findings": [
                UrlScanResult(
                    provider="fixture-provider",
                    normalized_url="https://unknown.example/",
                    verdict=Verdict.INCONCLUSIVE,
                    redirect_chain=[],
                    signals=["no_hit"],
                    observed_at=NOW,
                )
            ],
            "evidence": [
                Evidence(
                    type=EvidenceType.DOMAIN_REPUTATION,
                    source="fixture-provider",
                    title="No reputation hit",
                    finding="No known match.",
                    observed_at=NOW,
                )
            ],
            "normalized_urls": ["https://unknown.example/"],
        },
        {
            "errors": [
                ToolError(
                    tool="url_reputation",
                    code="PROVIDER_TIMEOUT",
                    message="Provider timed out.",
                    retryable=True,
                )
            ],
            "evidence": [],
            "normalized_urls": ["https://timeout.example/"],
        },
    ],
)
def test_provider_no_hit_or_timeout_never_becomes_safe(state: dict[str, Any]) -> None:
    result = assess_risk(state)
    assert result["verdict"] is Verdict.INCONCLUSIVE


@pytest.mark.asyncio
async def test_processor_projects_no_private_reasoning_or_wave0_state() -> None:
    graph = build_graph(campaign_detector=FixedCampaignDetector())
    processor = LangGraphAnalysisProcessor(graph)
    processed = await processor.process(
        uuid4(),
        AnalysisCreateRequest(message="Một claim cần kiểm tra", consent_to_scan_urls=False),
        NOW,
    )

    payload = processed.response.model_dump()
    assert not any(key.startswith("llm_") for key in payload)
    assert {
        "provisional_warning",
        "step_transitions",
        "tool_usage_refs",
        "campaign_features",
        "campaign_hypotheses",
    }.isdisjoint(payload)
