from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src.agents.security_risk import assess_security_risk
from src.models import (
    AssistantGenerationModeV4,
    ClaimVerificationV4,
    IdentityAssociationAssuranceV4,
    IdentityAssociationV4,
    IdentityRelationshipV4,
    OfficialLinkVerificationReportV4,
    OfficialVerificationComponentV4,
    PublisherVerificationV4,
    RequestedActionV4,
    ResourceIdentityV4,
    ResourceMatchStatusV4,
    ResourceMatchV4,
    ResourceTypeV4,
    ResourceVerificationV4,
    SecurityEvidenceTypeV4,
    SecurityEvidenceV4,
    SecurityRecommendedActionV4,
    SecurityRiskV4,
    SecurityTriageCreateRequestV4,
    VerificationIntentV4,
    VerificationStatusV4,
)
from src.security_ai.contracts import AssistantSynthesis, ModelResponse, SynthesisReason
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.security_response import (
    GroundedSecurityResponseService,
    SynthesisGroundingFailure,
    check_grounded_ai_response,
    grounded_ai_response,
    policy_grounded_assistant_response,
)
from src.services.security_triage import SecurityTriageScopeService


def _risk_result():
    request = SecurityTriageCreateRequestV4(message="Ngân hàng yêu cầu gửi OTP ngay")
    scoped = SecurityTriageScopeService().assess(request)
    evidence = SecurityEvidenceV4(
        evidence_ref="evidence:0123456789abcdef",
        type=SecurityEvidenceTypeV4.SECURITY_CONTEXT,
        source="security-context-v1",
        target="message",
        signal="account_verification+CREDENTIAL_THEFT+otp_request",
        description="Nội dung yêu cầu chia sẻ OTP với tính khẩn cấp.",
        observed_at=datetime(2026, 8, 14, tzinfo=UTC),
    )
    return assess_security_risk(scoped.model_copy(update={"evidence": [evidence]}))


def test_grounding_verifier_rejects_hallucinated_refs_and_urls() -> None:
    scoped = _risk_result()
    invented = AssistantSynthesis(
        summary="Rủi ro cao.",
        top_reasons=[SynthesisReason(text="Threat hit", evidence_refs=["evidence:ffffffffffffffff"])],
    )
    linked = AssistantSynthesis(
        summary="Mở https://unsafe.example để kiểm tra.",
        top_reasons=[SynthesisReason(text="OTP request", evidence_refs=["evidence:0123456789abcdef"])],
    )
    statistical = AssistantSynthesis(
        summary="Rủi ro cao với điểm số 95/100 và độ tin cậy 90%.",
        top_reasons=[SynthesisReason(text="Có yêu cầu OTP.", evidence_refs=["evidence:0123456789abcdef"])],
    )
    statistical_reason = AssistantSynthesis(
        summary="Nội dung này có nguy cơ cao.",
        top_reasons=[
            SynthesisReason(
                text="Tín hiệu OTP có độ tin cậy 90%.",
                evidence_refs=["evidence:0123456789abcdef"],
            )
        ],
    )
    natural_destination = AssistantSynthesis(
        summary="Liên kết này cần được xem xét thận trọng.",
        top_reasons=[
            SynthesisReason(
                text="Điểm đến cuối của liên kết cần được kiểm tra.",
                evidence_refs=["evidence:0123456789abcdef"],
            )
        ],
    )

    assert grounded_ai_response(scoped, invented) is None
    assert grounded_ai_response(scoped, linked) is None
    assert grounded_ai_response(scoped, statistical) is None
    assert grounded_ai_response(scoped, statistical_reason) is None
    assert grounded_ai_response(scoped, natural_destination) is not None

    assert check_grounded_ai_response(scoped, invented).failure is SynthesisGroundingFailure.UNKNOWN_EVIDENCE_REF
    assert check_grounded_ai_response(scoped, linked).failure is SynthesisGroundingFailure.UNSAFE_URL
    assert check_grounded_ai_response(scoped, statistical).failure is SynthesisGroundingFailure.TECHNICAL_METRIC


def test_grounding_verifier_allows_a_single_natural_reply_without_report_sections() -> None:
    scoped = _risk_result()
    synthesis = AssistantSynthesis(summary="Nội dung này cần được xem xét thận trọng.")

    checked = check_grounded_ai_response(scoped, synthesis)

    assert checked.response is not None
    assert checked.failure is None


def test_composer_receives_and_must_cover_semantic_identity_mismatch_reasoning() -> None:
    """A valid domain must not be mistaken for validation of the message claim."""
    scoped = SecurityTriageScopeService().assess(
        SecurityTriageCreateRequestV4(message="Tổ chức A yêu cầu bạn mở liên kết.")
    )
    assert scoped.security_context is not None
    context = scoped.security_context.model_copy(update={"claimed_entity": "Tổ chức A"})
    mismatch = SecurityEvidenceV4(
        evidence_ref="evidence:aaaaaaaaaaaaaaaa",
        type=SecurityEvidenceTypeV4.BRAND_MATCH,
        source="brand-registry",
        target="organization-b.example",
        signal="entity_target_mismatch",
        description="internal diagnostic deliberately excluded from synthesis",
        observed_at=datetime(2026, 8, 14, tzinfo=UTC),
        confidence=1,
    )
    result = assess_security_risk(scoped.model_copy(update={"security_context": context, "evidence": [mismatch]}))

    payload = GroundedSecurityResponseService._synthesis_payload(result)

    assert payload["decisive_facts"] == [
        {
            "category": "claimed_entity_target_mismatch",
            "finding": (
                "Tên miền organization-b.example đã được đối chiếu thuộc một tổ chức khác, "
                "trong khi nội dung gắn nó với Tổ chức A."
            ),
            "security_meaning": (
                "Tên miền có thể là một địa chỉ hợp lệ, nhưng điều đó không xác minh nó được "
                "tổ chức trong tin nhắn sử dụng cho yêu cầu này."
            ),
            "evidence_refs": ["evidence:aaaaaaaaaaaaaaaa"],
        }
    ]
    assert payload["available_explanation_evidence_refs"] == ["evidence:aaaaaaaaaaaaaaaa"]
    assert "internal diagnostic" not in str(payload)

    omitted = check_grounded_ai_response(result, AssistantSynthesis(summary="Nội dung này đáng ngờ."))
    assert omitted.response is not None
    covered = check_grounded_ai_response(
        result,
        AssistantSynthesis(
            summary=(
                "Tin nhắn gắn liên kết với Tổ chức A, nhưng tên miền này thuộc một tổ chức khác; "
                "vì vậy tên miền hợp lệ không xác minh yêu cầu trong tin nhắn."
            ),
            top_reasons=[
                SynthesisReason(
                    text="Tên miền đã được đối chiếu với một tổ chức khác.",
                    evidence_refs=["evidence:aaaaaaaaaaaaaaaa"],
                )
            ],
        ),
    )
    assert covered.response is not None


@pytest.mark.asyncio
async def test_natural_composer_summary_without_audit_reasons_stays_on_ai_happy_path() -> None:
    """A valid prose-only GPT response must not be replaced by field templates."""
    scoped = _exact_resource_endorsement_scope(
        organization="Example University",
        resource_url="https://forms.example/enrollment",
    )
    natural_reply = AssistantSynthesis(
        summary=(
            "Biểu mẫu này đã được nguồn chính thức của Example University xác nhận sử dụng. "
            "Tuy nhiên, chương trình được nhắc trong tin nhắn chưa có xác nhận riêng; "
            "vì vậy biểu mẫu có cơ sở chính thức nhưng chưa đủ để xác nhận toàn bộ nội dung tin nhắn."
        )
    )

    class _ProseOnlyComposer:
        async def synthesize(self, payload):
            del payload
            return ModelResponse(output=natural_reply, provider="fake", model="synthesis-v1")

    result = await GroundedSecurityResponseService(
        ai_enabled=True,
        model=_ProseOnlyComposer(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(scoped)

    assert result.assistant_response is not None
    assert result.assistant_response.generation_mode is AssistantGenerationModeV4.AI
    assert result.assistant_response.summary == natural_reply.summary


def test_composer_prefers_verified_domain_and_unverified_action_over_sender_status() -> None:
    """The response should explain the decision, not enumerate verification fields."""
    domain = SecurityEvidenceV4(
        evidence_ref="evidence:1111111111111111",
        type=SecurityEvidenceTypeV4.OFFICIAL_VERIFICATION,
        source="official-verification",
        target="northstar.example",
        signal="official_domain_verified",
        description="fixture",
        observed_at=datetime(2026, 8, 14, tzinfo=UTC),
    )
    sender = SecurityEvidenceV4(
        evidence_ref="evidence:2222222222222222",
        type=SecurityEvidenceTypeV4.OFFICIAL_VERIFICATION,
        source="official-verification",
        target="Northstar Utilities",
        signal="sender_identity_unverified",
        description="fixture",
        observed_at=datetime(2026, 8, 14, tzinfo=UTC),
    )
    action = SecurityEvidenceV4(
        evidence_ref="evidence:3333333333333333",
        type=SecurityEvidenceTypeV4.OFFICIAL_VERIFICATION,
        source="official-verification",
        target="login",
        signal="action_endorsement_unverified",
        description="fixture",
        observed_at=datetime(2026, 8, 14, tzinfo=UTC),
    )
    scoped = _risk_result().model_copy(update={"evidence": [domain, sender, action]})

    payload = GroundedSecurityResponseService._synthesis_payload(scoped)

    assert [fact["category"] for fact in payload["decisive_facts"]] == [
        "official_domain_verified",
        "requested_action_unverified",
    ]
    assert payload["available_explanation_evidence_refs"] == [
        "evidence:1111111111111111",
        "evidence:3333333333333333",
    ]
    instruction = payload["presentation_constraints"]["explain_decisive_facts"]
    assert instruction is not None and "Do not serialize facts" in instruction


@pytest.mark.asyncio
async def test_composer_keeps_structured_verified_ownership_without_projected_evidence() -> None:
    """Ownership status must survive context, prompt, validator, and AI output."""
    scoped = SecurityTriageScopeService().assess(
        SecurityTriageCreateRequestV4(
            message="Vingroup hoàn 20 triệu cho khách hàng. Đăng nhập tại https://vingroup.net/vi/lien-he"
        )
    )
    report = OfficialLinkVerificationReportV4(
        schema_version="official-link-verification-v4",
        intent=VerificationIntentV4(
            organization_name="Vingroup",
            claim_summary="hoàn 20 triệu cho khách hàng",
            requested_action=RequestedActionV4.LOGIN,
            action_url_indices=[0],
        ),
        publisher_verification=PublisherVerificationV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="publisher_not_confirmed"
        ),
        claim_verification=ClaimVerificationV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="claim_not_confirmed"
        ),
        resource_verification=ResourceVerificationV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="resource_not_confirmed"
        ),
        domain_ownership_verification=OfficialVerificationComponentV4(
            applicable=True, status=VerificationStatusV4.VERIFIED, reason_code="official_domain_confirmed"
        ),
        sender_verification=OfficialVerificationComponentV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="sender_not_confirmed"
        ),
        action_endorsement_verification=OfficialVerificationComponentV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="action_not_confirmed"
        ),
        overall_status=VerificationStatusV4.PARTIALLY_VERIFIED,
        reason_code="ownership_only",
    )
    result = assess_security_risk(scoped.model_copy(update={"official_verification": report}))
    payload = GroundedSecurityResponseService._synthesis_payload(result)

    assert [fact["category"] for fact in payload["decisive_facts"]] == [
        "official_domain_verified",
        "requested_claim_unverified",
        "requested_action_unverified",
    ]
    assert payload["decisive_facts"][0]["finding"] == "Tên miền vingroup.net đã được xác minh thuộc tổ chức được nêu."
    assert all(fact["category"] != "sender_identity_unverified" for fact in payload["decisive_facts"])

    expected = (
        "Đây là website chính thức của Vingroup. Tuy nhiên, chưa tìm thấy nguồn chính thức xác nhận "
        "thông tin hoàn 20 triệu hoặc việc Vingroup yêu cầu đăng nhập tại trang liên hệ này. "
        "Vì vậy, website chính thức không đồng nghĩa với nội dung tin nhắn là thật. "
        "Không nhập mật khẩu hoặc OTP chỉ dựa trên tin nhắn này."
    )

    class _NaturalComposer:
        async def synthesize(self, composer_payload):
            assert composer_payload["decisive_facts"] == payload["decisive_facts"]
            return ModelResponse(output=AssistantSynthesis(summary=expected), provider="fake", model="synthesis-v1")

    enriched = await GroundedSecurityResponseService(
        ai_enabled=True,
        model=_NaturalComposer(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(result)

    assert enriched.assistant_response is not None
    assert enriched.assistant_response.generation_mode is AssistantGenerationModeV4.AI
    assert enriched.assistant_response.summary == expected


class _ValidSynthesisModel:
    async def synthesize(self, result):
        ref = result["evidence"][0]["evidence_ref"]
        return ModelResponse(
            output=AssistantSynthesis(
                summary="Yêu cầu OTP khẩn cấp có rủi ro cao.",
                top_reasons=[SynthesisReason(text="Có yêu cầu OTP.", evidence_refs=[ref])],
                uncertainties=["Invented provider uncertainty must be ignored."],
                follow_up_offer="Invented procedural advice must be ignored.",
            ),
            provider="fake",
            model="synthesis-v1",
        )


class _MalformedSynthesisModel:
    async def synthesize(self, result):
        del result
        return ModelResponse(
            output=AssistantSynthesis(
                summary="Unsupported claim.",
                top_reasons=[SynthesisReason(text="Invented signal.", evidence_refs=["evidence:ffffffffffffffff"])],
            ),
            provider="fake",
            model="synthesis-v1",
        )


class _TerminalComposer:
    def __init__(self, prose: str) -> None:
        self.prose = prose
        self.payload: dict | None = None

    async def synthesize(self, result):
        self.payload = result
        return ModelResponse(
            output=AssistantSynthesis(summary=self.prose),
            provider="fake",
            model="terminal-composer-v1",
        )


@pytest.mark.asyncio
async def test_terminal_boundary_is_composed_from_structured_reason_not_a_template() -> None:
    scoped = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message="xin chào"))
    composer = _TerminalComposer("Chào bạn, mình có thể hỗ trợ kiểm tra tin nhắn hoặc liên kết đáng ngờ.")

    result = await GroundedSecurityResponseService(
        ai_enabled=True,
        model=composer,
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich_terminal(scoped)

    assert result.boundary_message == composer.prose
    assert composer.payload is not None
    assert composer.payload["contract"] == "security-terminal-message-context-v1"
    assert composer.payload["response_kind"] == "boundary"
    assert composer.payload["boundary_reason"] == scoped.scope_reasons


@pytest.mark.asyncio
async def test_terminal_clarification_rejects_invalid_composer_output_and_uses_emergency_copy(caplog) -> None:
    scoped = SecurityTriageScopeService().assess(SecurityTriageCreateRequestV4(message="có vẻ lừa đảo"))
    composer = _TerminalComposer("Liên kết này đã được xác minh là an toàn?")

    with caplog.at_level("WARNING", logger="trustguard.security_ai"):
        result = await GroundedSecurityResponseService(
            ai_enabled=True,
            model=composer,
            runtime=SecurityAssistantRuntime(max_retries=0),
        ).enrich_terminal(scoped)

    assert result.follow_up_question is not None
    assert result.follow_up_question != composer.prose
    assert any(item.getMessage() == "security_ai_terminal_composer_fallback" for item in caplog.records)


@pytest.mark.asyncio
async def test_ai_response_keeps_actions_and_uncertainties_deterministic() -> None:
    scoped = _risk_result()
    result = await GroundedSecurityResponseService(
        ai_enabled=True,
        model=_ValidSynthesisModel(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(scoped)

    response = result.assistant_response
    assert response is not None
    assert response.generation_mode is AssistantGenerationModeV4.AI
    assert [step.action for step in response.immediate_steps] == result.recommended_actions
    assert {step.policy_ref for step in response.immediate_steps} == {result.policy_version}
    assert response.uncertainties == scoped.limitations
    assert "Invented" not in response.follow_up_offer


@pytest.mark.asyncio
async def test_invalid_synthesis_uses_the_deterministic_fallback_only_when_composition_fails(caplog) -> None:
    with caplog.at_level("WARNING", logger="trustguard.security_ai"):
        result = await GroundedSecurityResponseService(
            ai_enabled=True,
            model=_MalformedSynthesisModel(),
            runtime=SecurityAssistantRuntime(max_retries=0),
        ).enrich(_risk_result())

    response = result.assistant_response
    assert response is not None
    assert response.generation_mode is AssistantGenerationModeV4.POLICY_GROUNDED
    assert response.degradation_reason == "grounding_rejected"
    assert "Unsupported claim" not in response.summary
    assert not any("grounding" in item.casefold() for item in response.uncertainties)
    assert any(item.getMessage() == "security_ai_composer_fallback" for item in caplog.records)


class _MetricSynthesisModel:
    async def synthesize(self, result):
        ref = result["evidence"][0]["evidence_ref"]
        return ModelResponse(
            output=AssistantSynthesis(
                summary="Nội dung này đáng ngờ. Điểm số rủi ro là 95/100.",
                top_reasons=[
                    SynthesisReason(text="Có yêu cầu OTP.", evidence_refs=[ref]),
                    SynthesisReason(text="Độ tin cậy 90%.", evidence_refs=[ref]),
                ],
            ),
            provider="fake",
            model="synthesis-v1",
        )


@pytest.mark.asyncio
async def test_metric_violation_falls_back_without_showing_internal_metrics() -> None:
    result = await GroundedSecurityResponseService(
        ai_enabled=True,
        model=_MetricSynthesisModel(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(_risk_result())

    response = result.assistant_response
    assert response is not None
    assert response.generation_mode is AssistantGenerationModeV4.POLICY_GROUNDED
    assert "95/100" not in response.summary
    assert "độ tin cậy" not in response.summary.casefold()


@pytest.mark.asyncio
async def test_disabled_ai_still_returns_a_policy_grounded_answer_without_failure_limitation() -> None:
    result = await GroundedSecurityResponseService(
        ai_enabled=False,
        model=None,
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(_risk_result())

    assert result.assistant_response is not None
    assert result.assistant_response.generation_mode is AssistantGenerationModeV4.POLICY_GROUNDED
    assert "điểm số" not in result.assistant_response.summary.casefold()
    assert "độ tin cậy" not in result.assistant_response.summary.casefold()
    assert "Không chia sẻ mã OTP" in result.assistant_response.summary
    assert result.assistant_response.top_reasons[0].text == (
        "Người gửi yêu cầu mã OTP, là thông tin không nên chia sẻ."
    )
    assert not any("AI explanation" in item for item in result.limitations)


def test_composer_context_excludes_review_workflow_diagnostics() -> None:
    scoped = _risk_result().model_copy(
        update={
            "limitations": [
                "Chưa có reviewed identity hoặc exact-resource association để xác nhận quan hệ giữa URL và tổ chức.",
                "Không thể xác nhận đầy đủ hành động được yêu cầu.",
            ]
        }
    )

    payload = GroundedSecurityResponseService._synthesis_payload(scoped)

    assert payload["important_uncertainties"] == ["Không thể xác nhận đầy đủ hành động được yêu cầu."]
    assert all("description" not in item for item in payload["evidence"])
    assert all("reviewed" not in str(value).casefold() for value in payload.values())


def test_composer_and_fallback_receive_case_specific_unverified_verification_truth() -> None:
    report = OfficialLinkVerificationReportV4(
        schema_version="official-link-verification-v4",
        intent=VerificationIntentV4(
            organization_name="Example Telecom",
            claim_summary="chương trình hỗ trợ khách hàng 500.000đ",
            requested_action=RequestedActionV4.SUBMIT_FORM,
            action_url_indices=[0],
        ),
        publisher_verification=PublisherVerificationV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="publisher_not_confirmed"
        ),
        claim_verification=ClaimVerificationV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="claim_not_confirmed"
        ),
        resource_verification=ResourceVerificationV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="resource_not_confirmed"
        ),
        domain_ownership_verification=OfficialVerificationComponentV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="ownership_not_confirmed"
        ),
        sender_verification=OfficialVerificationComponentV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="sender_not_confirmed"
        ),
        action_endorsement_verification=OfficialVerificationComponentV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="action_not_confirmed"
        ),
        overall_status=VerificationStatusV4.UNVERIFIED,
        reason_code="evidence_insufficient",
    )
    redirect = SecurityEvidenceV4(
        evidence_ref="evidence:fedcba9876543210",
        type=SecurityEvidenceTypeV4.REDIRECT,
        source="redirect",
        target="submitted_url",
        signal="redirect_destination_unresolved+http_404",
        description="bounded",
        observed_at=datetime(2026, 8, 14, tzinfo=UTC),
    )
    scoped = _risk_result().model_copy(
        update={
            "official_verification": report,
            "evidence": [redirect],
            "risk": SecurityRiskV4.LOW_RISK,
            "recommended_actions": [SecurityRecommendedActionV4.PROCEED_WITH_CAUTION],
        }
    )

    payload = GroundedSecurityResponseService._synthesis_payload(scoped)

    assert payload["verification_state"] == {
        "claimed_organization": "Example Telecom",
        "program_claim": {
            "value": "chương trình hỗ trợ khách hàng 500.000đ",
            "topic": None,
            "status": "UNVERIFIED",
        },
        "requested_action": {
            "value": "submit_form",
            "endorsement_status": "UNVERIFIED",
            "exact_resource_endorsed": False,
        },
        "submitted_resource": {
            "claimed_platforms": [],
            "status": "UNVERIFIED",
            "final_destination": "unresolved",
            "official_association": "not_established",
        },
        "domain_ownership": "UNVERIFIED",
        "sender_identity": "UNVERIFIED",
        "uncertainty_boundaries": {
            "sender_identity": "The sender identity is a separate fact from resource and action verification.",
            "domain_ownership": None,
        },
        "malicious_evidence": "none_observed",
        "unverified_is_not_a_risk_signal_by_itself": True,
    }
    fallback = policy_grounded_assistant_response(scoped).summary
    assert "Example Telecom" in fallback
    assert "chương trình hỗ trợ khách hàng 500.000đ" in fallback
    assert "Điểm đến cuối của liên kết vẫn chưa xác định được." in fallback


def test_verified_resource_does_not_project_http_failure_as_unknown_final_destination() -> None:
    """A retrieval failure is not evidence that the already-known URL redirects elsewhere."""
    scoped = _exact_resource_endorsement_scope(
        organization="Northstar Utilities",
        resource_url="https://portal.northstar.example/contact",
    )
    redirect = SecurityEvidenceV4(
        evidence_ref="evidence:1234567890abcdef",
        type=SecurityEvidenceTypeV4.REDIRECT,
        source="redirect",
        target="https://portal.northstar.example/contact",
        # Regression coverage for an in-flight/older projection as well as
        # the corrected source signal tested in security_investigation_v4.
        signal="redirect_destination_unresolved+http_404",
        description="The guarded request reached the submitted URL but returned HTTP 404.",
        observed_at=datetime(2026, 8, 14, tzinfo=UTC),
    )
    result = scoped.model_copy(update={"evidence": [*scoped.evidence, redirect]})

    payload = GroundedSecurityResponseService._synthesis_payload(result)

    assert payload["verification_state"]["submitted_resource"]["final_destination"] == "not_reported"
    assert all(fact["category"] != "redirect_destination_unresolved" for fact in payload["decisive_facts"])


def _exact_resource_endorsement_scope(*, organization: str, resource_url: str):
    scoped = SecurityTriageScopeService().assess(
        SecurityTriageCreateRequestV4(message=f"Please use {resource_url} for the enrollment.")
    )
    report = OfficialLinkVerificationReportV4(
        schema_version="official-link-verification-v4",
        intent=VerificationIntentV4(
            organization_name=organization,
            claim_summary="a public enrollment campaign",
            requested_action=RequestedActionV4.SUBMIT_FORM,
            action_url_indices=[0],
        ),
        publisher_verification=PublisherVerificationV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="publisher_not_reviewed"
        ),
        claim_verification=ClaimVerificationV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="claim_not_separately_confirmed"
        ),
        resource_verification=ResourceVerificationV4(
            applicable=True,
            status=VerificationStatusV4.VERIFIED,
            reason_code="official_exact_resource",
            evidence_refs=["identity-evidence:0123456789abcdef"],
            match=ResourceMatchV4(
                status=ResourceMatchStatusV4.EXACT_RESOURCE,
                user_resource=ResourceIdentityV4(
                    resource_type=ResourceTypeV4.URL,
                    canonical_url=resource_url,
                    match_key=resource_url,
                ),
                official_resource=ResourceIdentityV4(
                    resource_type=ResourceTypeV4.URL,
                    canonical_url=resource_url,
                    match_key=resource_url,
                ),
                reason_code="exact_resource",
            ),
        ),
        domain_ownership_verification=OfficialVerificationComponentV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="ownership_not_confirmed"
        ),
        sender_verification=OfficialVerificationComponentV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="sender_not_confirmed"
        ),
        action_endorsement_verification=OfficialVerificationComponentV4(
            applicable=True, status=VerificationStatusV4.UNVERIFIED, reason_code="action_not_confirmed"
        ),
        overall_status=VerificationStatusV4.PARTIALLY_VERIFIED,
        reason_code="publisher_unreviewed_exact_resource_endorsed",
        identity_associations=[
            IdentityAssociationV4(
                entity_name=organization,
                canonical_url=resource_url,
                canonical_domain=resource_url.split("/")[2],
                relationship=IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE,
                assurance=IdentityAssociationAssuranceV4.VERIFIED,
                confidence=1,
                evidence_refs=["identity-evidence:0123456789abcdef"],
                discovered_at=datetime(2026, 8, 14, tzinfo=UTC),
                verified_at=datetime(2026, 8, 14, tzinfo=UTC),
            )
        ],
    )
    assessed = assess_security_risk(scoped.model_copy(update={"official_verification": report}))
    return assessed.model_copy(
        update={
            "risk": SecurityRiskV4.INSUFFICIENT_EVIDENCE,
            "recommended_actions": [SecurityRecommendedActionV4.PROCEED_WITH_CAUTION],
        }
    )


@pytest.mark.parametrize(
    ("organization", "resource_url"),
    [
        ("Harbor Arts Council", "https://forms.pacific.example/open-call-2026"),
        ("North Valley Library", "https://apply.river.example/summer-reading"),
    ],
)
@pytest.mark.asyncio
async def test_exact_resource_endorsement_survives_grounding_without_granting_domain_or_campaign_assurance(
    organization: str, resource_url: str
) -> None:
    """Regression: resource endorsement must not disappear behind publisher uncertainty."""
    scoped = _exact_resource_endorsement_scope(organization=organization, resource_url=resource_url)

    payload = GroundedSecurityResponseService._synthesis_payload(scoped)
    assert payload["authoritative_security_truth"]["verified_exact_resource_endorsement"] is True
    assert payload["verification_state"]["submitted_resource"]["official_association"] == "exact_resource_endorsed"
    assert payload["verification_state"]["domain_ownership"] == "UNVERIFIED"
    assert payload["verification_state"]["sender_identity"] == "UNVERIFIED"
    assert payload["verification_state"]["requested_action"]["exact_resource_endorsed"] is False

    contradiction = AssistantSynthesis(
        summary="The exact submitted form could not be verified from an official source."
    )
    assert (
        check_grounded_ai_response(scoped, contradiction).failure
        is SynthesisGroundingFailure.CONTRADICTS_VERIFIED_EXACT_RESOURCE_ENDORSEMENT
    )
    mixed_scope = scoped.model_copy(
        update={
            "evidence": [
                SecurityEvidenceV4(
                    evidence_ref="evidence:fedcba9876543210",
                    type=SecurityEvidenceTypeV4.OFFICIAL_VERIFICATION,
                    source="official-verification",
                    target=resource_url.split("/")[2],
                    signal="exact_resource_endorsed",
                    description="fixture",
                    observed_at=datetime(2026, 8, 14, tzinfo=UTC),
                )
            ]
        }
    )
    natural_mixed_reply = AssistantSynthesis(
        summary=(
            f"Biểu mẫu này đã được nguồn chính thức của {organization} xác nhận sử dụng. "
            "Tuy nhiên, chưa tìm thấy bằng chứng chính thức xác nhận riêng chương trình hoặc lời mời đăng ký "
            "trong tin nhắn này; vì vậy biểu mẫu có cơ sở chính thức nhưng chưa đủ để xác nhận toàn bộ nội dung."
        ),
        top_reasons=[
            SynthesisReason(
                text="Nguồn chính thức xác nhận biểu mẫu cụ thể; chương trình vẫn chưa được xác nhận riêng.",
                evidence_refs=["evidence:fedcba9876543210"],
            )
        ],
    )
    assert check_grounded_ai_response(mixed_scope, natural_mixed_reply).response is not None

    class _NaturalMixedComposer:
        async def synthesize(self, payload):
            del payload
            return ModelResponse(output=natural_mixed_reply, provider="fake", model="synthesis-v1")

    composed = await GroundedSecurityResponseService(
        ai_enabled=True,
        model=_NaturalMixedComposer(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(mixed_scope)
    assert composed.assistant_response is not None
    assert composed.assistant_response.generation_mode is AssistantGenerationModeV4.AI
    assert composed.assistant_response.summary == natural_mixed_reply.summary
    accepted = check_grounded_ai_response(
        scoped,
        AssistantSynthesis(
            summary=(
                "An official provenance chain endorses this exact submitted resource; "
                "the publisher domain and sender are not independently verified."
            )
        ),
    )
    assert accepted.response is not None

    fallback = policy_grounded_assistant_response(scoped).summary.casefold()
    assert "tài nguyên bạn gửi đã được nguồn chính thức xác nhận" in fallback
    assert "chưa xác nhận được thông tin về" not in fallback

    assert scoped.official_verification is not None
    action_endorsed = scoped.model_copy(
        update={
            "official_verification": scoped.official_verification.model_copy(
                update={
                    "action_endorsement_verification": OfficialVerificationComponentV4(
                        applicable=True,
                        status=VerificationStatusV4.VERIFIED,
                        reason_code="official_exact_resource_action_confirmed",
                    )
                }
            )
        }
    )
    action_payload = GroundedSecurityResponseService._synthesis_payload(action_endorsed)
    assert action_payload["verification_state"]["requested_action"]["exact_resource_endorsed"] is True
    assert action_payload["important_uncertainties"] == []
    assert "does not change" in action_payload["verification_state"]["uncertainty_boundaries"]["sender_identity"]
    rejected = check_grounded_ai_response(
        action_endorsed,
        AssistantSynthesis(summary="Chưa có xác nhận chính thức cho hành động đăng ký này."),
    )
    assert rejected.failure is SynthesisGroundingFailure.CONTRADICTS_VERIFIED_EXACT_RESOURCE_ENDORSEMENT

    endorsed_allow_open = action_endorsed.model_copy(
        update={"recommended_actions": [SecurityRecommendedActionV4.ALLOW_OPEN]}
    )
    generic_caution = check_grounded_ai_response(
        endorsed_allow_open,
        AssistantSynthesis(summary="Biểu mẫu đã được xác nhận, nhưng hãy xác minh thêm trước khi tiếp tục đăng ký."),
    )
    assert generic_caution.failure is SynthesisGroundingFailure.CONTRADICTS_VERIFIED_EXACT_RESOURCE_ENDORSEMENT
