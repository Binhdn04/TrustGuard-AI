from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from src.agents.security_scope import classify_security_scope, extract_security_context
from src.models import (
    AssistantContextV4,
    AssistantProcessingModeV4,
    AssistantSourceSpanV4,
    ExposureStateV4,
    PotentialThreatV4,
    RequestedActionV4,
    ScopeDecisionV4,
    SecurityContextV4,
    SecurityScenarioV4,
    SecurityTriageCreateRequestV4,
    VerificationIntentV4,
    VerificationTopicV4,
)
from src.security_ai.contracts import ModelResponse, Understanding, UnderstandingSourceSpan
from src.security_ai.runtime import SecurityAssistantRuntime
from src.services.official_verification_intent import (
    DerivedOrganizationName,
    GroundedTextValue,
    GroundedVerificationIntent,
    OfficialVerificationQueryBuilder,
    VerificationQuery,
    build_grounded_verification_intent,
)
from src.services.security_pipeline import SecurityTriagePipeline
from src.services.security_triage import SecurityTriageScopeService
from src.services.security_understanding import SecuritySemanticUnderstandingService


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        ("Công ty đang tuyển dụng kỹ sư", "neutral_recruitment_context"),
        ("Chương trình khuyến mãi tháng này", "neutral_promotion_context"),
        ("Điền form khảo sát khách hàng", "neutral_form_context"),
        ("Sự kiện công nghệ tổ chức vào thứ hai", "neutral_event_context"),
        ("Khóa học Python cơ bản", "neutral_course_context"),
        ("Khảo sát chất lượng dịch vụ", "neutral_survey_context"),
    ],
)
def test_neutral_context_alone_is_deterministic_out_of_scope(message: str, reason: str) -> None:
    result = classify_security_scope(message)

    assert result.decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK
    assert reason in result.reason_codes


class _MustNotCallModel:
    def __init__(self) -> None:
        self.calls = 0

    async def understand(self, message, conversation_summary):
        del message, conversation_summary
        self.calls += 1
        raise AssertionError("deterministic OOS invoked semantic AI")


class _MustNotRunStage:
    async def enrich(self, *args, **kwargs):
        del args, kwargs
        raise AssertionError("deterministic OOS reached a later pipeline stage")


class _PassthroughStage:
    async def enrich(self, *args, **kwargs):
        del kwargs
        return args[-1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message",
    [
        "Công ty đang tuyển dụng kỹ sư",
        "Chương trình khuyến mãi tháng này",
        "Điền form khảo sát khách hàng",
        "Sự kiện công nghệ tổ chức vào thứ hai",
        "Khóa học Python cơ bản",
    ],
)
async def test_nonlocal_oos_runs_only_semantic_scope_before_terminating(message: str) -> None:
    request = SecurityTriageCreateRequestV4(message=message)
    scoped = SecurityTriageScopeService().assess(request)
    model = _MustNotCallModel()
    resolved: list[str] = []

    async def resolve_investigation():
        resolved.append("investigation")
        raise AssertionError("deterministic OOS resolved investigation providers")

    pipeline = SecurityTriagePipeline(
        understanding=SecuritySemanticUnderstandingService(
            enabled=True,
            model=model,
            runtime=SecurityAssistantRuntime(max_retries=0),
        ),
        investigation_resolver=resolve_investigation,
        trust=_MustNotRunStage(),
        responses=_MustNotRunStage(),
    )
    result = await pipeline.process(request, scoped, runtime=SecurityAssistantRuntime(max_retries=0))

    assert result.scope_decision is ScopeDecisionV4.OUT_OF_SCOPE_GENERAL_FACT_CHECK
    assert result.tool_calls_used == 0
    assert model.calls == 1
    assert resolved == []


@pytest.mark.asyncio
async def test_incident_exposure_short_circuits_before_investigation_and_trust() -> None:
    request = SecurityTriageCreateRequestV4(message="Tôi đã bấm link https://example.test/login")
    scoped = (
        SecurityTriageScopeService()
        .assess(request)
        .model_copy(
            update={
                "assistant_context": AssistantContextV4(
                    processing_mode=AssistantProcessingModeV4.RULES_ONLY,
                    exposure_state=ExposureStateV4.LINK_OPENED,
                    model_version="rules-only-v1",
                )
            }
        )
    )
    resolved: list[str] = []

    async def resolve_investigation():
        resolved.append("investigation")
        raise AssertionError("incident exposure resolved online investigation")

    pipeline = SecurityTriagePipeline(
        understanding=SecuritySemanticUnderstandingService(
            enabled=False,
            model=None,
            runtime=SecurityAssistantRuntime(max_retries=0),
        ),
        investigation_resolver=resolve_investigation,
        trust=_MustNotRunStage(),
        responses=_PassthroughStage(),
    )

    result = await pipeline.process(request, scoped, runtime=SecurityAssistantRuntime(max_retries=0))

    assert result.assistant_context is not None
    assert result.assistant_context.exposure_state is ExposureStateV4.LINK_OPENED
    assert resolved == []


@pytest.mark.parametrize(
    ("message", "action"),
    [
        ("Họ yêu cầu tôi điền form gấp", RequestedActionV4.SUBMIT_FORM),
        ("Nhà tuyển dụng yêu cầu đăng ký gấp", RequestedActionV4.REGISTER_OR_APPLY),
        ("Người lạ bảo tôi tải file đính kèm", RequestedActionV4.DOWNLOAD_FILE),
        ("Nhân viên hỗ trợ bảo cài AnyDesk gấp", RequestedActionV4.INSTALL_APP),
        ("Họ bảo bật chia sẻ màn hình ngay", RequestedActionV4.SHARE_SCREEN),
        ("Quét mã QR này ngay", RequestedActionV4.SCAN_QR),
    ],
)
def test_sensitive_actions_are_detected_by_rules(message: str, action: RequestedActionV4) -> None:
    scope = classify_security_scope(message)
    context = extract_security_context(message)

    assert scope.decision is ScopeDecisionV4.IN_SCOPE
    assert context.requested_action is action


@pytest.mark.parametrize(
    ("message", "action"),
    [
        ("Ngan hag bao tai khoan sap khoa, dua ma xac thcc gap", RequestedActionV4.SHARE_OTP),
        (
            "Ben giao hang noi can toi dua thong tin the de nhan buu kien",
            RequestedActionV4.PROVIDE_PERSONAL_INFORMATION,
        ),
        (
            "Muon nhan qua thi lam theo huong dan va nhap thong tin dang nhap",
            RequestedActionV4.LOGIN,
        ),
    ],
)
def test_vietnamese_no_accent_typo_and_slang_stay_in_scope(message: str, action: RequestedActionV4) -> None:
    scope = classify_security_scope(message)
    context = extract_security_context(message)

    assert scope.decision is ScopeDecisionV4.IN_SCOPE
    assert context.requested_action is action


def test_ambiguous_slang_uses_semantic_gate_instead_of_rule_inventing_payment() -> None:
    message = "ck le 2 cu de giu suat"

    scope = classify_security_scope(message)
    context = extract_security_context(message)

    assert scope.decision is ScopeDecisionV4.NEED_MORE_INFO
    assert scope.reason_codes == ("ambiguous_sensitive_action",)
    assert context.payment_request is False
    assert context.requested_action is None


def test_security_concern_makes_neutral_recruitment_applicable_to_triage() -> None:
    result = classify_security_scope("Tin tuyển dụng này có lừa đảo không?")

    assert result.decision is ScopeDecisionV4.IN_SCOPE
    assert "security_verification_request" in result.reason_codes
    assert "neutral_recruitment_context" in result.reason_codes


def test_bare_url_has_no_grounded_official_verification_intent() -> None:
    message = "https://example.test/application"
    context = extract_security_context(message)

    assert context.requested_action is RequestedActionV4.OPEN_LINK
    assert build_grounded_verification_intent(message, context) is None


def test_rule_intent_has_confidence_and_literal_spans_for_every_accepted_field() -> None:
    message = "Vingroup thông báo tuyển dụng, hãy đăng ký tại https://jobs.example/apply"
    context = extract_security_context(message)
    intent = build_grounded_verification_intent(message, context)

    assert intent is not None
    assert intent.contract.organization_name == "Vingroup"
    assert intent.contract.topic is VerificationTopicV4.RECRUITMENT
    assert intent.contract.requested_action is RequestedActionV4.REGISTER_OR_APPLY
    assert intent.contract.action_url_indices == [0]
    for field in (intent.organization, intent.claim, intent.action):
        assert field is not None and field.confidence >= 0.8
        assert all(message[span.start : span.end].strip() for span in field.source_spans)


def test_quoted_program_title_is_used_as_bounded_literal_claim() -> None:
    message = (
        '[Online] Chương Trình Trải Nghiệm "Future Learning With AI" '
        "Do Đại Học Thanh Hoa Tổ Chức 2026. Please visit https://example.test/apply to apply."
    )
    context = extract_security_context(message)

    intent = build_grounded_verification_intent(message, context)

    assert intent is not None and intent.claim is not None
    assert intent.contract.claim_summary == "Future Learning With AI"
    span = intent.claim.source_spans[0]
    assert message[span.start : span.end] == "Future Learning With AI"


def test_quoted_secret_like_value_cannot_become_a_persisted_claim() -> None:
    message = 'ACME yêu cầu nhập "OTP 123456" tại https://example.test/login'
    context = extract_security_context(message)

    intent = build_grounded_verification_intent(message, context)

    assert intent is not None
    assert intent.contract.claim_summary is None


def test_semantic_normalization_is_derived_and_not_misrepresented_as_source_text() -> None:
    message = "Bên giao hàng yêu cầu hoàn tất thủ tục"
    organization_end = len("Bên giao hàng")
    action_start = message.index("hoàn tất thủ tục")
    context = SecurityContextV4(
        claimed_entity="delivery company",
        scenario=SecurityScenarioV4.UNKNOWN,
        requested_action=RequestedActionV4.REGISTER_OR_APPLY,
        urgency=False,
        credential_request=False,
        otp_request=False,
        payment_request=False,
        personal_information_request=False,
        potential_threat=PotentialThreatV4.UNDETERMINED_SECURITY_THREAT,
    )
    assistant = AssistantContextV4(
        processing_mode=AssistantProcessingModeV4.HYBRID,
        field_confidences={"claimed_entity": 0.9, "requested_action": 0.9},
        source_spans=[
            AssistantSourceSpanV4(field_name="claimed_entity", start=0, end=organization_end),
            AssistantSourceSpanV4(
                field_name="requested_action",
                start=action_start,
                end=len(message),
            ),
        ],
        model_version="semantic-v2",
    )

    intent = build_grounded_verification_intent(message, context, assistant)

    assert intent is not None and intent.organization is not None
    assert intent.organization.value == "Bên giao hàng"
    assert intent.contract.organization_name == "Bên giao hàng"
    derived = next(item for item in intent.derived_organizations if item.value == "delivery company")
    assert derived.provenance == "semantic_normalization"
    assert not hasattr(derived, "source_spans")


def test_low_confidence_semantic_action_cannot_create_verification_work() -> None:
    message = "Họ muốn tôi hoàn tất thủ tục"
    action_start = message.index("hoàn tất thủ tục")
    context = SecurityContextV4(
        scenario=SecurityScenarioV4.UNKNOWN,
        requested_action=RequestedActionV4.REGISTER_OR_APPLY,
        urgency=False,
        credential_request=False,
        otp_request=False,
        payment_request=False,
        personal_information_request=False,
        potential_threat=PotentialThreatV4.UNDETERMINED_SECURITY_THREAT,
    )
    assistant = AssistantContextV4(
        processing_mode=AssistantProcessingModeV4.HYBRID,
        field_confidences={"requested_action": 0.79},
        source_spans=[
            AssistantSourceSpanV4(
                field_name="requested_action",
                start=action_start,
                end=len(message),
            )
        ],
        model_version="semantic-v2",
    )

    assert build_grounded_verification_intent(message, context, assistant) is None


def test_grounded_value_contract_rejects_confidence_below_policy_threshold() -> None:
    with pytest.raises(ValueError, match="below the accepted threshold"):
        GroundedTextValue(
            "ACME",
            0.79,
            (AssistantSourceSpanV4(field_name="claimed_entity", start=0, end=4),),
        )


def test_whole_raw_message_cannot_be_used_as_a_derived_organization() -> None:
    message = "Vingroup tuyển dụng và yêu cầu đăng ký ngay"
    context = extract_security_context(message)
    intent = build_grounded_verification_intent(
        message,
        context,
        derived_organization_names=(DerivedOrganizationName(message, "configured_alias"),),
    )

    assert intent is not None
    assert message not in [item.value for item in intent.derived_organizations]
    queries = OfficialVerificationQueryBuilder().build(intent)
    assert all(message.casefold() not in query.text.casefold() for query in queries)


def test_whole_message_semantic_span_cannot_become_an_organization_query() -> None:
    message = "Bên giao hàng nói cần làm thủ tục và gửi thông tin riêng tư"
    context = SecurityContextV4(
        claimed_entity="delivery company",
        scenario=SecurityScenarioV4.UNKNOWN,
        urgency=False,
        credential_request=False,
        otp_request=False,
        payment_request=False,
        personal_information_request=False,
        potential_threat=PotentialThreatV4.UNDETERMINED_SECURITY_THREAT,
    )
    assistant = AssistantContextV4(
        processing_mode=AssistantProcessingModeV4.HYBRID,
        field_confidences={"claimed_entity": 0.95},
        source_spans=[AssistantSourceSpanV4(field_name="claimed_entity", start=0, end=len(message))],
        model_version="semantic-v2",
    )

    assert build_grounded_verification_intent(message, context, assistant) is None


@pytest.mark.asyncio
async def test_grounded_semantic_output_can_add_a_new_action_without_a_network_target() -> None:
    message = "Tôi nhận được tin nhắn lạ, họ muốn tôi hoàn tất thủ tục"
    action_start = message.index("hoàn tất thủ tục")

    class _SemanticActionModel:
        async def understand(self, received_message, conversation_summary):
            del conversation_summary
            assert received_message == message
            return ModelResponse(
                output=Understanding(
                    scope_decision=ScopeDecisionV4.IN_SCOPE,
                    requested_action=RequestedActionV4.REGISTER_OR_APPLY,
                    field_confidences={"scope_decision": 0.9, "requested_action": 0.9},
                    source_spans=[
                        UnderstandingSourceSpan(field_name="scope_decision", start=0, end=len(message)),
                        UnderstandingSourceSpan(
                            field_name="requested_action",
                            start=action_start,
                            end=len(message),
                        ),
                    ],
                ),
                provider="fake",
                model="semantic-v2",
            )

    request = SecurityTriageCreateRequestV4(message=message)
    scoped = SecurityTriageScopeService().assess(request)
    result = await SecuritySemanticUnderstandingService(
        enabled=True,
        model=_SemanticActionModel(),
        runtime=SecurityAssistantRuntime(max_retries=0),
    ).enrich(request, scoped)

    assert result.scope_decision is ScopeDecisionV4.IN_SCOPE
    assert result.security_context is not None
    assert result.security_context.requested_action is RequestedActionV4.REGISTER_OR_APPLY
    assert result.security_context.urls == []


def test_query_builder_redacts_urls_emails_otps_credentials_and_tokens() -> None:
    span = AssistantSourceSpanV4(field_name="claimed_entity", start=0, end=1)
    organization = GroundedTextValue(
        "ACME https://evil.test user@example.com",
        0.9,
        (span,),
    )
    claim = GroundedTextValue(
        "tuyển dụng OTP 123456 password=hunter2 token=abc12345678901234567890",
        0.9,
        (AssistantSourceSpanV4(field_name="claim_summary", start=0, end=1),),
    )
    contract = VerificationIntentV4(
        organization_name=organization.value,
        derived_organization_names=["ACME eyJabc1234567890.xyz1234567890"],
        claim_summary=claim.value,
        topic=VerificationTopicV4.RECRUITMENT,
    )
    intent = GroundedVerificationIntent(
        contract=contract,
        organization=organization,
        claim=claim,
        action=None,
        derived_organizations=(DerivedOrganizationName("ACME eyJabc1234567890.xyz1234567890", "configured_alias"),),
    )

    queries = OfficialVerificationQueryBuilder().build(intent)

    assert 0 < len(queries) <= 6
    assert len({query.text.casefold() for query in queries}) == len(queries)
    assert all(len(query.text) <= 300 for query in queries)
    serialized = " ".join(query.text for query in queries).casefold()
    for forbidden in (
        "http",
        "evil.test",
        "user@example.com",
        "123456",
        "hunter2",
        "abc12345678901234567890",
        "eyjabc",
    ):
        assert forbidden not in serialized


@pytest.mark.asyncio
async def test_query_attempts_are_sequential_and_capped_at_four() -> None:
    builder = OfficialVerificationQueryBuilder()
    queries = [
        VerificationQuery(query_id=f"query:{index:016x}", text=f"query {index}", source_fields=("topic",))
        for index in range(6)
    ]
    calls: list[str] = []
    active = 0
    max_active = 0

    async def search_one(query: str) -> str:
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        calls.append(query)
        await asyncio.sleep(0)
        active -= 1
        return query.upper()

    results = await builder.execute_sequentially(queries, search_one)

    assert calls == [f"query {index}" for index in range(4)]
    assert max_active == 1
    assert [item.result for item in results] == [f"QUERY {index}" for index in range(4)]


def test_ai_output_cannot_supply_url_or_network_target() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Understanding.model_validate(
            {
                "requested_action": "open_link",
                "urls": ["https://invented.example"],
                "network_target": "https://invented.example",
            }
        )
