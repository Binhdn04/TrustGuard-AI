from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from src.main import app
from src.models import (
    AnalysisStatus,
    AssistantContextV4,
    AssistantProcessingModeV4,
    BrandRecordV4,
    ClaimVerificationV4,
    OfficialIdentityTypeV4,
    OfficialIdentityV4,
    OfficialLinkVerificationReportV4,
    PotentialThreatV4,
    PublisherVerificationV4,
    RequestedActionV4,
    ResourceIdentityV4,
    ResourceMatchStatusV4,
    ResourceMatchV4,
    ResourceTypeV4,
    ResourceVerificationV4,
    ScopeDecisionV4,
    SecurityContextV4,
    SecurityRiskV4,
    SecurityScenarioV4,
    SecurityScopeResponseV4,
    TrustLifecycleV4,
    VerificationIntentV4,
    VerificationStatusV4,
    VerificationTopicV4,
)
from src.repositories.blacklist import SQLiteBlacklistRepository
from src.repositories.postgres import _json_value
from src.security_ai.contracts import Understanding

NOW = datetime(2026, 8, 20, 4, tzinfo=UTC)


def _context(*, version: str = "security-context-v2") -> SecurityContextV4:
    return SecurityContextV4(
        schema_version=version,
        claimed_entity="Example University",
        scenario=SecurityScenarioV4.RECRUITMENT,
        requested_action=RequestedActionV4.REGISTER_OR_APPLY,
        urgency=False,
        urls=["https://forms.example/application"],
        credential_request=False,
        otp_request=False,
        payment_request=False,
        personal_information_request=True,
        potential_threat=PotentialThreatV4.RECRUITMENT_IMPERSONATION,
    )


def _report() -> OfficialLinkVerificationReportV4:
    identity = OfficialIdentityV4(
        identity_type=OfficialIdentityTypeV4.WEBSITE,
        canonical_value="example.edu",
        display_value="example.edu",
        entity_name="Example University",
        reviewed=True,
    )
    resource = ResourceIdentityV4(
        resource_type=ResourceTypeV4.URL,
        canonical_url="https://forms.example/application",
        match_key="url-v1:https://forms.example/application",
    )
    return OfficialLinkVerificationReportV4(
        intent=VerificationIntentV4(
            organization_name="Example University",
            claim_summary="Example University is recruiting.",
            topic=VerificationTopicV4.RECRUITMENT,
            requested_action=RequestedActionV4.REGISTER_OR_APPLY,
            action_url_indices=[0],
        ),
        publisher_verification=PublisherVerificationV4(
            applicable=True,
            status=VerificationStatusV4.VERIFIED,
            reason_code="reviewed_exact_identity",
            identity=identity,
        ),
        claim_verification=ClaimVerificationV4(
            applicable=True,
            status=VerificationStatusV4.PARTIALLY_VERIFIED,
            reason_code="official_topic_partial",
            topic=VerificationTopicV4.RECRUITMENT,
        ),
        resource_verification=ResourceVerificationV4(
            applicable=True,
            status=VerificationStatusV4.VERIFIED,
            reason_code="exact_resource",
            match=ResourceMatchV4(
                status=ResourceMatchStatusV4.EXACT_RESOURCE,
                user_resource=resource,
                official_resource=resource,
                reason_code="same_resource_id",
            ),
        ),
        overall_status=VerificationStatusV4.PARTIALLY_VERIFIED,
        reason_code="claim_partial",
    )


def _response(*, report: OfficialLinkVerificationReportV4 | None = None) -> SecurityScopeResponseV4:
    return SecurityScopeResponseV4(
        status=AnalysisStatus.COMPLETED,
        scope_decision=ScopeDecisionV4.IN_SCOPE,
        terminal=True,
        next_step="END",
        scope_reasons=["security_request"],
        security_context=_context(),
        official_verification=report,
        risk=SecurityRiskV4.INSUFFICIENT_EVIDENCE,
        score=0,
        confidence=0.5,
        threat_type=PotentialThreatV4.RECRUITMENT_IMPERSONATION,
        policy_version="security-risk-v3",
        recommended_actions=["VERIFY_VIA_OFFICIAL_CHANNEL"],
        explanation="Verification contracts do not change risk behavior in CP2.",
        created_at=NOW,
        completed_at=NOW,
    )


def test_openapi_adds_cp2_contracts_without_removing_v1_read_shapes() -> None:
    components = app.openapi()["components"]["schemas"]

    requested_actions = set(components["RequestedActionV4"]["enum"])
    assert {"submit_form", "register_or_apply", "download_file"} <= requested_actions
    assert components["SecurityContextV4"]["properties"]["schema_version"]["default"] == "security-context-v2"
    assert components["SecurityConsentV4"]["properties"]["official_source_lookup"]["default"] is False
    assert "official_verification" in components["SecurityScopeResponseV4"]["properties"]
    assert "official_link_verification" in components["SecurityCapabilitiesResponseV4"]["properties"]
    assert "official_web_search_ready" in components["SecurityCapabilitiesResponseV4"]["properties"]
    assert set(components["VerificationStatusV4"]["enum"]) == {
        "VERIFIED",
        "PARTIALLY_VERIFIED",
        "UNVERIFIED",
        "CONFLICTING",
    }


def test_old_context_risk_and_brand_json_remain_readable() -> None:
    old_context = _context(version="security-context-v1")
    assert SecurityContextV4.model_validate_json(old_context.model_dump_json()).schema_version == "security-context-v1"

    old_response = _response().model_dump(mode="json")
    old_response["security_context"]["schema_version"] = "security-context-v1"
    old_response["policy_version"] = "security-risk-v1"
    assert SecurityScopeResponseV4.model_validate(old_response).official_verification is None

    old_brand = BrandRecordV4(
        name="Example University",
        official_domains=["example.edu"],
        provenance="Reviewed fixture",
        effective_from=NOW,
        lifecycle=TrustLifecycleV4.ACTIVE,
        reviewer_id="reviewer",
        created_at=NOW,
    )
    assert BrandRecordV4.model_validate_json(old_brand.model_dump_json()).official_domains == ["example.edu"]


def test_old_official_report_defaults_new_verification_layers_to_not_applicable() -> None:
    payload = _report().model_dump(mode="json")
    payload.pop("domain_ownership_verification", None)
    payload.pop("sender_verification", None)
    payload.pop("action_endorsement_verification", None)

    restored = OfficialLinkVerificationReportV4.model_validate(payload)

    assert restored.domain_ownership_verification.reason_code == "not_applicable"
    assert restored.sender_verification.applicable is False
    assert restored.action_endorsement_verification.status is None


def test_understanding_reads_v1_and_new_contracts_emit_v2() -> None:
    old_provider_output = Understanding(understanding_version="security-understanding-v1")
    old_public_context = AssistantContextV4(
        processing_mode=AssistantProcessingModeV4.RULES_ONLY,
        understanding_version="security-understanding-v1",
        model_version="rules-only-v1",
    )

    assert Understanding.model_validate_json(old_provider_output.model_dump_json()).understanding_version == (
        "security-understanding-v1"
    )
    assert AssistantContextV4.model_validate_json(old_public_context.model_dump_json()).understanding_version == (
        "security-understanding-v1"
    )
    assert Understanding().understanding_version == "security-understanding-v2"
    assert (
        AssistantContextV4(
            processing_mode=AssistantProcessingModeV4.RULES_ONLY,
            model_version="rules-only-v1",
        ).understanding_version
        == "security-understanding-v2"
    )
    assert _context().schema_version == "security-context-v2"


def test_new_response_jsonb_round_trip_preserves_report_and_risk_v3() -> None:
    response = _response(report=_report())
    old_response = _response().model_copy(
        update={
            "security_context": _context(version="security-context-v1"),
            "policy_version": "security-risk-v1",
        }
    )

    for expected in (old_response, response):
        postgres_jsonb = json.loads(expected.model_dump_json())
        assert SecurityScopeResponseV4.model_validate(_json_value(postgres_jsonb)) == expected

    restored = SecurityScopeResponseV4.model_validate(_json_value(json.loads(response.model_dump_json())))

    assert restored == response
    assert restored.policy_version == "security-risk-v3"
    assert restored.official_verification is not None
    assert restored.official_verification.resource_verification.match is not None
    assert restored.official_verification.resource_verification.match.status is ResourceMatchStatusV4.EXACT_RESOURCE


@pytest.mark.asyncio
async def test_sqlite_round_trip_reads_new_and_old_analysis_json() -> None:
    repository = SQLiteBlacklistRepository(":memory:")
    new_response = _response(report=_report())
    old_response = _response()
    old_response = old_response.model_copy(
        update={
            "security_context": old_response.security_context.model_copy(
                update={"schema_version": "security-context-v1"}
            )
        }
    )
    try:
        await repository.save_security_analysis("owner", new_response, [])
        await repository.save_security_analysis("owner", old_response, [])
        new_loaded = await repository.load_security_analysis(str(new_response.analysis_id))
        old_loaded = await repository.load_security_analysis(str(old_response.analysis_id))
    finally:
        await repository.close()

    assert new_loaded is not None and new_loaded[1] == new_response
    assert old_loaded is not None and old_loaded[1].security_context is not None
    assert old_loaded[1].security_context.schema_version == "security-context-v1"
    assert old_loaded[1].official_verification is None


def test_none_report_is_omitted_and_component_applicability_is_not_unverified() -> None:
    assert "official_verification" not in _response().model_dump(mode="json")

    non_applicable = ResourceVerificationV4(
        applicable=False,
        status=None,
        reason_code="no_user_action_url",
    )
    assert non_applicable.status is None
    with pytest.raises(ValidationError, match="non-applicable ones must omit"):
        ResourceVerificationV4(
            applicable=False,
            status=VerificationStatusV4.UNVERIFIED,
            reason_code="no_user_action_url",
        )


@pytest.mark.asyncio
async def test_cp2_runtime_emits_context_v2_without_enabling_official_verification(client) -> None:
    response = await client.post(
        "/api/v4/analyses",
        headers={"Authorization": "Bearer dev-user-token"},
        json={"message": "Ngan hang yeu cau toi gui OTP ngay"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["security_context"]["schema_version"] == "security-context-v2"
    assert body["policy_version"] == "security-risk-v6"
    assert "official_verification" not in body
