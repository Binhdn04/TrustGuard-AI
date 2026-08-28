from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

from src.models import (
    SECURITY_RISK_POLICY_VERSION_V7,
    ExposureStateV4,
    IdentityAssociationAssuranceV4,
    PotentialThreatV4,
    RequestedActionV4,
    SecurityEvidenceV4,
    SecurityPolicyMetadataV4,
    SecurityRecommendedActionV4,
    SecurityRiskV4,
    SecurityScopeResponseV4,
    VerificationStatusV4,
)
from src.services.official_verification_coordinator import has_verified_exact_resource_action_endorsement


@dataclass(frozen=True, slots=True)
class _Contribution:
    points: int
    evidence_ref: str


_WEAK_SIGNAL_POINTS = {
    "punycode_domain": 12,
    # A routine login/verify/account path is workflow metadata, not evidence
    # that credentials were requested or disclosed.
    "credential_path": 0,
    "promotion_lure_domain": 8,
    "ssrf_blocked": 15,
    "new_domain": 15,
    "recent_registration": 15,
    "domain_mismatch": 15,
    "lookalike_domain": 20,
}
_MALICIOUS_REPUTATION_SIGNALS = {"malicious", "confirmed_threat", "threat_intelligence_hit"}
_CORROBORATED_REPUTATION_SIGNAL = "corroborated_provider_hit"
_SAFE_SIGNALS = {
    "approved_whitelist",
    "official_match",
    "official_contact_match",
    "safe",
}
_OFFICIAL_SUPPRESSIBLE_SIGNALS = {
    "domain_mismatch",
    "lookalike_domain",
    "promotion_lure_domain",
}
_SENSITIVE_ACTIONS = {
    RequestedActionV4.LOGIN,
    RequestedActionV4.SHARE_OTP,
    RequestedActionV4.SHARE_CREDENTIALS,
    RequestedActionV4.TRANSFER_MONEY,
    RequestedActionV4.PAY_FEE,
    RequestedActionV4.PROVIDE_PERSONAL_INFORMATION,
    RequestedActionV4.INSTALL_APP,
    RequestedActionV4.SHARE_SCREEN,
    RequestedActionV4.SCAN_QR,
    RequestedActionV4.SUBMIT_FORM,
    RequestedActionV4.REGISTER_OR_APPLY,
    RequestedActionV4.DOWNLOAD_FILE,
}
_INCIDENT_EXPOSURES = {
    ExposureStateV4.LINK_OPENED,
    ExposureStateV4.CREDENTIAL_SHARED,
    ExposureStateV4.OTP_SHARED,
    ExposureStateV4.PAYMENT_SENT,
}


def _risk_for_score(score: int) -> SecurityRiskV4:
    if score >= 65:
        return SecurityRiskV4.HIGH_RISK
    if score >= 40:
        return SecurityRiskV4.SUSPICIOUS
    if score >= 20:
        return SecurityRiskV4.LOW_RISK
    return SecurityRiskV4.INSUFFICIENT_EVIDENCE


def _target_matches(reviewed_target: str | None, weak_target: str | None) -> bool:
    if reviewed_target is None:
        return True
    if weak_target is None:
        return False
    hostname = urlsplit(weak_target if "://" in weak_target else f"//{weak_target}").hostname
    reviewed_hostname = urlsplit(reviewed_target if "://" in reviewed_target else f"//{reviewed_target}").hostname
    candidate = (hostname or weak_target).casefold().rstrip(".")
    reviewed = (reviewed_hostname or reviewed_target).casefold().rstrip(".")
    return candidate == reviewed or candidate.endswith(f".{reviewed}")


def _official_can_suppress(scope: SecurityScopeResponseV4, evidence: SecurityEvidenceV4) -> bool:
    """Allow only reviewed-brand, exact-target mismatch suppression.

    The provenance check deliberately excludes generic URL/RDAP signals: a
    VERIFIED report may only neutralize the brand-registry comparison that was
    produced from the same reviewed identity domain and matches the verified
    source/resource target.
    """
    signal_parts = set(evidence.signal.casefold().split("+"))
    if scope.assistant_context is not None and scope.assistant_context.exposure_state in _INCIDENT_EXPOSURES:
        return False
    if not signal_parts or not signal_parts <= _OFFICIAL_SUPPRESSIBLE_SIGNALS:
        return False
    provenance_parts = (evidence.provenance_ref or "").split(":", 2)
    if evidence.type.value != "brand_match" or len(provenance_parts) != 3 or provenance_parts[0] != "brand":
        return False
    report = scope.official_verification
    if report is None:
        return False
    if any(
        association.assurance is IdentityAssociationAssuranceV4.VERIFIED
        and _target_matches(association.canonical_url, evidence.target)
        for association in report.identity_associations
    ):
        return True
    if report.overall_status is not VerificationStatusV4.VERIFIED:
        return False
    brand_policy_version = provenance_parts[2]
    matching_sources = {
        source.source_ref
        for source in report.source_refs
        if source.identity is not None
        and source.identity.policy_version == brand_policy_version
        and (
            _target_matches(source.identity.canonical_value, evidence.target)
            or _target_matches(source.canonical_url, evidence.target)
        )
    }
    if matching_sources:
        return True
    policy_source_ids = {
        source.source_ref
        for source in report.source_refs
        if source.identity is not None and source.identity.policy_version == brand_policy_version
    }
    return any(
        link.source_ref in policy_source_ids and _target_matches(link.canonical_url, evidence.target)
        for link in report.link_refs
    )


def _association_is_unverified_target(scope: SecurityScopeResponseV4, evidence: SecurityEvidenceV4) -> bool:
    report = scope.official_verification
    return bool(
        report
        and any(
            item.assurance is IdentityAssociationAssuranceV4.DISCOVERED
            and _target_matches(item.canonical_url, evidence.target)
            for item in report.identity_associations
        )
    )


def _has_reviewed_official_match(scope: SecurityScopeResponseV4, target: str | None) -> bool:
    """Whether authoritative reviewed evidence independently owns this target.

    A reputation-provider result for a reviewed first-party target conflicts
    with an official fact.  One provider alone is not enough to call that
    target malicious; a blacklist hit or other corroborated threat evidence is
    still allowed to do so.
    """
    return any(
        (
            (item.type.value == "brand_match" and item.signal.casefold() == "official_match")
            # Domain familiarity is produced directly from the same reviewed
            # identity registry.  It remains affirmative first-party ownership
            # evidence even when semantic entity matching did not emit a
            # brand_match row (for example, a bare passive domain check).
            or (item.type.value == "domain_familiarity" and item.signal == "reviewed_first_party_domain")
            or (item.type.value == "official_verification" and item.signal == "official_domain_verified")
        )
        and _target_matches(item.target, target)
        for item in scope.evidence
    )


def _is_neutral_url_inspection(scope: SecurityScopeResponseV4) -> bool:
    """Whether the submitted URL is being inspected without risky context.

    Naming the owner of a submitted domain is not a dangerous requested
    action.  In particular, a reviewed gazetteer may identify that owner for
    a plain domain-check request; treating that useful semantic enrichment as
    a reason to withhold a positive target decision turns benign uncertainty
    into caution.
    """
    context = scope.security_context
    return bool(
        context
        and context.urls
        and not context.impersonation_signals
        and not _has_sensitive_action(scope)
        and context.requested_action in {None, RequestedActionV4.OPEN_LINK}
    )


def _has_reviewed_first_party_domain(scope: SecurityScopeResponseV4, target: str | None) -> bool:
    """Exclude shared-platform URLs whose exact resource remains unreviewed."""
    return any(
        item.type.value == "domain_familiarity"
        and item.signal == "reviewed_first_party_domain"
        and _target_matches(item.target, target)
        for item in scope.evidence
    )


def _is_origin_only_url(url: str) -> bool:
    """Whether a submitted URL names only a reviewed service origin.

    A reviewed platform controls its own origin, but can host unreviewed user
    resources below it.  The root URL is therefore a safe passive target while
    a path, query, or fragment must retain the stricter resource policy.
    """
    parsed = urlsplit(url)
    return parsed.path in {"", "/"} and not parsed.query and not parsed.fragment


def _has_authoritative_passive_target_ownership(scope: SecurityScopeResponseV4, url: str) -> bool:
    """Return positive ownership proof appropriate to this passive target."""
    if _has_reviewed_official_match(scope, url):
        return True
    return _is_origin_only_url(url) and any(
        item.type.value == "domain_familiarity"
        and item.signal == "reviewed_platform_service"
        and _target_matches(item.target, url)
        for item in scope.evidence
    )


def _has_verified_exact_resource_action(scope: SecurityScopeResponseV4) -> bool:
    context = scope.security_context
    return has_verified_exact_resource_action_endorsement(
        scope.official_verification,
        context.urls if context is not None else (),
    )


def _complete_official_verification(scope: SecurityScopeResponseV4) -> bool:
    report = scope.official_verification
    if report is None or report.overall_status is VerificationStatusV4.CONFLICTING:
        return False
    if any(
        association.assurance
        in {IdentityAssociationAssuranceV4.CONFLICTING, IdentityAssociationAssuranceV4.CONFIRMED_MISMATCH}
        for association in report.identity_associations
    ):
        return False
    if report.schema_version in {"official-link-verification-v1", "official-link-verification-v2"}:
        legacy_components = [
            component
            for component in (
                report.publisher_verification,
                report.claim_verification,
                report.resource_verification,
                report.action_endorsement_verification,
            )
            if component.applicable
        ]
        return bool(legacy_components) and all(
            component.status is VerificationStatusV4.VERIFIED for component in legacy_components
        )
    required = [report.resource_verification]
    if report.action_endorsement_verification.applicable:
        required.append(report.action_endorsement_verification)
    return bool(required) and all(
        component.applicable and component.status is VerificationStatusV4.VERIFIED for component in required
    )


def _has_sensitive_action(scope: SecurityScopeResponseV4) -> bool:
    context = scope.security_context
    if context is None:
        return False
    return bool(
        context.credential_request
        or context.otp_request
        or context.payment_request
        or context.personal_information_request
        or context.requested_action in _SENSITIVE_ACTIONS
        or (scope.assistant_context is not None and scope.assistant_context.exposure_state in _INCIDENT_EXPOSURES)
    )


def _action_intent_unavailable(scope: SecurityScopeResponseV4) -> bool:
    context = scope.assistant_context
    return bool(context and context.action_candidate_present and not context.action_intent_available)


def _has_contextual_threat(scope: SecurityScopeResponseV4) -> bool:
    """Whether a sensitive action has an independent malicious context.

    Login, OTP, and credential-entry are common legitimate flows.  They are
    protective signals only when the deterministic context has already
    identified a specific threat pattern; they never manufacture that pattern
    from missing official verification or an unverified reputation result.
    """
    context = scope.security_context
    return bool(context and context.potential_threat is not PotentialThreatV4.UNDETERMINED_SECURITY_THREAT)


def _actions(
    scope: SecurityScopeResponseV4,
    risk: SecurityRiskV4,
    *,
    familiarity_low_risk: bool = False,
) -> list[SecurityRecommendedActionV4]:
    context = scope.security_context
    if context is None:
        return [SecurityRecommendedActionV4.PROCEED_WITH_CAUTION]
    actions: list[SecurityRecommendedActionV4] = []
    exposure = (
        scope.assistant_context.exposure_state if scope.assistant_context is not None else ExposureStateV4.UNKNOWN
    )
    exact_resource_action_endorsed = _has_verified_exact_resource_action(scope)
    incident_actions = {
        ExposureStateV4.LINK_OPENED: [
            SecurityRecommendedActionV4.CLOSE_PAGE_AND_DO_NOT_RETURN,
            SecurityRecommendedActionV4.PRESERVE_MESSAGE_FOR_REPORTING,
        ],
        ExposureStateV4.CREDENTIAL_SHARED: [
            SecurityRecommendedActionV4.CHANGE_PASSWORD_FROM_TRUSTED_DEVICE,
            SecurityRecommendedActionV4.REVOKE_ACTIVE_SESSIONS,
            SecurityRecommendedActionV4.PRESERVE_MESSAGE_FOR_REPORTING,
        ],
        ExposureStateV4.OTP_SHARED: [
            SecurityRecommendedActionV4.REVOKE_ACTIVE_SESSIONS,
            SecurityRecommendedActionV4.CONTACT_BANK_OR_PAYMENT_PROVIDER,
            SecurityRecommendedActionV4.PRESERVE_MESSAGE_FOR_REPORTING,
        ],
        ExposureStateV4.PAYMENT_SENT: [
            SecurityRecommendedActionV4.CONTACT_BANK_OR_PAYMENT_PROVIDER,
            SecurityRecommendedActionV4.PRESERVE_MESSAGE_FOR_REPORTING,
        ],
    }
    actions.extend(incident_actions.get(exposure, []))
    if context.urls or context.requested_action is RequestedActionV4.OPEN_LINK:
        # A SAFE verdict requires reviewed trust evidence. A conflicting
        # provider hit may already have been discredited by that evidence; do
        # not contradict the resulting verdict with an unconditional block.
        actions.append(
            SecurityRecommendedActionV4.ALLOW_OPEN
            if risk is SecurityRiskV4.SAFE
            or (
                exact_resource_action_endorsed
                and risk in {SecurityRiskV4.INSUFFICIENT_EVIDENCE, SecurityRiskV4.LOW_RISK}
            )
            else SecurityRecommendedActionV4.PROCEED_WITH_CAUTION
            if familiarity_low_risk or risk in {SecurityRiskV4.INSUFFICIENT_EVIDENCE, SecurityRiskV4.LOW_RISK}
            else SecurityRecommendedActionV4.DO_NOT_OPEN_LINK
        )
    if context.credential_request and risk in {
        SecurityRiskV4.SUSPICIOUS,
        SecurityRiskV4.HIGH_RISK,
        SecurityRiskV4.MALICIOUS,
    }:
        actions.append(SecurityRecommendedActionV4.DO_NOT_SHARE_CREDENTIALS)
        actions.append(SecurityRecommendedActionV4.CHANGE_PASSWORD_IF_ALREADY_SHARED)
    if context.otp_request and risk in {
        SecurityRiskV4.SUSPICIOUS,
        SecurityRiskV4.HIGH_RISK,
        SecurityRiskV4.MALICIOUS,
    }:
        actions.append(SecurityRecommendedActionV4.DO_NOT_SHARE_OTP)
    if context.payment_request and risk in {
        SecurityRiskV4.SUSPICIOUS,
        SecurityRiskV4.HIGH_RISK,
        SecurityRiskV4.MALICIOUS,
    }:
        actions.append(SecurityRecommendedActionV4.DO_NOT_TRANSFER_MONEY)
        actions.append(SecurityRecommendedActionV4.CONTACT_BANK_IF_ALREADY_PAID)
    if (
        (context.claimed_entity or context.impersonation_signals)
        and risk is not SecurityRiskV4.SAFE
        and not exact_resource_action_endorsed
    ):
        actions.append(SecurityRecommendedActionV4.VERIFY_VIA_OFFICIAL_CHANNEL)
    if risk in {SecurityRiskV4.HIGH_RISK, SecurityRiskV4.MALICIOUS}:
        actions.append(SecurityRecommendedActionV4.REPORT_AND_BLOCK_SENDER)
    if not actions:
        actions.append(SecurityRecommendedActionV4.PROCEED_WITH_CAUTION)
    return list(dict.fromkeys(actions))


def _explanation(risk: SecurityRiskV4, evidence: list[SecurityEvidenceV4]) -> str:
    descriptions = [item.description for item in evidence[:3]]
    prefix = {
        SecurityRiskV4.SAFE: "Bằng chứng xác thực hiện có cho thấy mục tiêu phù hợp với nguồn tin cậy.",
        SecurityRiskV4.LOW_RISK: "Chỉ ghi nhận tín hiệu rủi ro yếu; chưa đủ để kết luận nội dung độc hại.",
        SecurityRiskV4.SUSPICIOUS: "Có nhiều tín hiệu bảo mật đáng ngờ cần được xử lý thận trọng.",
        SecurityRiskV4.HIGH_RISK: "Các yêu cầu và tín hiệu độc lập cho thấy nguy cơ mất tài khoản hoặc tiền cao.",
        SecurityRiskV4.MALICIOUS: "Có bằng chứng mạnh đã được xác nhận về mục tiêu độc hại.",
        SecurityRiskV4.INSUFFICIENT_EVIDENCE: "Chưa có đủ bằng chứng để đánh giá mục tiêu là an toàn hay độc hại.",
    }[risk]
    return prefix + (" Căn cứ: " + " ".join(descriptions) if descriptions else "")


def assess_security_risk(
    scope: SecurityScopeResponseV4,
    *,
    memory_enabled: bool = False,
    official_verification_enforced: bool = False,
    familiarity_enforced: bool = False,
) -> SecurityScopeResponseV4:
    """Apply the versioned v4 policy without claim-stance or prose inputs."""
    context = scope.security_context
    if context is None:
        return scope
    context_evidence = next((item for item in scope.evidence if item.type.value == "security_context"), None)
    context_ref = context_evidence.evidence_ref if context_evidence else ""
    has_whitelist = any(item.signal.casefold() == "approved_whitelist" for item in scope.evidence)
    action_intent_unavailable = _action_intent_unavailable(scope)
    contributions: list[_Contribution] = []
    reviewed_target_ownership = bool(context.urls) and all(
        _has_reviewed_official_match(scope, url) for url in context.urls
    )
    passive_target_ownership = bool(context.urls) and all(
        _has_authoritative_passive_target_ownership(scope, url) for url in context.urls
    )
    # A reviewed exact first-party target is affirmative ownership evidence.
    # It cannot erase blacklist/reputation findings below, but it means that a
    # normal sign-in or application action is not itself a threat signal while
    # a fuller action-endorsement chain is unavailable.
    action_chain_verified = (
        official_verification_enforced and _complete_official_verification(scope)
    ) or reviewed_target_ownership
    # Sensitive actions are not malicious evidence by themselves.  They can
    # strengthen an independently identified threat pattern, and a verified
    # official action chain can neutralize even that contextual concern.
    contextual_threat = _has_contextual_threat(scope)
    credential_action = context.credential_request or context.requested_action is RequestedActionV4.LOGIN
    if credential_action and contextual_threat and not action_chain_verified:
        contributions.append(_Contribution(35, context_ref))
    if context.otp_request and contextual_threat and not action_chain_verified:
        contributions.append(_Contribution(40, context_ref))
    if context.payment_request and contextual_threat and not action_chain_verified:
        contributions.append(_Contribution(35, context_ref))
    if context.urgency:
        contributions.append(_Contribution(15, context_ref))
    if context.impersonation_signals and not has_whitelist:
        contributions.append(_Contribution(18, context_ref))
    if (
        not action_chain_verified
        and contextual_threat
        and (
            context.credential_request
            or context.otp_request
            or context.payment_request
            or context.requested_action is RequestedActionV4.LOGIN
        )
    ):
        contributions.append(_Contribution(20, context_ref))
    if (
        not action_chain_verified
        and context.scenario.value in {"recruitment", "promotion_prize"}
        and (
            context.payment_request or context.credential_request or context.requested_action is RequestedActionV4.LOGIN
        )
    ):
        contributions.append(_Contribution(10, context_ref))
    if (
        not action_chain_verified
        and context.scenario.value == "account_verification"
        and context.requested_action is RequestedActionV4.LOGIN
    ):
        contributions.append(_Contribution(10, context_ref))
    if (
        not action_chain_verified
        and context.payment_request
        and context.scenario.value in {"investment", "online_task", "refund"}
    ):
        contributions.append(_Contribution(15, context_ref))

    strong_refs: list[str] = []
    reputation_conflicts: list[SecurityEvidenceV4] = []
    safe_refs: list[str] = []
    reviewed_risk_refs: list[str] = []
    reviewed_suppressions: list[SecurityEvidenceV4] = []
    platform_familiarity = [
        item
        for item in scope.evidence
        if item.type.value == "domain_familiarity" and item.signal == "reviewed_platform_service"
    ]
    weak_contributions: list[_Contribution] = []
    residual_official_mismatch = False
    for item in scope.evidence:
        signal_parts = set(item.signal.casefold().split("+"))
        if memory_enabled and item.type.value == "reviewed_security_memory":
            exact_match = bool(signal_parts & {"domain", "redirect"})
            if "reviewed_memory_malicious" in signal_parts:
                contributions.append(_Contribution(50 if exact_match else 30, item.evidence_ref))
                reviewed_risk_refs.append(item.evidence_ref)
            elif "reviewed_campaign_confirmed" in signal_parts:
                contributions.append(_Contribution(35 if exact_match else 20, item.evidence_ref))
                reviewed_risk_refs.append(item.evidence_ref)
            elif signal_parts & {"reviewed_memory_safe", "reviewed_memory_false_positive"}:
                reviewed_suppressions.append(item)
            continue
        if item.type.value == "blacklist" and "approved_blacklist_hit" in signal_parts:
            strong_refs.append(item.evidence_ref)
        if item.type.value == "url_reputation" and signal_parts & _MALICIOUS_REPUTATION_SIGNALS:
            if _CORROBORATED_REPUTATION_SIGNAL in signal_parts:
                strong_refs.append(item.evidence_ref)
            elif _has_reviewed_official_match(scope, item.target):
                reputation_conflicts.append(item)
            else:
                strong_refs.append(item.evidence_ref)
        if signal_parts & _SAFE_SIGNALS and not (familiarity_enforced and item.signal.casefold() == "official_match"):
            safe_refs.append(item.evidence_ref)
        points = max((_WEAK_SIGNAL_POINTS.get(signal, 0) for signal in signal_parts), default=0)
        if (
            familiarity_enforced
            and item.type.value == "brand_match"
            and "domain_mismatch" in signal_parts
            and any(_target_matches(reviewed.target, item.target) for reviewed in platform_familiarity)
        ):
            points = 0
        if has_whitelist and item.type.value in {"local_url_rule", "rdap"}:
            points = 0
        if points and official_verification_enforced:
            if _official_can_suppress(scope, item):
                points = 0
            elif signal_parts & _OFFICIAL_SUPPRESSIBLE_SIGNALS and _association_is_unverified_target(scope, item):
                points = 0
            elif signal_parts & _OFFICIAL_SUPPRESSIBLE_SIGNALS:
                residual_official_mismatch = True
        if points:
            weak_contributions.append(_Contribution(points, item.evidence_ref))

    reputation_conflict_refs: list[str] = []
    conflicts_by_target: dict[str | None, list[SecurityEvidenceV4]] = {}
    for item in reputation_conflicts:
        conflicts_by_target.setdefault(item.target, []).append(item)
    for target_conflicts in conflicts_by_target.values():
        if len({item.source for item in target_conflicts}) > 1:
            # Official ownership alone does not discredit corroborated
            # evidence for the same target.
            strong_refs.extend(item.evidence_ref for item in target_conflicts)
        else:
            reputation_conflict_refs.extend(item.evidence_ref for item in target_conflicts)

    if reviewed_suppressions:
        weak_types = {"local_url_rule", "rdap", "brand_match"}
        evidence_by_ref = {item.evidence_ref: item for item in scope.evidence}
        weak_contributions = [
            item
            for item in weak_contributions
            if evidence_by_ref[item.evidence_ref].type.value not in weak_types
            or not any(
                _target_matches(reviewed.target, evidence_by_ref[item.evidence_ref].target)
                for reviewed in reviewed_suppressions
            )
        ]
    weak_external = sum(item.points for item in weak_contributions)
    contributions.extend(weak_contributions)
    official_conflicting = bool(
        official_verification_enforced
        and scope.official_verification is not None
        and scope.official_verification.overall_status is VerificationStatusV4.CONFLICTING
    )
    identity_conflicting = False
    identity_confirmed_mismatch = False
    if official_verification_enforced and scope.official_verification is not None:
        identity_conflicting = any(
            item.assurance is IdentityAssociationAssuranceV4.CONFLICTING
            for item in scope.official_verification.identity_associations
        )
        identity_confirmed_mismatch = any(
            item.assurance is IdentityAssociationAssuranceV4.CONFIRMED_MISMATCH
            for item in scope.official_verification.identity_associations
        )
    identity_mismatch_evidence = next(
        (item for item in scope.evidence if item.signal.casefold() == "entity_target_mismatch"),
        None,
    )
    identity_confirmed_mismatch = identity_confirmed_mismatch or identity_mismatch_evidence is not None
    # Unverified identity and entity-to-URL association states describe a
    # coverage gap.  They may prevent a positive trust conclusion, but they
    # must never be converted into risk points or a higher risk tier.
    identity_relation_unresolved = any(
        item.signal.casefold()
        in {
            "claimed_identity_unverified",
            "entity_target_unverified",
            "entity_url_relation_unresolved",
        }
        # A reviewed first-party match for the exact target resolves this
        # association gap.  It remains visible in evidence, but a stale
        # pre-verification "unresolved" marker must not veto affirmative
        # ownership evidence.
        and not _has_reviewed_official_match(scope, item.target)
        for item in scope.evidence
    )
    claimed_url_indexes = {item.url_index for item in context.entity_url_claims}
    identity_relation_unresolved = identity_relation_unresolved or bool(
        context.claimed_entity
        and context.urls
        and set(range(len(context.urls))) - claimed_url_indexes
        and not (official_verification_enforced and _complete_official_verification(scope))
        and not all(_has_reviewed_official_match(scope, url) for url in context.urls)
    )
    ai_understanding_fallback = bool(
        scope.assistant_context is not None
        and scope.assistant_context.processing_mode.value == "fallback"
        and (context.urls or context.claimed_entity or context.entity_url_claims)
    )
    if identity_confirmed_mismatch:
        contributions.append(
            _Contribution(40, identity_mismatch_evidence.evidence_ref if identity_mismatch_evidence else context_ref)
        )
    elif identity_conflicting:
        contributions.append(_Contribution(20, context_ref))
    if official_conflicting:
        # The bounded conflict contribution can raise caution, but it is never
        # itself a malicious verdict and never exceeds 25 points.
        contributions.append(_Contribution(25, context_ref))
    if context.impersonation_signals and any(
        "lookalike_domain" in item.signal.casefold().split("+") for item in scope.evidence
    ):
        # A claimed organization plus a lookalike domain is stronger than either
        # weak signal alone, while still never being sufficient for MALICIOUS.
        contributions.append(_Contribution(5, context_ref))

    score = min(100, sum(item.points for item in contributions))
    if strong_refs:
        score = max(score, 95)
        risk = SecurityRiskV4.MALICIOUS
    elif (
        _is_neutral_url_inspection(scope)
        and passive_target_ownership
        and score == 0
        and not reviewed_risk_refs
        and not identity_confirmed_mismatch
        and not identity_relation_unresolved
        and not action_intent_unavailable
    ):
        # Reviewed official ownership is affirmative evidence for a passive
        # target inspection.  A semantic-model fallback and an unavailable
        # enrichment provider cannot change the user request into an action
        # or create adverse evidence.  They therefore cannot veto this
        # decision; no-hit/error data still never creates SAFE on its own.
        # A lone conflicting provider hit is retained as telemetry, but is
        # discredited rather than treated as residual risk.
        risk = SecurityRiskV4.SAFE
    elif (
        official_verification_enforced
        and _complete_official_verification(scope)
        and not scope.errors
        and not strong_refs
        and not reviewed_risk_refs
        and not residual_official_mismatch
        and not identity_confirmed_mismatch
        and not identity_relation_unresolved
        and not ai_understanding_fallback
        and not action_intent_unavailable
    ):
        risk = SecurityRiskV4.SAFE
    elif (
        not official_verification_enforced
        and safe_refs
        and score == 0
        and not scope.errors
        and not identity_confirmed_mismatch
        and not identity_relation_unresolved
        and not ai_understanding_fallback
        and not action_intent_unavailable
    ):
        risk = SecurityRiskV4.SAFE
    else:
        risk = _risk_for_score(score)
    # A lexical candidate is not an action finding, but it is enough to block
    # a positive trust decision until a grounded interpretation exists.
    if action_intent_unavailable and risk is SecurityRiskV4.SAFE:
        risk = SecurityRiskV4.INSUFFICIENT_EVIDENCE
    familiarity_refs = [
        item.evidence_ref
        for item in scope.evidence
        if item.type.value == "domain_familiarity"
        and (
            item.signal in {"reviewed_first_party_domain", "popular_top_100", "popular_top_10000"}
            or (
                item.signal == "reviewed_platform_service"
                and scope.official_verification is not None
                and scope.official_verification.resource_verification.status
                in {VerificationStatusV4.VERIFIED, VerificationStatusV4.PARTIALLY_VERIFIED}
            )
        )
    ]
    if (
        familiarity_enforced
        and risk is SecurityRiskV4.INSUFFICIENT_EVIDENCE
        and score == 0
        and familiarity_refs
        and not scope.errors
        and not official_conflicting
        and not identity_conflicting
        and not identity_confirmed_mismatch
        and context.requested_action in {None, RequestedActionV4.OPEN_LINK}
        and not _has_sensitive_action(scope)
    ):
        risk = SecurityRiskV4.LOW_RISK
    if identity_confirmed_mismatch and risk in {
        SecurityRiskV4.INSUFFICIENT_EVIDENCE,
        SecurityRiskV4.LOW_RISK,
    }:
        risk = SecurityRiskV4.SUSPICIOUS
    elif identity_conflicting and risk is SecurityRiskV4.INSUFFICIENT_EVIDENCE:
        risk = SecurityRiskV4.LOW_RISK
    action_verification_incomplete = bool(
        official_verification_enforced
        and scope.official_verification is not None
        and scope.official_verification.action_endorsement_verification.applicable
        and scope.official_verification.action_endorsement_verification.status is not VerificationStatusV4.VERIFIED
        and scope.official_verification.overall_status is VerificationStatusV4.PARTIALLY_VERIFIED
    )
    if (
        action_verification_incomplete
        and not weak_external
        and not strong_refs
        and not reviewed_risk_refs
        and not identity_confirmed_mismatch
        and not identity_conflicting
        and not residual_official_mismatch
    ):
        # Verified entity/resource but missing action endorsement is a coverage
        # gap, not affirmative evidence that the requested action is risky.
        risk = SecurityRiskV4.INSUFFICIENT_EVIDENCE
    # Registration/mismatch-style evidence alone is explicitly non-malicious.
    if (
        risk is not SecurityRiskV4.MALICIOUS
        and contributions
        and not official_conflicting
        and sum(item.points for item in contributions) == weak_external
    ):
        risk = SecurityRiskV4.LOW_RISK if score < 45 else SecurityRiskV4.SUSPICIOUS
    familiarity_low_risk = bool(
        familiarity_enforced and risk is SecurityRiskV4.LOW_RISK and score == 0 and familiarity_refs
    )

    refs = list(
        dict.fromkeys(
            [item.evidence_ref for item in contributions if item.evidence_ref]
            + strong_refs
            + safe_refs
            + (
                [
                    item.evidence_ref
                    for item in scope.evidence
                    if item.type.value == "domain_familiarity"
                    and item.signal == "reviewed_platform_service"
                    and any(_is_origin_only_url(url) and _target_matches(item.target, url) for url in context.urls)
                ]
                if risk is SecurityRiskV4.SAFE and passive_target_ownership
                else []
            )
            + reviewed_risk_refs
            + (familiarity_refs if familiarity_enforced and risk is SecurityRiskV4.LOW_RISK else [])
            + ([item.evidence_ref for item in reviewed_suppressions] if memory_enabled else [])
        )
    )
    refs.extend(
        item.evidence_ref
        for item in scope.evidence
        if item.type.value == "official_verification"
        and item.signal
        in {
            "official_domain_verified",
            "sender_identity_unverified",
            "action_endorsement_unverified",
        }
    )
    # An exact resource endorsement can resolve a stale "unverified identity"
    # evidence item without turning it into risk. Keep that resolved evidence
    # in the explanation so the result states the actual verification boundary.
    refs.extend(
        item.evidence_ref
        for item in scope.evidence
        if item.signal in {"claimed_identity_unverified", "entity_target_unverified"}
        and item.description.startswith("Official verification đã xác nhận chuỗi endorsement")
    )
    refs = list(dict.fromkeys(refs))
    grounded = [item for item in scope.evidence if item.evidence_ref in refs]
    if not grounded and scope.evidence:
        grounded = [scope.evidence[0]]
        refs = [scope.evidence[0].evidence_ref]
    confidence = 0.35
    if context.credential_request or context.otp_request or context.payment_request:
        confidence += 0.3
    if strong_refs or safe_refs:
        confidence += 0.55
    elif reviewed_risk_refs:
        confidence += 0.15
    elif len({item.type for item in grounded}) > 1:
        confidence += 0.15
    if (
        identity_relation_unresolved and risk not in {SecurityRiskV4.HIGH_RISK, SecurityRiskV4.MALICIOUS}
    ) or ai_understanding_fallback:
        confidence = min(confidence, 0.65)
    elif (scope.errors or scope.limitations) and not (strong_refs or safe_refs):
        confidence = min(confidence, 0.65)

    payload = scope.model_dump()
    limitations = list(scope.limitations)
    if reputation_conflict_refs:
        limitations.append(
            "Kết quả reputation đơn lẻ mâu thuẫn với reviewed official-domain evidence; cần bằng chứng độc lập "
            "khác trước khi kết luận tên miền độc hại."
        )
    if strong_refs or risk is SecurityRiskV4.MALICIOUS:
        decision_assurance = "adverse_evidence"
    elif action_intent_unavailable:
        decision_assurance = "action_intent_unavailable"
    elif _has_sensitive_action(scope) or context.requested_action is not None:
        decision_assurance = "action_resource_verified" if action_chain_verified else "verification_incomplete"
    elif passive_target_ownership and risk is SecurityRiskV4.SAFE:
        decision_assurance = "passive_target_verified"
    else:
        decision_assurance = "verification_incomplete"
    activated_features = ["semantic-action-enforcement", "action-assurance-enforcement"]
    if memory_enabled:
        activated_features.append("security-memory")
    if official_verification_enforced:
        activated_features.append("official-verification")
    if familiarity_enforced:
        activated_features.append("domain-familiarity")
    payload.update(
        status="completed",
        completed_at=datetime.now(UTC),
        terminal=True,
        next_step="END",
        risk=risk,
        score=score,
        confidence=round(min(confidence, 0.95), 2),
        threat_type=(
            PotentialThreatV4.BRAND_IMPERSONATION
            if context.claimed_entity
            and (
                identity_confirmed_mismatch
                or any(
                    item.type.value == "brand_match" and "domain_mismatch" in item.signal.casefold().split("+")
                    for item in scope.evidence
                )
            )
            else context.potential_threat
        ),
        policy_version=SECURITY_RISK_POLICY_VERSION_V7,
        policy_metadata=SecurityPolicyMetadataV4(
            activated_features=sorted(activated_features), decision_assurance=decision_assurance
        ),
        recommended_actions=_actions(scope, risk, familiarity_low_risk=familiarity_low_risk),
        explanation=_explanation(risk, grounded),
        explanation_evidence_refs=refs,
        limitations=list(dict.fromkeys(limitations)),
    )
    return SecurityScopeResponseV4.model_validate(payload)


__all__ = ["assess_security_risk"]
