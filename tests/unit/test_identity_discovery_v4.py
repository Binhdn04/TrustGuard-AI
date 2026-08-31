from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from src.core.auth import Principal, UserRole
from src.core.errors import PlatformError
from src.models import (
    AssistantSourceSpanV4,
    IdentityAssociationAssuranceV4,
    IdentityCandidateDecisionActionV4,
    IdentityCandidateDecisionRequestV4,
    IdentityCandidateV4,
    IdentityEvidenceFamilyV4,
    IdentityEvidenceObservationV4,
    IdentityRelationshipV4,
    ManualIdentityCandidateCreateRequestV4,
    OfficialIdentityTypeV4,
    VerificationIntentV4,
)
from src.repositories import SQLiteBlacklistRepository
from src.services.official_verification_coordinator import OfficialLinkVerificationCoordinator
from src.services.official_verification_intent import (
    DerivedOrganizationName,
    GroundedTextValue,
    GroundedVerificationIntent,
)
from src.services.security_trust import SecurityTrustAdminService

NOW = datetime(2026, 8, 21, tzinfo=UTC)
ADMIN = Principal("identity-reviewer", UserRole.SECURITY_ADMIN)
USER = Principal("ordinary-user", UserRole.USER)


def _observation(family: IdentityEvidenceFamilyV4, host: str, suffix: str) -> IdentityEvidenceObservationV4:
    return IdentityEvidenceObservationV4(
        evidence_ref=f"identity-evidence:{suffix * 16}",
        family=family,
        source_host=host,
        canonical_url=f"https://{host}/evidence",
        content_hash=hashlib.sha256(f"{host}:{family}".encode()).hexdigest(),
        observed_at=NOW,
    )


def _candidate(*, suffix: str = "a") -> IdentityCandidateV4:
    observations = [
        _observation(IdentityEvidenceFamilyV4.EXACT_RESOURCE_ENDORSEMENT, "hospital.example", suffix),
        _observation(IdentityEvidenceFamilyV4.TARGET_RESOURCE_MATCH, "isofhcare.vn", chr(ord(suffix) + 1)),
    ]
    return IdentityCandidateV4(
        entity_name="Bệnh viện Đại học Y Hà Nội",
        canonical_url="https://benhviendaihocyhanoi.isofhcare.vn/dang-ky",
        canonical_domain="benhviendaihocyhanoi.isofhcare.vn",
        relationship=IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE,
        assurance=IdentityAssociationAssuranceV4.VERIFIED,
        confidence=0.86,
        evidence_refs=[item.evidence_ref for item in observations],
        discovered_at=NOW,
        verified_at=NOW,
        expires_at=NOW + timedelta(days=7),
        observations=observations,
    )


@pytest.mark.asyncio
async def test_sqlite_versions_candidates_and_admin_promotion_is_terminal(tmp_path) -> None:
    repository = SQLiteBlacklistRepository(tmp_path / "identity.db")
    first = await repository.save_identity_candidate(_candidate())
    second = await repository.save_identity_candidate(_candidate(suffix="c"))
    assert (first.version, second.version) == (1, 2)
    assert second.supersedes == first.association_id

    service = SecurityTrustAdminService(repository)
    with pytest.raises(PlatformError) as denied:
        await service.decide_identity_candidate(
            str(second.association_id),
            IdentityCandidateDecisionRequestV4(action="approve", note="reviewed evidence"),
            USER,
        )
    assert denied.value.status_code == 403

    promoted = await service.decide_identity_candidate(
        str(second.association_id),
        IdentityCandidateDecisionRequestV4(
            action=IdentityCandidateDecisionActionV4.APPROVE,
            note="Exact hospital endorsement and exact target resource were reviewed.",
        ),
        ADMIN,
    )
    assert promoted.assurance is IdentityAssociationAssuranceV4.PROMOTED
    assert promoted.terminal_decision_id is not None
    brands = await repository.list_brands()
    assert len(brands) == 1
    assert brands[0].official_identities[0].reviewed is True
    assert brands[0].official_identities[0].relationship == "endorsed_third_party_service"
    assert str(second.association_id) in brands[0].provenance

    with pytest.raises(PlatformError) as duplicate:
        await service.decide_identity_candidate(
            str(second.association_id),
            IdentityCandidateDecisionRequestV4(action="reject", note="cannot overwrite terminal decision"),
            ADMIN,
        )
    assert duplicate.value.status_code == 409
    audit = await repository.list_security_admin_audit()
    assert any(item.resource_type.value == "identity_candidate" and item.action == "approve" for item in audit)
    await repository.close()


@pytest.mark.asyncio
async def test_manual_identity_stays_review_gated_and_does_not_broaden_social_domain(tmp_path) -> None:
    repository = SQLiteBlacklistRepository(tmp_path / "manual-identity.db")
    service = SecurityTrustAdminService(repository)

    candidate = await service.create_manual_identity_candidate(
        ManualIdentityCandidateCreateRequestV4(
            entity_name="ACME Bank",
            identity_value="https://social.example/acme-bank?private=query#fragment",
            identity_type=OfficialIdentityTypeV4.SOCIAL_PROFILE,
            relationship=IdentityRelationshipV4.OFFICIAL_CONTROLLED,
            source_url="https://acme.example/about/social?private=query#fragment",
        ),
        ADMIN,
    )

    assert candidate.assurance is IdentityAssociationAssuranceV4.DISCOVERED
    assert candidate.canonical_url == "https://social.example/acme-bank"
    assert candidate.observations[0].canonical_url == "https://acme.example/about/social"
    assert not await repository.list_brands()

    promoted = await service.decide_identity_candidate(
        str(candidate.association_id),
        IdentityCandidateDecisionRequestV4(
            action=IdentityCandidateDecisionActionV4.APPROVE,
            note="Reviewed the official social-profile reference.",
            identity_type=OfficialIdentityTypeV4.SOCIAL_PROFILE,
        ),
        ADMIN,
    )

    assert promoted.assurance is IdentityAssociationAssuranceV4.PROMOTED
    brand = (await repository.list_brands())[0]
    assert brand.official_domains == []
    assert brand.official_identities[0].identity_type is OfficialIdentityTypeV4.SOCIAL_PROFILE
    await repository.close()


def test_identity_candidate_ttl_is_exactly_seven_days() -> None:
    candidate = _candidate()
    assert candidate.expires_at - candidate.discovered_at == timedelta(days=7)


def test_discovery_query_is_natural_entity_first_and_bounded() -> None:
    span = AssistantSourceSpanV4(field_name="claimed_entity", start=0, end=25)
    name = "Bệnh viện Đại học Y Hà Nội"
    intent = GroundedVerificationIntent(
        contract=VerificationIntentV4(
            organization_name=name,
            derived_organization_names=["Benh vien Dai hoc Y Ha Noi"],
        ),
        organization=GroundedTextValue(name, 1, (span,)),
        claim=None,
        action=None,
        derived_organizations=(DerivedOrganizationName("Benh vien Dai hoc Y Ha Noi", "accent_fold"),),
    )
    queries = OfficialLinkVerificationCoordinator._identity_discovery_queries(intent)
    assert queries[0] == name
    assert len(queries) <= 3
    assert all("official website" not in query.casefold() for query in queries)
    assert all("https://" not in query and "otp" not in query.casefold() for query in queries)


@pytest.mark.parametrize(
    ("relationship", "anchor", "corroboration"),
    [
        (
            IdentityRelationshipV4.OFFICIAL_CONTROLLED,
            IdentityEvidenceFamilyV4.ENTITY_SELF_IDENTIFICATION,
            IdentityEvidenceFamilyV4.INDEPENDENT_ENTITY_LINK,
        ),
        (
            IdentityRelationshipV4.PARENT_ORGANIZATION,
            IdentityEvidenceFamilyV4.PARENT_DECLARATION,
            IdentityEvidenceFamilyV4.INDEPENDENT_ENTITY_LINK,
        ),
        (
            IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE,
            IdentityEvidenceFamilyV4.EXACT_RESOURCE_ENDORSEMENT,
            IdentityEvidenceFamilyV4.TARGET_RESOURCE_MATCH,
        ),
    ],
)
def test_two_independent_evidence_families_verify_each_relationship(relationship, anchor, corroboration) -> None:
    observations = [
        _observation(anchor, "entity.example", "e"),
        _observation(corroboration, "authority.example", "f"),
    ]
    association = OfficialLinkVerificationCoordinator._association_from_observations(
        "Entity", "https://target.example/resource", relationship, observations, NOW
    )
    assert association.relationship is relationship
    assert association.assurance is IdentityAssociationAssuranceV4.VERIFIED


def test_one_external_exact_endorsement_verifies_only_the_submitted_resource() -> None:
    observation = _observation(
        IdentityEvidenceFamilyV4.EXACT_RESOURCE_ENDORSEMENT,
        "publisher.example",
        "a",
    )

    association = OfficialLinkVerificationCoordinator._association_from_observations(
        "Entity",
        "https://forms.example/resource/123",
        IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE,
        [observation],
        NOW,
    )

    assert association.assurance is IdentityAssociationAssuranceV4.VERIFIED
    assert association.confidence == 0.7
    assert association.canonical_url == "https://forms.example/resource/123"


@pytest.mark.parametrize(
    "observation",
    [
        _observation(IdentityEvidenceFamilyV4.TARGET_RESOURCE_MATCH, "forms.example", "b"),
        _observation(IdentityEvidenceFamilyV4.EXACT_RESOURCE_ENDORSEMENT, "forms.example", "c"),
    ],
)
def test_target_cannot_verify_its_own_endorsement_with_one_source(
    observation: IdentityEvidenceObservationV4,
) -> None:
    association = OfficialLinkVerificationCoordinator._association_from_observations(
        "Entity",
        "https://forms.example/resource/123",
        IdentityRelationshipV4.ENDORSED_THIRD_PARTY_SERVICE,
        [observation],
        NOW,
    )

    assert association.assurance is IdentityAssociationAssuranceV4.DISCOVERED
