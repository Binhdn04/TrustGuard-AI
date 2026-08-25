from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from src.agents.security_trust import BrandMatcher
from src.core.auth import Principal, UserRole
from src.core.errors import PlatformError
from src.models import (
    BrandCreateRequestV4,
    BrandRecordV4,
    OfficialIdentityMatchScopeV4,
    OfficialIdentityTypeV4,
    OfficialIdentityV4,
    SecurityTriageCreateRequestV4,
)
from src.repositories import SQLiteBlacklistRepository
from src.services.official_identity_registry import (
    BrandResolutionMatch,
    BrandResolutionStatus,
    OfficialIdentityRegistry,
    SourceIdentityAssessment,
    normalize_official_identity,
    runtime_official_identities,
)
from src.services.platform_wave2 import SourceDiscoveryRecord
from src.services.security_triage import SecurityTriageScopeService
from src.services.security_trust import SecurityTrustAdminService

NOW = datetime(2026, 8, 20, 9, tzinfo=UTC)
ADMIN = Principal(user_id="security-reviewer", role=UserRole.SECURITY_ADMIN)
USER = Principal(user_id="ordinary-user", role=UserRole.USER)


def _brand(name: str = "Đại học Ánh Dương", **updates) -> BrandRecordV4:
    values = {
        "name": name,
        "aliases": ["Anh Duong University", "ADU"],
        "official_domains": ["anhduong.example"],
        "provenance": "reviewed organization registry",
        "policy_version": "brand-registry-v2",
        "effective_from": NOW - timedelta(days=1),
        "reviewer_id": ADMIN.user_id,
        "created_at": NOW,
    }
    values.update(updates)
    return BrandRecordV4(**values)


def test_old_brand_json_projects_primary_website_identity() -> None:
    old_payload = {
        "name": "Legacy University",
        "aliases": ["Legacy U"],
        "official_domains": ["legacy.example"],
        "official_contacts": [],
        "provenance": "legacy reviewed fixture",
        "policy_version": "brand-registry-v1",
        "effective_from": "2026-01-01T00:00:00Z",
        "reviewer_id": "legacy-reviewer",
        "created_at": "2026-01-01T00:00:00Z",
    }

    brand = BrandRecordV4.model_validate(old_payload)
    identities = runtime_official_identities(brand, NOW)

    assert brand.official_identities == []
    assert len(identities) == 1
    assert identities[0].identity_type is OfficialIdentityTypeV4.PRIMARY_WEBSITE
    assert identities[0].canonical_value == "legacy.example"
    assert identities[0].reviewed is True


def test_empty_official_domains_requires_an_active_identity() -> None:
    identity = OfficialIdentityV4(
        identity_type=OfficialIdentityTypeV4.SOCIAL_PROFILE,
        canonical_value="https://www.linkedin.com/company/example",
        display_value="LinkedIn Example",
        entity_name="Example",
        reviewed=True,
    )
    brand = _brand("Example", official_domains=[], official_identities=[identity])

    assert brand.official_domains == []
    with pytest.raises(ValidationError, match="official domain or an active official identity"):
        _brand("Invalid", official_domains=[], official_identities=[])


def test_resolution_order_supports_accent_folding_alias_and_bounded_phrase() -> None:
    registry = OfficialIdentityRegistry()
    brand = _brand()

    canonical = registry.resolve("Dai hoc Anh Duong", [brand], NOW)
    alias = registry.resolve("Anh Duong University", [brand], NOW)
    phrase = registry.resolve("Thông báo chính thức từ ADU dành cho sinh viên", [brand], NOW)

    assert canonical.status is BrandResolutionStatus.RESOLVED
    assert canonical.match is BrandResolutionMatch.EXACT_CANONICAL_NAME
    assert alias.match is BrandResolutionMatch.EXACT_ALIAS
    assert phrase.match is BrandResolutionMatch.BOUNDED_PHRASE


def test_ambiguous_brand_never_returns_identity_or_implicit_allowlist() -> None:
    first = _brand("Alpha Holdings", aliases=["Shared Brand"])
    second = _brand("Beta Holdings", aliases=["Shared Brand"])

    result = OfficialIdentityRegistry().resolve("Shared Brand", [first, second], NOW)

    assert result.status is BrandResolutionStatus.AMBIGUOUS
    assert result.brand is None
    assert result.identities == ()
    assert set(result.candidate_brand_ids) == {str(first.brand_id), str(second.brand_id)}


@pytest.mark.parametrize(
    ("identity_type", "value", "relationship", "scope"),
    [
        (
            OfficialIdentityTypeV4.SOCIAL_PROFILE,
            "https://linkedin.com/company/anh-duong?tracking=1",
            "official_social",
            OfficialIdentityMatchScopeV4.EXACT,
        ),
        (
            OfficialIdentityTypeV4.CAREERS_PAGE,
            "careers.anhduong.example/jobs?source=test",
            "careers",
            OfficialIdentityMatchScopeV4.EXACT,
        ),
        (
            OfficialIdentityTypeV4.SUB_ORGANIZATION,
            "  Khoa   Công nghệ  ",
            "sub_organization",
            OfficialIdentityMatchScopeV4.BOUNDED_PHRASE,
        ),
    ],
)
def test_social_careers_and_suborganization_identities_are_normalized(
    identity_type: OfficialIdentityTypeV4,
    value: str,
    relationship: str,
    scope: OfficialIdentityMatchScopeV4,
) -> None:
    normalized = normalize_official_identity(
        OfficialIdentityV4(
            identity_type=identity_type,
            canonical_value=value,
            display_value=value,
            entity_name="Đại học Ánh Dương",
        ),
        brand_name="Đại học Ánh Dương",
        brand_provenance="reviewed organization registry",
        brand_policy_version="brand-registry-v2",
        brand_effective_from=NOW,
    )

    assert normalized.reviewed is True
    assert normalized.relationship == relationship
    assert normalized.match_scope is scope
    assert "?" not in normalized.canonical_value
    assert "  " not in normalized.canonical_value


def test_social_and_careers_are_exact_while_suborganization_resolves_by_phrase() -> None:
    identities = [
        normalize_official_identity(
            OfficialIdentityV4(
                identity_type=identity_type,
                canonical_value=value,
                display_value=value,
                entity_name=entity,
            ),
            brand_name="Đại học Ánh Dương",
            brand_provenance="reviewed organization registry",
            brand_policy_version="brand-registry-v2",
            brand_effective_from=NOW - timedelta(days=1),
        )
        for identity_type, value, entity in (
            (
                OfficialIdentityTypeV4.SOCIAL_PROFILE,
                "https://linkedin.com/company/anh-duong",
                "Đại học Ánh Dương",
            ),
            (
                OfficialIdentityTypeV4.CAREERS_PAGE,
                "https://careers.anhduong.example/jobs",
                "Đại học Ánh Dương",
            ),
            (
                OfficialIdentityTypeV4.SUB_ORGANIZATION,
                "Khoa Công nghệ",
                "Khoa Công nghệ",
            ),
        )
    ]
    brand = _brand(official_domains=[], official_identities=identities)
    registry = OfficialIdentityRegistry()

    suborganization = registry.resolve("Thông báo từ Khoa Cong nghe", [brand], NOW)
    assert suborganization.status is BrandResolutionStatus.RESOLVED
    assert suborganization.brand == brand

    exact_message = "ADU yêu cầu mở link https://linkedin.com/company/anh-duong"
    exact_request = SecurityTriageCreateRequestV4(message=exact_message)
    exact_scope = SecurityTriageScopeService().assess(exact_request)
    _, exact_evidence = BrandMatcher().match(exact_request, exact_scope, [brand], NOW)
    assert any(item.signal == "official_match" for item in exact_evidence)

    other_message = "ADU yêu cầu mở link https://linkedin.com/company/unrelated"
    other_request = SecurityTriageCreateRequestV4(message=other_message)
    other_scope = SecurityTriageScopeService().assess(other_request)
    _, other_evidence = BrandMatcher().match(other_request, other_scope, [brand], NOW)
    assert any(item.signal == "domain_mismatch" for item in other_evidence)


@dataclass(frozen=True)
class _SourceEntry:
    publisher: str
    normalized_pattern: str
    active: bool = True
    explicit_deny: bool = False
    effective_from: datetime = NOW - timedelta(days=1)
    effective_to: datetime | None = None
    reviewed_at: datetime = NOW - timedelta(hours=1)


def test_source_registry_only_exact_entity_bound_review_confirms_identity() -> None:
    brand = _brand()
    identity = normalize_official_identity(
        OfficialIdentityV4(
            identity_type=OfficialIdentityTypeV4.CAREERS_PAGE,
            canonical_value="https://careers.anhduong.example/jobs",
            display_value="Careers",
            entity_name=brand.name,
        ),
        brand_name=brand.name,
        brand_provenance=brand.provenance,
        brand_policy_version=brand.policy_version,
        brand_effective_from=brand.effective_from,
    )
    registry = OfficialIdentityRegistry()

    exact = registry.assess_source_entry(
        identity,
        brand,
        _SourceEntry(brand.name, "careers.anhduong.example"),
        NOW,
    )
    wildcard = registry.assess_source_entry(
        identity,
        brand,
        _SourceEntry(brand.name, "*.anhduong.example"),
        NOW,
    )
    wrong_entity = registry.assess_source_entry(
        identity,
        brand,
        _SourceEntry("Unrelated Publisher", "careers.anhduong.example"),
        NOW,
    )

    assert exact is SourceIdentityAssessment.CONFIRMS_IDENTITY
    assert wildcard is SourceIdentityAssessment.CORROBORATES
    assert wrong_entity is SourceIdentityAssessment.CORROBORATES


def test_online_discovery_cannot_confirm_or_create_official_identity() -> None:
    brand = _brand()
    identity = runtime_official_identities(brand, NOW)[0]
    discovery = SourceDiscoveryRecord(
        domain="discovered.example",
        publisher=brand.name,
        first_seen_at=NOW,
        last_seen_at=NOW,
    )

    result = OfficialIdentityRegistry().assess_source_entry(identity, brand, discovery, NOW)

    assert result is SourceIdentityAssessment.NO_MATCH
    assert brand.official_identities == []


@pytest.mark.asyncio
async def test_brand_supersede_and_disable_append_versions_with_immutable_audit(tmp_path) -> None:
    repository = SQLiteBlacklistRepository(tmp_path / "cp4-trust.db")
    service = SecurityTrustAdminService(repository)
    initial_request = BrandCreateRequestV4(
        name="Versioned Brand",
        aliases=["VB"],
        official_domains=["version-one.example"],
        provenance="reviewed fixture",
        effective_from=NOW - timedelta(days=2),
    )
    next_request = initial_request.model_copy(
        update={
            "official_domains": ["version-two.example"],
            "effective_from": NOW - timedelta(days=1),
            "policy_version": "brand-registry-v2",
        }
    )

    initial = await service.create_brand(initial_request, ADMIN)
    with pytest.raises(PlatformError) as denied:
        await service.create_brand_version(str(initial.brand_id), next_request, USER)
    version = await service.create_brand_version(str(initial.brand_id), next_request, ADMIN)
    disabled = await service.disable_brand(str(version.brand_id), ADMIN)

    records = await repository.list_brands()
    audit = await repository.list_security_admin_audit()
    assert denied.value.status_code == 403
    assert len(records) == 3
    assert records[0] == initial
    assert records[0].lifecycle.value == "active"
    assert version.supersedes == initial.brand_id
    assert disabled.supersedes == version.brand_id
    assert disabled.brand_id != version.brand_id
    assert await repository.list_active_brands(disabled.created_at) == []
    brand_actions = [item.action for item in audit if item.resource_type.value == "brand"]
    assert sorted(brand_actions) == ["created", "disabled", "superseded"]
    await repository.close()
