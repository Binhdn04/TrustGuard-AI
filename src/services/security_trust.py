from __future__ import annotations

import logging
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

from src.agents.security_trust import canonical_whitelist_url
from src.core.auth import Principal, require_security_admin
from src.core.errors import PlatformError
from src.models import (
    BrandCreateRequestV4,
    BrandRecordV4,
    ErrorCode,
    IdentityAssociationAssuranceV4,
    IdentityCandidateDecisionActionV4,
    IdentityCandidateDecisionRequestV4,
    IdentityCandidateDecisionV4,
    IdentityCandidateV4,
    OfficialIdentityMatchScopeV4,
    OfficialIdentityTypeV4,
    OfficialIdentityV4,
    TrustLifecycleV4,
    WhitelistCreateRequestV4,
    WhitelistRecordV4,
    WhitelistScopeV4,
)
from src.repositories.blacklist import normalize_domain
from src.services.official_identity_registry import normalize_official_identity


class SecurityTrustAdminService:
    def __init__(self, repository) -> None:
        self._repository = repository

    async def create_brand(self, request: BrandCreateRequestV4, principal: Principal) -> BrandRecordV4:
        require_security_admin(principal)
        record = self._brand_record(request, principal, datetime.now(UTC))
        await self._repository.create_brand(record)
        return record

    async def list_identity_candidates(self, principal: Principal) -> list[IdentityCandidateV4]:
        require_security_admin(principal)
        return await self._repository.list_identity_candidates()

    async def decide_identity_candidate(
        self,
        candidate_id: str,
        request: IdentityCandidateDecisionRequestV4,
        principal: Principal,
    ) -> IdentityCandidateV4:
        require_security_admin(principal)
        candidates = await self._repository.list_identity_candidates()
        candidate = next((item for item in candidates if str(item.association_id) == candidate_id), None)
        if candidate is None:
            raise PlatformError(status_code=404, code=ErrorCode.NOT_FOUND, message="Identity candidate was not found.", retryable=False)
        if candidate.terminal_decision_id is not None:
            raise PlatformError(status_code=409, code=ErrorCode.CONFLICT, message="Identity candidate already has a terminal decision.", retryable=False)

        now = datetime.now(UTC)
        decision = IdentityCandidateDecisionV4(
            candidate_id=candidate.association_id,
            action=request.action,
            reviewer_id=principal.user_id,
            note=request.note,
            target_brand_id=request.target_brand_id,
            relationship=request.relationship,
            identity_type=request.identity_type,
            evidence_refs=candidate.evidence_refs,
            decided_at=now,
        )
        assurance = {
            IdentityCandidateDecisionActionV4.APPROVE: IdentityAssociationAssuranceV4.PROMOTED,
            IdentityCandidateDecisionActionV4.REJECT: IdentityAssociationAssuranceV4.REJECTED,
            IdentityCandidateDecisionActionV4.CONFIRM_MISMATCH: IdentityAssociationAssuranceV4.CONFIRMED_MISMATCH,
        }[request.action]
        updated = candidate.model_copy(
            update={
                "assurance": assurance,
                "relationship": request.relationship or candidate.relationship,
                "terminal_decision_id": decision.decision_id,
                "expires_at": None,
            }
        )
        if request.action is IdentityCandidateDecisionActionV4.APPROVE:
            await self._promote_identity_candidate(candidate, request, principal, now)
        try:
            await self._repository.create_identity_decision(decision, updated)
        except ValueError as exc:
            raise PlatformError(status_code=409, code=ErrorCode.CONFLICT, message=str(exc), retryable=False) from exc
        logging.getLogger("trustguard.identity_discovery").info(
            "identity_reviewer_decision",
            extra={
                "identity_reviewer_decision": {
                    "action": decision.action.value,
                    "relationship": updated.relationship.value,
                    "assurance": updated.assurance.value,
                    "evidence_count": len(updated.evidence_refs),
                }
            },
        )
        return updated

    async def _promote_identity_candidate(
        self,
        candidate: IdentityCandidateV4,
        request: IdentityCandidateDecisionRequestV4,
        principal: Principal,
        now: datetime,
    ) -> BrandRecordV4:
        records = await self._repository.list_active_brands(now)
        if request.target_brand_id is not None:
            matches = [item for item in records if item.brand_id == request.target_brand_id]
            if not matches:
                raise PlatformError(status_code=404, code=ErrorCode.NOT_FOUND, message="Target brand was not found.", retryable=False)
        else:
            entity = candidate.entity_name.casefold()
            matches = [
                item for item in records
                if entity in {item.name.casefold(), *(alias.casefold() for alias in item.aliases)}
            ]
            if len(matches) > 1:
                raise PlatformError(
                    status_code=409, code=ErrorCode.CONFLICT,
                    message="Identity candidate is ambiguous; target_brand_id is required.", retryable=False,
                )
        identity = OfficialIdentityV4(
            identity_type=request.identity_type or OfficialIdentityTypeV4.WEBSITE,
            canonical_value=candidate.canonical_url,
            display_value=candidate.canonical_url,
            entity_name=candidate.entity_name,
            match_scope=OfficialIdentityMatchScopeV4.EXACT,
            relationship=(request.relationship or candidate.relationship).value,
            provenance=f"identity-candidate:{candidate.association_id}",
            policy_version="reviewed-identity-promotion-v1",
            effective_from=now,
            reviewed=True,
        )
        host = (urlsplit(candidate.canonical_url).hostname or candidate.canonical_domain).casefold()
        provenance = f"identity-candidate:{candidate.association_id};evidence:{','.join(candidate.evidence_refs)}"
        if not matches:
            create = BrandCreateRequestV4(
                name=candidate.entity_name,
                official_domains=[host],
                official_identities=[identity],
                provenance=provenance,
                policy_version="brand-registry-identity-promotion-v1",
                effective_from=now,
            )
            return await self.create_brand(create, principal)
        previous = matches[0]
        create = BrandCreateRequestV4(
            name=previous.name,
            aliases=previous.aliases,
            official_domains=list(dict.fromkeys([*previous.official_domains, host])),
            official_identities=[*previous.official_identities, identity],
            official_contacts=previous.official_contacts,
            provenance=provenance,
            policy_version="brand-registry-identity-promotion-v1",
            effective_from=now,
        )
        return await self.create_brand_version(str(previous.brand_id), create, principal)

    async def create_brand_version(
        self,
        brand_id: str,
        request: BrandCreateRequestV4,
        principal: Principal,
    ) -> BrandRecordV4:
        require_security_admin(principal)
        records = await self._repository.list_brands()
        previous = next((item for item in records if str(item.brand_id) == brand_id), None)
        if previous is None:
            raise PlatformError(
                status_code=404,
                code=ErrorCode.NOT_FOUND,
                message="Brand was not found.",
                retryable=False,
            )
        if any(item.supersedes == previous.brand_id for item in records):
            raise PlatformError(
                status_code=409,
                code=ErrorCode.CONFLICT,
                message="Brand version was already superseded.",
                retryable=False,
            )
        record = self._brand_record(
            request,
            principal,
            datetime.now(UTC),
            supersedes=previous.brand_id,
        )
        if record.effective_from < previous.effective_from:
            raise PlatformError(
                status_code=422,
                code=ErrorCode.VALIDATION_ERROR,
                message="A brand version cannot become effective before the version it supersedes.",
                retryable=False,
            )
        await self._repository.create_brand(record, audit_action="superseded")
        return record

    @staticmethod
    def _brand_record(
        request: BrandCreateRequestV4,
        principal: Principal,
        created_at: datetime,
        *,
        supersedes: UUID | None = None,
    ) -> BrandRecordV4:
        try:
            domains = list(dict.fromkeys(normalize_domain(item) for item in request.official_domains))
            identities = [
                normalize_official_identity(
                    item,
                    brand_name=request.name,
                    brand_provenance=request.provenance,
                    brand_policy_version=request.policy_version,
                    brand_effective_from=request.effective_from,
                )
                for item in request.official_identities
            ]
        except ValueError as exc:
            raise PlatformError(
                status_code=422,
                code=ErrorCode.VALIDATION_ERROR,
                message="An official brand identity is invalid.",
                retryable=False,
            ) from exc

        unique_identities = {
            (item.identity_type.value, item.canonical_value.casefold()): item for item in identities
        }
        return BrandRecordV4(
            **request.model_dump(exclude={"official_domains", "official_identities"}),
            official_domains=domains,
            official_identities=list(unique_identities.values()),
            supersedes=supersedes,
            lifecycle=TrustLifecycleV4.ACTIVE,
            reviewer_id=principal.user_id,
            created_at=created_at,
        )

    async def disable_brand(self, brand_id: str, principal: Principal) -> BrandRecordV4:
        require_security_admin(principal)
        record = await self._repository.disable_brand(brand_id, principal.user_id, datetime.now(UTC))
        if record is None:
            raise PlatformError(
                status_code=404, code=ErrorCode.NOT_FOUND, message="Brand was not found.", retryable=False
            )
        return record

    async def create_whitelist(self, request: WhitelistCreateRequestV4, principal: Principal) -> WhitelistRecordV4:
        require_security_admin(principal)
        indicator = request.indicator
        try:
            if request.scope is WhitelistScopeV4.DOMAIN:
                indicator = normalize_domain(indicator)
            elif request.scope is WhitelistScopeV4.URL:
                indicator = canonical_whitelist_url(indicator) or ""
                if not indicator:
                    raise ValueError("URL is not canonicalizable")
            else:
                indicator = indicator.casefold().strip()
        except ValueError as exc:
            raise PlatformError(
                status_code=422,
                code=ErrorCode.VALIDATION_ERROR,
                message="Whitelist indicator is invalid for its scope.",
                retryable=False,
            ) from exc
        record = WhitelistRecordV4(
            **request.model_dump(exclude={"indicator"}),
            indicator=indicator,
            reviewer_id=principal.user_id,
            created_at=datetime.now(UTC),
        )
        await self._repository.create_whitelist(record)
        return record

    async def disable_whitelist(self, whitelist_id: str, principal: Principal) -> WhitelistRecordV4:
        require_security_admin(principal)
        record = await self._repository.disable_whitelist(whitelist_id, principal.user_id, datetime.now(UTC))
        if record is None:
            raise PlatformError(
                status_code=404, code=ErrorCode.NOT_FOUND, message="Whitelist entry was not found.", retryable=False
            )
        return record

    async def list_brands(self, principal: Principal) -> list[BrandRecordV4]:
        require_security_admin(principal)
        return await self._repository.list_brands()

    async def list_whitelist(self, principal: Principal) -> list[WhitelistRecordV4]:
        require_security_admin(principal)
        return await self._repository.list_whitelist()


__all__ = ["SecurityTrustAdminService"]
