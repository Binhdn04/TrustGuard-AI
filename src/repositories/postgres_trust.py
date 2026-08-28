from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from src.models import (
    BrandRecordV4,
    IdentityCandidateDecisionV4,
    IdentityCandidateV4,
    TrustLifecycleV4,
    WhitelistRecordV4,
)


def _json_value(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


class PostgresTrustRepositoryMixin:
    """Reviewed brand, identity, whitelist, and trust-audit persistence."""

    async def create_brand(self, record: BrandRecordV4, *, audit_action: str = "created") -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO security_brands(
                       id,name,aliases,official_domains,official_contacts,provenance,policy_version,
                       lifecycle,effective_from,effective_until,reviewer_id,created_at,record
                   ) VALUES($1,$2,$3::jsonb,$4::jsonb,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)""",
                record.brand_id,
                record.name,
                json.dumps(record.aliases),
                json.dumps(record.official_domains),
                json.dumps(record.official_contacts),
                record.provenance,
                record.policy_version,
                record.lifecycle.value,
                record.effective_from,
                record.effective_until,
                record.reviewer_id,
                record.created_at,
                record.model_dump_json(),
            )
            await self._insert_trust_audit(
                connection,
                "brand",
                record.brand_id,
                audit_action,
                record.reviewer_id,
                record.created_at,
            )

    async def list_brands(self) -> list[BrandRecordV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch("SELECT record FROM security_brands ORDER BY created_at")
        return [BrandRecordV4.model_validate(_json_value(row["record"])) for row in rows]

    async def list_active_brands(self, at: datetime) -> list[BrandRecordV4]:
        effective = [
            item
            for item in await self.list_brands()
            if item.effective_from <= at and (item.effective_until is None or at < item.effective_until)
        ]
        superseded = {item.supersedes for item in effective if item.supersedes is not None}
        return [
            item for item in effective if item.lifecycle is TrustLifecycleV4.ACTIVE and item.brand_id not in superseded
        ]

    async def save_identity_candidate(self, record: IdentityCandidateV4) -> IdentityCandidateV4:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            previous = await connection.fetchrow(
                """SELECT id,version FROM security_identity_candidates
                   WHERE entity_name=$1 AND canonical_domain=$2 AND relationship=$3
                   ORDER BY version DESC LIMIT 1 FOR UPDATE""",
                record.entity_name,
                record.canonical_domain,
                record.relationship.value,
            )
            version = max(record.version, (previous["version"] if previous else 0) + 1)
            stored = record.model_copy(
                update={"version": version, "supersedes": previous["id"] if previous else record.supersedes}
            )
            await connection.execute(
                """INSERT INTO security_identity_candidates(
                       id,entity_name,canonical_url,canonical_domain,relationship,assurance,
                       confidence,version,expires_at,terminal_decision_id,record,created_at
                   ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12)""",
                stored.association_id,
                stored.entity_name,
                stored.canonical_url,
                stored.canonical_domain,
                stored.relationship.value,
                stored.assurance.value,
                stored.confidence,
                stored.version,
                stored.expires_at,
                stored.terminal_decision_id,
                stored.model_dump_json(),
                stored.discovered_at,
            )
            for observation in stored.observations:
                await connection.execute(
                    """INSERT INTO security_identity_evidence(
                           evidence_ref,candidate_id,source_host,family,canonical_url,content_hash,
                           observation,observed_at
                       ) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8) ON CONFLICT DO NOTHING""",
                    observation.evidence_ref,
                    stored.association_id,
                    observation.source_host,
                    observation.family.value,
                    observation.canonical_url,
                    observation.content_hash,
                    observation.model_dump_json(),
                    observation.observed_at,
                )
        return stored

    async def list_identity_candidates(self) -> list[IdentityCandidateV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch("SELECT record FROM security_identity_candidates ORDER BY created_at DESC")
        return [IdentityCandidateV4.model_validate(_json_value(row["record"])) for row in rows]

    async def create_identity_decision(
        self, decision: IdentityCandidateDecisionV4, updated: IdentityCandidateV4
    ) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                "SELECT terminal_decision_id FROM security_identity_candidates WHERE id=$1 FOR UPDATE",
                decision.candidate_id,
            )
            if row is None:
                raise LookupError("identity candidate not found")
            if row["terminal_decision_id"] is not None:
                raise ValueError("identity candidate already has a terminal decision")
            await connection.execute(
                """INSERT INTO security_identity_decisions(
                       id,candidate_id,action,reviewer_id,note,target_brand_id,relationship,
                       identity_type,evidence_refs,decision,decided_at
                   ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11)""",
                decision.decision_id,
                decision.candidate_id,
                decision.action.value,
                decision.reviewer_id,
                decision.note,
                decision.target_brand_id,
                decision.relationship.value if decision.relationship else None,
                decision.identity_type.value if decision.identity_type else None,
                json.dumps(decision.evidence_refs),
                decision.model_dump_json(),
                decision.decided_at,
            )
            await connection.execute(
                """UPDATE security_identity_candidates
                   SET assurance=$1,terminal_decision_id=$2,record=$3::jsonb WHERE id=$4""",
                updated.assurance.value,
                decision.decision_id,
                updated.model_dump_json(),
                updated.association_id,
            )
            await self._insert_trust_audit(
                connection,
                "identity_candidate",
                updated.association_id,
                decision.action.value,
                decision.reviewer_id,
                decision.decided_at,
            )

    async def disable_brand(self, brand_id: str, reviewer_id: str, at: datetime) -> BrandRecordV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow("SELECT record FROM security_brands WHERE id=$1 FOR UPDATE", UUID(brand_id))
            if row is None:
                return None
            already_superseded = await connection.fetchval(
                "SELECT EXISTS(SELECT 1 FROM security_brands WHERE record->>'supersedes'=$1)",
                brand_id,
            )
            if already_superseded:
                return None
            previous = BrandRecordV4.model_validate(_json_value(row["record"]))
            record = BrandRecordV4.model_validate(
                {
                    **previous.model_dump(),
                    "brand_id": uuid4(),
                    "supersedes": previous.brand_id,
                    "lifecycle": TrustLifecycleV4.DISABLED,
                    "effective_from": at,
                    "effective_until": None,
                    "reviewer_id": reviewer_id,
                    "created_at": at,
                }
            )
            await connection.execute(
                """INSERT INTO security_brands(
                       id,name,aliases,official_domains,official_contacts,provenance,policy_version,
                       lifecycle,effective_from,effective_until,reviewer_id,created_at,record
                   ) VALUES($1,$2,$3::jsonb,$4::jsonb,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)""",
                record.brand_id,
                record.name,
                json.dumps(record.aliases),
                json.dumps(record.official_domains),
                json.dumps(record.official_contacts),
                record.provenance,
                record.policy_version,
                record.lifecycle.value,
                record.effective_from,
                record.effective_until,
                record.reviewer_id,
                record.created_at,
                record.model_dump_json(),
            )
            await self._insert_trust_audit(
                connection,
                "brand",
                record.brand_id,
                "disabled",
                reviewer_id,
                at,
            )
        return record

    async def create_whitelist(self, record: WhitelistRecordV4) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO security_whitelist(
                       id,scope,indicator,provenance,policy_version,lifecycle,effective_from,
                       effective_until,reviewer_id,created_at,record
                   ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)""",
                record.whitelist_id,
                record.scope.value,
                record.indicator,
                record.provenance,
                record.policy_version,
                record.lifecycle.value,
                record.effective_from,
                record.effective_until,
                record.reviewer_id,
                record.created_at,
                record.model_dump_json(),
            )
            await self._insert_trust_audit(
                connection, "whitelist", record.whitelist_id, "created", record.reviewer_id, record.created_at
            )

    async def list_whitelist(self) -> list[WhitelistRecordV4]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch("SELECT record FROM security_whitelist ORDER BY created_at")
        return [WhitelistRecordV4.model_validate(_json_value(row["record"])) for row in rows]

    async def list_active_whitelist(self, at: datetime) -> list[WhitelistRecordV4]:
        return [
            item
            for item in await self.list_whitelist()
            if item.lifecycle is TrustLifecycleV4.ACTIVE
            and item.effective_from <= at
            and (item.effective_until is None or at < item.effective_until)
        ]

    async def disable_whitelist(self, whitelist_id: str, reviewer_id: str, at: datetime) -> WhitelistRecordV4 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                "SELECT record FROM security_whitelist WHERE id=$1 FOR UPDATE", UUID(whitelist_id)
            )
            if row is None:
                return None
            record = WhitelistRecordV4.model_validate(_json_value(row["record"])).model_copy(
                update={"lifecycle": TrustLifecycleV4.DISABLED, "reviewer_id": reviewer_id}
            )
            await connection.execute(
                "UPDATE security_whitelist SET lifecycle='disabled', reviewer_id=$2, record=$3::jsonb WHERE id=$1",
                UUID(whitelist_id),
                reviewer_id,
                record.model_dump_json(),
            )
            await self._insert_trust_audit(connection, "whitelist", UUID(whitelist_id), "disabled", reviewer_id, at)
        return record

    async def _insert_trust_audit(
        self, connection, resource_type: str, resource_id: UUID, action: str, reviewer_id: str, at: datetime
    ) -> None:
        await connection.execute(
            """INSERT INTO security_trust_audit(
                   id,resource_type,resource_id,action,reviewer_id,occurred_at
               ) VALUES($1,$2,$3,$4,$5,$6)""",
            uuid4(),
            resource_type,
            resource_id,
            action,
            reviewer_id,
            at,
        )


__all__ = ["PostgresTrustRepositoryMixin"]
