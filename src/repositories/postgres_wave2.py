from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

from src.core.errors import PlatformError
from src.models import (
    CampaignAggregateSignalV3,
    CampaignDetailV3,
    CampaignReviewerStatus,
    CampaignSummaryV3,
    ErrorCode,
)
from src.repositories.postgres_jobs import DurableJob
from src.services.platform_wave2 import (
    CampaignWrite,
    FactCheckCorpusRecordWrite,
    FactCheckResultWrite,
    SourceDiscoveryRecord,
    SourceRegistryEntry,
    SourceTier,
    UsageLedgerEntry,
)


def _json_value(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _safe_url_or_text(value: str) -> str:
    """Remove credentials, query strings, and fragments before persistence."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value[:500]
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return value[:500]
    port = f":{parsed.port}" if parsed.port else ""
    return urlunsplit((parsed.scheme, f"{parsed.hostname}{port}", parsed.path, "", ""))[:2000]


def _platform_conflict(message: str) -> PlatformError:
    return PlatformError(
        status_code=409,
        code=ErrorCode.INTERNAL_ERROR,
        message=message,
        retryable=False,
    )


class PostgresWave2RepositoryMixin:
    """Reviewed source, corpus, usage, and campaign persistence."""

    async def register_source(self, entry: SourceRegistryEntry) -> None:
        pool = await self._get_pool()
        try:
            async with pool.acquire() as connection:
                await connection.execute(
                    """INSERT INTO fact_check_sources(
                           id,publisher,normalized_pattern,tier,source_type,active,explicit_deny,
                           trusted_claim_review,allowed_operations,policy_version,effective_from,effective_to,
                           default_freshness_seconds,reviewer_id,reviewed_at,created_at
                       ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$14,$15,$15)""",
                    entry.source_id,
                    entry.publisher,
                    entry.normalized_pattern,
                    entry.tier.value,
                    entry.source_type,
                    entry.active,
                    entry.explicit_deny,
                    entry.trusted_claim_review,
                    json.dumps(sorted(entry.allowed_operations)),
                    entry.policy_version,
                    entry.effective_from,
                    entry.effective_to,
                    entry.default_freshness_seconds,
                    entry.reviewer_id,
                    entry.reviewed_at,
                )
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == "23505":
                raise _platform_conflict("This source policy version already exists.") from exc
            raise

    async def load_source_policies(self, at: datetime) -> list[SourceRegistryEntry]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT * FROM fact_check_sources
                   WHERE active AND effective_from <= $1 AND (effective_to IS NULL OR effective_to > $1)""",
                at,
            )
        return [
            SourceRegistryEntry(
                source_id=row["id"],
                publisher=row["publisher"],
                normalized_pattern=row["normalized_pattern"],
                tier=SourceTier(row["tier"]),
                source_type=row["source_type"],
                active=row["active"],
                explicit_deny=row["explicit_deny"],
                trusted_claim_review=row["trusted_claim_review"],
                allowed_operations=set(_json_value(row["allowed_operations"])),
                policy_version=row["policy_version"],
                effective_from=row["effective_from"],
                effective_to=row["effective_to"],
                default_freshness_seconds=row["default_freshness_seconds"],
                reviewer_id=row["reviewer_id"],
                reviewed_at=row["reviewed_at"],
            )
            for row in rows
        ]

    async def observe_source_discovery(
        self,
        *,
        url: str,
        publisher: str,
        event: str,
        claim_hash: str | None,
        agrees_with_curated: bool | None,
        allow_auto_promotion: bool = True,
    ) -> None:
        from src.agents.fact_check import registrable_domain  # noqa: PLC0415

        domain = registrable_domain(url)
        if not domain:
            return
        pool = await self._get_pool()
        now = datetime.now(UTC)
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow("SELECT * FROM source_discoveries WHERE domain=$1 FOR UPDATE", domain)
            urls = list(dict.fromkeys([*(_json_value(row["representative_urls"]) if row else []), url]))[-5:]
            claims = list(_json_value(row["claim_hashes"]) if row else [])
            if claim_hash and claim_hash not in claims:
                claims.append(claim_hash)
            claims = claims[-1000:]
            search_delta = int(event == "search")
            extract_delta = int(event == "extract")
            comparison_delta = int(event == "comparison" and agrees_with_curated is not None)
            agreement_delta = int(event == "comparison" and agrees_with_curated is True)
            conflict_delta = int(event == "comparison" and agrees_with_curated is False)
            await connection.execute(
                """INSERT INTO source_discoveries(
                       domain,publisher,first_seen_at,last_seen_at,search_count,extract_success_count,
                       claim_hashes,curated_comparison_count,curated_agreement_count,curated_conflict_count,
                       representative_urls,status
                   ) VALUES($1,$2,$3,$3,$4,$5,$6::jsonb,$7,$8,$9,$10::jsonb,'observing')
                   ON CONFLICT(domain) DO UPDATE SET
                     publisher=EXCLUDED.publisher,last_seen_at=EXCLUDED.last_seen_at,
                     search_count=source_discoveries.search_count+EXCLUDED.search_count,
                     extract_success_count=source_discoveries.extract_success_count+EXCLUDED.extract_success_count,
                     claim_hashes=EXCLUDED.claim_hashes,
                     curated_comparison_count=source_discoveries.curated_comparison_count+EXCLUDED.curated_comparison_count,
                     curated_agreement_count=source_discoveries.curated_agreement_count+EXCLUDED.curated_agreement_count,
                     curated_conflict_count=source_discoveries.curated_conflict_count+EXCLUDED.curated_conflict_count,
                     representative_urls=EXCLUDED.representative_urls""",
                domain,
                publisher,
                now,
                search_delta,
                extract_delta,
                json.dumps(claims),
                comparison_delta,
                agreement_delta,
                conflict_delta,
                json.dumps(urls),
            )
            await connection.execute(
                """INSERT INTO source_discovery_observations(
                       id,domain,event,claim_hash,agrees_with_curated,observed_at
                   ) VALUES($1,$2,$3,$4,$5,$6)""",
                uuid4(),
                domain,
                event,
                claim_hash,
                agrees_with_curated,
                now,
            )
            current = await connection.fetchrow("SELECT * FROM source_discoveries WHERE domain=$1", domain)
            comparisons = current["curated_comparison_count"]
            agreement_rate = current["curated_agreement_count"] / comparisons if comparisons else 0.0
            conflict_rate = current["curated_conflict_count"] / comparisons if comparisons else 0.0
            eligible = (
                now - current["first_seen_at"] >= timedelta(days=30)
                and current["extract_success_count"] >= 20
                and len(_json_value(current["claim_hashes"])) >= 10
                and comparisons >= 10
                and agreement_rate >= 0.9
                and conflict_rate <= 0.05
            )
            if allow_auto_promotion and eligible and current["status"] == "observing":
                await connection.execute(
                    """INSERT INTO fact_check_sources(
                           id,publisher,normalized_pattern,tier,source_type,active,explicit_deny,
                           trusted_claim_review,allowed_operations,policy_version,effective_from,
                           default_freshness_seconds,reviewer_id,reviewed_at,created_at
                       VALUES($1,$2,$3,'B','auto_reviewed_web',true,false,false,$4::jsonb,$5,$6,21600,
                              'system-auto-promotion',$6,$6)
                       ON CONFLICT(normalized_pattern,policy_version) DO NOTHING""",
                    uuid4(),
                    publisher,
                    f"*.{domain}",
                    json.dumps(["search", "read", "compare"]),
                    f"auto-tier-b-{now.date().isoformat()}",
                    now,
                )
                await connection.execute("UPDATE source_discoveries SET status='promoted' WHERE domain=$1", domain)
            rolling = await connection.fetchrow(
                """SELECT count(*) FILTER (WHERE event='comparison') AS comparisons,
                          count(*) FILTER (WHERE event='comparison' AND agrees_with_curated=false) AS conflicts
                   FROM source_discovery_observations
                   WHERE domain=$1 AND observed_at >= $2""",
                domain,
                now - timedelta(days=30),
            )
            rolling_comparisons = int(rolling["comparisons"] or 0)
            rolling_conflict_rate = int(rolling["conflicts"] or 0) / rolling_comparisons if rolling_comparisons else 0.0
            if current["status"] == "promoted" and rolling_comparisons >= 10 and rolling_conflict_rate > 0.1:
                await connection.execute(
                    """UPDATE fact_check_sources SET active=false,effective_to=$2
                       WHERE normalized_pattern=$1 AND source_type='auto_reviewed_web' AND active""",
                    f"*.{domain}",
                    now,
                )
                await connection.execute("UPDATE source_discoveries SET status='demoted' WHERE domain=$1", domain)

    async def list_source_discoveries(self) -> list[SourceDiscoveryRecord]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch("SELECT * FROM source_discoveries ORDER BY last_seen_at DESC")
        output = []
        for row in rows:
            comparisons = row["curated_comparison_count"]
            eligible = (
                (
                    datetime.now(UTC) - row["first_seen_at"] >= timedelta(days=30)
                    and row["extract_success_count"] >= 20
                    and len(_json_value(row["claim_hashes"])) >= 10
                    and comparisons >= 10
                    and row["curated_agreement_count"] / comparisons >= 0.9
                    and row["curated_conflict_count"] / comparisons <= 0.05
                )
                if comparisons
                else False
            )
            output.append(
                SourceDiscoveryRecord(
                    domain=row["domain"],
                    publisher=row["publisher"],
                    first_seen_at=row["first_seen_at"],
                    last_seen_at=row["last_seen_at"],
                    search_count=row["search_count"],
                    extract_success_count=row["extract_success_count"],
                    independent_claim_count=len(_json_value(row["claim_hashes"])),
                    curated_comparison_count=comparisons,
                    curated_agreement_count=row["curated_agreement_count"],
                    curated_conflict_count=row["curated_conflict_count"],
                    representative_urls=list(_json_value(row["representative_urls"])),
                    status=row["status"],
                    eligible_for_auto_promotion=eligible,
                )
            )
        return output

    async def set_source_discovery_status(
        self, domain: str, status: str, *, decision: str, note: str, reviewer_id: str
    ) -> None:
        pool = await self._get_pool()
        now = datetime.now(UTC)
        async with pool.acquire() as connection, connection.transaction():
            result = await connection.execute("UPDATE source_discoveries SET status=$2 WHERE domain=$1", domain, status)
            if result == "UPDATE 0":
                return
            await connection.execute(
                """INSERT INTO source_discovery_decisions(id,domain,decision,note,reviewer_id,decided_at)
                   VALUES($1,$2,$3,$4,$5,$6)""",
                uuid4(),
                domain,
                decision,
                note,
                reviewer_id,
                now,
            )
            if status in {"demoted", "denied"}:
                await connection.execute(
                    """UPDATE fact_check_sources SET active=false,effective_to=$2
                       WHERE normalized_pattern=$1 AND active AND NOT explicit_deny""",
                    f"*.{domain}",
                    now,
                )

    async def cache_fact_check_result(self, result: FactCheckResultWrite) -> UUID:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            existing = await connection.fetchval(
                """SELECT id FROM fact_check_results
                   WHERE analysis_id=$1 AND claim_hash=$2 AND comparator_version=$3
                     AND source_policy_version=$4""",
                result.analysis_id,
                result.claim_hash,
                result.comparator_version,
                result.source_policy_version,
            )
            if existing:
                return existing
            await connection.execute(
                """INSERT INTO fact_check_results(
                       id,analysis_id,claim_hash,claim_ciphertext,language,is_temporal,claim_date_start,claim_date_end,
                       stance,evidence_refs,contradiction_refs,limitations,comparator_model,
                       comparator_version,source_policy_version,fresh_until,embedding_status,created_at,updated_at
                   ) VALUES($1,$2,$3,CASE WHEN $4::text IS NULL THEN NULL ELSE pgp_sym_encrypt($4,$5) END,
                            $6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13::jsonb,$14,$15,$16,$17,$18,$19,$19)""",
                result.result_id,
                result.analysis_id,
                result.claim_hash,
                result.normalized_claim,
                self._encryption_key,
                result.language,
                result.is_temporal,
                result.claim_date_start,
                result.claim_date_end,
                result.stance,
                json.dumps(result.evidence_refs),
                json.dumps(result.contradiction_refs),
                json.dumps(result.limitations),
                result.comparator_model,
                result.comparator_version,
                result.source_policy_version,
                result.fresh_until,
                result.embedding_status,
                result.created_at,
            )
            snapshot_ids: dict[str, UUID] = {}
            for evidence in result.evidence:
                snapshot_id = uuid4()
                row = await connection.fetchrow(
                    """INSERT INTO fact_check_evidence_snapshots(
                           id,result_id,evidence_ref,source,source_version,source_tier,policy_version,
                           canonical_url,cleaned_content,published_at,source_updated_at,effective_from,effective_to,
                           retrieved_at,temporal_compatible,proxy_penalty,content_hash,validation_status,promotion_status
                       ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'runtime')
                       ON CONFLICT(canonical_url,content_hash,source_version) DO UPDATE
                         SET retrieved_at=GREATEST(fact_check_evidence_snapshots.retrieved_at,EXCLUDED.retrieved_at)
                       RETURNING id""",
                    snapshot_id,
                    result.result_id,
                    evidence.evidence_ref,
                    evidence.source,
                    evidence.source_version,
                    evidence.source_tier.value,
                    evidence.policy_version,
                    evidence.canonical_url,
                    evidence.cleaned_content,
                    evidence.published_at,
                    evidence.source_updated_at,
                    evidence.effective_from,
                    evidence.effective_to,
                    evidence.retrieved_at,
                    evidence.temporal_compatible,
                    evidence.proxy_penalty,
                    evidence.content_hash,
                    evidence.validation_status,
                )
                snapshot_ids[evidence.evidence_ref] = row["id"]
            for chunk in result.chunks:
                snapshot_id = snapshot_ids.get(chunk.evidence_ref)
                if snapshot_id is None:
                    continue
                await connection.execute(
                    """INSERT INTO fact_check_chunks(
                           id,evidence_snapshot_id,chunk_index,cleaned_text,content_hash,source,source_version,
                           source_tier,published_at,effective_from,effective_to,retrieved_at,splitter_version
                       ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
                       ON CONFLICT(evidence_snapshot_id,chunk_index,splitter_version) DO NOTHING""",
                    chunk.chunk_ref,
                    snapshot_id,
                    chunk.index,
                    chunk.text,
                    chunk.content_hash,
                    chunk.source,
                    chunk.source_version,
                    chunk.source_tier.value,
                    chunk.published_at,
                    chunk.effective_from,
                    chunk.effective_to,
                    chunk.retrieved_at,
                    chunk.splitter_version,
                )
            if result.embedding_status == "pending":
                now = datetime.now(UTC)
                await connection.execute(
                    """INSERT INTO analysis_jobs(
                           id,analysis_id,kind,status,max_attempts,available_at,idempotency_key,created_at,updated_at
                       ) VALUES($1,$2,'reembed_fact_check_result','queued',3,$3,$4,$3,$3)
                       ON CONFLICT(idempotency_key) DO NOTHING""",
                    uuid4(),
                    result.analysis_id,
                    now,
                    f"fact-result:{result.result_id}:embed:{result.embedding_model}:{result.embedding_version}",
                )
        return result.result_id

    async def cache_corpus_record(self, record: FactCheckCorpusRecordWrite) -> UUID:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            existing = await connection.fetchval(
                """SELECT id FROM fact_check_records
                   WHERE source_id=$1 AND content_hash=$2 AND record_version=$3""",
                record.source_id,
                record.content_hash,
                record.record_version,
            )
            if existing:
                return existing
            await connection.execute(
                """INSERT INTO fact_check_records(
                       id,source_id,source_url,publisher,normalized_claim,stance,language,
                       claim_date_start,claim_date_end,published_at,source_updated_at,
                       effective_from,effective_to,retrieved_at,ingested_at,fresh_until,
                       temporal_proxy,temporal_penalty,content_hash,record_version,
                       ingestion_provenance,policy_version,promotion_status
                   ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                            $17,$18,$19,$20,$21,$22,$23)""",
                record.record_id,
                record.source_id,
                _safe_url_or_text(record.source_url),
                record.publisher,
                record.normalized_claim,
                record.stance,
                record.language,
                record.claim_date_start,
                record.claim_date_end,
                record.published_at,
                record.source_updated_at,
                record.effective_from,
                record.effective_to,
                record.retrieved_at,
                datetime.now(UTC),
                record.fresh_until,
                record.temporal_proxy,
                record.temporal_penalty,
                record.content_hash,
                record.record_version,
                record.ingestion_provenance,
                record.policy_version,
                record.promotion_status,
            )
        return record.record_id

    async def promote_corpus_record(self, record_id: UUID, reviewer_id: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """SELECT r.id,r.promotion_status,s.tier,s.explicit_deny
                   FROM fact_check_records r JOIN fact_check_sources s ON s.id=r.source_id
                   WHERE r.id=$1 FOR UPDATE OF r""",
                record_id,
            )
            if row is None or row["explicit_deny"] or row["tier"] not in {SourceTier.A.value, SourceTier.B.value}:
                return False
            if row["promotion_status"] == "trusted":
                return True
            await connection.execute(
                """UPDATE fact_check_records SET promotion_status='trusted',promoted_by=$2,promoted_at=now()
                   WHERE id=$1""",
                record_id,
                reviewer_id,
            )
        return True

    async def search_fact_check_corpus(
        self,
        query: str,
        *,
        language: str,
        claim_date_start: datetime | None = None,
        claim_date_end: datetime | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """WITH eligible AS (
                     SELECT r.*,s.tier AS source_tier FROM fact_check_records r
                     JOIN fact_check_sources s ON s.id=r.source_id
                     WHERE r.promotion_status='trusted' AND r.language=$2
                       AND s.active AND NOT s.explicit_deny
                       AND (r.fresh_until IS NULL OR r.fresh_until > now())
                       AND ($3::timestamptz IS NULL OR r.published_at <= coalesce($4,$3))
                       AND ($4::timestamptz IS NULL OR coalesce(r.effective_to,r.source_updated_at) >= $3)
                   )
                   SELECT r.*,
                          ts_rank_cd(search_vector,websearch_to_tsquery('simple',$1)) AS lexical_score
                   FROM eligible r
                   WHERE search_vector @@ websearch_to_tsquery('simple',$1)
                   ORDER BY lexical_score DESC,r.published_at DESC LIMIT $5""",
                query,
                language,
                claim_date_start,
                claim_date_end,
                min(limit, 20),
            )
        return [dict(row) for row in rows]

    async def get_reembedding_claim(self, job: DurableJob) -> tuple[UUID, str] | None:
        parts = job.idempotency_key.split(":")
        if len(parts) < 3 or parts[0] != "fact-result":
            return None
        try:
            result_id = UUID(parts[1])
        except ValueError:
            return None
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT id,pgp_sym_decrypt(claim_ciphertext,$2) AS normalized_claim
                   FROM fact_check_results WHERE id=$1 AND embedding_status='pending'""",
                result_id,
                self._encryption_key,
            )
        if row is None or not row["normalized_claim"]:
            return None
        return row["id"], row["normalized_claim"]

    async def complete_reembedding(
        self,
        result_id: UUID,
        *,
        vector: list[float],
        model: str,
        model_version: str,
        embedding_version: str,
        embedded_at: datetime,
    ) -> None:
        if len(vector) != 1536:
            raise ValueError("fact-check embeddings must contain 1536 dimensions")
        pool = await self._get_pool()
        vector_literal = "[" + ",".join(str(value) for value in vector) + "]"
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO fact_check_result_embeddings(
                       result_id,embedding_version,model,model_version,dimensions,embedding,embedded_at
                   ) VALUES($1,$2,$3,$4,1536,$5::double precision[],$6)
                   ON CONFLICT(result_id,embedding_version) DO NOTHING""",
                result_id,
                embedding_version,
                model,
                model_version,
                vector_literal,
                embedded_at,
            )
            await connection.execute(
                """UPDATE fact_check_results SET embedding_status='complete',updated_at=$2
                   WHERE id=$1 AND embedding_status='pending'""",
                result_id,
                embedded_at,
            )

    async def promote_evidence(self, result_id: UUID, evidence_ref: str, reviewer_id: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """SELECT e.id,e.source_tier,e.validation_status,e.promotion_status
                   FROM fact_check_evidence_snapshots e
                   WHERE e.result_id=$1 AND e.evidence_ref=$2 FOR UPDATE""",
                result_id,
                evidence_ref,
            )
            if (
                row is None
                or row["source_tier"] not in {SourceTier.A.value, SourceTier.B.value}
                or row["validation_status"] != "validated"
            ):
                return False
            if row["promotion_status"] == "trusted":
                return True
            await connection.execute(
                """UPDATE fact_check_evidence_snapshots
                   SET promotion_status='trusted',promoted_by=$2,promoted_at=now() WHERE id=$1""",
                row["id"],
                reviewer_id,
            )
        return True

    async def record_usage(self, entry: UsageLedgerEntry) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            await connection.execute(
                """INSERT INTO tool_usage(
                       id,analysis_id,step_id,provider,model,provider_version,operation,units,
                       input_tokens,output_tokens,estimated_cost,latency_ms,cache_status,outcome,
                       http_class,observed_at,quota_used
                   ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
                   ON CONFLICT(id) DO NOTHING""",
                entry.usage_id,
                entry.analysis_id,
                entry.step_id,
                entry.provider,
                entry.model,
                entry.provider_version,
                entry.operation,
                entry.units,
                entry.input_tokens,
                entry.output_tokens,
                entry.estimated_cost_usd,
                entry.latency_ms,
                entry.cache_status,
                entry.outcome,
                entry.http_class,
                entry.observed_at,
                entry.quota_used,
            )

    async def record_campaign(self, campaign: CampaignWrite) -> CampaignDetailV3:
        if len({item[0] for item in campaign.members}) < 3:
            raise ValueError("campaign requires at least three distinct analyses")
        pool = await self._get_pool()
        now = datetime.now(UTC)
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO campaign_clusters(
                       id,hypothesis,window_started_at,window_ended_at,similarity_threshold,
                       minimum_analyses,clustering_version,reviewer_status,created_at,updated_at
                   ) VALUES($1,$2,$3,$4,$5,$6,$7,'pending_review',$8,$8)
                   ON CONFLICT(id) DO NOTHING""",
                campaign.campaign_id,
                campaign.hypothesis,
                campaign.window_started_at,
                campaign.window_ended_at,
                campaign.similarity_threshold,
                campaign.minimum_analyses,
                campaign.clustering_version,
                now,
            )
            for analysis_id, match_kind, similarity, refs in campaign.members:
                await connection.execute(
                    """INSERT INTO campaign_members(
                           campaign_id,analysis_id,match_kind,similarity,evidence_refs
                       ) VALUES($1,$2,$3,$4,$5::jsonb) ON CONFLICT DO NOTHING""",
                    campaign.campaign_id,
                    analysis_id,
                    match_kind,
                    similarity,
                    json.dumps(refs),
                )
            signals = dict(campaign.aggregate_signals)
            signals.update({f"domain:{value}": 1 for value in campaign.registrable_domains})
            signals.update({f"redirect:{value}": 1 for value in campaign.redirect_targets})
            for signal, count in signals.items():
                await connection.execute(
                    """INSERT INTO campaign_signals(campaign_id,signal,signal_count) VALUES($1,$2,$3)
                       ON CONFLICT(campaign_id,signal) DO UPDATE
                       SET signal_count=GREATEST(campaign_signals.signal_count,EXCLUDED.signal_count)""",
                    campaign.campaign_id,
                    signal,
                    count,
                )
        detail = await self.get_campaign(campaign.campaign_id)
        if detail is None:
            raise RuntimeError("campaign persistence failed")
        return detail

    async def add_campaign_observation(self, observation: Any) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """INSERT INTO campaign_observations(
                       analysis_id,observed_at,registrable_domains,redirect_targets,evidence_refs
                   ) VALUES($1,$2,$3::jsonb,$4::jsonb,$5::jsonb) ON CONFLICT(analysis_id) DO NOTHING""",
                UUID(observation.analysis_id),
                observation.observed_at,
                json.dumps(observation.registrable_domains),
                json.dumps(observation.redirect_targets),
                json.dumps(observation.evidence_refs),
            )
            for feature in observation.claim_features:
                if len(feature.vector) != 1536:
                    continue
                await connection.execute(
                    """INSERT INTO campaign_claim_features(analysis_id,feature_ref,embedding)
                       VALUES($1,$2,$3::double precision[]) ON CONFLICT DO NOTHING""",
                    UUID(observation.analysis_id),
                    feature.feature_ref,
                    feature.vector,
                )

    async def recent_campaign_observations(self, since: datetime):
        from src.agents.campaign import CampaignObservation, ClaimFeature

        pool = await self._get_pool()
        async with pool.acquire() as connection:
            rows = await connection.fetch(
                """SELECT analysis_id,observed_at,registrable_domains,redirect_targets,evidence_refs
                   FROM campaign_observations WHERE observed_at >= $1 ORDER BY observed_at""",
                since,
            )
            features = await connection.fetch(
                """SELECT f.analysis_id,f.feature_ref,f.embedding
                   FROM campaign_claim_features f JOIN campaign_observations o ON o.analysis_id=f.analysis_id
                   WHERE o.observed_at >= $1""",
                since,
            )
        by_analysis: dict[UUID, list[ClaimFeature]] = {}
        for row in features:
            values = tuple(float(value) for value in row["embedding"])
            by_analysis.setdefault(row["analysis_id"], []).append(ClaimFeature(row["feature_ref"], values))
        return [
            CampaignObservation(
                analysis_id=str(row["analysis_id"]),
                observed_at=row["observed_at"],
                registrable_domains=tuple(_json_value(row["registrable_domains"])),
                redirect_targets=tuple(_json_value(row["redirect_targets"])),
                claim_features=tuple(by_analysis.get(row["analysis_id"], ())),
                evidence_refs=tuple(_json_value(row["evidence_refs"])),
            )
            for row in rows
        ]

    async def list_campaigns(
        self, reviewer_status: CampaignReviewerStatus | None, limit: int, offset: int
    ) -> tuple[list[CampaignSummaryV3], int]:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            where, args = (
                ("", []) if reviewer_status is None else ("WHERE c.reviewer_status=$1", [reviewer_status.value])
            )
            limit_pos, offset_pos = len(args) + 1, len(args) + 2
            rows = await connection.fetch(
                f"""SELECT c.*,count(DISTINCT m.analysis_id) AS analysis_count
                    FROM campaign_clusters c LEFT JOIN campaign_members m ON m.campaign_id=c.id
                    {where} GROUP BY c.id ORDER BY c.created_at DESC
                    LIMIT ${limit_pos} OFFSET ${offset_pos}""",
                *args,
                limit,
                offset,
            )
            total = await connection.fetchval(f"SELECT count(*) FROM campaign_clusters c {where}", *args)
            signals = await self._campaign_signals(connection, [row["id"] for row in rows])
        return [self._campaign_summary(row, signals[row["id"]]) for row in rows], int(total)

    async def get_campaign(self, campaign_id: UUID) -> CampaignDetailV3 | None:
        pool = await self._get_pool()
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT c.*,count(DISTINCT m.analysis_id) AS analysis_count
                   FROM campaign_clusters c LEFT JOIN campaign_members m ON m.campaign_id=c.id
                   WHERE c.id=$1 GROUP BY c.id""",
                campaign_id,
            )
            if row is None:
                return None
            signals = (await self._campaign_signals(connection, [campaign_id]))[campaign_id]
            members = await connection.fetch(
                "SELECT evidence_refs FROM campaign_members WHERE campaign_id=$1", campaign_id
            )
        domains = [signal.removeprefix("domain:") for signal, _ in signals if signal.startswith("domain:")]
        redirects = [signal.removeprefix("redirect:") for signal, _ in signals if signal.startswith("redirect:")]
        public_signals = [
            (signal, count) for signal, count in signals if not signal.startswith(("domain:", "redirect:"))
        ]
        evidence_refs = list(dict.fromkeys(ref for member in members for ref in _json_value(member["evidence_refs"])))
        return CampaignDetailV3(
            **self._campaign_summary(row, public_signals).model_dump(),
            evidence_refs=evidence_refs,
            registrable_domains=domains,
            redirect_targets=redirects,
            reviewer_id=row["reviewer_id"],
            review_note=row["review_note"],
            reviewed_at=row["reviewed_at"],
        )

    async def review_campaign(
        self, campaign_id: UUID, status: CampaignReviewerStatus, note: str, reviewer_id: str
    ) -> CampaignDetailV3 | None:
        if status is CampaignReviewerStatus.PENDING_REVIEW:
            raise ValueError("campaign review must be confirmed or rejected")
        pool = await self._get_pool()
        now = datetime.now(UTC)
        async with pool.acquire() as connection:
            updated = await connection.execute(
                """UPDATE campaign_clusters SET reviewer_status=$2,reviewer_id=$3,review_note=$4,
                          reviewed_at=$5,updated_at=$5,version=version+1
                   WHERE id=$1 AND reviewer_status='pending_review'""",
                campaign_id,
                status.value,
                reviewer_id,
                note.strip(),
                now,
            )
        if updated != "UPDATE 1":
            existing = await self.get_campaign(campaign_id)
            if existing is None:
                return None
            raise PlatformError(
                status_code=409,
                code=ErrorCode.INTERNAL_ERROR,
                message="Campaign was already reviewed.",
                retryable=False,
            )
        return await self.get_campaign(campaign_id)

    @staticmethod
    async def _campaign_signals(connection, campaign_ids: list[UUID]) -> dict[UUID, list[tuple[str, int]]]:
        result: dict[UUID, list[tuple[str, int]]] = {item: [] for item in campaign_ids}
        if not campaign_ids:
            return result
        rows = await connection.fetch(
            "SELECT campaign_id,signal,signal_count FROM campaign_signals WHERE campaign_id=ANY($1::uuid[])",
            campaign_ids,
        )
        for row in rows:
            result[row["campaign_id"]].append((row["signal"], row["signal_count"]))
        return result

    @staticmethod
    def _campaign_summary(row, signals: list[tuple[str, int]]) -> CampaignSummaryV3:
        return CampaignSummaryV3(
            campaign_id=row["id"],
            hypothesis=row["hypothesis"],
            window_started_at=row["window_started_at"],
            window_ended_at=row["window_ended_at"],
            analysis_count=row["analysis_count"],
            aggregate_signals=[
                CampaignAggregateSignalV3(signal=signal, count=count)
                for signal, count in signals
                if not signal.startswith(("domain:", "redirect:"))
            ],
            reviewer_status=CampaignReviewerStatus(row["reviewer_status"]),
            clustering_version=row["clustering_version"],
        )



__all__ = ["PostgresWave2RepositoryMixin"]

