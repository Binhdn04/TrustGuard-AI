"""Create Wave 2 review lifecycle, Source Registry, and fact-check corpus."""

from alembic import op

revision = "0005_fact_check_corpus"
down_revision = "0004_review_queue"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE tool_usage ADD COLUMN quota_used numeric(12,6);

        CREATE TABLE appeals (
          id uuid PRIMARY KEY,
          analysis_id uuid NOT NULL REFERENCES analyses(id) ON DELETE RESTRICT,
          owner_id text NOT NULL,
          reason text NOT NULL,
          comment text,
          status text NOT NULL CONSTRAINT ck_appeals_status
            CHECK(status IN ('submitted','under_review','resolved')),
          outcome text CONSTRAINT ck_appeals_outcome
            CHECK(outcome IS NULL OR outcome IN ('uphold','overturn','inconclusive')),
          resolution_note text,
          created_at timestamptz NOT NULL,
          updated_at timestamptz NOT NULL,
          resolved_at timestamptz,
          version integer NOT NULL DEFAULT 1,
          CONSTRAINT ck_appeals_resolution CHECK (
            (status = 'resolved' AND outcome IS NOT NULL AND resolution_note IS NOT NULL AND resolved_at IS NOT NULL)
            OR (status <> 'resolved' AND outcome IS NULL AND resolution_note IS NULL AND resolved_at IS NULL)
          )
        );
        CREATE UNIQUE INDEX uq_appeals_active_owner_analysis
          ON appeals(analysis_id,owner_id) WHERE status <> 'resolved';
        CREATE INDEX ix_appeals_owner_created ON appeals(owner_id,created_at DESC);
        CREATE INDEX ix_appeals_status_created ON appeals(status,created_at);

        CREATE TABLE admin_actions (
          id uuid PRIMARY KEY,
          analysis_id uuid REFERENCES analyses(id) ON DELETE RESTRICT,
          campaign_id uuid,
          action text NOT NULL CONSTRAINT ck_admin_actions_action
            CHECK(action IN ('add_to_blacklist','disable_blacklist','block_domain','publish_broad_warning','none')),
          canonical_target text,
          status text NOT NULL CONSTRAINT ck_admin_actions_status
            CHECK(status IN ('pending_review','approved','rejected','executed','failed')),
          evidence_snapshot jsonb NOT NULL DEFAULT '[]'::jsonb,
          proposed_at timestamptz NOT NULL,
          reviewer_id text,
          review_note text,
          reviewed_at timestamptz,
          executed_at timestamptz,
          approved_decision_id uuid,
          version integer NOT NULL DEFAULT 1,
          CONSTRAINT ck_admin_actions_target CHECK (
            (action = 'none' AND canonical_target IS NULL)
            OR (action <> 'none' AND canonical_target IS NOT NULL AND jsonb_array_length(evidence_snapshot) > 0)
          ),
          CONSTRAINT ck_admin_actions_review CHECK (
            (status = 'pending_review' AND reviewer_id IS NULL AND review_note IS NULL AND reviewed_at IS NULL)
            OR (status <> 'pending_review' AND reviewer_id IS NOT NULL AND review_note IS NOT NULL AND reviewed_at IS NOT NULL)
          ),
          CONSTRAINT ck_admin_actions_approval CHECK (
            status IN ('pending_review','rejected') OR approved_decision_id IS NOT NULL)
        );
        CREATE INDEX ix_admin_actions_status_proposed ON admin_actions(status,proposed_at);
        CREATE INDEX ix_admin_actions_target ON admin_actions(action,canonical_target);

        CREATE TABLE review_decisions (
          id uuid PRIMARY KEY,
          analysis_id uuid REFERENCES analyses(id) ON DELETE RESTRICT,
          appeal_id uuid REFERENCES appeals(id) ON DELETE RESTRICT,
          action_id uuid REFERENCES admin_actions(id) ON DELETE RESTRICT,
          reviewer_id text NOT NULL,
          decision text NOT NULL,
          outcome text,
          action text,
          evidence_snapshot jsonb NOT NULL DEFAULT '[]'::jsonb,
          note text NOT NULL,
          decided_at timestamptz NOT NULL,
          predecessor_decision_id uuid REFERENCES review_decisions(id) ON DELETE RESTRICT,
          CONSTRAINT ck_review_decisions_resource CHECK (
            num_nonnulls(appeal_id,action_id) = 1
          )
        );
        CREATE INDEX ix_review_decisions_appeal ON review_decisions(appeal_id,decided_at DESC);
        CREATE INDEX ix_review_decisions_action ON review_decisions(action_id,decided_at DESC);
        CREATE INDEX ix_review_decisions_time ON review_decisions(decided_at DESC);
        ALTER TABLE admin_actions ADD CONSTRAINT fk_admin_actions_approved_decision
          FOREIGN KEY(approved_decision_id) REFERENCES review_decisions(id) ON DELETE RESTRICT;

        CREATE TABLE blacklist_entries (
          id uuid PRIMARY KEY,
          canonical_domain text NOT NULL UNIQUE,
          active boolean NOT NULL,
          enabling_decision_id uuid NOT NULL REFERENCES review_decisions(id) ON DELETE RESTRICT,
          disabling_decision_id uuid REFERENCES review_decisions(id) ON DELETE RESTRICT,
          created_at timestamptz NOT NULL,
          updated_at timestamptz NOT NULL,
          version integer NOT NULL DEFAULT 1,
          CONSTRAINT ck_blacklist_disable_provenance CHECK (active OR disabling_decision_id IS NOT NULL)
        );
        CREATE INDEX ix_blacklist_active_domain ON blacklist_entries(canonical_domain) WHERE active;
        CREATE INDEX ix_blacklist_updated ON blacklist_entries(updated_at DESC);

        CREATE TABLE user_notifications (
          id uuid PRIMARY KEY,
          owner_id text NOT NULL,
          resource_type text NOT NULL,
          resource_id uuid NOT NULL,
          event_type text NOT NULL,
          payload jsonb NOT NULL DEFAULT '{}'::jsonb,
          created_at timestamptz NOT NULL,
          read_at timestamptz,
          idempotency_key text NOT NULL UNIQUE
        );
        CREATE INDEX ix_notifications_owner_created ON user_notifications(owner_id,created_at DESC);

        CREATE TABLE fact_check_sources (
          id uuid PRIMARY KEY,
          publisher text NOT NULL,
          normalized_pattern text NOT NULL,
          tier text NOT NULL CONSTRAINT ck_fact_check_sources_tier
            CHECK(tier IN ('A','B','C','UNTRUSTED')),
          source_type text NOT NULL,
          active boolean NOT NULL DEFAULT true,
          explicit_deny boolean NOT NULL DEFAULT false,
          trusted_claim_review boolean NOT NULL DEFAULT false,
          allowed_operations jsonb NOT NULL DEFAULT '[]'::jsonb,
          policy_version text NOT NULL,
          effective_from timestamptz NOT NULL,
          effective_to timestamptz,
          default_freshness_seconds integer NOT NULL CHECK(default_freshness_seconds > 0),
          reviewer_id text NOT NULL,
          reviewed_at timestamptz NOT NULL,
          created_at timestamptz NOT NULL,
          CONSTRAINT ck_fact_check_sources_interval CHECK (
            effective_to IS NULL OR effective_to > effective_from
          ),
          UNIQUE(normalized_pattern,policy_version)
        );
        CREATE INDEX ix_fact_check_sources_active_tier ON fact_check_sources(active,tier);
        CREATE INDEX ix_fact_check_sources_effective ON fact_check_sources(effective_from,effective_to);
        INSERT INTO fact_check_sources(
          id,publisher,normalized_pattern,tier,source_type,active,explicit_deny,
          trusted_claim_review,allowed_operations,policy_version,effective_from,
          default_freshness_seconds,reviewer_id,reviewed_at,created_at
        ) VALUES(
          '00000000-0000-4000-8000-000000000005','Vietnam government','*.gov.vn','A',
          'government',true,false,false,'["search","read","compare","promote"]'::jsonb,
          'source-policy-v1','2026-01-01T00:00:00Z',21600,'system-bootstrap',now(),now()
        );

        CREATE TABLE fact_check_records (
          id uuid PRIMARY KEY,
          source_id uuid NOT NULL REFERENCES fact_check_sources(id) ON DELETE RESTRICT,
          source_url text NOT NULL,
          publisher text NOT NULL,
          normalized_claim text NOT NULL,
          stance text NOT NULL,
          language text NOT NULL,
          claim_date_start timestamptz,
          claim_date_end timestamptz,
          published_at timestamptz NOT NULL,
          source_updated_at timestamptz NOT NULL,
          effective_from timestamptz,
          effective_to timestamptz,
          retrieved_at timestamptz NOT NULL,
          ingested_at timestamptz NOT NULL,
          fresh_until timestamptz,
          temporal_proxy boolean NOT NULL DEFAULT false,
          temporal_penalty numeric(5,4) NOT NULL DEFAULT 0,
          content_hash text NOT NULL,
          record_version text NOT NULL,
          ingestion_provenance text NOT NULL,
          policy_version text NOT NULL,
          promotion_status text NOT NULL CONSTRAINT ck_fact_check_records_promotion
            CHECK(promotion_status IN ('runtime','pending_review','trusted','rejected')),
          promoted_by text,
          promoted_at timestamptz,
          search_vector tsvector GENERATED ALWAYS AS (
            to_tsvector('simple', coalesce(normalized_claim,'') || ' ' || coalesce(publisher,''))
          ) STORED,
          CONSTRAINT ck_fact_check_records_dates CHECK (
            claim_date_end IS NULL OR claim_date_start IS NULL OR claim_date_end >= claim_date_start
          ),
          UNIQUE(source_id,content_hash,record_version)
        );
        CREATE INDEX ix_fact_check_records_search ON fact_check_records USING gin(search_vector);
        CREATE INDEX ix_fact_check_records_temporal ON fact_check_records(claim_date_start,claim_date_end);
        CREATE INDEX ix_fact_check_records_promotion ON fact_check_records(promotion_status,ingested_at);

        CREATE TABLE fact_check_embeddings (
          record_id uuid NOT NULL REFERENCES fact_check_records(id) ON DELETE CASCADE,
          embedding_version text NOT NULL,
          model text NOT NULL,
          model_version text NOT NULL,
          dimensions integer NOT NULL CHECK(dimensions = 1536),
          embedding vector(1536) NOT NULL,
          embedded_at timestamptz NOT NULL,
          PRIMARY KEY(record_id,embedding_version)
        );
        CREATE INDEX ix_fact_check_embeddings_model
          ON fact_check_embeddings(model,model_version,dimensions,embedding_version);
        CREATE INDEX ix_fact_check_embeddings_cosine
          ON fact_check_embeddings USING hnsw(embedding vector_cosine_ops);

        CREATE TABLE fact_check_results (
          id uuid PRIMARY KEY,
          analysis_id uuid REFERENCES analyses(id) ON DELETE RESTRICT,
          claim_hash text NOT NULL,
          claim_ciphertext bytea,
          language text NOT NULL,
          is_temporal boolean NOT NULL,
          claim_date_start timestamptz,
          claim_date_end timestamptz,
          stance text NOT NULL,
          evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
          contradiction_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
          limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
          comparator_model text NOT NULL,
          comparator_version text NOT NULL,
          source_policy_version text NOT NULL,
          fresh_until timestamptz,
          embedding_status text NOT NULL CONSTRAINT ck_fact_check_results_embedding
            CHECK(embedding_status IN ('complete','pending','not_configured')),
          created_at timestamptz NOT NULL,
          updated_at timestamptz NOT NULL,
          CONSTRAINT ck_fact_check_results_dates CHECK (
            claim_date_end IS NULL OR claim_date_start IS NULL OR claim_date_end >= claim_date_start
          )
        );
        CREATE INDEX ix_fact_check_results_claim ON fact_check_results(claim_hash,created_at DESC);
        CREATE INDEX ix_fact_check_results_dates ON fact_check_results(claim_date_start,claim_date_end);
        CREATE INDEX ix_fact_check_results_fresh ON fact_check_results(fresh_until);
        CREATE INDEX ix_fact_check_results_pending ON fact_check_results(created_at)
          WHERE embedding_status='pending';
        CREATE UNIQUE INDEX uq_fact_check_results_runtime
          ON fact_check_results(analysis_id,claim_hash,comparator_version,source_policy_version);

        CREATE TABLE fact_check_result_embeddings (
          result_id uuid NOT NULL REFERENCES fact_check_results(id) ON DELETE CASCADE,
          embedding_version text NOT NULL,
          model text NOT NULL,
          model_version text NOT NULL,
          dimensions integer NOT NULL CHECK(dimensions = 1536),
          embedding vector(1536) NOT NULL,
          embedded_at timestamptz NOT NULL,
          PRIMARY KEY(result_id,embedding_version)
        );
        CREATE INDEX ix_fact_check_result_embeddings_cosine
          ON fact_check_result_embeddings USING hnsw(embedding vector_cosine_ops);

        CREATE TABLE fact_check_evidence_snapshots (
          id uuid PRIMARY KEY,
          result_id uuid NOT NULL REFERENCES fact_check_results(id) ON DELETE CASCADE,
          evidence_ref text NOT NULL,
          source text NOT NULL,
          source_version text NOT NULL,
          source_tier text NOT NULL,
          policy_version text NOT NULL,
          canonical_url text NOT NULL,
          cleaned_content text NOT NULL,
          published_at timestamptz,
          source_updated_at timestamptz,
          effective_from timestamptz,
          effective_to timestamptz,
          retrieved_at timestamptz NOT NULL,
          temporal_compatible boolean NOT NULL,
          proxy_penalty numeric(5,4) NOT NULL DEFAULT 0,
          content_hash text NOT NULL,
          validation_status text NOT NULL CONSTRAINT ck_evidence_validation
            CHECK(validation_status IN ('unreviewed','validated','rejected')),
          promotion_status text NOT NULL CONSTRAINT ck_evidence_promotion
            CHECK(promotion_status IN ('runtime','pending_review','trusted','rejected')),
          promoted_by text,
          promoted_at timestamptz,
          UNIQUE(result_id,evidence_ref),
          UNIQUE(canonical_url,content_hash,source_version)
        );
        CREATE INDEX ix_evidence_snapshots_result ON fact_check_evidence_snapshots(result_id);
        CREATE INDEX ix_evidence_snapshots_source_time
          ON fact_check_evidence_snapshots(source,retrieved_at);
        CREATE INDEX ix_evidence_snapshots_promotion
          ON fact_check_evidence_snapshots(promotion_status,retrieved_at);

        CREATE TABLE fact_check_chunks (
          id text PRIMARY KEY,
          evidence_snapshot_id uuid NOT NULL REFERENCES fact_check_evidence_snapshots(id) ON DELETE CASCADE,
          chunk_index integer NOT NULL CHECK(chunk_index >= 0),
          cleaned_text text NOT NULL,
          content_hash text NOT NULL,
          source text NOT NULL,
          source_version text NOT NULL,
          source_tier text NOT NULL,
          published_at timestamptz,
          effective_from timestamptz,
          effective_to timestamptz,
          retrieved_at timestamptz NOT NULL,
          splitter_version text NOT NULL,
          UNIQUE(evidence_snapshot_id,chunk_index,splitter_version)
        );
        CREATE INDEX ix_fact_check_chunks_snapshot ON fact_check_chunks(evidence_snapshot_id,chunk_index);
        CREATE INDEX ix_fact_check_chunks_hash ON fact_check_chunks(content_hash);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE fact_check_chunks, fact_check_evidence_snapshots,
          fact_check_result_embeddings, fact_check_results,
          fact_check_embeddings, fact_check_records, fact_check_sources,
          user_notifications, blacklist_entries;
        ALTER TABLE admin_actions DROP CONSTRAINT fk_admin_actions_approved_decision;
        DROP TABLE review_decisions, admin_actions, appeals;
        ALTER TABLE tool_usage DROP COLUMN quota_used;
        """
    )
