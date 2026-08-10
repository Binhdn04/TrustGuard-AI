"""Create campaign hypotheses and retained artifact metadata."""

from alembic import op

revision = "0006_campaign_artifacts"
down_revision = "0005_fact_check_corpus"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE analyses ADD COLUMN content_expires_at timestamptz;
        ALTER TABLE analyses ADD COLUMN content_deleted_at timestamptz;
        UPDATE analyses SET content_expires_at=created_at+interval '30 days'
          WHERE content_expires_at IS NULL;
        ALTER TABLE analyses ALTER COLUMN content_expires_at SET NOT NULL;
        CREATE INDEX ix_analyses_content_expiry ON analyses(content_expires_at)
          WHERE content_deleted_at IS NULL;

        CREATE TABLE campaign_clusters (
          id uuid PRIMARY KEY,
          hypothesis text NOT NULL,
          window_started_at timestamptz NOT NULL,
          window_ended_at timestamptz NOT NULL,
          similarity_threshold numeric(5,4) NOT NULL,
          minimum_analyses integer NOT NULL CHECK(minimum_analyses >= 3),
          clustering_version text NOT NULL,
          reviewer_status text NOT NULL CONSTRAINT ck_campaign_reviewer_status
            CHECK(reviewer_status IN ('pending_review','confirmed','rejected')),
          reviewer_id text,
          review_note text,
          reviewed_at timestamptz,
          created_at timestamptz NOT NULL,
          updated_at timestamptz NOT NULL,
          version integer NOT NULL DEFAULT 1,
          CONSTRAINT ck_campaign_window CHECK(window_ended_at >= window_started_at),
          CONSTRAINT ck_campaign_review CHECK (
            (reviewer_status='pending_review' AND reviewer_id IS NULL AND review_note IS NULL AND reviewed_at IS NULL)
            OR (reviewer_status<>'pending_review' AND reviewer_id IS NOT NULL AND review_note IS NOT NULL
                AND reviewed_at IS NOT NULL)
          )
        );
        CREATE INDEX ix_campaign_status_created ON campaign_clusters(reviewer_status,created_at);
        CREATE INDEX ix_campaign_window ON campaign_clusters(window_started_at,window_ended_at);

        ALTER TABLE admin_actions ADD CONSTRAINT fk_admin_actions_campaign
          FOREIGN KEY(campaign_id) REFERENCES campaign_clusters(id) ON DELETE RESTRICT;

        CREATE TABLE campaign_members (
          campaign_id uuid NOT NULL REFERENCES campaign_clusters(id) ON DELETE CASCADE,
          analysis_id uuid NOT NULL REFERENCES analyses(id) ON DELETE RESTRICT,
          match_kind text NOT NULL,
          similarity numeric(5,4),
          evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
          PRIMARY KEY(campaign_id,analysis_id)
        );
        CREATE INDEX ix_campaign_members_analysis ON campaign_members(analysis_id);

        CREATE TABLE campaign_signals (
          campaign_id uuid NOT NULL REFERENCES campaign_clusters(id) ON DELETE CASCADE,
          signal text NOT NULL,
          signal_count integer NOT NULL CHECK(signal_count > 0),
          PRIMARY KEY(campaign_id,signal)
        );

        CREATE TABLE artifacts (
          id uuid PRIMARY KEY,
          analysis_id uuid NOT NULL REFERENCES analyses(id) ON DELETE RESTRICT,
          owner_id text NOT NULL,
          storage_key text NOT NULL UNIQUE,
          media_type text NOT NULL,
          size_bytes bigint NOT NULL CHECK(size_bytes >= 0),
          sha256 text NOT NULL CHECK(sha256 ~ '^[a-f0-9]{64}$'),
          created_at timestamptz NOT NULL,
          expires_at timestamptz NOT NULL,
          deleted_at timestamptz,
          CONSTRAINT ck_artifact_expiry CHECK(expires_at > created_at)
        );
        CREATE INDEX ix_artifacts_expiry ON artifacts(expires_at) WHERE deleted_at IS NULL;
        CREATE INDEX ix_artifacts_owner_created ON artifacts(owner_id,created_at DESC);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE artifacts, campaign_signals, campaign_members;
        ALTER TABLE admin_actions DROP CONSTRAINT fk_admin_actions_campaign;
        DROP TABLE campaign_clusters;
        DROP INDEX ix_analyses_content_expiry;
        ALTER TABLE analyses DROP COLUMN content_deleted_at;
        ALTER TABLE analyses DROP COLUMN content_expires_at;
        """
    )
