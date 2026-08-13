"""Add explainable v4 security memory and reviewer-gated campaigns."""

from alembic import op

revision = "0014_security_memory_campaigns"
down_revision = "0013_security_hitl_actions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE security_memory (
      id uuid PRIMARY KEY,
      analysis_id uuid NOT NULL UNIQUE REFERENCES security_analyses(id) ON DELETE RESTRICT,
      record jsonb NOT NULL,
      admin_verdict text NOT NULL CHECK(admin_verdict IN ('unreviewed','suspicious','malicious','safe','false_positive')),
      first_seen_at timestamptz NOT NULL,
      last_seen_at timestamptz NOT NULL,
      report_count integer NOT NULL DEFAULT 0 CHECK(report_count >= 0),
      fingerprint_version text NOT NULL,
      risk_policy_version text NOT NULL,
      CONSTRAINT ck_security_memory_seen CHECK(last_seen_at >= first_seen_at)
    );
    CREATE INDEX ix_security_memory_seen ON security_memory(last_seen_at DESC);
    CREATE INDEX ix_security_memory_verdict_seen ON security_memory(admin_verdict,last_seen_at DESC);

    CREATE TABLE security_memory_audit (
      id uuid PRIMARY KEY,
      memory_id uuid NOT NULL REFERENCES security_memory(id) ON DELETE RESTRICT,
      record jsonb NOT NULL,
      occurred_at timestamptz NOT NULL
    );
    CREATE INDEX ix_security_memory_audit_record ON security_memory_audit(memory_id,occurred_at);

    CREATE TABLE security_campaigns_v4 (
      id uuid PRIMARY KEY,
      record jsonb NOT NULL,
      reviewer_status text NOT NULL CHECK(reviewer_status IN ('pending_review','confirmed','rejected')),
      window_started_at timestamptz NOT NULL,
      window_ended_at timestamptz NOT NULL,
      clustering_version text NOT NULL,
      reviewer_id text,
      review_note text,
      reviewed_at timestamptz,
      created_at timestamptz NOT NULL,
      CONSTRAINT ck_security_campaign_window CHECK(window_ended_at >= window_started_at),
      CONSTRAINT ck_security_campaign_review CHECK(
        (reviewer_status='pending_review' AND reviewer_id IS NULL AND review_note IS NULL AND reviewed_at IS NULL)
        OR (reviewer_status IN ('confirmed','rejected') AND reviewer_id IS NOT NULL AND review_note IS NOT NULL AND reviewed_at IS NOT NULL)
      )
    );
    CREATE INDEX ix_security_campaign_status_window
      ON security_campaigns_v4(reviewer_status,window_ended_at DESC);

    CREATE TABLE security_campaign_members_v4 (
      campaign_id uuid NOT NULL REFERENCES security_campaigns_v4(id) ON DELETE RESTRICT,
      analysis_id uuid NOT NULL REFERENCES security_analyses(id) ON DELETE RESTRICT,
      PRIMARY KEY(campaign_id,analysis_id)
    );
    CREATE INDEX ix_security_campaign_member_analysis ON security_campaign_members_v4(analysis_id);

    CREATE TABLE security_campaign_audit (
      id uuid PRIMARY KEY,
      campaign_id uuid NOT NULL REFERENCES security_campaigns_v4(id) ON DELETE RESTRICT,
      record jsonb NOT NULL,
      occurred_at timestamptz NOT NULL
    );
    CREATE INDEX ix_security_campaign_audit_record ON security_campaign_audit(campaign_id,occurred_at);
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE security_campaign_audit;
    DROP TABLE security_campaign_members_v4;
    DROP TABLE security_campaigns_v4;
    DROP TABLE security_memory_audit;
    DROP TABLE security_memory;
    """)
