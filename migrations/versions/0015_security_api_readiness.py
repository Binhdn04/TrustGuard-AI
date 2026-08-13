"""Add v4 admin feedback lifecycle and unified feedback audit."""

from alembic import op

revision = "0015_security_api_readiness"
down_revision = "0014_security_memory_campaigns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    ALTER TABLE security_analysis_reports_v4
      ADD COLUMN status text NOT NULL DEFAULT 'submitted';
    ALTER TABLE security_analysis_reports_v4 ADD CONSTRAINT ck_security_report_status
      CHECK(status IN ('submitted','reviewing','processed'));
    CREATE INDEX ix_security_reports_status_created
      ON security_analysis_reports_v4(status,created_at DESC);
    CREATE INDEX ix_security_appeals_status_created
      ON security_analysis_appeals_v4(status,created_at DESC);
    CREATE TABLE security_feedback_audit_v4 (
      id uuid PRIMARY KEY,
      resource_type text NOT NULL CHECK(resource_type IN ('report','appeal')),
      resource_id uuid NOT NULL,
      action text NOT NULL,
      actor_id text NOT NULL,
      note text,
      evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
      occurred_at timestamptz NOT NULL
    );
    CREATE INDEX ix_security_feedback_audit_time
      ON security_feedback_audit_v4(occurred_at DESC);
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE security_feedback_audit_v4;
    DROP INDEX ix_security_appeals_status_created;
    DROP INDEX ix_security_reports_status_created;
    ALTER TABLE security_analysis_reports_v4 DROP CONSTRAINT ck_security_report_status;
    ALTER TABLE security_analysis_reports_v4 DROP COLUMN status;
    """)
