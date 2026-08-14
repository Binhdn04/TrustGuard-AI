"""security admin copilot suggestions

Revision ID: 0017_security_admin_copilot
Revises: 0016_security_v4_durable_jobs
"""

from alembic import op

revision = "0017_security_admin_copilot"
down_revision = "0016_security_v4_durable_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE security_admin_copilot_suggestions_v4 (
      id uuid PRIMARY KEY,
      analysis_id uuid NOT NULL REFERENCES security_analyses(id) ON DELETE RESTRICT,
      reviewer_id text NOT NULL,
      suggestion jsonb NOT NULL,
      usage_metadata jsonb NOT NULL,
      evidence_snapshot_hash text NOT NULL CHECK(evidence_snapshot_hash ~ '^[a-f0-9]{64}$'),
      requested_at timestamptz NOT NULL,
      completed_at timestamptz NOT NULL CHECK(completed_at >= requested_at)
    );
    CREATE INDEX ix_security_admin_copilot_analysis_time
      ON security_admin_copilot_suggestions_v4(analysis_id, completed_at DESC);
    ALTER TABLE security_feedback_audit_v4
      DROP CONSTRAINT security_feedback_audit_v4_resource_type_check;
    ALTER TABLE security_feedback_audit_v4
      ADD CONSTRAINT security_feedback_audit_v4_resource_type_check
      CHECK(resource_type IN ('report','appeal','copilot'));
    """)


def downgrade() -> None:
    op.execute("""
    ALTER TABLE security_feedback_audit_v4
      DROP CONSTRAINT security_feedback_audit_v4_resource_type_check;
    ALTER TABLE security_feedback_audit_v4
      ADD CONSTRAINT security_feedback_audit_v4_resource_type_check
      CHECK(resource_type IN ('report','appeal'));
    DROP TABLE security_admin_copilot_suggestions_v4;
    """)
