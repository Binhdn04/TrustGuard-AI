"""Connect v4 security analyses to executable reviewed admin actions."""

from alembic import op

revision = "0013_security_hitl_actions"
down_revision = "0012_security_feedback"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    ALTER TABLE admin_actions
      ADD COLUMN security_analysis_id uuid REFERENCES security_analyses(id) ON DELETE RESTRICT,
      ADD COLUMN execution_error text;
    ALTER TABLE review_decisions
      ADD COLUMN execution_status text,
      ADD COLUMN execution_error text;
    ALTER TABLE admin_actions ADD CONSTRAINT ck_admin_actions_single_analysis CHECK (
      num_nonnulls(analysis_id,security_analysis_id) <= 1
    );
    UPDATE admin_actions
      SET executed_at=COALESCE(executed_at,reviewed_at,proposed_at),
          execution_error=CASE WHEN status='failed' THEN 'LEGACY_EXECUTION_FAILURE' ELSE NULL END
      WHERE status IN ('executed','failed');
    ALTER TABLE admin_actions ADD CONSTRAINT ck_admin_actions_execution CHECK (
      (status = 'executed' AND executed_at IS NOT NULL AND execution_error IS NULL)
      OR (status = 'failed' AND executed_at IS NOT NULL AND execution_error IS NOT NULL)
      OR (status NOT IN ('executed','failed') AND executed_at IS NULL AND execution_error IS NULL)
    );
    UPDATE review_decisions d SET
      execution_status=a.status,
      execution_error=a.execution_error
      FROM admin_actions a WHERE d.action_id=a.id;
    ALTER TABLE review_decisions ADD CONSTRAINT ck_review_decisions_execution_status CHECK (
      action_id IS NULL OR execution_status IN ('approved','rejected','executed','failed')
    );
    CREATE UNIQUE INDEX uq_admin_actions_security_proposal
      ON admin_actions(security_analysis_id,action,canonical_target)
      WHERE security_analysis_id IS NOT NULL;
    CREATE INDEX ix_admin_actions_security_analysis
      ON admin_actions(security_analysis_id,proposed_at DESC)
      WHERE security_analysis_id IS NOT NULL;
    """)


def downgrade() -> None:
    op.execute("""
    DROP INDEX ix_admin_actions_security_analysis;
    DROP INDEX uq_admin_actions_security_proposal;
    ALTER TABLE review_decisions DROP CONSTRAINT ck_review_decisions_execution_status;
    ALTER TABLE review_decisions DROP COLUMN execution_error, DROP COLUMN execution_status;
    ALTER TABLE admin_actions DROP CONSTRAINT ck_admin_actions_single_analysis;
    ALTER TABLE admin_actions DROP CONSTRAINT ck_admin_actions_execution;
    ALTER TABLE admin_actions DROP COLUMN execution_error, DROP COLUMN security_analysis_id;
    """)
