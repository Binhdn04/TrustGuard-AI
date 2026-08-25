"""Support the reviewer-gated v4 security blacklist lifecycle."""

from alembic import op

revision = "0021_security_blacklist_v4"
down_revision = "0020_report_audit_details"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DROP INDEX uq_admin_actions_security_proposal;
        CREATE UNIQUE INDEX uq_admin_actions_pending_target
          ON admin_actions(
            COALESCE(security_analysis_id,'00000000-0000-0000-0000-000000000000'::uuid),
            action,canonical_target
          )
          WHERE status='pending_review';
        ALTER TABLE security_feedback_audit_v4
          DROP CONSTRAINT security_feedback_audit_v4_resource_type_check;
        ALTER TABLE security_feedback_audit_v4
          ADD CONSTRAINT security_feedback_audit_v4_resource_type_check
          CHECK(resource_type IN ('report','appeal','copilot','blacklist'));
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE security_feedback_audit_v4
          DROP CONSTRAINT security_feedback_audit_v4_resource_type_check;
        ALTER TABLE security_feedback_audit_v4
          ADD CONSTRAINT security_feedback_audit_v4_resource_type_check
          CHECK(resource_type IN ('report','appeal','copilot'));
        DROP INDEX uq_admin_actions_pending_target;
        CREATE UNIQUE INDEX uq_admin_actions_security_proposal
          ON admin_actions(security_analysis_id,action,canonical_target)
          WHERE security_analysis_id IS NOT NULL;
        """
    )
