"""Store structured report decision and remediation details in immutable audit."""

from alembic import op

revision = "0020_report_audit_details"
down_revision = "0019_security_identity_discovery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE security_feedback_audit_v4
          ADD COLUMN details JSONB NOT NULL DEFAULT '{}'::jsonb;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE security_feedback_audit_v4 DROP COLUMN details;
        """
    )
