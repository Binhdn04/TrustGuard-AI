"""Reserve durable metadata/audit storage for security-risk-v7 assurance."""

from alembic import op

revision = "0022_action_assurance_metadata"
down_revision = "0021_security_blacklist_v4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The complete report (including policy_metadata) remains the atomic
    # canonical payload.  This indexed companion is intentionally metadata
    # only and contains no message, raw model content, or URL query strings.
    op.execute(
        """
        ALTER TABLE security_analyses
          ADD COLUMN IF NOT EXISTS policy_metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
        ALTER TABLE security_feedback_audit_v4
          ADD COLUMN IF NOT EXISTS assurance_metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE security_feedback_audit_v4 DROP COLUMN IF EXISTS assurance_metadata;
        ALTER TABLE security_analyses DROP COLUMN IF EXISTS policy_metadata;
        """
    )
