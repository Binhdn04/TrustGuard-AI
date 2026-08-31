"""Persist account-wide lookup consent without storing submitted content."""

from alembic import op

revision = "0023_account_lookup_consent"
down_revision = "0022_action_assurance_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS security_account_lookup_consent (
          owner_id TEXT PRIMARY KEY,
          status TEXT NOT NULL CHECK (status IN ('granted', 'denied')),
          decided_at TIMESTAMPTZ NOT NULL,
          disclosure_version TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS security_account_lookup_consent_audit (
          audit_id UUID PRIMARY KEY, owner_id TEXT NOT NULL, actor_id TEXT NOT NULL,
          status TEXT NOT NULL CHECK (status IN ('granted', 'denied')),
          note TEXT NOT NULL, occurred_at TIMESTAMPTZ NOT NULL
        );
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS security_account_lookup_consent_audit; DROP TABLE IF EXISTS security_account_lookup_consent")
