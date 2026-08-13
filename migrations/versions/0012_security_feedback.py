"""Add v4 security reports and appeals without coupling to legacy analyses."""

from alembic import op

revision = "0012_security_feedback"
down_revision = "0011_security_conversations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE security_analysis_reports_v4 (
      id uuid PRIMARY KEY, analysis_id uuid NOT NULL REFERENCES security_analyses(id) ON DELETE RESTRICT,
      owner_id text NOT NULL, record jsonb NOT NULL, created_at timestamptz NOT NULL
    );
    CREATE INDEX ix_security_reports_analysis ON security_analysis_reports_v4(analysis_id,created_at);
    CREATE TABLE security_analysis_appeals_v4 (
      id uuid PRIMARY KEY, analysis_id uuid NOT NULL REFERENCES security_analyses(id) ON DELETE RESTRICT,
      owner_id text NOT NULL, status text NOT NULL, record jsonb NOT NULL, created_at timestamptz NOT NULL,
      CONSTRAINT ck_security_appeal_status CHECK(status IN ('submitted','under_review','resolved'))
    );
    CREATE INDEX ix_security_appeals_analysis ON security_analysis_appeals_v4(analysis_id,created_at);
    CREATE UNIQUE INDEX uq_security_active_appeal ON security_analysis_appeals_v4(analysis_id)
      WHERE status <> 'resolved';
    """)


def downgrade() -> None:
    op.execute("DROP TABLE security_analysis_appeals_v4, security_analysis_reports_v4")
