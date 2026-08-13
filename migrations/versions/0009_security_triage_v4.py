"""Add isolated v4 security analysis lifecycle storage."""

from alembic import op

revision = "0009_security_triage_v4"
down_revision = "0008_source_discovery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE security_analyses (
      id uuid PRIMARY KEY, owner_id text NOT NULL,
      status text NOT NULL CONSTRAINT ck_security_analyses_status
        CHECK (status IN ('queued','running','completed','failed')),
      response jsonb NOT NULL, policy_version text,
      created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
      completed_at timestamptz,
      CONSTRAINT ck_security_analyses_completed CHECK (
        status <> 'completed' OR (completed_at IS NOT NULL))
    );
    CREATE INDEX ix_security_analyses_owner_created
      ON security_analyses(owner_id, created_at DESC);
    CREATE TABLE security_analysis_events (
      event_id uuid PRIMARY KEY,
      analysis_id uuid NOT NULL REFERENCES security_analyses(id) ON DELETE RESTRICT,
      sequence integer NOT NULL CHECK(sequence >= 1), event_type text NOT NULL,
      payload jsonb NOT NULL, occurred_at timestamptz NOT NULL,
      UNIQUE(analysis_id, sequence)
    );
    CREATE INDEX ix_security_analysis_events_time
      ON security_analysis_events(analysis_id, sequence);
    CREATE TABLE security_tool_executions (
      analysis_id uuid NOT NULL, step_id text NOT NULL, target_ref text NOT NULL,
      provider text NOT NULL, status text NOT NULL,
      attempt_count integer NOT NULL DEFAULT 1, updated_at timestamptz NOT NULL,
      PRIMARY KEY(analysis_id, step_id, target_ref, provider),
      CONSTRAINT ck_security_tool_execution_status
        CHECK (status IN ('running','completed','failed','skipped'))
    );
    """)


def downgrade() -> None:
    op.execute("DROP TABLE security_tool_executions, security_analysis_events, security_analyses")
