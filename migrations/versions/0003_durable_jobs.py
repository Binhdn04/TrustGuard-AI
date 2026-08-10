"""Create durable jobs, transactional outbox, usage, and import ledger."""

from alembic import op

revision = "0003_durable_jobs"
down_revision = "0002_analysis_core"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE analysis_jobs (
      id uuid PRIMARY KEY, analysis_id uuid NOT NULL REFERENCES analyses(id) ON DELETE RESTRICT,
      kind text NOT NULL, status text NOT NULL CONSTRAINT ck_jobs_status
        CHECK(status IN ('queued','running','retry','completed','failed')),
      attempt integer NOT NULL DEFAULT 0, max_attempts integer NOT NULL CHECK(max_attempts > 0),
      available_at timestamptz NOT NULL, claimed_at timestamptz, lease_expires_at timestamptz,
      worker_id text, idempotency_key text NOT NULL UNIQUE, failure_code text,
      created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
    );
    CREATE INDEX ix_jobs_claim ON analysis_jobs(available_at,created_at)
      WHERE status IN ('queued','retry');
    CREATE INDEX ix_jobs_analysis_kind ON analysis_jobs(analysis_id,kind);
    CREATE TABLE outbox (
      id uuid PRIMARY KEY, aggregate_type text NOT NULL, aggregate_id uuid NOT NULL,
      event_type text NOT NULL, payload jsonb NOT NULL, created_at timestamptz NOT NULL,
      published_at timestamptz, attempt_count integer NOT NULL DEFAULT 0,
      lease_expires_at timestamptz, worker_id text, idempotency_key text NOT NULL UNIQUE
    );
    CREATE INDEX ix_outbox_unpublished ON outbox(created_at) WHERE published_at IS NULL;
    CREATE TABLE tool_usage (
      id uuid PRIMARY KEY, analysis_id uuid NOT NULL REFERENCES analyses(id) ON DELETE RESTRICT,
      step_id text, provider text NOT NULL, model text, provider_version text NOT NULL,
      operation text NOT NULL, units integer NOT NULL DEFAULT 0, input_tokens integer,
      output_tokens integer, estimated_cost numeric(12,6), latency_ms integer NOT NULL,
      cache_status text NOT NULL, outcome text NOT NULL, http_class text,
      observed_at timestamptz NOT NULL
    );
    CREATE INDEX ix_usage_analysis_time ON tool_usage(analysis_id,observed_at);
    CREATE INDEX ix_usage_provider_time ON tool_usage(provider,observed_at);
    CREATE INDEX ix_usage_outcome_time ON tool_usage(outcome,observed_at);
    CREATE TABLE schema_imports (
      importer_name text NOT NULL, source_fingerprint text NOT NULL,
      started_at timestamptz NOT NULL, completed_at timestamptz,
      row_counts jsonb NOT NULL DEFAULT '{}', error_summary jsonb NOT NULL DEFAULT '{}',
      PRIMARY KEY(importer_name,source_fingerprint)
    );
    CREATE INDEX ix_schema_imports_completed ON schema_imports(completed_at);
    """)


def downgrade() -> None:
    op.execute("DROP TABLE schema_imports, tool_usage, outbox, analysis_jobs")
