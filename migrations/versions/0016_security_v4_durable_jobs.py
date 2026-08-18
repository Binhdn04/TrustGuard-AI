"""Add isolated durable execution records for Security v4."""

from alembic import op

revision = "0016_security_v4_durable_jobs"
down_revision = "0015_security_api_readiness"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE security_analysis_jobs_v4 (
      id uuid PRIMARY KEY,
      analysis_id uuid NOT NULL UNIQUE REFERENCES security_analyses(id) ON DELETE RESTRICT,
      status text NOT NULL CHECK(status IN ('queued','running','completed','failed')),
      attempt integer NOT NULL DEFAULT 0 CHECK(attempt >= 0),
      max_attempts integer NOT NULL DEFAULT 3 CHECK(max_attempts >= 1),
      available_at timestamptz NOT NULL,
      claimed_at timestamptz,
      lease_expires_at timestamptz,
      worker_id text,
      failure_code text,
      created_at timestamptz NOT NULL,
      updated_at timestamptz NOT NULL
    );
    CREATE INDEX ix_security_jobs_v4_claim
      ON security_analysis_jobs_v4(available_at,created_at)
      WHERE status IN ('queued','running');

    CREATE TABLE security_analysis_payloads_v4 (
      analysis_id uuid PRIMARY KEY REFERENCES security_analyses(id) ON DELETE CASCADE,
      payload_ciphertext bytea NOT NULL,
      context_snapshot jsonb NOT NULL,
      created_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL
    );
    CREATE INDEX ix_security_payloads_v4_expiry
      ON security_analysis_payloads_v4(expires_at);

    CREATE TABLE security_analysis_outbox_v4 (
      id uuid PRIMARY KEY,
      analysis_id uuid NOT NULL REFERENCES security_analyses(id) ON DELETE RESTRICT,
      event_type text NOT NULL,
      payload jsonb NOT NULL,
      created_at timestamptz NOT NULL,
      published_at timestamptz,
      lease_expires_at timestamptz,
      worker_id text,
      idempotency_key text NOT NULL UNIQUE
    );
    CREATE INDEX ix_security_outbox_v4_unpublished
      ON security_analysis_outbox_v4(created_at) WHERE published_at IS NULL;

    CREATE TABLE security_analysis_idempotency_v4 (
      owner_id text NOT NULL,
      idempotency_key text NOT NULL,
      payload_hash text NOT NULL,
      analysis_id uuid NOT NULL REFERENCES security_analyses(id) ON DELETE RESTRICT,
      created_at timestamptz NOT NULL,
      PRIMARY KEY(owner_id,idempotency_key)
    );
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE security_analysis_idempotency_v4;
    DROP TABLE security_analysis_outbox_v4;
    DROP TABLE security_analysis_payloads_v4;
    DROP TABLE security_analysis_jobs_v4;
    """)
