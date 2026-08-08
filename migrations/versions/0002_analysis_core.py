"""Create owner-scoped analyses and append-only core records."""

from alembic import op

revision = "0002_analysis_core"
down_revision = "0001_extensions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE analyses (
      id uuid PRIMARY KEY, owner_id text NOT NULL, input_ciphertext bytea NOT NULL,
      input_hash text NOT NULL, consent boolean NOT NULL, status text NOT NULL
        CONSTRAINT ck_analyses_status CHECK (status IN ('queued','running','completed','failed')),
      response jsonb NOT NULL, case_status text,
      scoring_version text, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
      completed_at timestamptz, version integer NOT NULL DEFAULT 1,
      CONSTRAINT ck_analyses_completed CHECK (
        status <> 'completed' OR (completed_at IS NOT NULL AND scoring_version IS NOT NULL))
    );
    CREATE INDEX ix_analyses_owner_created ON analyses(owner_id, created_at DESC);
    CREATE INDEX ix_analyses_status_created ON analyses(status, created_at);
    CREATE INDEX ix_analyses_case_created ON analyses(case_status, created_at);
    CREATE TABLE analysis_events (
      event_id uuid PRIMARY KEY, analysis_id uuid NOT NULL REFERENCES analyses(id) ON DELETE RESTRICT,
      sequence integer NOT NULL CHECK(sequence >= 1), event_type text NOT NULL,
      payload jsonb NOT NULL, occurred_at timestamptz NOT NULL,
      UNIQUE(analysis_id, sequence)
    );
    CREATE INDEX ix_analysis_events_time ON analysis_events(occurred_at);
    CREATE TABLE investigation_steps (
      analysis_id uuid NOT NULL REFERENCES analyses(id) ON DELETE CASCADE, step_id text NOT NULL,
      tool text NOT NULL, target_ref text NOT NULL, reason_code text NOT NULL,
      dependency_ids jsonb NOT NULL DEFAULT '[]', status text NOT NULL, attempt_count integer NOT NULL DEFAULT 0,
      created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
      PRIMARY KEY(analysis_id, step_id)
    );
    CREATE INDEX ix_steps_analysis_status ON investigation_steps(analysis_id,status);
    CREATE TABLE evidence (
      id uuid PRIMARY KEY, analysis_id uuid NOT NULL REFERENCES analyses(id) ON DELETE RESTRICT,
      type text NOT NULL, source text NOT NULL, source_version text NOT NULL,
      title text NOT NULL, safe_url text, artifact_ref text, finding text NOT NULL,
      observed_at timestamptz NOT NULL, created_at timestamptz NOT NULL, content_hash text NOT NULL
    );
    CREATE INDEX ix_evidence_analysis_created ON evidence(analysis_id,created_at);
    CREATE INDEX ix_evidence_content_hash ON evidence(content_hash);
    CREATE TABLE analysis_reports (
      id uuid PRIMARY KEY, analysis_id uuid NOT NULL REFERENCES analyses(id) ON DELETE RESTRICT,
      reporter_id text NOT NULL, reason text NOT NULL, comment text, created_at timestamptz NOT NULL
    );
    CREATE INDEX ix_reports_analysis_created ON analysis_reports(analysis_id,created_at);
    CREATE INDEX ix_reports_created ON analysis_reports(created_at DESC);
    """)


def downgrade() -> None:
    op.execute("DROP TABLE analysis_reports, evidence, investigation_steps, analysis_events, analyses")
