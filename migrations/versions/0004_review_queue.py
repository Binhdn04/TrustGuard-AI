"""Create the persisted user-report review queue and decision audit fields."""

from alembic import op

revision = "0004_review_queue"
down_revision = "0003_durable_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE review_queue_items (
          id uuid PRIMARY KEY,
          report_id uuid NOT NULL UNIQUE REFERENCES analysis_reports(id) ON DELETE RESTRICT,
          analysis_id uuid NOT NULL REFERENCES analyses(id) ON DELETE RESTRICT,
          status text NOT NULL CONSTRAINT ck_review_queue_status
            CHECK(status IN ('submitted','reviewing','processed')),
          evidence_snapshot jsonb NOT NULL DEFAULT '[]'::jsonb,
          decision text CONSTRAINT ck_review_queue_decision
            CHECK(decision IS NULL OR decision IN ('approved','rejected','dismissed')),
          reviewer_id text,
          reviewer_note text,
          reviewed_at timestamptz,
          created_at timestamptz NOT NULL,
          updated_at timestamptz NOT NULL
        );
        CREATE INDEX ix_review_queue_status_created ON review_queue_items(status,created_at);
        CREATE INDEX ix_review_queue_analysis ON review_queue_items(analysis_id,created_at DESC);
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE review_queue_items")
