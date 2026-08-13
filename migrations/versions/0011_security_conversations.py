"""Add owner-scoped, versioned security conversations and turns."""

from alembic import op

revision = "0011_security_conversations"
down_revision = "0010_security_trust_registry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE security_conversations (
      id uuid PRIMARY KEY, owner_id text NOT NULL,
      status text NOT NULL CONSTRAINT ck_security_conversations_status
        CHECK(status IN ('active','expired')),
      active_analysis_id uuid NOT NULL, context_version integer NOT NULL CHECK(context_version >= 1),
      summary jsonb NOT NULL, created_at timestamptz NOT NULL,
      updated_at timestamptz NOT NULL, expires_at timestamptz NOT NULL
    );
    CREATE INDEX ix_security_conversations_owner_updated
      ON security_conversations(owner_id,updated_at DESC);
    CREATE INDEX ix_security_conversations_expiry ON security_conversations(expires_at);
    CREATE TABLE security_conversation_turns (
      conversation_id uuid NOT NULL REFERENCES security_conversations(id) ON DELETE CASCADE,
      context_version integer NOT NULL, analysis_id uuid NOT NULL UNIQUE,
      created_at timestamptz NOT NULL,
      PRIMARY KEY(conversation_id,context_version)
    );
    ALTER TABLE security_analyses ADD COLUMN conversation_id uuid
      REFERENCES security_conversations(id) ON DELETE SET NULL;
    CREATE INDEX ix_security_analyses_conversation ON security_analyses(conversation_id,created_at);
    """)


def downgrade() -> None:
    op.execute("""
    DROP INDEX ix_security_analyses_conversation;
    ALTER TABLE security_analyses DROP COLUMN conversation_id;
    DROP TABLE security_conversation_turns, security_conversations;
    """)
