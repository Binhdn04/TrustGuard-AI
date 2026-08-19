"""Enable the cryptographic extension required by encrypted persistence."""

from alembic import op

revision = "0001_extensions"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")


def downgrade() -> None:
    # Shared extensions are intentionally retained during an application rollback.
    pass
