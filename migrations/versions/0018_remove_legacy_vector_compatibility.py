"""Remove retired fact-check, vector, and v2/v3 discovery persistence."""

from alembic import op

revision = "0018_remove_vector_compat"
down_revision = "0017_security_admin_copilot"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS source_discovery_decisions;
        DROP TABLE IF EXISTS source_discovery_observations;
        DROP TABLE IF EXISTS source_discoveries;
        DROP TABLE IF EXISTS campaign_claim_features;
        DROP TABLE IF EXISTS campaign_observations;
        DROP TABLE IF EXISTS fact_check_chunks;
        DROP TABLE IF EXISTS fact_check_evidence_snapshots;
        DROP TABLE IF EXISTS fact_check_result_embeddings;
        DROP TABLE IF EXISTS fact_check_results;
        DROP TABLE IF EXISTS fact_check_embeddings;
        DROP TABLE IF EXISTS fact_check_records;
        DROP TABLE IF EXISTS fact_check_sources;
        DROP EXTENSION IF EXISTS vector;
        """
    )


def downgrade() -> None:
    raise RuntimeError("Retired v2/v3 vector compatibility storage cannot be restored by downgrade")
