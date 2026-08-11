"""Persist campaign observations and bootstrap reviewed source policies."""

from alembic import op

revision = "0007_runtime_integration"
down_revision = "0006_campaign_artifacts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE campaign_observations (
          analysis_id uuid PRIMARY KEY REFERENCES analyses(id) ON DELETE CASCADE,
          observed_at timestamptz NOT NULL,
          registrable_domains jsonb NOT NULL DEFAULT '[]'::jsonb,
          redirect_targets jsonb NOT NULL DEFAULT '[]'::jsonb,
          evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb
        );
        CREATE INDEX ix_campaign_observations_time ON campaign_observations(observed_at);

        CREATE TABLE campaign_claim_features (
          analysis_id uuid NOT NULL REFERENCES campaign_observations(analysis_id) ON DELETE CASCADE,
          feature_ref text NOT NULL,
          embedding vector(1536) NOT NULL,
          PRIMARY KEY(analysis_id,feature_ref)
        );
        CREATE INDEX ix_campaign_claim_features_cosine
          ON campaign_claim_features USING hnsw(embedding vector_cosine_ops);

        INSERT INTO fact_check_sources(
          id,publisher,normalized_pattern,tier,source_type,active,explicit_deny,
          trusted_claim_review,allowed_operations,policy_version,effective_from,
          default_freshness_seconds,reviewer_id,reviewed_at,created_at
        )
        SELECT gen_random_uuid(),v.publisher,v.pattern,'B','reviewed_news',true,false,false,
               '["search","read","compare"]'::jsonb,'source-policy-v2','2026-08-11T00:00:00Z',
               21600,'system-bootstrap','2026-08-11T00:00:00Z',now()
        FROM (VALUES
          ('VTV','*.vtv.vn'),('VOV','*.vov.vn'),('Nhan Dan','*.nhandan.vn'),
          ('VietnamPlus','*.vietnamplus.vn'),('VnExpress','*.vnexpress.net'),
          ('Tuoi Tre','*.tuoitre.vn'),('Thanh Nien','*.thanhnien.vn')
        ) AS v(publisher,pattern)
        ON CONFLICT(normalized_pattern,policy_version) DO NOTHING;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DELETE FROM fact_check_sources WHERE policy_version='source-policy-v2' AND reviewer_id='system-bootstrap';
        DROP TABLE campaign_claim_features;
        DROP TABLE campaign_observations;
        """
    )
