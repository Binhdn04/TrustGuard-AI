"""Add source discovery telemetry for provisional Tier C evidence."""

from alembic import op

revision = "0008_source_discovery"
down_revision = "0007_runtime_integration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE source_discoveries (
          domain text PRIMARY KEY,
          publisher text NOT NULL,
          first_seen_at timestamptz NOT NULL,
          last_seen_at timestamptz NOT NULL,
          search_count integer NOT NULL DEFAULT 0 CHECK(search_count >= 0),
          extract_success_count integer NOT NULL DEFAULT 0 CHECK(extract_success_count >= 0),
          claim_hashes jsonb NOT NULL DEFAULT '[]'::jsonb,
          curated_comparison_count integer NOT NULL DEFAULT 0 CHECK(curated_comparison_count >= 0),
          curated_agreement_count integer NOT NULL DEFAULT 0 CHECK(curated_agreement_count >= 0),
          curated_conflict_count integer NOT NULL DEFAULT 0 CHECK(curated_conflict_count >= 0),
          representative_urls jsonb NOT NULL DEFAULT '[]'::jsonb,
          status text NOT NULL DEFAULT 'observing'
            CHECK(status IN ('observing','promoted','demoted','denied'))
        );
        CREATE INDEX ix_source_discoveries_status_last_seen
          ON source_discoveries(status,last_seen_at DESC);
        CREATE TABLE source_discovery_observations (
          id uuid PRIMARY KEY,
          domain text NOT NULL REFERENCES source_discoveries(domain) ON DELETE CASCADE,
          event text NOT NULL CHECK(event IN ('search','extract','comparison')),
          claim_hash text,
          agrees_with_curated boolean,
          observed_at timestamptz NOT NULL
        );
        CREATE INDEX ix_source_discovery_observations_domain_time
          ON source_discovery_observations(domain,observed_at DESC);
        CREATE TABLE source_discovery_decisions (
          id uuid PRIMARY KEY,
          domain text NOT NULL REFERENCES source_discoveries(domain) ON DELETE RESTRICT,
          decision text NOT NULL CHECK(decision IN ('promote','deny','demote')),
          note text NOT NULL,
          reviewer_id text NOT NULL,
          decided_at timestamptz NOT NULL
        );
        CREATE INDEX ix_source_discovery_decisions_domain_time
          ON source_discovery_decisions(domain,decided_at DESC);

        INSERT INTO fact_check_sources(
          id,publisher,normalized_pattern,tier,source_type,active,explicit_deny,
          trusted_claim_review,allowed_operations,policy_version,effective_from,
          default_freshness_seconds,reviewer_id,reviewed_at,created_at
        ) VALUES
          (gen_random_uuid(),'FIFA','*.fifa.com','A','sports_governing_body',true,false,false,
           '["search","read","compare","promote"]'::jsonb,'source-policy-international-v1',
           '2026-01-01T00:00:00Z',21600,'system-bootstrap','2026-01-01T00:00:00Z',now()),
          (gen_random_uuid(),'UEFA','*.uefa.com','A','sports_governing_body',true,false,false,
           '["search","read","compare","promote"]'::jsonb,'source-policy-international-v1',
           '2026-01-01T00:00:00Z',21600,'system-bootstrap','2026-01-01T00:00:00Z',now()),
          (gen_random_uuid(),'Olympics','*.olympics.com','A','sports_governing_body',true,false,false,
           '["search","read","compare","promote"]'::jsonb,'source-policy-international-v1',
           '2026-01-01T00:00:00Z',21600,'system-bootstrap','2026-01-01T00:00:00Z',now()),
          (gen_random_uuid(),'World Health Organization','*.who.int','A','international_organization',true,false,false,
           '["search","read","compare","promote"]'::jsonb,'source-policy-international-v1',
           '2026-01-01T00:00:00Z',21600,'system-bootstrap','2026-01-01T00:00:00Z',now()),
          (gen_random_uuid(),'United Nations','*.un.org','A','international_organization',true,false,false,
           '["search","read","compare","promote"]'::jsonb,'source-policy-international-v1',
           '2026-01-01T00:00:00Z',21600,'system-bootstrap','2026-01-01T00:00:00Z',now()),
          (gen_random_uuid(),'World Bank','*.worldbank.org','A','international_organization',true,false,false,
           '["search","read","compare","promote"]'::jsonb,'source-policy-international-v1',
           '2026-01-01T00:00:00Z',21600,'system-bootstrap','2026-01-01T00:00:00Z',now()),
          (gen_random_uuid(),'International Monetary Fund','*.imf.org','A','international_organization',true,false,false,
           '["search","read","compare","promote"]'::jsonb,'source-policy-international-v1',
           '2026-01-01T00:00:00Z',21600,'system-bootstrap','2026-01-01T00:00:00Z',now()),
          (gen_random_uuid(),'OECD','*.oecd.org','A','international_organization',true,false,false,
           '["search","read","compare","promote"]'::jsonb,'source-policy-international-v1',
           '2026-01-01T00:00:00Z',21600,'system-bootstrap','2026-01-01T00:00:00Z',now()),
          (gen_random_uuid(),'European Union','*.europa.eu','A','international_organization',true,false,false,
           '["search","read","compare","promote"]'::jsonb,'source-policy-international-v1',
           '2026-01-01T00:00:00Z',21600,'system-bootstrap','2026-01-01T00:00:00Z',now()),
          (gen_random_uuid(),'CDC','*.cdc.gov','A','government_health',true,false,false,
           '["search","read","compare","promote"]'::jsonb,'source-policy-international-v1',
           '2026-01-01T00:00:00Z',21600,'system-bootstrap','2026-01-01T00:00:00Z',now()),
          (gen_random_uuid(),'NIH','*.nih.gov','A','government_health',true,false,false,
           '["search","read","compare","promote"]'::jsonb,'source-policy-international-v1',
           '2026-01-01T00:00:00Z',21600,'system-bootstrap','2026-01-01T00:00:00Z',now()),
          (gen_random_uuid(),'FDA','*.fda.gov','A','government_health',true,false,false,
           '["search","read","compare","promote"]'::jsonb,'source-policy-international-v1',
           '2026-01-01T00:00:00Z',21600,'system-bootstrap','2026-01-01T00:00:00Z',now())
        ON CONFLICT(normalized_pattern,policy_version) DO NOTHING;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DELETE FROM fact_check_sources WHERE policy_version='source-policy-international-v1';
        DROP TABLE source_discovery_decisions;
        DROP TABLE source_discovery_observations;
        DROP TABLE source_discoveries;
        """
    )
