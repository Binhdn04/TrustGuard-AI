"""Add security brand registry, whitelist, and immutable trust audit."""

from alembic import op

revision = "0010_security_trust_registry"
down_revision = "0009_security_triage_v4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE security_brands (
      id uuid PRIMARY KEY, name text NOT NULL, aliases jsonb NOT NULL DEFAULT '[]',
      official_domains jsonb NOT NULL, official_contacts jsonb NOT NULL DEFAULT '[]',
      provenance text NOT NULL, policy_version text NOT NULL, lifecycle text NOT NULL,
      effective_from timestamptz NOT NULL, effective_until timestamptz,
      reviewer_id text NOT NULL, created_at timestamptz NOT NULL, record jsonb NOT NULL,
      CONSTRAINT ck_security_brand_lifecycle CHECK(lifecycle IN ('active','disabled')),
      CONSTRAINT ck_security_brand_interval CHECK(effective_until IS NULL OR effective_until > effective_from)
    );
    CREATE INDEX ix_security_brands_lifecycle_time
      ON security_brands(lifecycle,effective_from,effective_until);
    CREATE TABLE security_whitelist (
      id uuid PRIMARY KEY, scope text NOT NULL, indicator text NOT NULL,
      provenance text NOT NULL, policy_version text NOT NULL, lifecycle text NOT NULL,
      effective_from timestamptz NOT NULL, effective_until timestamptz,
      reviewer_id text NOT NULL, created_at timestamptz NOT NULL, record jsonb NOT NULL,
      CONSTRAINT uq_security_whitelist_version UNIQUE(scope,indicator,effective_from),
      CONSTRAINT ck_security_whitelist_scope CHECK(scope IN ('domain','url','contact')),
      CONSTRAINT ck_security_whitelist_lifecycle CHECK(lifecycle IN ('active','disabled')),
      CONSTRAINT ck_security_whitelist_interval CHECK(effective_until IS NULL OR effective_until > effective_from)
    );
    CREATE INDEX ix_security_whitelist_lifecycle_time
      ON security_whitelist(lifecycle,effective_from,effective_until);
    CREATE TABLE security_trust_audit (
      id uuid PRIMARY KEY, resource_type text NOT NULL, resource_id uuid NOT NULL,
      action text NOT NULL, reviewer_id text NOT NULL, occurred_at timestamptz NOT NULL
    );
    CREATE INDEX ix_security_trust_audit_resource
      ON security_trust_audit(resource_type,resource_id,occurred_at DESC);
    """)


def downgrade() -> None:
    op.execute("DROP TABLE security_trust_audit, security_whitelist, security_brands")
