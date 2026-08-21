"""Add security-specific identity discovery candidates and immutable review evidence."""

from alembic import op

revision = "0019_security_identity_discovery"
down_revision = "0018_remove_vector_compat"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE security_identity_candidates (
          id UUID PRIMARY KEY,
          entity_name TEXT NOT NULL,
          canonical_url TEXT NOT NULL,
          canonical_domain TEXT NOT NULL,
          relationship TEXT NOT NULL CHECK (relationship IN
            ('official_controlled','parent_organization','endorsed_third_party_service')),
          assurance TEXT NOT NULL CHECK (assurance IN
            ('discovered','verified','conflicting','promoted','rejected','confirmed_mismatch')),
          confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
          version INTEGER NOT NULL CHECK (version > 0),
          expires_at TIMESTAMPTZ,
          terminal_decision_id UUID,
          record JSONB NOT NULL,
          created_at TIMESTAMPTZ NOT NULL,
          UNIQUE(entity_name, canonical_domain, relationship, version)
        );
        CREATE INDEX ix_security_identity_candidates_queue
          ON security_identity_candidates(assurance,relationship,created_at DESC);

        CREATE TABLE security_identity_evidence (
          evidence_ref TEXT PRIMARY KEY,
          candidate_id UUID NOT NULL REFERENCES security_identity_candidates(id),
          source_host TEXT NOT NULL,
          family TEXT NOT NULL,
          canonical_url TEXT NOT NULL,
          content_hash TEXT NOT NULL,
          observation JSONB NOT NULL,
          observed_at TIMESTAMPTZ NOT NULL
        );
        CREATE INDEX ix_security_identity_evidence_candidate
          ON security_identity_evidence(candidate_id,source_host,family);

        CREATE TABLE security_identity_decisions (
          id UUID PRIMARY KEY,
          candidate_id UUID NOT NULL UNIQUE REFERENCES security_identity_candidates(id),
          action TEXT NOT NULL CHECK (action IN ('approve','reject','confirm_mismatch')),
          reviewer_id TEXT NOT NULL,
          note TEXT NOT NULL,
          target_brand_id UUID,
          relationship TEXT,
          identity_type TEXT,
          evidence_refs JSONB NOT NULL,
          decision JSONB NOT NULL,
          decided_at TIMESTAMPTZ NOT NULL
        );
        ALTER TABLE security_identity_candidates
          ADD CONSTRAINT fk_security_identity_terminal_decision
          FOREIGN KEY (terminal_decision_id) REFERENCES security_identity_decisions(id);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE security_identity_candidates DROP CONSTRAINT fk_security_identity_terminal_decision;
        DROP TABLE security_identity_decisions;
        DROP TABLE security_identity_evidence;
        DROP TABLE security_identity_candidates;
        """
    )
