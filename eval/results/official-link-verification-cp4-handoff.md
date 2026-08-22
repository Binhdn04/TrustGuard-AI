# Official Link Verification CP4 Handoff

## Result

WP4 implementation is complete and verified. Brand records now support reviewed, versioned official identities
while legacy `official_domains` remain readable and are projected at runtime as deterministic primary-website
identities. Resolution is ordered and ambiguity-safe, and all Brand mutations append immutable versions and
audit events.

Machine-readable evidence is in `eval/results/official-link-verification-cp4-evidence.json`.

## Handoff

```text
WP/Checkpoint: WP4 / CP4
Base commit SHA: 2d7a6c4 (completed CP3)
Contract changes: additive identity type/match-scope/version fields, Brand official_identities and Brand supersedes
Resolution: exact canonical name -> exact alias -> bounded phrase; accent-folded; ambiguous results expose no
            selected identity or implicit allowlist
Legacy compatibility: official_domains are projected as reviewed PRIMARY_WEBSITE identities with stable IDs
Source Registry boundary: only exact entity-bound reviewed entries confirm; wildcard/broad entries corroborate;
                          online discoveries cannot create or confirm official identities
Admin behavior: POST /api/v4/admin/brands/{brand_id}/versions appends a reviewed superseding version;
                disable appends a disabled version; neither mutates the previous JSON record
Migration/head: 0018_remove_vector_compat; no migration added because Brand source-of-truth records are JSON-backed
Commands run and result: backend canonical checks pass; CP4 unit/contract/API tests pass; frontend unit/lint/
                         typecheck pass; equivalent cutover scan passes
Known limitations: canonical frontend check:cutover is blocked by Node 24.14.1 URL-path encoding on this Unicode
                   workspace; online transport and verification coordinator remain owned by WP5/WP7
Required review: independent Security admin reviewer
Next WP entry conditions satisfied: implementation and automated CP4 gates are satisfied; independent review and
                                    commit/merge are required before WP5
```

## CP4-Owned Changes

```text
src/models/security_v4.py
src/models/__init__.py
src/services/official_identity_registry.py
src/services/security_trust.py
src/agents/security_trust.py
src/repositories/blacklist.py
src/repositories/postgres.py
src/api/security_v4.py
tests/unit/test_official_link_verification_cp4.py
tests/test_api/test_official_link_verification_cp4.py
eval/results/official-link-verification-cp4-evidence.json
eval/results/official-link-verification-cp4-handoff.md
```

## Safety and Compatibility Boundary

- Existing Brand JSON without `official_identities` or `supersedes` remains valid.
- `official_domains=[]` is accepted only with an active structurally valid identity; persisted identities must be
  reviewer-approved.
- Legacy domains become stable `PRIMARY_WEBSITE` identities without rewriting persisted legacy records.
- Social and careers URLs use exact canonical matching; their shared host is not an allowlist.
- Multiple matches at the winning resolution tier return `AMBIGUOUS` with candidate IDs only.
- Source discovery and wildcard/tier policies cannot confirm or persist an official identity.
- Create, supersede and disable require `security_admin` and write immutable trust-audit events.
- No provider, network fetch, rollout flag, migration or risk-policy behavior was introduced by WP4.

The pre-existing deleted pytest session artifacts listed in the evidence file were not modified or included in
WP4 ownership.
