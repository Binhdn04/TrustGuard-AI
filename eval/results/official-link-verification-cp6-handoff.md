# Official Link Verification CP6 Handoff

## Result

WP6 implementation is complete and verified. The new deterministic extraction layer parses bounded HTML anchors,
keeps fetch and persisted URL representations separate, reclassifies the final page after redirects, and compares
Google Forms and Microsoft Forms by provider resource ID. Generic providers require exact canonical URL equality;
same-domain URLs never imply the same resource.

Machine-readable evidence is in `eval/results/official-link-verification-cp6-evidence.json`.

## Handoff

```text
WP/Checkpoint: WP6 / CP6
Base commit SHA: 0eefeca0b2d1033b9f37e2fdabcbb9d7de790cc6 (completed CP5)
Contract/schema changes: no new public response schema; CP2 ResourceIdentityV4/ResourceMatchV4 are populated by
                         deterministic WP6 factories and internal bounded extraction evidence
Dependency change: beautifulsoup4>=4.12,<5 locked with html.parser; no browser runtime added
Extraction boundary: first valid base, relative/protocol-relative anchors, bounded refs/text/hash; javascript/data/
                     mailto and credential URLs are rejected; raw HTML and fetch URLs are not serialized
Resource boundary: Google Forms and Microsoft Forms match by provider ID; Bitly/forms.gle are redirect-only;
                   other providers require exact canonical URL; same domain alone never matches
Fallback boundary: provider extract is accepted only after an eligible direct-fetch failure and only when the
                   candidate URL is explicit in extracted content; evidence is capped at PARTIALLY_VERIFIED
Migration/head: 0018_remove_vector_compat; no migration added
Commands run and result: backend canonical checks, CP5/CP6 regression, dependency lock, frontend unit/lint/
                         typecheck and equivalent cutover scan pass
Known limitations: canonical frontend check:cutover is blocked by Node 24.14.1 URL-path encoding on this Unicode
                   workspace; coordinator/fusion and consent-driven invocation remain WP7
Required review: independent Network security reviewer
Next WP entry conditions satisfied: implementation and automated CP6 gates are satisfied; independent review and
                                    commit/merge are required before WP7
```

## CP6-Owned Changes

```text
pyproject.toml
uv.lock
src/services/official_resource_identity.py
tests/unit/test_official_link_verification_cp6.py
eval/results/official-link-verification-cp6-evidence.json
eval/results/official-link-verification-cp6-handoff.md
```

## Safety Boundary

- Fetch URLs remain in memory only and preserve path, query order, duplicate parameters and signed query material.
- Display/canonical URLs remove fragments, tracking keys and sensitive query keys before persistence.
- Anchor and context text are bounded and redact URLs, email addresses and labeled credential/token material.
- Only a reviewed identity can authorize parsing of the final redirected page; mismatches yield no outbound links.
- HTML is hashed for stable source/link refs and is never included in the extraction envelope.
- Google and Microsoft form aliases converge only when their provider resource IDs match.
- Different form IDs, different generic canonical URLs and unresolved shorteners cannot produce an exact match.
- No coordinator, rollout flag, public response mutation, migration or risk-policy behavior was introduced by WP6.

The pre-existing deleted pytest session artifacts listed in the evidence file were not modified or included in
WP6 ownership.
