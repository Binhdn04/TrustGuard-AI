# Official Link Verification CP3 Handoff

## Result

WP3 implementation is complete and verified. Official-verification work can now be constructed only from
grounded organization, claim, or action values. Neutral recruitment, promotion, form, event and course text
does not enter security triage by itself; deterministic out-of-scope turns terminate with zero AI or external
calls. Existing URL-safety triage and recovery-first incident behavior are preserved.

Machine-readable evidence is in `eval/results/official-link-verification-cp3-evidence.json`.

## Handoff

```text
WP/Checkpoint: WP3 / CP3
Base commit SHA: 3f7b4287f524cd54171313cf62581a77171e645b (completed CP2)
Scope changes: neutral recruitment/promotion/form/event/course categories are deterministic OOS unless a
               security signal or sensitive action is present; new actions are recognized by rules or
               confidence-and-span-validated semantic output
Intent/query changes: grounded intent separates literal organization text from derived aliases; deterministic
                      query builder emits at most 6 redacted variants and executes at most 4 sequential attempts
Runtime boundary: no official verification coordinator, search provider, fetch target or network behavior enabled
Migration/head: 0018_remove_vector_compat; no migration added
Commands run and result: backend canonical checks pass; CP3 safety/regression tests pass; frontend unit/lint/
                         typecheck pass; equivalent cutover scan passes
Known limitations: canonical frontend check:cutover is blocked by Node 24.14.1 URL-path encoding on this Unicode
                   workspace; official verification remains unintegrated until WP7
Required review: independent Security policy reviewer
Next WP entry conditions satisfied: implementation and automated CP3 gates are satisfied; independent review and
                                    commit/merge are required before WP4
```

## CP3-Owned Changes

```text
src/agents/security_scope.py
src/evaluation/security_ai_v1.py
src/services/security_understanding.py
src/services/official_verification_intent.py
tests/unit/test_official_link_verification_cp3.py
eval/results/official-link-verification-cp3-evidence.json
eval/results/official-link-verification-cp3-handoff.md
```

## Safety Boundary

- Every accepted entity, claim and action carries confidence and a non-empty source span.
- Semantic confidence below policy threshold cannot create verification work.
- English names and aliases are derived values with explicit provenance, never user source spans.
- Whole raw messages, URLs, emails, OTPs, credential assignments and token-like values cannot enter a query.
- Query variants are deterministic, bounded, deduplicated and attempted sequentially.
- AI understanding output remains unable to provide URLs or network targets.
- Incident exposure continues to bypass investigation/trust and enter recovery-first handling.
- No provider, coordinator, environment flag, migration or risk-policy behavior was introduced by WP3.

The pre-existing deleted pytest session artifacts listed in the evidence file were not modified or included in
WP3 ownership.
