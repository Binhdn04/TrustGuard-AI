# Official Link Verification CP9 Handoff

## Result

WP9 is implemented and verified. The frontend consumes the CP8 v4 report directly, keeps submitted and suspicious
URLs as copyable plain text, and exposes separate simple and analyst presentations. Admin trust changes create an
immutable brand version through the supersede endpoint; the UI does not edit an existing trust record in place.

Machine-readable evidence is in `eval/results/official-link-verification-cp9-evidence.json`.

## Handoff

```text
WP/Checkpoint: WP9 / CP9
Base commit SHA: 885ceb41dbf833fdfe83740dc632c8c3cca0b491 (completed CP8)
Contract: generated v4 types cover verification intent/report, official identities/resources, consent and capabilities
Simple view: overall API conclusion plus API-recommended safe next actions
Analyst view: publisher, claim, resource, identity, source refs, outbound refs, canonical chain, strength and limitations
URL safety: report URLs render only in code/text containers with explicit copy buttons; no anchor/Link is created
Signal graph: risk edges remain restricted to returned evidence named by explanation_evidence_refs
Admin workflow: POST /api/v4/admin/brands/{brand_id}/versions with explicit review/confirmation and visible supersedes
Rollback visibility: capability-derived off, local-source and web-ready states; no hard-coded readiness claim
Commands: frontend focused 28 passed; full unit 75 passed; lint/typecheck/build pass; production E2E 2 passed;
          backend 381 passed; Ruff pass; Alembic head 0018_remove_vector_compat; equivalent cutover scan pass
Known limitation: canonical npm run check:cutover is environment-blocked because Node 24.14.1 keeps the Unicode
                  workspace path percent-encoded; the script's exact source patterns were scanned with zero matches
Required review: independent Backend contract reviewer
Next WP entry conditions: automated CP9 behavior is verified; independent review and commit/merge remain governance
```

## Safety Boundary

- The UI never upgrades verification status, risk, score, identity review state or recommended actions.
- A missing official-verification report renders no synthetic verification result.
- Non-applicable components are labeled as such and never receive an invented status.
- User, source and outbound URLs are plain text with a copy control; no report URL is an anchor.
- Analyst strength is the returned verification status, not a frontend-derived confidence score.
- The canonical chain shows only returned user and official resource identities; it does not invent redirect hops.
- Admin changes use the existing reviewed v4 version endpoint and preserve the superseded record for audit.
- Capability visibility comes from the v4 capability response and distinguishes unavailable, off, local and web-ready.
- No public v2/v3 route, general fact-check behavior or vector dependency was added.

The pre-existing deleted pytest session artifacts and generated Playwright last-run state were not included in WP9
ownership.
