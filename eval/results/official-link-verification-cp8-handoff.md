# Official Link Verification CP8 Handoff

## Result

WP8 implementation is complete and verified. Production inline and durable-worker pipelines now share the
`off|shadow|visible|enforced` rollout stage. Only `enforced` selects deterministic `security-risk-v3`; all other
modes preserve v1/v2 risk fields, and shadow outcomes never enter the public or persisted analysis response.

Machine-readable evidence is in `eval/results/official-link-verification-cp8-evidence.json`.

## Handoff

```text
WP/Checkpoint: WP8 / CP8
Base commit SHA: 1ed8a45335b3ec3221ac5ff9de96b20c4506b6b9 (completed CP7)
Contract/schema changes: no new database or public response schema; CP2 report/capability fields and
                         security-risk-v3 policy literal are now activated behind the WP8 rollout setting
Risk policy: VERIFIED suppresses only mismatch/lookalike-style Brand Registry contributions with reviewed-brand
             provenance and a verified matching target; strong/sensitive/incident evidence is never suppressed;
             CONFLICTING contributes at most 25; UNVERIFIED/no-hit/not-applicable contributes zero
SAFE boundary: complete applicable VERIFIED report, no report limitation, no sensitive action, no tool error and
               no malicious reputation/blacklist indicator
Rollout: off=no stage; shadow=aggregate telemetry only; visible=report plus risk v1/v2;
         enforced=report plus risk v3
Provider boundary: exact reviewed identity/direct verification remains available without Tavily; missing Tavily
                   produces partial/unverified output and never fails startup; OpenAI is not required
Telemetry: only analysis ID, stage, provider, operation, aggregate counts, latency, cost, status, strength,
           target hash and normalized error code; adapter attempts and actual network units remain distinct
Capabilities: official_link_verification and official_web_search_ready are advertised independently while an
              off deployment remains byte-compatible with the previous capabilities response
Rollback: enforced -> visible -> off; no database downgrade or migration
Migration/head: 0018_remove_vector_compat; no migration added
Commands run and result: CP8 focused 16 passed; CP7/CP8/risk/config regression 56 passed; full backend 381 passed;
                         Ruff, lock and Alembic pass; frontend 67 passed plus lint/typecheck/equivalent cutover scan
Known limitations: canonical frontend check:cutover is blocked by Node 24.14.1 URL-path encoding on this Unicode
                   workspace; independent CP7/CP8 review evidence has not been provided
Required review: independent Security risk policy reviewer
Next WP entry conditions: automated CP8 gates pass; independent review and commit/merge remain release governance
```

## CP8-Owned Changes

```text
.env.example
docs/DEPLOYMENT.md
src/agents/security_risk.py
src/api/dependencies.py
src/api/security_v4.py
src/config.py
src/core/logging.py
src/main.py
src/services/official_verification_rollout.py
src/services/security_pipeline.py
tests/conftest.py
tests/unit/test_official_link_verification_cp8.py
eval/results/official-link-verification-cp8-evidence.json
eval/results/official-link-verification-cp8-handoff.md
```

## Safety Boundary

- `off` does not construct or invoke an old/new official verifier and preserves the existing Security v4 path.
- `shadow` calls `coordinate()` directly, logs one redacted aggregate event and returns the original scope object;
  report, limitations and tool-call counters are not attached to persisted/public output.
- `visible` attaches the bounded CP2 report but calls the unchanged risk-v1/v2 policy.
- `enforced` is the only path that selects risk-v3, including conservative fallback when search or AI is absent.
- VERIFIED suppression requires a Brand Registry evidence type, `brand:` provenance, a suppressible signal and a
  verified source/resource target match. Reputation, blacklist, punycode, credentials, OTP, payment, personal data
  and recovery-first exposure cannot be suppressed.
- Unexpected coordinator failures normalize to telemetry/error limitations without exception detail or raw input;
  they cannot upgrade a result to SAFE.
- Rollout state is configuration-only. Moving `enforced -> visible -> off` does not mutate or downgrade the database.
- No raw query, private message, URL, context, credential, OTP, token or provider response is logged by WP8 telemetry.
- No legacy fact-check orchestrator, public v2/v3 route, general fact-check behavior or vector dependency was added.

The pre-existing deleted pytest session artifacts listed in the evidence file were not modified or included in
WP8 ownership.
