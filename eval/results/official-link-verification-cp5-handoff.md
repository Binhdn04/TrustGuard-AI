# Official Link Verification CP5 Handoff

## Result

WP5 implementation is complete and verified. Official-link verification now has provider-neutral one-query
search and bounded extract contracts, standalone Tavily adapters, and a guarded HTML fetcher that shares the
request-scoped network budget across every direct redirect hop. Provider errors return normalized limitations
without generating citation substitutes.

Machine-readable evidence is in `eval/results/official-link-verification-cp5-evidence.json`.

## Handoff

```text
WP/Checkpoint: WP5 / CP5
Base commit SHA: 843c722 (completed CP4)
Provider boundary: WebSearchProvider.search_one and WebExtractProvider.extract use normalized envelopes;
                   Tavily adapters are independent of FactCheckOrchestrator
Direct fetch boundary: GuardedHtmlFetcher accepts only HTML/XHTML, at most 1 MB and 5 redirects; every hop is
                       DNS/SSRF revalidated and connected through the pinned validated address
Budget/telemetry: every provider request and direct HTTP hop reserves one TurnExecutionContext network unit;
                  adapter attempts/tool_calls_used remain distinct from actual network units
Failure behavior: timeout, 429, provider errors, unsafe targets, redirect failures, oversized and non-HTML
                  responses return stable limitation codes and no substitute citation
Offline behavior: missing Tavily returns provider_unavailable while local/exact-registry verification stays available
Migration/head: 0018_remove_vector_compat; no migration added
Commands run and result: backend canonical checks pass; CP5 security/regression tests pass; frontend unit/lint/
                         typecheck pass; equivalent cutover scan passes
Known limitations: canonical frontend check:cutover is blocked by Node 24.14.1 URL-path encoding on this Unicode
                   workspace; HTML parsing/resource identity remain WP6 and coordinator invocation remains WP7
Required review: independent SSRF/security reviewer
Next WP entry conditions satisfied: implementation and automated CP5 gates are satisfied; independent review and
                                    commit/merge are required before WP6
```

## CP5-Owned Changes

```text
src/agents/tools/network.py
src/services/official_verification_transport.py
tests/unit/test_official_link_verification_cp5.py
eval/results/official-link-verification-cp5-evidence.json
eval/results/official-link-verification-cp5-handoff.md
```

## Security Boundary

- Query input is bounded and rejects URLs, emails and labeled credential/token material before a provider call.
- Tavily endpoint redirects are rejected; untrusted provider payloads are size-bounded and structurally normalized.
- Direct HTTP validates scheme, credentials, port, host and every DNS answer before each send.
- DNS pinning retains the original Host/SNI while connecting to the exact validated address.
- Redirects are resolved manually, revalidated per hop, loop-detected and capped at five.
- The seventeenth network unit is rejected before send; its adapter attempt remains visible with zero network units.
- Raw HTML/extracted content is available only in-memory and excluded from envelope serialization.
- Missing provider configuration does not disable the local registry path.
- No coordinator, rollout flag, public response field, migration or risk-policy behavior was introduced by WP5.

The pre-existing deleted pytest session artifacts listed in the evidence file were not modified or included in
WP5 ownership.
