# Offline contract fixtures

These fixtures are offline, deterministic inputs for contract, integration, and evaluation tests.
The current product matrix is defined in `docs/02-CONTRACT_AND_FIXTURES.md` and follows
`docs/scope.md`.

The `mocks` values reference records in `tool_responses/`:

- URL scanner entries contain exactly one of `result` or `error`.
- Legacy claim-retriever entries contain exactly one of `results` or `error`; they must not be used
  as the expected product path for new tests.
- Blacklist entries contain the approved domains visible to that test.
- Wave 0 v3 tool seams use `url_reputation_v3.json`, `redirect_resolver.json`, `rdap_v3.json`,
  `screenshot_renderer.json`, and `tool_policy.json`. Every provider outcome uses the same strict
  result/error/cache/usage envelope.

All timestamps and provider payloads are synthetic. Tests must not replace these
records with live provider calls or raw provider responses.

Some frozen fixtures and tests still encode the previous general fact-check scope. Keep them only as
legacy regression coverage during migration; do not copy their claim-only routing into new product
fixtures. New coverage must include phishing, OTP/payment, recruitment, fake promotion, safe official,
official `NOT_FOUND`, no-consent, `NEED_MORE_INFO`, and general fact-check out-of-scope cases. Domain
cases continue to cover subdomain/eTLD+1, public suffix, IDNA, IP literals, redirect loops and private
hops.
