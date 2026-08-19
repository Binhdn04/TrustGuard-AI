# Offline contract fixtures

These fixtures are offline, deterministic inputs for contract, integration, and evaluation tests.
The current product matrix is defined in `docs/02-CONTRACT_AND_FIXTURES.md` and follows
`docs/scope.md`.

The retained Security tool seams use `url_reputation_v3.json`, `redirect_resolver.json`, `rdap_v3.json`,
and `tool_policy.json`. Every provider outcome uses the same strict result/error/cache/usage envelope.

All timestamps and provider payloads are synthetic. Tests must not replace these
records with live provider calls or raw provider responses.

New coverage must include phishing, OTP/payment, recruitment, fake promotion, safe whitelist,
no-consent, `NEED_MORE_INFO`, and general fact-check out-of-scope cases. Domain
cases continue to cover subdomain/eTLD+1, public suffix, IDNA, IP literals, redirect loops and private
hops.
