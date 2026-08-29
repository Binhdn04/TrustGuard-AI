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

`chrome_extension/phase0_cases.json` is the versioned capture/client characterization set for the Chrome Extension
Phase 0 review. It contains only synthetic selected text or an explicit link target, request-scoped consent and stable
scope/threat/risk and tool-plan projections. It intentionally excludes page URL/title, DOM/HTML, cookies, form fields
and browsing history. The fixture drives both extension-specific parity tests and the existing real investigation
call-order test.
