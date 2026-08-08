# Offline contract fixtures

These fixtures are the offline, deterministic inputs for contract, integration,
and evaluation tests. `analyses.jsonl` contains the 12 frozen scenarios from
`docs/02-CONTRACT_AND_FIXTURES.md`.

The `mocks` values reference records in `tool_responses/`:

- URL scanner entries contain exactly one of `result` or `error`.
- Claim retriever entries contain exactly one of `results` or `error`.
- Blacklist entries contain the approved domains visible to that test.
- Wave 0 v3 tool seams use `url_reputation_v3.json`, `redirect_resolver.json`, `rdap_v3.json`,
  `screenshot_renderer.json`, and `tool_policy.json`. Every provider outcome uses the same strict
  result/error/cache/usage envelope.

All timestamps and provider payloads are synthetic. Tests must not replace these
records with live provider calls or raw provider responses.

Wave 1 extends the executable matrix in `tests/unit/test_tools_data_wave1.py`: claim-only input is
kept in `analyses.jsonl`; domain cases cover subdomain/eTLD+1, public suffix, IDNA and IP literals;
provider cases cover memory hits and disagreement; redirect cases cover loops and private hops.
