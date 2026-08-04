# Contract v1 fixtures

These fixtures are the offline, deterministic inputs for contract, integration,
and evaluation tests. `analyses.jsonl` contains the 12 frozen scenarios from
`docs/02-CONTRACT_AND_FIXTURES.md`.

The `mocks` values reference records in `tool_responses/`:

- URL scanner entries contain exactly one of `result` or `error`.
- Claim retriever entries contain exactly one of `results` or `error`.
- Blacklist entries contain the approved domains visible to that test.

All timestamps and provider payloads are synthetic. Tests must not replace these
records with live provider calls or raw provider responses.
