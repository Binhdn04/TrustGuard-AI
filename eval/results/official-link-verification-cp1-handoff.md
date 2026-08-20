# Official Link Verification CP1 Handoff

## Result

CP1 is implemented and verified in the local working tree. Inline `/api/v4/analyses` now executes through
the same `SecurityTriagePipeline` abstraction as the durable worker. A request-scoped
`TurnExecutionContext` owns the end-to-end monotonic deadline and shared AI, network-unit and estimated-cost
budgets. No official-source verification behavior is enabled in this checkpoint.

Machine-readable evidence is in `eval/results/official-link-verification-cp1-evidence.json`.

## Handoff

```text
WP/Checkpoint: WP1 / CP1
Commit SHA: f52c0a75b494927ae6d72e12a9a298e29e485c10 plus recorded dirty worktree
Contract/schema changes: none; OpenAPI SHA-256 matches CP0
Risk policy changes: none
Migration/head: 0018_remove_vector_compat; no migration added
Commands run and result: backend and frontend canonical checks pass
Checkpoint tests: inline/worker result parity, event order, OOS lazy boundary, shared budget and deadline pass
Known deferral: provider/redirect network-unit enforcement is owned by WP5
Next WP entry conditions satisfied: no; review and commit/merge CP1 before starting CP2
```

## CP1-Owned Changes

```text
src/agents/security_investigation.py
src/api/dependencies.py
src/api/security_v4.py (CP1 orchestration section only; this file also had pre-existing user changes)
src/security_ai/__init__.py
src/security_ai/runtime.py
src/services/security_pipeline.py
tests/test_api/test_security_pipeline_cp1.py
tests/unit/test_security_pipeline_cp1.py
eval/results/official-link-verification-cp1-evidence.json
eval/results/official-link-verification-cp1-handoff.md
```

The pipeline accepts either a concrete investigation service for the worker or a lazy resolver for the inline
route. Investigation and memory dependencies remain unresolved for terminal OOS turns. Memory resolution in
in-scope turns remains at its previous incident/non-incident stage to preserve side-effect ordering.

## Verification

```powershell
uv run --no-cache --no-sync ruff check .
uv run --no-cache --no-sync pytest -q -p no:cacheprovider --basetemp <new-workspace-data-path>
uv run --no-cache --no-sync alembic heads

cd frontend
npm.cmd test
npm.cmd run lint
npm.cmd run typecheck
npm.cmd run check:cutover
npm.cmd run build
npm.cmd run test:e2e
```

OpenAPI was hashed from canonical JSON using sorted keys and compact separators. Its current SHA-256 is
`94f4e934a9a93d2172493b091e4e0b218d75a200f4d28b46ba42750c3c7ddf0a`, identical to CP0.

## Existing Worktree Ownership

The CP0 handoff records pre-existing modified files. CP1 preserved those changes. In particular,
`src/api/security_v4.py` already contained unrelated edits; CP1 changed only the analysis orchestration path
and imports needed for that path. Review this file by hunk, not as wholly CP1-owned.

Do not update canonical current status until CP1 has been reviewed and merged.
