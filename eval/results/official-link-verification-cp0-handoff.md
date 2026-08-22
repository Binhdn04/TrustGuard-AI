# Official Link Verification CP0 Handoff

## Result

CP0 baseline and contract freeze are complete in the local working tree. The machine-readable contract,
environment and representative scope snapshot is in
`eval/results/official-link-verification-cp0-baseline.json`.

## Handoff

```text
WP/Checkpoint: WP0 / CP0
Commit SHA: f52c0a75b494927ae6d72e12a9a298e29e485c10 plus recorded dirty worktree
Contract/schema changes: none; proposed changes are frozen in docs/OFFICIAL_LINK_VERIFICATION_PLAN.md
Migration/head: 0018_remove_vector_compat; no migration added
Commands run and result: backend and frontend canonical checks pass
Ownership: role-based owner/reviewer matrix is frozen in the implementation plan
Known limitations: npm.ps1, default uv cache and default pytest temp paths are blocked by local ACL/policy;
                   the baseline records the non-mutating command workarounds
Next WP entry conditions satisfied: no; review and commit/merge the CP0 plan/evidence first
```

## Commands

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

## Existing worktree ownership

The following pre-existing modified files were included in the baseline but were not changed by CP0:

```text
src/agents/security_scope.py
src/api/security_v4.py
src/security_ai/openai.py
src/services/security_analysis.py
src/services/security_triage.py
src/services/security_understanding.py
tests/test_api/test_security_ai_wp1.py
tests/test_api/test_security_conversations_v4.py
tests/test_api/test_security_v4.py
tests/unit/test_security_ai_wp1.py
tests/unit/test_security_scope_v4.py
```

The CP0-owned files are the implementation plan and the two CP0 evidence files. CP1 must preserve the
pre-existing changes above and must not start until this checkpoint has been reviewed and merged.
