# Repository Instructions

TrustGuard AI is a Security Triage product. Public runtime is `/api/v4`; do not reintroduce public v2/v3,
general fact-check product behavior or vector-store dependencies.

Canonical docs: `docs/PRODUCT_ARCHITECTURE.md`, `docs/CURRENT_STATUS.md`, `docs/DEPLOYMENT.md`,
`docs/TESTING.md`.

Do not edit `docs/evidence`, `docs/gate1`, `docs/guide` or `docs/templates` unless explicitly requested.

## Development and verification

- Python 3.11+, FastAPI/Pydantic/PostgreSQL/Alembic; SQLite is local/test fallback.
- Next.js frontend is under `frontend/` and has additional local instructions.
- Prefer `uv run`; hook scripts use `scripts/_pyrun.cmd` or `scripts/_pyrun.sh`.
- Add an environment key/flag only when runtime consumes it and document its gate.
- Preserve unrelated user changes in a dirty worktree.
- Backend checks: `uv run ruff check .`, `uv run pytest -q`, `uv run alembic heads`.
- Frontend checks: `npm test`, `npm run lint`, `npm run typecheck`, `npm run check:cutover`.
- Update status only from current evidence; do not preserve stale test counts.

## Safety invariants

- Out-of-scope terminates before investigation/provider calls.
- AI never directly sets risk, score, consent, targets or admin decisions.
- External lookup needs request-scoped consent and SSRF/redirect validation.
- Provider no-hit/error/timeout does not imply `SAFE`.
- User reads are owner-scoped; admin APIs require `security_admin`.
- Do not persist raw private messages, credentials, OTPs, tokens or unnecessary URL queries.
- Admin Copilot remains suggestion-only; real actions require human review and immutable audit.
- Migration `0018_remove_vector_compat` is destructive; require verified backup/restore.

