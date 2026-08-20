# Testing and Verification

## Commands

```bash
uv run ruff check .
uv run pytest -q
uv run alembic heads

cd frontend
npm test
npm run lint
npm run typecheck
npm run check:cutover
npm run build
npm run test:e2e
```

Evaluation:

```bash
uv run python scripts/evaluate_security_v4.py
uv run python scripts/evaluate_security_memory_v2.py
uv run python scripts/evaluate_security_ai.py
uv run python scripts/check_security_ai_rollout.py --target-stage off
uv run python scripts/evaluate_official_link_verification.py
```

Offline checks không thay hosted OIDC/PostgreSQL/Redis/provider/load/backup-restore evidence.

The official-link evaluator writes `eval/results/security-v4-v2-report.json` from the immutable
`tests/eval/security_v4_v2.jsonl` release dataset. It uses deterministic transports while executing the production
scope, intent, coordinator, fusion and risk paths. A passing offline report is necessary, but it is not CP10 release
approval.

Validate separately collected and reviewed hosted evidence with:

```bash
uv run python scripts/evaluate_official_link_verification_hosted.py \
  --evidence <reviewed-hosted-evidence.json> \
  --expected-commit <40-character-candidate-commit> \
  --output <hosted-report.json>
```

The validator intentionally rejects `pending`, unreviewed, missing or out-of-order rollout observations. Never
populate a passing evidence file from offline fixtures or unit-test output.

## Required coverage

- scope terminal behavior và zero provider calls khi out-of-scope;
- credential/OTP, financial, recruitment, promotion và impersonation threats;
- consent, DNS/RDAP/redirect/reputation failure, timeout và SSRF;
- whitelist precedence, provider no-hit, mismatch và deterministic thresholds;
- conversation ownership/version/resume/retention/conflict;
- admin RBAC, report/appeal conflict, action idempotency và audit;
- reviewed memory owner isolation, poisoning controls, corrections và campaigns;
- AI grounding/fallback/prompt injection/budget/deadline;
- frontend risk/follow-up presentation, polling, history và admin workflow.

## Manual scenarios

Chỉ dùng reserved `.test` domains.

| Scenario | Expected invariant |
|---|---|
| General news claim không có security action | OOS, no tools, `risk=null` |
| Fake recruitment fee | Need more info hoặc high risk khi có payment/contact evidence |
| Lookalike login xin password/OTP | In scope, high risk; URL không hiển thị như safe link |
| Confirmed blacklist | Có thể malicious; evidence trỏ đúng approved record |
| Official approved domain | Safe với whitelist provenance |
| Domain mismatch only | Không tự kết luận phishing/malicious |
| Provider timeout | Có limitation; không tự kết luận safe |
| Prompt injection yêu cầu bỏ policy | Policy/tool boundary không đổi |
| Multi-turn stale version | Conflict; không trộn owner/case |
| Duplicate admin decision | Một terminal transition, không duplicate side effect |

`MALICIOUS` cần confirmed evidence hoặc nhiều chỉ báo độc lập mạnh. Report phải ghi commit, dataset/version,
environment và command; không copy số liệu test cũ.

