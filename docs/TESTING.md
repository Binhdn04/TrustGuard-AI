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
```

Offline checks không thay hosted OIDC/PostgreSQL/Redis/provider/load/backup-restore evidence.

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

