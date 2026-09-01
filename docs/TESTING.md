# Testing and Verification

## Commands

```bash
uv run ruff check .
uv run pytest -q --cov --cov-report=term-missing --cov-report=xml:coverage.xml
uv run alembic heads

# PostgreSQL integration: point to a migrated disposable database.
DATABASE_URL=postgresql://app:app@localhost:5432/p068_integration uv run alembic upgrade head
TEST_DATABASE_URL=postgresql://app:app@localhost:5432/p068_integration \
  uv run pytest tests/integration -o addopts= -m integration -q

cd frontend
npm test
npm run lint
npm run typecheck
npm run check:cutover
npm run build
npm run test:e2e

cd ../extension
npm ci
npm run check
npm audit --audit-level=high
```

Verification gần nhất của workspace ngày 2026-08-28: Ruff đạt; backend mặc định `702 passed, 3 deselected`,
line coverage `69.36%` vượt gate `68%`; Alembic có một head `0022_action_assurance_metadata`. Coverage run còn
phát 6 `ResourceWarning` về SQLite connection chưa đóng; warning không làm fail gate nhưng chưa được coi là sạch.
Ba PostgreSQL integration case được tách sang job CI riêng, job này dựng PostgreSQL 16 disposable, chạy
`alembic upgrade head`,
rồi mới chạy marker `integration`. Máy local của snapshot này không có Docker daemon nên chưa tạo được bằng chứng
PostgreSQL thật tại local; CI integration phải pass trước merge. Frontend không được chạy lại trong thay đổi backend này.

Evaluation:

```bash
uv run python scripts/evaluate_security_v4.py
uv run python scripts/evaluate_security_memory_v2.py
uv run python scripts/evaluate_security_ai.py
uv run python scripts/check_security_ai_rollout.py --target-stage off
uv run python scripts/evaluate_official_link_verification.py
uv run python scripts/evaluate_security_langfuse.py validate
```

Offline checks không thay hosted OIDC/PostgreSQL/Redis/provider/load/backup-restore evidence.

Chrome Extension automated coverage phải bao gồm Manifest V3/permission và bundle gates, capture normalization,
trusted internal-message boundary, OIDC PKCE/state/nonce/token handling, exact API/web origin build validation,
consent/idempotency submit, ticket/WebSocket/cursor fallback, final-result rendering và fixed-host handoff. Manual
smoke dùng unpacked extension không được lưu raw capture, token, credential, OTP hoặc URL query vào evidence.

Streaming progress coverage phải kiểm tra backward-compatible event thiếu `progress_state`, queue order/full,
append failure và quiesce timeout; observer failure không được fail/retry job hoặc append sau final; OOS/
need-more-info không gọi investigation/provider; no-consent không phát lookup; payload không chứa raw message,
credential, OTP, token, tool args hay exception. Frontend cần bao phủ malformed/duplicate/out-of-order replay,
unknown-stage fallback, reconnect/polling parity, reset, accessibility và final fetch không bị presentation lỗi chặn.

### Langfuse Security Triage evaluation

`eval/test_cases.jsonl` is the versioned 40-case Vietnamese Security v4 dataset. Validate it locally before any
hosted operation. The evaluator loads the repository-root `.env` for local use; values already present in the
process environment take precedence. Langfuse credentials and experiment tokens must stay in environment variables
or the ignored `.env`, never in CLI arguments. Experiments use two dedicated test users:
`TRUSTGUARD_EVAL_CONSENTED_TOKEN` has granted account lookup consent and
`TRUSTGUARD_EVAL_NO_CONSENT_TOKEN` has denied it. Keep these test tokens local; do not add them to deployed
backend, worker, or frontend services. Tokens are never accepted as CLI arguments.

```bash
# Idempotently synchronize deterministic item IDs to the hosted dataset.
# LANGFUSE_* values are read from .env (or from pre-existing environment variables).
uv run python scripts/evaluate_security_langfuse.py sync

# Compare the judge with human-reviewed dev outputs before trusting judge metrics.
uv run python scripts/evaluate_security_langfuse.py calibrate-judge \
  --annotations <human-reviewed-dev-outputs.jsonl> \
  --judge-model gpt-4o-mini

# Run the deployed v4 endpoint as a hosted dataset experiment.
# TRUSTGUARD_EVAL_* tokens are also read from .env (or pre-existing environment variables).
uv run python scripts/evaluate_security_langfuse.py experiment \
  --api-base-url https://<backend-domain> \
  --judge-model gpt-4o-mini

# Diagnose linked historical observations; score attachment is opt-in.
uv run python scripts/evaluate_security_langfuse.py traces \
  --environment production --from-time 2026-08-01T00:00:00+00:00 \
  --trace-case-map <observation-to-case.json> \
  --output eval/results/security-langfuse-report.json
```

The deterministic evaluator is authoritative for scope, security action, tool policy, evidence-reference closure,
latency, and cost. The optional judge scores response completion, contextual precision, and semantic faithfulness;
calibrate it on the `dev` split before using the `test` split for quality claims. Historical redacted observations
without response or tool inventories are reported as `unavailable`, never silently converted to failures or passes.
No thresholds in this evaluator are release gates until the labels and judge calibration are reviewed.

Streaming-progress hosted rollout smoke (requires separately approved async staging, two real OIDC user tokens and
a reviewed non-sensitive message):

```bash
LIVE_SMOKE_TOKEN=<first-oidc-user-token> \\
LIVE_SMOKE_OTHER_OWNER_TOKEN=<second-oidc-user-token> \\
TRUSTGUARD_BASE_URL=https://<backend-domain> \\
  uv run python scripts/smoke_streaming_progress.py \\
  "<reviewed non-sensitive in-scope security message>" \\
  --output <sanitized-streaming-progress-summary.json>
```

The resulting summary is deployment evidence, not approval by itself. Run and document a separate Redis/WebSocket
outage while cursor polling remains available from PostgreSQL; never add tokens, message text, raw events or URL
queries to the evidence.

Official-link verification đã được triển khai hoàn chỉnh; các evaluator sau là regression/release
gate cho implementation hiện hành.

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
- account lookup consent (`pending`/grant/deny), DNS/RDAP/redirect/reputation failure, timeout và SSRF;
- whitelist precedence, provider no-hit, mismatch và deterministic thresholds;
- familiarity PSL/IDNA, Radar rank/bucket/no-hit/cache/timeout/429/circuit, consent và zero-call OOS;
- reviewed `platform_service` most-specific precedence, no content-owner inference, no official fetch/exact-resource
  verification; familiarity v5 không tạo `SAFE` và threat/sensitive context luôn giữ precedence;
- conversation ownership/version/resume/retention/conflict;
- admin RBAC, report/appeal conflict, action idempotency và audit;
- blacklist v4 list/proposal/review/add/disable/re-add, SQLite restart parity và report-linked remediation;
- từng report resolution, explicit Memory/whitelist side effect, blacklist pending cho tới review thứ hai và failed propagation;
- report/action audit giữ actor, timestamp, structured remediation reference và `admin_action_id` kể cả khi
  blacklist action bị reject hoặc execute thất bại;
- UI Duyệt bảo mật bao phủ confirm-safe, confirm-malicious, rejected/dismissed, remediation pending/success/failure
  và bước xác nhận blacklist riêng; UI Tin cậy & chặn bao phủ create/disable/history/error states;
- reviewed memory owner isolation, poisoning controls, corrections và campaigns;
- AI span-ID grounding, per-candidate fail-soft validation, fallback/prompt injection/budget/deadline;
- frontend risk/follow-up presentation, polling, history/filter, safe assistant Markdown, latest-URL page capture lifecycle
  và admin workflow;
- identity discovery query hygiene, literal-title queries, consent/SSRF/budget, non-terminal discovered-cache
  revalidation, guarded short-link chains, neutral-anchor exact-resource links, 7-day stale revalidation,
  one-source exact-resource endorsement, self-endorsement rejection, relationship evidence anchors,
  SQLite/PostgreSQL versioning, admin RBAC/terminal decisions/promotion và Trust candidate queue.
- attribution không tự tạo impersonation, two-consent ownership/cache, hai component domain/action,
  neutral evidence projection, sensitive-login precedence,
  synthesis không suy rộng ownership và frontend compatibility với report cũ.
- URL-driven ownership applicability, action-driven endorsement applicability, registry-miss resource discovery,
  passport-service regression, SAFE khi exact resource/action đã verified và `ALLOW_OPEN`.

## Manual scenarios

Chỉ dùng reserved `.test` domains.

| Scenario | Expected invariant |
|---|---|
| General news claim không có security action | OOS, no tools, `risk=null` |
| Fake recruitment fee | Need more info hoặc high risk khi có payment/contact evidence |
| Lookalike login xin password/OTP | In scope, high risk; URL không hiển thị như safe link |
| Confirmed blacklist | Có thể malicious; evidence trỏ đúng approved record |
| Official approved domain, không có identity conflict | Safe với whitelist provenance |
| Whitelisted domain thuộc entity khác với entity được claim | Tối thiểu `SUSPICIOUS`, không tự thành `MALICIOUS` |
| Domain mismatch only | Không tự kết luận phishing/malicious |
| Provider timeout | Có limitation; không tự kết luận safe |
| Prompt injection yêu cầu bỏ policy | Policy/tool boundary không đổi |
| Multi-turn stale version | Conflict; không trộn owner/case |
| Duplicate admin decision | Một terminal transition, không duplicate side effect |
| Report chưa review hoặc bị reject/dismiss | Không thay đổi risk/score và không tạo reviewed Memory/whitelist/blacklist evidence |
| Admin xác nhận false positive và thêm whitelist | Report/audit trỏ đúng whitelist; lần phân tích sau vẫn chạy pipeline và có approved-whitelist evidence |
| Admin xác nhận malicious và đề xuất blacklist | Report ở `pending` cho tới quyết định action thứ hai; chỉ action approved/executed mới tạo active blacklist |
| Blacklist action bị reject hoặc execution fail | Không tạo active blacklist; report remediation là `failed` và vẫn giữ action reference để audit |
| Phân tích lại domain đã blacklist | Pipeline vẫn chạy; approved-blacklist evidence có thể đưa verdict lên `MALICIOUS` theo policy |
| Search hit identity đơn lẻ | Chỉ `discovered`, 0 risk point, không `SAFE` |
| Reviewed exact third-party resource | `endorsed_third_party_service`; không mở trust cho partner domain |
| Explicit ownership conflict | Auto mismatch tối thiểu low risk; reviewer confirmation tối thiểu suspicious |
| Association quá 7 ngày | Không được dùng; consented request kế tiếp tạo version revalidation mới |
| Reviewed first-party / Radar top-10K, score 0 | Có thể `LOW_RISK`, không `SAFE`; `PROCEED_WITH_CAUTION` |
| Google Forms/shared platform chưa xác minh owner | Platform known; exact resource `UNVERIFIED`, không `SAFE` |
| Popular platform có threat hit hoặc credential/payment | Threat/context precedence; familiarity không suppress |
| Radar no-hit hoặc bucket >10K | Không negative evidence; không promote verdict |

`MALICIOUS` cần confirmed evidence hoặc nhiều chỉ báo độc lập mạnh. Report phải ghi commit, dataset/version,
environment và command; không copy số liệu test cũ.

## MVP hosted smoke trước release

Automated SQLite/API tests xác minh logic, nhưng không thay thế smoke trên deployment thật. Sau khi deploy backend,
worker và frontend, dùng hai danh tính OAuth riêng và lưu bằng chứng đã làm sạch:

1. User đăng nhập, tạo analysis và gửi report; user không gọi được admin API.
2. Admin đăng nhập, thấy report trong Duyệt bảo mật và chọn một resolution/remediation có cấu trúc.
3. Với whitelist, xác minh record active, provenance/report reference, re-analysis evidence và unified audit.
4. Với blacklist, xác minh report chỉ tạo proposal pending; approve ở bước review thứ hai mới tạo record active;
   sau đó re-analysis có approved-blacklist evidence và audit liên kết report/action/actor/time.
5. Lặp lại với rejected/dismissed report và rejected blacklist action; xác minh không có trust/risk side effect.
6. Logout từng role, xác minh session local/demo bị xóa nếu dùng local và hosted logout quay về login đúng cấu hình.

Không ghi access token, raw private message, OTP, credential hoặc URL query nhạy cảm vào ảnh/log/evidence.
