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
```

Offline checks không thay hosted OIDC/PostgreSQL/Redis/provider/load/backup-restore evidence.

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
- consent, DNS/RDAP/redirect/reputation failure, timeout và SSRF;
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
- bounded sender attribution không dùng registry riêng, attribution không tự tạo impersonation, two-consent
  ownership/cache, ba component domain/sender/action, neutral evidence projection, sensitive-login precedence,
  synthesis không suy rộng ownership và frontend compatibility với report cũ.
- URL-driven ownership applicability, action-driven endorsement applicability, registry-miss resource discovery,
  passport-service regression, sender-independent SAFE khi exact resource/action đã verified và `ALLOW_OPEN`.

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
