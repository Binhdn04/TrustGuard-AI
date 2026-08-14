# WP9 Security v4 release and cutover runbook

**Trạng thái:** executable runbook đã có; các bước hosted/restore/compatibility phải được operator chạy và lưu evidence trước khi chuyển sang `cutover`.

Runbook này không tự drop legacy schema. `pre_cutover` là profile mặc định và là trạng thái đúng cho tới khi toàn bộ gate bên dưới đạt.

## 1. Release invariants

- Production dùng PostgreSQL, Redis, HTTPS OIDC/CORS và hai secret độc lập tối thiểu 32 ký tự.
- `LIVE_PROVIDERS_REQUIRED=true` kiểm tra Web Risk, official verifier và VirusTotal khi secondary reputation được bật.
  OpenAI không thuộc base Security v4/Web Risk readiness, nhưng cấu hình OpenAI hợp lệ là bắt buộc trước khi bật bất kỳ
  AI stage nào; Google Fact Check và Tavily vẫn không thuộc Security v4 readiness.
- `SECURITY_RELEASE_PROFILE=cutover` chỉ khởi động khi legacy write/source-discovery/provisional/promotion đã tắt và live-provider profile đầy đủ.
- `/api/v3/admin/actions` vẫn là reviewed-action compatibility contract; telemetry của nó tách khỏi legacy analysis.
- Redis là coordination/cache, không phải source of truth. PostgreSQL backup là recovery artifact bắt buộc.

## 2. Preflight và local release gate

Chạy từ repository root với đúng image/revision dự kiến release:

```powershell
.\.venv\Scripts\python.exe -c "from src.config import Settings; print(Settings().model_dump_json(include={'app_env','security_release_profile','live_providers_required','legacy_api_writes_enabled','source_discovery_enabled','source_provisional_enabled','source_auto_promotion_enabled'}))"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe scripts\evaluate_security_v4.py
.\.venv\Scripts\python.exe scripts\evaluate_security_memory_v2.py
.\.venv\Scripts\python.exe scripts\evaluate_security_ai.py
.\.venv\Scripts\python.exe scripts\check_security_ai_rollout.py --target-stage off
.\.venv\Scripts\python.exe -m alembic heads
```

Ba evaluation phải exit `0`, `passed=true`, có `dataset_sha256`; report được lưu ở `docs/evidence/security-v4-v1-report.json`,
`docs/evidence/security-memory-v2-v1-report.json` và `docs/evidence/security-ai-v1-report.json`. Đây là deterministic
offline evidence, không thay thế smoke hosted.

## 3. PostgreSQL backup và restore rehearsal

Đặt URI nguồn/restore trong secret manager hoặc session của operator; không commit credential. Restore target phải là database cô lập, không phải production.

```powershell
pg_dump --dbname "$env:WP9_SOURCE_DATABASE_URL" --format custom --no-owner --no-acl --file "wp9-precutover.dump"
pg_restore --list "wp9-precutover.dump"
createdb --maintenance-db "$env:WP9_RESTORE_ADMIN_URL" "wp9_restore_rehearsal"
pg_restore --dbname "$env:WP9_RESTORE_DATABASE_URL" --clean --if-exists --no-owner --no-acl --exit-on-error "wp9-precutover.dump"
$env:DATABASE_URL=$env:WP9_RESTORE_DATABASE_URL
.\.venv\Scripts\python.exe -m alembic current
.\.venv\Scripts\python.exe -m alembic upgrade head
```

Sau restore, kiểm tra tối thiểu row count và owner/audit consistency cho `security_analyses`, `security_analysis_events`, `security_conversations`, feedback/report/appeal, trust registry, Security Memory/campaign và action/audit tables. Lưu checksum SHA-256 của dump, thời gian backup/restore, Alembic revision, row counts và người thực hiện vào release evidence. Xóa restore DB chỉ theo change approval riêng.

Không dùng `alembic downgrade` làm rollback production. Migration WP0–WP9 là additive; rollback ứng dụng giữ schema hiện tại. Downgrade chỉ được rehearsal trên database disposable sau khi đã có verified backup.

## 4. Hosted readiness, OIDC và provider smoke

```powershell
$env:TRUSTGUARD_BASE_URL="https://api.example"
$env:LIVE_SMOKE_TOKEN="<short-lived OIDC user access token>"
.\.venv\Scripts\python.exe scripts\live_provider_smoke.py "Khoa tai khoan, dang nhap ngay tai https://public-test-target.example/login" --expect-risk HIGH_RISK
```

Smoke chỉ đạt khi `/health/ready` ready, API quảng bá Security v4, analysis hoàn thành, có network call, `url_reputation` evidence và explanation refs trỏ tới evidence trả về. Với brand/official fixture đã được reviewer đăng ký, chạy thêm `--require-official-verification`.

Thực hiện riêng:

- login/callback/refresh/logout bằng tenant OIDC thật cho user và admin;
- PostgreSQL restart, Redis restart, WebSocket ticket/stream và retention worker;
- RBAC/ownership/rate-limit/SSRF/redirect-revalidation/provider-timeout/idempotency regression;
- load test theo SLO đã duyệt cho cả inline compatibility và durable Security v4 worker. Durable path đã có trong revision `0016` nhưng chỉ được tuyên bố production-ready sau hosted lease-loss/idempotency/Redis-outage evidence; nếu SLO không đạt, tắt `SECURITY_ASYNC_EXECUTION_ENABLED` và giữ `pre_cutover`.
- bật `SECURITY_MEMORY_RETRIEVAL_ENABLED` trên fixture đã review để xác minh owner isolation, non-self match, pending/unreviewed exclusion, privacy-minimized evidence và `security-risk-v2`; nếu scoring/poisoning gate không đạt, tắt flag này để mọi turn mới quay lại `security-risk-v1`.

Thu observation AI thật theo `docs/templates/security-ai-hosted-evidence.example.json`, sau đó validate và kiểm tra
stage rollout tuần tự:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_security_ai_hosted.py --evidence hosted-observations.json --output docs/evidence/security-ai-hosted-release.json
.\.venv\Scripts\python.exe scripts\check_security_ai_rollout.py --target-stage understanding --hosted-report docs/evidence/security-ai-hosted-release.json
```

Thứ tự target bắt buộc: `understanding → conversation → explanation → planning → async_execution → reviewed_memory → admin_copilot`.
Mỗi stage phải chạy lại hosted gate. Rollback bằng tắt flag được report chỉ ra; không downgrade database.

## 5. Compatibility window và freeze

Trước window: drain toàn bộ legacy durable jobs, xác minh không còn scheduled fact-check/source-discovery producer, deploy:

```dotenv
SECURITY_RELEASE_PROFILE=pre_cutover
LEGACY_API_WRITES_ENABLED=false
SOURCE_DISCOVERY_ENABLED=false
SOURCE_PROVISIONAL_ENABLED=false
SOURCE_AUTO_PROMOTION_ENABLED=false
```

Export structured application logs đầy đủ của window đã định, sau đó chạy:

```powershell
.\.venv\Scripts\python.exe scripts\check_compatibility_window.py exported-http.jsonl --window-start 2026-08-01T00:00:00Z --window-end 2026-08-08T00:00:00Z --minimum-hours 168 --require-zero-legacy-reads --output docs/evidence/wp9-compatibility-window.json
```

Gate chỉ đạt khi window đủ dài, `legacy_read=legacy_write=0` và có Security v4 traffic. `reviewed_action_*` được báo cáo riêng và không bị tính nhầm là legacy fact-check usage. API telemetry chưa chứng minh DB/provider zero usage; operator phải đối chiếu job queue, provider dashboard/egress và PostgreSQL query telemetry trước cleanup.

## 6. Cutover, rollback và incident response

Chỉ sau evaluation, hosted smoke, restore rehearsal, load/security gate và compatibility gate đều đạt mới đổi:

```dotenv
SECURITY_RELEASE_PROFILE=cutover
LIVE_PROVIDERS_REQUIRED=true
LEGACY_API_WRITES_ENABLED=false
SOURCE_DISCOVERY_ENABLED=false
SOURCE_PROVISIONAL_ENABLED=false
SOURCE_AUTO_PROMOTION_ENABLED=false
```

Rollback ứng dụng: đưa frontend/backend về image đã duyệt trước đó, giữ additive schema, và chỉ mở lại legacy writes nếu incident commander xác nhận consumer rollback thực sự cần. Không drop/restore production database để rollback code.

Provider incident: tắt adapter bị lỗi hoặc secondary cascade theo cấu hình, giữ verdict ở insufficient/limited evidence, không chuyển no-hit/error thành `SAFE`; ghi incident window và affected analysis IDs từ privacy-minimized audit.

Scoring incident: rollback image/policy version, giữ evidence và audit cũ immutable. Security/privacy incident: revoke OIDC/session credentials, rotate provider/encryption/signing secrets theo phạm vi ảnh hưởng, cô lập export, bảo toàn audit và chạy notification procedure của tổ chức.

Destructive cleanup route/provider/table/pgvector là change riêng sau cutover observation. Bắt buộc có owner approval, verified restore và rollback rehearsal; không phải điều kiện được tự động thực hiện bởi script WP9.

## 7. Evidence checklist

- [x] Ba offline evaluation report pass và hash trùng dataset release.
- [ ] Hosted AI reliability/cost/latency/grounding/overturn report pass.
- [ ] Hosted user/admin OIDC lifecycle pass.
- [ ] Hosted PostgreSQL/Redis/readiness/provider/WebSocket/retention smoke pass.
- [ ] Backup checksum, isolated restore, row-count/audit validation pass.
- [ ] Security, reliability và load/SLO evidence pass.
- [ ] Zero legacy API + provider/job/DB usage window pass.
- [ ] Rollback/incident owner, image versions và on-call contacts đã ghi nhận.
- [ ] Cutover approval; sau đó mới đặt `SECURITY_RELEASE_PROFILE=cutover`.
