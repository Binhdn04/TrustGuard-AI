# Deployment and Operations

Tài liệu hợp nhất Railway deployment và release/cutover runbook. Production gồm `frontend`, `backend`,
`worker`, `postgres`, `redis` trong cùng project/environment.

## Topology

1. Tạo managed PostgreSQL và Redis cùng region.
2. Backend: root `/`, config `/railway.backend.json`.
3. Worker: root `/`, config `/railway.worker.json`.
4. Frontend: root `/frontend`, config `/frontend/railway.json`.
5. Chỉ frontend/backend có public domain.

Backend là service duy nhất chạy `alembic upgrade head` ở pre-deploy. Worker không chạy migration.
Giữ Backend Watch Paths trống trong Railway Dashboard; `railway.backend.json` cũng đặt `watchPatterns: []` để
source, migration, dependency và Dockerfile changes không bị Railway bỏ qua. GitHub Actions chịu trách nhiệm xác
định service nào thực sự cần deploy.

## Production configuration

```dotenv
APP_ENV=production
DEMO_AUTH_ENABLED=false
DATABASE_URL=${{postgres.DATABASE_URL}}
REDIS_URL=${{redis.REDIS_URL}}
DATABASE_ENCRYPTION_KEY=<secret-at-least-32-characters>
OIDC_ISSUER=https://<tenant>/
OIDC_AUDIENCE=<api-audience>
OIDC_ROLES_CLAIM=roles
OIDC_ADMIN_ROLE=security_admin
CORS_ORIGINS=https://${{frontend.RAILWAY_PUBLIC_DOMAIN}}
SECURITY_RELEASE_PROFILE=pre_cutover
SECURITY_ASYNC_EXECUTION_ENABLED=false
LIVE_PROVIDERS_REQUIRED=false
SECURITY_PAGE_CAPTURE_ENABLED=false
```

Backend đặt `RUN_DURABLE_WORKER=false`; worker đặt `RUN_DURABLE_WORKER=true`. Frontend cần API URL và
OIDC Authorization Code + PKCE. Không đưa demo token vào hosted build. Chỉ thêm AI/provider secrets khi
capability được duyệt. Google Web Risk, Google Fact Check, Jina, flash model và ChromaDB không thuộc setup.

Page capture mặc định tắt. Chỉ bật `SECURITY_PAGE_CAPTURE_ENABLED=true` khi backend Chromium đã được giới hạn
egress khỏi private/metadata/service network; Docker image cài Chromium cho API target. Frontend tự yêu cầu ảnh
của URL mới nhất sau khi case có kết quả; chỉ Blob mới nhất nằm trong RAM của tab, Blob trước được thu hồi, không
lưu bền và response dùng `no-store`. Chromium không vượt CAPTCHA/access denial và chặn download, popup cùng
active stream. Tắt flag là rollback tức thời, không cần migration.

### Langfuse tracing

Tracing mặc định tắt. Cấu hình cùng một project key pair trên backend và worker, rồi bật gate sau khi kiểm tra
data region/base URL:

```dotenv
APP_ENV=production
LANGFUSE_TRACING_ENABLED=true
LANGFUSE_PUBLIC_KEY=<project-public-key>
LANGFUSE_SECRET_KEY=<project-secret-key>
LANGFUSE_BASE_URL=https://cloud.langfuse.com
LANGFUSE_SAMPLE_RATE=1.0
LANGFUSE_DEBUG=false
```

SDK chỉ gửi operation names, model/token/cost/latency, trạng thái chuẩn hóa, tags, environment, session UUID và
user ID đã HMAC. Prompt, completion, private message, provider error, credential, OTP, token và URL payload được
redact tại export boundary. Giảm `LANGFUSE_SAMPLE_RATE` theo volume/cost; rollback tức thời bằng
`LANGFUSE_TRACING_ENABLED=false`. Không đưa Langfuse keys vào frontend hoặc log.

Mỗi process ghi `langfuse_observability_initialized` hoặc `langfuse_observability_disabled` lúc startup với
chỉ host, environment, sample rate và trạng thái gate (không ghi key). Root request có cặp log
`langfuse_trace_started`/`langfuse_trace_completed`; shutdown sạch có `langfuse_shutdown_completed`. Nếu trace
không tới Langfuse dù các log này có mặt, tạm đặt `LANGFUSE_DEBUG=true` trên đúng service rồi redeploy để xem log
exporter của SDK; trả lại `false` sau khi điều tra vì debug log có độ ồn cao.

`APP_ENV` được truyền trực tiếp vào thuộc tính environment của Langfuse: local dùng `development`, còn cả
backend và worker trên Railway dùng `production`. Không cần cấu hình thêm `LANGFUSE_TRACING_ENVIRONMENT`.
Trên Railway, tạo `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY` và `LANGFUSE_BASE_URL` dưới Project Settings →
Shared Variables, seal secret key, rồi share/reference chúng vào đúng hai service `backend` và `worker`. Đặt
`APP_ENV=production`, `LANGFUSE_TRACING_ENABLED=true` và `LANGFUSE_SAMPLE_RATE` trên cả hai service; không share
các biến Langfuse sang `frontend`. Review và deploy staged changes, sau đó chạy một request v4 inline và một job
async (nếu async đang bật), rồi lọc `environment=production` trong Langfuse để xác minh cả hai execution path.

## Preflight and migration

Chạy toàn bộ checks trong [TESTING.md](TESTING.md). Trước migration destructive trên database cũ:

1. backup và ghi checksum/timestamp;
2. restore vào database rehearsal riêng;
3. drain legacy jobs/outbox nếu từng chạy v2/v3;
4. chạy `alembic upgrade head` trên staging copy;
5. xác minh v4, worker và dữ liệu cần giữ.

`0018_remove_vector_compat` không downgrade. Không chạy nếu chưa chứng minh restore.
`0019_security_identity_discovery` là additive và không tái tạo các bảng source-discovery/fact-check đã xóa.
Sau upgrade, kiểm tra candidate/evidence/decision tables và một Alembic head trước khi bật discovery rollout.

## Deploy and verify

Deploy backend → worker → frontend sau khi database dependency ready, rồi kiểm tra:

```bash
curl https://<backend-domain>/health
curl https://<backend-domain>/health/ready
curl https://<backend-domain>/api/v4/capabilities
```

Acceptance: readiness `200`; OpenAPI chỉ public v4; user/admin OIDC và RBAC pass; frontend không gọi
localhost/CORS lỗi; worker không crash-loop/duplicate job; polling/WebSocket fallback hoạt động; database,
Redis và worker không public; restart không mất dữ liệu.

## Rollout and rollback

Official-link verification đã được triển khai hoàn chỉnh; các bước dưới đây là hosted
rollout/release gate, không phải phần triển khai còn thiếu.

Bật riêng từng capability: understanding → planning → explanation → reviewed memory → admin copilot →
async. Official-link verification mặc định `visible`, dùng
`SECURITY_OFFICIAL_VERIFICATION_MODE=off|shadow|visible|enforced` và
phải đi theo thứ tự `off → shadow → visible → enforced`; Tavily/OpenAI không phải điều kiện startup cho stage
này. Web search vẫn yêu cầu `official_source_lookup=true` riêng trên từng request. Frontend mặc định gửi giá trị
này cùng `external_url_lookup=true`, nhưng backend vẫn giữ hai gate độc lập. Kiểm tra riêng capabilities
`official_link_verification`, `official_web_search_ready`, evaluation,
latency/cost/error và rollback sau mỗi stage. Chỉ đổi profile sang `cutover` sau hosted smoke, backup/restore và
load rehearsal.

Khi official-link verification có incident, rollback `enforced → visible → off`; thay đổi này không yêu cầu
database downgrade. Với incident khác: tắt flag mới bật, rollback application image, giữ schema. Không tự động downgrade/drop/restore
database để rollback code. Provider failure không được suy diễn thành `SAFE`; worker failure phải cho phép
quay về inline/polling path và giữ audit evidence.

Identity candidates đã persist được giữ nguyên khi rollback mode. `off` không discovery; `shadow` vẫn persist và
telemetry nhưng không đổi response/risk; `visible` chỉ hiển thị association; `enforced` mới áp dụng mismatch policy.
Không drop `0019` để rollback application vì quyết định reviewer là immutable audit data.

## Official-link CP10 hosted evidence

Run the Vietnamese hard-case smoke at every applicable observation stage using a reviewed message and a real OIDC
user token. The script emits only a minimized summary; store the protected raw deployment logs outside the repo.

```bash
LIVE_SMOKE_TOKEN=<oidc-user-token> TRUSTGUARD_BASE_URL=https://<backend-domain> \
  uv run python scripts/smoke_official_link_verification.py \
  "<reviewed Vietnamese recruitment message with the submitted third-party form URL>" \
  --output <stage-hard-case-summary.json>
```

The final hosted evidence must identify the deployed 40-character commit SHA and include reviewed checks named
`hosted_smoke`, `postgres_persistence`, `redis_worker`, `oidc_user`, `oidc_admin_rbac`, `backup_restore`, `ssrf`,
`prompt_injection`, `provider_failure`, `load` and `rollback`. Record positive-duration observation windows in the
exact sequence `shadow -> visible -> enforced -> visible -> off`. Each window records sample count, p95 latency,
maximum estimated provider cost, error rate and an evidence reference. The hard case records Vietnamese input,
English derived query, an actual official social source, short URL, third-party form, exact resource match, reference
closure and zero fabrication.

Pass the collected JSON through the hosted validator documented in `TESTING.md`. CP10 remains unapproved until the
generated hosted report passes and the tech lead and security lead review the referenced evidence. Offline fakes,
local SQLite tests and manually authored `passed` claims cannot substitute for PostgreSQL/Redis/worker, OIDC/RBAC,
backup/restore, live provider/failure, load or rollback observations.
