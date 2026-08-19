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
```

Backend đặt `RUN_DURABLE_WORKER=false`; worker đặt `RUN_DURABLE_WORKER=true`. Frontend cần API URL và
OIDC Authorization Code + PKCE. Không đưa demo token vào hosted build. Chỉ thêm AI/provider secrets khi
capability được duyệt. Google Web Risk, Google Fact Check, Jina, flash model và ChromaDB không thuộc setup.

## Preflight and migration

Chạy toàn bộ checks trong [TESTING.md](TESTING.md). Trước migration destructive trên database cũ:

1. backup và ghi checksum/timestamp;
2. restore vào database rehearsal riêng;
3. drain legacy jobs/outbox nếu từng chạy v2/v3;
4. chạy `alembic upgrade head` trên staging copy;
5. xác minh v4, worker và dữ liệu cần giữ.

`0018_remove_vector_compat` không downgrade. Không chạy nếu chưa chứng minh restore.

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

Bật riêng từng capability: understanding → planning → explanation → reviewed memory → admin copilot →
async. Kiểm tra evaluation, capabilities, latency/cost/error và rollback sau mỗi stage. Chỉ đổi profile sang
`cutover` sau hosted smoke, backup/restore và load rehearsal.

Khi incident: tắt flag mới bật, rollback application image, giữ schema. Không tự động downgrade/drop/restore
database để rollback code. Provider failure không được suy diễn thành `SAFE`; worker failure phải cho phép
quay về inline/polling path và giữ audit evidence.

