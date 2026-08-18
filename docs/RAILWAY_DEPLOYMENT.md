# Railway production deployment

Runbook này triển khai TrustGuard AI thành năm service trong cùng một Railway project:
`frontend`, `backend`, `worker`, `postgres`, `redis`. Production dùng OIDC thật; demo auth
và demo token không được phép xuất hiện trong frontend bundle.

## 1. Topology và thứ tự tạo service

Tạo service theo thứ tự sau trong cùng environment và cùng region gần Việt Nam nhất:

1. `postgres`: dùng Railway managed PostgreSQL mặc định. Migration chỉ cần `pgcrypto`;
   flow Security v4 không còn phụ thuộc pgvector hoặc vector search.
2. `redis`: dùng Railway managed Redis.
3. `backend`: kết nối GitHub branch `LeTrungHieu`, root directory `/`, config path
   `/railway.backend.json`.
4. `worker`: kết nối cùng repo/branch, root directory `/`, config path
   `/railway.worker.json`.
5. `frontend`: kết nối cùng repo/branch, root directory `/frontend`, config path
   `/frontend/railway.json`.

Chỉ generate public domain cho `backend` và `frontend`. Không bật public networking cho
worker, PostgreSQL hoặc Redis. Sau khi thay đổi config/variables, review staged changes rồi
deploy database trước, backend/worker sau và frontend cuối.

`railway.backend.json` là service duy nhất chạy `alembic upgrade head` ở pre-deploy.
Migration failure phải chặn deployment mới. Worker không chạy migration. Docker Compose
local vẫn chạy migration trong backend command trước khi khởi động Uvicorn.

## 2. Variables

Tên service phải giữ đúng như trên vì reference variables dùng tên làm namespace.

### Shared cho backend và worker

Tạo các shared variables sau, share cho cả `backend` và `worker`, rồi seal các secret:

```dotenv
APP_ENV=production
DEMO_AUTH_ENABLED=false
DATABASE_ENCRYPTION_KEY=<random-secret-at-least-32-characters>
OIDC_ISSUER=https://<tenant>/
OIDC_AUDIENCE=<api-audience>
OIDC_ROLES_CLAIM=roles
OIDC_ADMIN_ROLE=security_admin
CORS_ORIGINS=https://${{frontend.RAILWAY_PUBLIC_DOMAIN}}
SECURITY_RELEASE_PROFILE=pre_cutover
SECURITY_ASYNC_EXECUTION_ENABLED=false
SECURITY_AI_UNDERSTANDING_ENABLED=false
SECURITY_AI_PLANNING_ENABLED=false
SECURITY_AI_EXPLANATION_ENABLED=false
SECURITY_MEMORY_RETRIEVAL_ENABLED=false
SECURITY_ADMIN_COPILOT_ENABLED=false
LIVE_PROVIDERS_REQUIRED=false
LOG_LEVEL=INFO
```

`OIDC_JWKS_URL` là optional; để trống sẽ dùng JWKS discovery từ issuer. Provider keys như
`OPENAI_API_KEY`, `VIRUSTOTAL_API_KEY`, `GOOGLE_WEB_RISK_API_KEY`,
`GOOGLE_SAFE_BROWSING_API_KEY` chỉ thêm
khi capability tương ứng được duyệt bật. Seal mọi API key.

### Backend

```dotenv
DATABASE_URL=${{postgres.DATABASE_URL}}
REDIS_URL=${{redis.REDIS_URL}}
RUN_DURABLE_WORKER=false
```

Không tự đặt `PORT`; Railway inject biến này và Dockerfile bind đúng giá trị đó. Generate
domain backend trước khi build frontend.

### Worker

```dotenv
DATABASE_URL=${{postgres.DATABASE_URL}}
REDIS_URL=${{redis.REDIS_URL}}
RUN_DURABLE_WORKER=true
```

Worker là always-on service, một replica ban đầu và không có public domain/HTTP healthcheck.
Nó xử lý durable jobs, outbox và retention. Async API vẫn bị khóa bởi
`SECURITY_ASYNC_EXECUTION_ENABLED=false` trong rollout đầu.

### Frontend

Các biến `NEXT_PUBLIC_*` được bake lúc `npm run build`; đổi biến phải redeploy frontend.

```dotenv
NEXT_PUBLIC_API_URL=https://${{backend.RAILWAY_PUBLIC_DOMAIN}}
NEXT_PUBLIC_OIDC_ISSUER=https://<tenant>/
NEXT_PUBLIC_OIDC_CLIENT_ID=<public-spa-client-id>
NEXT_PUBLIC_OIDC_AUDIENCE=<api-audience>
NEXT_PUBLIC_OIDC_REDIRECT_URI=https://${{frontend.RAILWAY_PUBLIC_DOMAIN}}/auth/callback
NEXT_PUBLIC_OIDC_LOGOUT_URL=<provider-logout-url-with-frontend-return-url>
NEXT_PUBLIC_OIDC_ROLES_CLAIM=roles
NEXT_PUBLIC_OIDC_ADMIN_ROLE=security_admin
NEXT_PUBLIC_OIDC_SCOPE=openid profile email offline_access
```

Chỉ khai báo `NEXT_PUBLIC_OIDC_AUTHORIZATION_ENDPOINT` và `NEXT_PUBLIC_OIDC_TOKEN_ENDPOINT`
nếu IdP không hỗ trợ discovery đúng chuẩn. Không khai báo `NEXT_PUBLIC_DEMO_USER_TOKEN`,
`NEXT_PUBLIC_DEMO_ADMIN_TOKEN` hoặc bất kỳ secret nào có prefix `NEXT_PUBLIC_`.

## 3. OIDC và deploy

Sau khi frontend có domain, cấu hình public SPA client tại IdP:

- Allowed callback: `https://<frontend-domain>/auth/callback`
- Allowed logout/return URL: `https://<frontend-domain>`
- Allowed web origin/CORS origin: `https://<frontend-domain>`
- Authorization Code Flow với PKCE; không đặt client secret trong frontend.
- Access token audience phải khớp `OIDC_AUDIENCE`; admin token phải có role
  `security_admin` trong claim đã cấu hình.

Redeploy backend sau khi reference frontend domain được resolve. Redeploy frontend sau khi
toàn bộ OIDC và backend-domain variables đã có. Không bật cutover hoặc async trong lần đầu.

## 4. Verification

Kiểm tra deployment logs của backend phải có Alembic upgrade thành công trước khi image mới
được activate. Sau đó chạy:

```bash
curl https://<backend-domain>/health
curl https://<backend-domain>/health/ready
curl https://<backend-domain>/api/v4/capabilities
```

Acceptance criteria:

- `/health/ready` trả `200` với database và Redis healthy.
- `/api/v4/capabilities` không quảng bá async ở rollout đầu.
- Frontend tải được, gọi API không gặp CORS error và không trỏ về localhost.
- Login/callback/logout pass với cả user và security admin; user không truy cập admin route.
- Worker logs cho thấy startup thành công, không crash-loop và không tạo duplicate jobs.
- PostgreSQL/Redis/worker không có public domain.
- Restart backend/worker không mất dữ liệu; chạy lại `alembic upgrade head` không tạo thay đổi.

## 5. Rollback và troubleshooting

Rollback frontend/backend/worker về deployment/image đã duyệt trước đó; giữ nguyên database
schema vì migrations là additive. Không chạy `alembic downgrade`, drop database hoặc restore
production chỉ để rollback code. Nếu migration pre-deploy fail, giữ deployment cũ phục vụ,
kiểm tra `DATABASE_URL`, sửa migration rồi redeploy.

- Backend không start: kiểm tra production validation cho OIDC, HTTPS CORS, PostgreSQL,
  Redis và `DATABASE_ENCRYPTION_KEY`.
- Readiness `503`: xem field `checks` để phân biệt database, Redis hoặc provider.
- Frontend gọi localhost/URL cũ: sửa `NEXT_PUBLIC_API_URL` rồi rebuild/redeploy frontend.
- OIDC callback fail: so khớp chính xác scheme/domain/path, issuer có trailing slash và audience.
- Worker crash-loop: xác minh shared variables, database migrations và `RUN_DURABLE_WORKER=true`.

Chỉ sau hosted OIDC/provider/PostgreSQL/Redis/load/backup-restore evidence mới bật từng AI
flag hoặc `SECURITY_ASYNC_EXECUTION_ENABLED`. Chuyển `SECURITY_RELEASE_PROFILE=cutover` là
một rollout riêng theo `WP9_RELEASE_RUNBOOK.md`, không thực hiện cùng deployment đầu tiên.
