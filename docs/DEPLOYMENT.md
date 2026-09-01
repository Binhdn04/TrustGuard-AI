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

## CD reconciliation

CD dùng mô hình desired/actual state theo từng service:

- Desired state là SHA hiện tại của `main` tại lúc workflow bắt đầu.
- Actual state là tag `deploy/backend`, `deploy/worker` hoặc `deploy/frontend`; mỗi tag chỉ được cập nhật sau khi
  Railway deploy service tương ứng thành công.
- Workflow chạy `git diff <actual-sha> <desired-sha>` và chỉ deploy service có production build input thay đổi.
  Chưa có tag actual thì service được deploy lần đầu.

Các tag deployment là mutable state, vì vậy chỉ GitHub Actions production được phép cập nhật chúng. Mỗi cập nhật
dùng Git force-with-lease với ref đã đọc khi reconcile; workflow sẽ fail thay vì ghi đè nếu tag bị thay đổi trong
lúc deploy. Workflow concurrency `railway-production` cũng tuần tự hóa các lần CD. Deploy thất bại không cập nhật
tag; lần chạy sau tiếp tục reconcile từ SHA deployed thành công gần nhất.

## Production configuration

```dotenv
APP_ENV=production
DEMO_AUTH_ENABLED=false
DATABASE_URL=${{postgres.DATABASE_URL}}
REDIS_URL=${{redis.REDIS_URL}}
DATABASE_ENCRYPTION_KEY=<secret-at-least-32-characters>
OIDC_ISSUER=https://<tenant>/
OIDC_AUDIENCE=<api-audience>
OIDC_ROLES_CLAIM=<api-audience>/roles
OIDC_ADMIN_ROLE=security_admin
CORS_ORIGINS=https://${{frontend.RAILWAY_PUBLIC_DOMAIN}}
# Empty until this environment has a reserved, stable extension ID.
CHROME_EXTENSION_ORIGINS=
IP_RATE_LIMIT_PER_MINUTE=240
# Leave empty unless this backend is reached through a deployment-controlled
# proxy. When configured, use only its IP/CIDR; never trust a public header.
TRUSTED_PROXY_IPS=
SECURITY_RELEASE_PROFILE=pre_cutover
SECURITY_ASYNC_EXECUTION_ENABLED=false
LIVE_PROVIDERS_REQUIRED=false
BKNS_WHOIS_API_KEY=
SECURITY_PAGE_CAPTURE_ENABLED=false
SECURITY_DOMAIN_FAMILIARITY_MODE=off
SECURITY_AI_MAX_CALLS_PER_TURN=8
SECURITY_AI_MAX_RETRIES=1
SECURITY_INVESTIGATION_MAX_EXTERNAL_CALLS=16
# CLOUDFLARE_RADAR_API_TOKEN=<optional-secret>
```

Backend đặt `RUN_DURABLE_WORKER=false`; worker đặt `RUN_DURABLE_WORKER=true`. Frontend cần API URL và
OIDC Authorization Code + PKCE. Không đưa demo token vào hosted build. Chỉ thêm AI/provider secrets khi
capability được duyệt. Google Web Risk, Google Fact Check, Jina, flash model và ChromaDB không thuộc setup.

`BKNS_WHOIS_API_KEY` là optional và không thuộc `LIVE_PROVIDERS_REQUIRED`. Khi có key, runtime dùng
[BKNS WHOIS API v2](https://whois.bkns.vn/vi/docs) cho registrable domain kết thúc bằng `.vn`, và làm fallback
cho domain khác chỉ khi IANA không công bố RDAP service. Khi để rỗng, toàn bộ domain giữ hành vi IANA RDAP hiện tại.

### Auth0 USER / Security Admin

Role contract của ứng dụng chỉ có `user` và `security_admin`. `user` là least-privilege mặc định cho mọi tài
khoản public signup; chỉ operator được gán role Auth0 `security_admin`. Frontend dùng role để trình bày navigation,
nhưng access token đã được FastAPI xác minh mới là authorization boundary. Không bật demo auth để xử lý sự cố
production.

1. Trong **Applications → APIs**, tạo API với Identifier ổn định, ví dụ
   `https://api.trustguard.example`, signing algorithm `RS256`, access-token lifetime 900 giây và Allow Offline
   Access. Bật RBAC; không bật Add Permissions in Access Token vì release này authorize theo role hai cấp.
2. Trong **Applications → Applications**, tạo Single Page Application dùng Universal Login. Bật Authorization
   Code và Refresh Token grant, Refresh Token Rotation/reuse detection, idle lifetime 24 giờ và absolute lifetime
   7 ngày. Database connection phải cho phép signup.
3. Sau khi Railway đã cấp domain, allow-list chính xác, không dùng wildcard:
   - callback: `https://<frontend-domain>/auth/callback`;
   - logout: `https://<frontend-domain>/login`;
   - Allowed Web Origins và Allowed Origins (CORS): `https://<frontend-domain>`.
4. Trong **User Management → Roles**, tạo `security_admin`. Chỉ gán role này thủ công cho reviewer/admin đã
   được duyệt; không tự cấp theo email hoặc domain.
5. Tạo Post Login Action dưới đây, thay `ROLE_CLAIM` bằng đúng `<api-audience>/roles`, deploy Action và kéo nó
   vào Login Flow:

```javascript
exports.onExecutePostLogin = async (event, api) => {
  const ROLE_CLAIM = "https://api.trustguard.example/roles";
  const assignedRoles = event.authorization?.roles ?? [];
  const applicationRoles = assignedRoles.includes("security_admin")
    ? ["security_admin"]
    : ["user"];

  api.accessToken.setCustomClaim(ROLE_CLAIM, applicationRoles);
  api.idToken.setCustomClaim(ROLE_CLAIM, applicationRoles);
};
```

Access-token claim điều khiển backend; ID-token claim chỉ điều khiển UI. Nếu claim thiếu, không nhận diện được hoặc
không chứa `security_admin`, ứng dụng hạ quyền xuống `user`. Sau khi cấp/gỡ admin role, yêu cầu người dùng đăng nhập
lại để thay đổi có hiệu lực ngay; nếu không, access token cũ có thể còn hợp lệ tối đa 15 phút.

### Railway OIDC variables

Gắn `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_ROLES_CLAIM` và `OIDC_ADMIN_ROLE` vào cả backend và worker vì cả hai
khởi động với production settings. Chỉ backend nhận public traffic và thực hiện JWT verification. Frontend đặt:

```dotenv
NEXT_PUBLIC_API_URL=https://${{backend.RAILWAY_PUBLIC_DOMAIN}}
NEXT_PUBLIC_OIDC_ISSUER=https://<tenant>.auth0.com/
NEXT_PUBLIC_OIDC_CLIENT_ID=<spa-client-id>
NEXT_PUBLIC_OIDC_AUDIENCE=<api-audience>
NEXT_PUBLIC_OIDC_REDIRECT_URI=https://${{frontend.RAILWAY_PUBLIC_DOMAIN}}/auth/callback
NEXT_PUBLIC_OIDC_ROLES_CLAIM=<api-audience>/roles
NEXT_PUBLIC_OIDC_ADMIN_ROLE=security_admin
NEXT_PUBLIC_OIDC_SCOPE=openid profile email offline_access
NEXT_PUBLIC_OIDC_LOGOUT_URL=https://<tenant>.auth0.com/v2/logout?client_id=<spa-client-id>&returnTo=<url-encoded-frontend-login>
```

Không đặt `NEXT_PUBLIC_DEMO_USER_TOKEN` hoặc `NEXT_PUBLIC_DEMO_ADMIN_TOKEN` trên hosted service. `NEXT_PUBLIC_*`
được đóng vào Next.js bundle trong Docker build, nên thay đổi biến phải redeploy frontend. Authorization/token
endpoint overrides để trống khi dùng endpoint chuẩn suy ra từ issuer. `CORS_ORIGINS` của backend phải là
`https://${{frontend.RAILWAY_PUBLIC_DOMAIN}}`.

### Chrome Extension origin allow-list

Backend ghép hai allow-list exact cho HTTP CORS và WebSocket handshake:

- `CORS_ORIGINS`: web origins `http://`/`https://`; production chỉ HTTPS.
- `CHROME_EXTENSION_ORIGINS`: các origin exact dạng `chrome-extension://<32-character-id>`; để trống khi extension
  chưa được bật cho environment.

Không chấp nhận wildcard, credential, path, query hoặc fragment. WebSocket thiếu `Origin` hoặc có origin không
được duyệt bị từ chối trước khi ticket single-use bị consume; ticket, owner check và JWT/RBAC vẫn là authorization
boundary. Không commit unpacked ID local. Trước hosted rollout, reserve ID riêng cho từng environment, đăng ký exact
OIDC redirect URI và cấu hình exact origin tương ứng; Store production ID được quản lý riêng.

Build extension chỉ nhận exact API và web origins. API origin được cấp host permission/CSP cho HTTP(S)/WS(S); web
origin chỉ dùng để tạo link `/cases/{validatedAnalysisId}`, không cấp host permission và không mang query/raw capture.

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
# Optional: capture scrubbed request/response content for debugging.
LANGFUSE_CAPTURE_SANITIZED_CONTENT=false
```

Mặc định SDK chỉ gửi operation names, model/token/cost/latency, trạng thái chuẩn hóa, tags, environment, session UUID và
user ID đã HMAC. Để debug, đặt `LANGFUSE_CAPTURE_SANITIZED_CONTENT=true`: trace root sẽ có request/response đã scrub
(credential, OTP, token, email, URL credentials và URL query bị che). Prompt/completion từ provider, private context và
provider error vẫn bị redact tại export boundary. Giảm `LANGFUSE_SAMPLE_RATE` theo volume/cost; rollback tức thời bằng
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
`0020_report_audit_details` chỉ thêm cột JSONB `details` có default `{}` vào feedback audit; không rewrite hoặc
xóa audit cũ. Sau upgrade, xác minh report decision mới có structured resolution/remediation details, audit cũ
vẫn đọc được và Alembic chỉ còn một head.
`0021_security_blacklist_v4` thay unique index cũ bằng unique index chỉ áp dụng cho proposal `pending_review` và
thêm `blacklist` vào feedback-audit constraint. Migration không sửa trực tiếp blacklist entry; sau upgrade phải
smoke add → approve → disable → approve → re-add và xác minh restart vẫn giữ lifecycle/audit.
`0022_action_assurance_metadata` là additive: thêm JSONB `policy_metadata` vào `security_analyses` và JSONB
`assurance_metadata` vào `security_feedback_audit_v4`, đều `NOT NULL DEFAULT '{}'`. Sau upgrade, xác minh hai cột,
default và một Alembic head; chạy analysis security-risk-v7 rồi kiểm tra canonical response và companion
`policy_metadata` nhất quán sau restart.
`assurance_metadata` hiện là schema reservation và có thể vẫn `{}` cho tới khi audit writer được nối end-to-end.
Hai cột chỉ dành cho metadata tối thiểu, không lưu message, raw model content, credential hoặc URL query. Downgrade
sẽ drop hai cột và metadata đã ghi, vì vậy phải backup trước khi rollback qua `0022`.

## Deploy and verify

Deploy backend → worker → frontend sau khi database dependency ready, rồi kiểm tra:

```bash
curl https://<backend-domain>/health
curl https://<backend-domain>/health/ready
curl https://<backend-domain>/api/v4/capabilities
```

Acceptance: readiness `200`; `/docs`, `/redoc` và `/openapi.json` trả `404` trong production; user/admin OIDC và RBAC pass; frontend không gọi
localhost/CORS lỗi; worker không crash-loop/duplicate job; polling/WebSocket fallback hoạt động; database,
Redis và worker không public; restart không mất dữ liệu.

### Async execution và streaming-progress rollout

Deploy contract `progress_state` là optional, nên backend và frontend có thể deploy backward-compatible. Giữ
`SECURITY_ASYNC_EXECUTION_ENABLED=false` trong release đầu tiên. Không tự bật async chỉ vì artifact đã merge.

Chỉ một release approver được bật `SECURITY_ASYNC_EXECUTION_ENABLED=true`, sau khi toàn bộ điều kiện sau có evidence
hosted đã làm sạch:

1. Backend và worker chạy cùng immutable commit SHA; backend có `RUN_DURABLE_WORKER=false`, worker có
   `RUN_DURABLE_WORKER=true`, cùng `DATABASE_URL`, `REDIS_URL` và production OIDC configuration.
2. `GET /health/ready` trả `200` sau migration, `/api/v4/capabilities` công bố async capability, và worker có
   heartbeat ổn định mà không duplicate claim/lease loss trong cửa sổ quan sát.
3. Redis notifier và WebSocket ticket store hoạt động; khi Redis hoặc WebSocket không khả dụng, owner-scoped
   `GET /api/v4/analyses/{analysis_id}/events?cursor=...` vẫn replay được event theo sequence từ PostgreSQL.
4. Hosted smoke chứng minh owner isolation, ticket single-use, disconnect/reconnect, polling replay và final fetch.
   Final response phải thay progress UI, không được tạo turn/history mới.
5. Release evidence có event count/payload size, time từ `202` đến event đầu, time từ worker claim đến `running`,
   duration/gap theo coarse stage, dropped/append-failure count, reconnect/fallback rate, lease/retry rate và
   time-to-final. Chỉ ghi ID, sequence, stage/state và duration; không ghi token, private message, OTP,
   credential, provider payload hoặc URL query nhạy cảm.

Run the operator smoke with two separate hosted OIDC user tokens after an approver has enabled async on staging.
It writes only an ID, sequences, stage/state and timings; its positional message is sent to the API but is never
printed or written to the summary. The script validates owner isolation, one-time ticket consumption, a fresh-ticket
reconnect, cursor replay, progress ordering and the authoritative final fetch. A Redis/WebSocket outage still needs
to be induced in the hosted environment while cursor polling is observed; the script must succeed on its polling
path and the outage/recovery window must be recorded separately.

```bash
LIVE_SMOKE_TOKEN=<first-oidc-user-token> \\
LIVE_SMOKE_OTHER_OWNER_TOKEN=<second-oidc-user-token> \\
TRUSTGUARD_BASE_URL=https://<backend-domain> \\
  uv run python scripts/smoke_streaming_progress.py \\
  "<reviewed non-sensitive in-scope security message>" \\
  --output <streaming-progress-summary.json>
```

Nếu bất kỳ check nào không đạt, giữ async tắt và rollback application image hoặc presentation observer; không
rewrite event/history hay đổi final result. Local PostgreSQL/Redis fakes và unit tests không thay thế checklist này.

### Chrome Extension rollout

Sau khi local lifecycle/capture/auth/HTTP/WebSocket/polling/final/handoff smoke đạt, rollout extension theo internal
→ staging → production cohort → general availability. Mỗi môi trường cần OIDC public client PKCE, stable extension
ID, exact origin allow-list và smoke bằng hai user để kiểm tra owner isolation, ticket single-use, reconnect/polling
fallback và final fetch. Kiểm tra riêng install/update/uninstall, browser restart, incognito policy và privacy runtime;
không lưu token, raw capture, OTP, credential, URL query hoặc provider payload trong evidence. Không quảng bá realtime
async trước khi toàn bộ gate streaming ở trên đạt.

### MVP post-deploy smoke

Giữ `/login` cho local/demo; hosted build dùng Authorization Code + PKCE và không có demo token. Sau deploy, cần
hai danh tính OAuth thật (`user` và `security_admin`) để xác minh xuyên suốt:

1. user tạo analysis rồi gửi report; admin thấy đúng report, còn user nhận `403` khi gọi admin API;
2. admin duyệt false positive/confirm safe với whitelist hoặc Memory remediation, rồi phân tích lại để xác minh
   pipeline vẫn chạy và chỉ reviewed record được dùng làm evidence;
3. admin duyệt malicious với blacklist remediation: report tạo proposal `pending_review`, sau đó admin phải approve
   action liên kết riêng; chỉ trạng thái `executed` mới tạo blacklist active;
4. phân tích lại target đã blacklist và xác minh approved-blacklist evidence, verdict theo policy, report/action
   reference cùng actor/time trong unified audit;
5. reject/dismiss một report và reject một blacklist action; xác minh không có active trust/block record mới,
   remediation thất bại vẫn giữ action reference;
6. restart backend/worker và xác minh whitelist/blacklist lifecycle cùng audit vẫn còn trên PostgreSQL.

Chỉ lưu ID và summary đã redact trong release evidence. Không lưu token, raw private message, credential, OTP hoặc
URL query nhạy cảm. Nếu bất kỳ bước nào thất bại, giữ release ở trạng thái pending và rollback application theo
phần dưới; không downgrade migration để che lỗi dữ liệu.

## Rollout and rollback

Official-link verification đã được triển khai hoàn chỉnh; các bước dưới đây là hosted
rollout/release gate, không phải phần triển khai còn thiếu.

Bật riêng từng capability: understanding → planning → explanation → reviewed memory → admin copilot →
async. Official-link verification mặc định `visible`, dùng
`SECURITY_OFFICIAL_VERIFICATION_MODE=off|shadow|visible|enforced` và
phải đi theo thứ tự `off → shadow → visible → enforced`; Tavily/OpenAI không phải điều kiện startup cho stage
này. Web search nhận `official_source_lookup` từ lựa chọn lookup cấp tài khoản đã lưu; frontend không tự gán consent
trước khi người dùng quyết định. Backend vẫn truyền cờ rõ ràng vào từng request pipeline.
này cùng `external_url_lookup=true`, và domain ownership discovery/cache chỉ được công bố khi request có cả hai;
backend vẫn kiểm tra từng gate trước provider tương ứng. Kiểm tra riêng capabilities
`official_link_verification`, `official_web_search_ready`, evaluation,
latency/cost/error và rollback sau mỗi stage. Chỉ đổi profile sang `cutover` sau hosted smoke, backup/restore và
load rehearsal.

Domain familiarity rollout độc lập theo `off → visible → enforced`. `visible` phát reviewed/Radar evidence nhưng
không đổi risk; `enforced` bật `security-risk-v5`, chỉ có thể đưa case score 0, action `OPEN_LINK`/không action và
không có conflict/sensitive context lên `LOW_RISK`. Radar dùng consent `external_url_lookup`, timeout tối đa 3 giây,
không retry 429 trong request và không phải điều kiện startup. Kiểm tra capability `domain_familiarity` và
`domain_popularity_lookup_ready`. Apply reviewed platform data bằng admin API sau review (dry-run mặc định):

```bash
TRUSTGUARD_ADMIN_TOKEN=<security-admin-token> uv run python scripts/seed_reviewed_platforms.py \
  --base-url https://<backend-domain>
# thêm --apply sau khi review output
```

Rollback `enforced → visible → off` không cần migration. Brand versions đã apply là audit data bất biến; disable
hoặc supersede qua admin API, không xóa record.

Khi official-link verification có incident, rollback `enforced → visible → off`; thay đổi này không yêu cầu
database downgrade. Với incident khác: tắt flag mới bật, rollback application image, giữ schema. Không tự động downgrade/drop/restore
database để rollback code. Provider failure không được suy diễn thành `SAFE`; worker failure phải cho phép
quay về inline/polling path và giữ audit evidence.

Identity candidates đã persist được giữ nguyên khi rollback mode. `off` không discovery; `shadow` vẫn persist và
telemetry nhưng không đổi response/risk; `visible` chỉ hiển thị association; `enforced` mới áp dụng mismatch policy.
Không drop `0019` để rollback application vì quyết định reviewer là immutable audit data.
Không drop `0020` khi rollback application; cột audit additive có thể được phiên bản cũ bỏ qua an toàn.
Không downgrade `0021` khi còn proposal trùng action/target ở lifecycle terminal; giữ schema và rollback application
trước, vì khôi phục unique index cũ có thể xung đột với lịch sử re-add hợp lệ.

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
