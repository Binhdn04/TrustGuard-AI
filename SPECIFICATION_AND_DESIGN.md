# TrustGuard AI — Đặc tả & thiết kế

## Mục tiêu và phạm vi

TrustGuard AI hỗ trợ người dùng triage tin nhắn hoặc URL có dấu hiệu lừa đảo trước khi họ mất tiền, tài khoản hoặc dữ liệu. Sản phẩm chỉ phục vụ Security Triage qua `/api/v4`; không có public API v2/v3, general fact-check flow hoặc vector-store runtime.

Đầu ra của một lượt là context có cấu trúc, evidence, limitations, risk, score, recommended actions và câu trả lời grounded. Risk enum hiện hành gồm `SAFE`, `LOW_RISK`, `SUSPICIOUS`, `HIGH_RISK`, `MALICIOUS` và `INSUFFICIENT_EVIDENCE`. Policy version của kết quả hiện là `security-risk-v7`.

## Người dùng và chức năng

| Vai trò | Chức năng |
|---|---|
| User | Tạo analysis, xem analysis/conversation của chính mình, gửi report/appeal, lấy event replay và WebSocket ticket. |
| Security Admin | Thêm/disable brand, whitelist; review report, appeal, blacklist proposal, memory/campaign/identity candidate; xem audit và intelligence. |
| Worker | Nhận durable Security v4 job, thực thi pipeline, lưu event và phát outbox. Không là public endpoint. |

Local/test dùng demo bearer token. Production bắt buộc OIDC issuer/audience/JWKS hợp lệ, `DEMO_AUTH_ENABLED=false` và role `security_admin` cho các API admin.

## Contract công khai

Prefix của toàn bộ API nghiệp vụ là `/api/v4`.

| Nhóm | Endpoints chính |
|---|---|
| Runtime | `GET /health`, `GET /health/ready`, `GET /api/v4/capabilities` |
| Triage | `POST /api/v4/analyses`, `GET /api/v4/analyses/{analysis_id}`, `GET /api/v4/analyses/page` |
| Hội thoại/realtime | `POST /api/v4/chat`, `GET /api/v4/conversations`, `GET /api/v4/analyses/{analysis_id}/events`, `POST /api/v4/ws-tickets`, `WS /api/v4/analyses/{analysis_id}/stream` |
| User feedback | `POST/GET /api/v4/analyses/{analysis_id}/reports`, `POST/GET /api/v4/analyses/{analysis_id}/appeals` |
| Consent | `GET/POST /api/v4/account/lookup-consent`; admin có endpoint override owner-specific |
| Admin | `/api/v4/admin/{reports,appeals,actions,blacklist,brands,whitelist,security-memory,security-campaigns,identity-candidates,intelligence,audit}` |

`POST /analyses` hỗ trợ `inline` và `async`. Async trả `202`, yêu cầu `Idempotency-Key`, feature flag và PostgreSQL durable runtime. Frontend phải đọc `/capabilities` thay vì suy capability từ một env flag.

## Thiết kế xử lý

### Pipeline đồng bộ

1. API lấy account lookup consent của owner, tạo effective consent cho lượt, scope request và tạo turn.
2. Semantic understanding có thể dùng AI nhưng backend chỉ nhận structured span ID/confidence đã validate; fallback rules giữ pipeline hoạt động.
3. Nếu out-of-scope hoặc need-more-info, pipeline trả terminal response ngay, không tạo investigation/provider call.
4. Với incident exposure, pipeline ưu tiên recovery; các case khác chạy investigation, trust và official-link verification khi applicable.
5. Policy xác định tổng hợp evidence và tạo verdict. Response synthesis phải grounded; lỗi/ungrounded AI rơi về deterministic policy response.
6. Analysis hoàn tất được persist; memory record và admin action proposal là side effect fail-soft có limitation rõ ràng.

### Investigation và evidence

Local rules, approved blacklist, brand registry và whitelist không cần external network. DNS, redirect, RDAP, reputation, domain-familiarity và official search chỉ chạy khi consent/capability và applicability cho phép. URL/redirect được validate để chặn SSRF/private/local/metadata destinations. Provider no-hit, timeout hoặc error không là bằng chứng an toàn.

Whitelist chỉ xác nhận target đã review; ownership/relationship/action endorsement là evidence riêng. Một mismatch không tự suy ra `MALICIOUS`, và threat/sensitive-action evidence có precedence trước familiarity/trust tích cực.

### Durable và realtime

PostgreSQL là source of truth ở production: analysis, conversation, events, trust/admin records, job, encrypted payload, idempotency và outbox. Worker claim lease, retry theo policy và publish outbox. Redis không là source of truth; nó chỉ hỗ trợ distributed rate limit, one-time ticket và wake-up notification. Client có cursor polling/replay fallback nếu WebSocket/Redis lỗi.

SQLite là fallback local/test; async durable execution không được coi là available chỉ vì SQLite hoạt động.

## Quy tắc an toàn bắt buộc

- Scope gate kết thúc out-of-scope trước investigation hoặc provider call.
- AI không trực tiếp set risk, score, consent, target hay admin decision.
- Owner isolation trước user read; admin endpoint yêu cầu `security_admin`.
- Consent, SSRF và redirect validation là điều kiện cho external lookup; không có evidence không được trả `SAFE`.
- Raw private message, credential, OTP, token và URL query không cần thiết không được persist/log. Langfuse tracing và sanitized-content capture đều opt-in.
- Memory/campaign/trust/blacklist chỉ tác động các lượt sau khi đã được review đúng luồng. Admin Copilot không thực thi action.

## Cấu hình vận hành quyết định hành vi

| Cờ/biến | Tác động |
|---|---|
| `SECURITY_ASYNC_EXECUTION_ENABLED` | Mở async khi `DATABASE_URL` là PostgreSQL; request async còn cần idempotency key. |
| `SECURITY_AI_*_ENABLED` | Kill switch riêng cho understanding, planning, explanation và admin copilot; production cần OpenAI key/model hợp lệ nếu AI bật. |
| `SECURITY_MEMORY_RETRIEVAL_ENABLED` | Cho phép đọc reviewed, owner-scoped memory. |
| `SECURITY_OFFICIAL_VERIFICATION_MODE` | `off`, `shadow`, `visible`, hoặc `enforced`. |
| `SECURITY_DOMAIN_FAMILIARITY_MODE` | `off`, `visible`, hoặc `enforced`; lookup popularity cần Radar token. |
| `SECURITY_PAGE_CAPTURE_ENABLED` | Cho phép page capture theo giới hạn timeout/bytes/concurrency/viewport. |
| `LIVE_PROVIDERS_REQUIRED` | Readiness/configuration fail khi provider bắt buộc thiếu; required provider hiện là VirusTotal. |

Nguồn cấu hình đầy đủ: [.env.example](.env.example) và [src/config.py](src/config.py). Sơ đồ hệ thống: [ARCHITECTURE.md](ARCHITECTURE.md).
