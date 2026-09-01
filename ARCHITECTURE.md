# TrustGuard AI — Architecture Diagram

Tài liệu này mô tả cấu trúc đã đối chiếu với `src/main.py`, `src/api/security_v4.py`,
`src/services/security_pipeline.py`, `src/api/dependencies.py` và `docker-compose.yml`.
Public runtime duy nhất là Security Triage tại `/api/v4`.

```mermaid
flowchart TB
    User[Người dùng] --> Web[Next.js 16 frontend]
    Admin[Security Admin] --> Web
    Web -->|OIDC Authorization Code + PKCE<br/>Bearer token| API

    subgraph Runtime[FastAPI backend]
        API[FastAPI /api/v4<br/>CORS · request logging · rate limit]
        Health[/health · /health/ready]
        Auth[Demo auth local/test<br/>hoặc OIDC/JWKS production]
        API --> Auth
        API --> Triage[Scope & conversation service]
        Triage --> Pipeline[Security Triage Pipeline]
        Pipeline --> Understand[Rules + optional grounded AI<br/>semantic understanding]
        Understand --> Gate{In scope?}
        Gate -->|No / need information| Terminal[Boundary or follow-up response]
        Gate -->|Exposure incident| Recovery[Recovery-first assessment]
        Gate -->|Investigation| Investigate[Local rules and consented tools]
        Investigate --> Trust[Brand · whitelist · blacklist<br/>official verification]
        Recovery --> Memory[Optional reviewed, owner-scoped memory]
        Trust --> Memory
        Memory --> Policy[Deterministic risk policy v7]
        Policy --> Response[Grounded response<br/>AI fail-soft to policy response]
        Response --> API
    end

    Investigate -->|only with effective consent| External[DNS · redirect · RDAP<br/>reputation · optional web search]
    External --> SSRF[SSRF and redirect validation]

    API --> Repo
    subgraph Persistence[Persistence and realtime]
        Repo[(PostgreSQL production<br/>SQLite fallback local/test)]
        Repo --> Events[Analysis events / reports / audit]
        Repo --> Jobs[Durable jobs + encrypted payloads<br/>idempotency + transactional outbox]
        Jobs --> Worker[Worker]
        Worker --> Pipeline
        Events --> Replay[Cursor event replay]
        Outbox[Outbox publisher] --> Redis[(Redis)]
        Redis --> Wake[WebSocket wake-up + one-time tickets]
        Wake --> Web
        Replay --> Web
    end

    API --> AdminFlow[Admin review, trust registry,<br/>memory/campaign, reports/appeals]
    AdminFlow --> Repo
    API -. sanitized metadata only, opt-in .-> Langfuse[Langfuse observability]
```

## Luồng xử lý

1. Frontend gọi `POST /api/v4/analyses` cho một lượt triage hoặc `POST /api/v4/chat` cho hội thoại tiếp nối. API xác thực trước khi đọc/ghi dữ liệu.
2. Scope gate và semantic understanding chạy trước investigation. Out-of-scope hoặc cần thêm thông tin kết thúc trước mọi provider call.
3. Lượt in-scope đi qua local checks; lookup bên ngoài chỉ chạy với effective consent và luôn qua SSRF/redirect guard. No-hit, lỗi hoặc timeout chỉ là limitation, không tạo `SAFE`.
4. Trust/official verification và reviewed memory (nếu capability bật) bổ sung evidence. Risk, score và action do policy xác định quyết định; AI chỉ làm understanding/planning/explanation có grounding.
5. Kết quả, audit và event được lưu owner-scoped. Với async, PostgreSQL giữ job/event là nguồn phát lại; Redis chỉ phát notification và giữ WebSocket ticket ngắn hạn.

## Deployment topology

`docker-compose.yml` có năm services: frontend, backend, worker, PostgreSQL 16 và Redis 7. Backend chạy `alembic upgrade head` trước Uvicorn; worker chạy durable worker/outbox/retention. Compose mặc định tắt async và các AI feature flags. Production bắt buộc PostgreSQL, Redis, OIDC, HTTPS CORS origins và encryption key không phải placeholder.

## Trust boundaries

- Client không được quyết định risk, score, admin decision hoặc target tool. API kiểm tra role `security_admin` cho mọi admin endpoint.
- Dữ liệu đọc của user bị owner-scoped. WebSocket cần ticket một lần; event replay đọc từ persistence authority.
- Chỉ reviewed memory/campaign và approved trust/blacklist record mới tác động policy. Admin Copilot là suggestion-only; action thực cần human review và audit.
- Không lưu raw credential, OTP, token hoặc URL query không cần thiết; tracing Langfuse là opt-in và việc capture nội dung đã sanitize có cờ riêng.

Đặc tả contract và quyết định thiết kế: [SPECIFICATION_AND_DESIGN.md](SPECIFICATION_AND_DESIGN.md). Hướng dẫn vận hành chi tiết: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
