# Architecture — Current Security Runtime

[scope.md](scope.md) định nghĩa product goal; [implementation-status.md](implementation-status.md)
định nghĩa trạng thái code hiện tại; [SECURITY_TRIAGE_IMPLEMENTATION_PLAN.md](SECURITY_TRIAGE_IMPLEMENTATION_PLAN.md)
là nguồn theo dõi WP và release gate.

## 1. Một product profile Security v4

Runtime public chỉ mount `/api/v4`. `/api/v2` và `/api/v3` đã được tháo khỏi FastAPI và OpenAPI;
frontend chỉ dùng Security v4. Middleware ghi contract/profile từ path mà không đọc body, query hay token.

## 2. Kiến trúc Security v4 hiện tại

```mermaid
flowchart TD
    UI[Next.js Investigation Workspace / Review Room] --> API[FastAPI /api/v4]
    API --> Auth[Demo token dev hoặc OIDC/JWKS]
    API --> Scope[Security scope + structured context]
    Scope -->|OUT_OF_SCOPE| Boundary[Terminal boundary; zero investigation calls]
    Scope -->|NEED_MORE_INFO| FollowUp[Focused follow-up + conversation version]
    Scope -->|IN_SCOPE| Planner[Allowlisted investigation planner]
    Planner --> Local[Local URL rules + blacklist]
    Planner --> External[DNS + redirect + RDAP + reputation]
    Planner --> Trust[Brand + whitelist]
    Local --> Evidence[Versioned evidence]
    External --> Evidence
    Trust --> Evidence
    Evidence --> Risk[Versioned deterministic security-risk-v1/v2]
    Risk --> Result[Grounded warning + recommendations]
    Result --> Store[(SQLite local / PostgreSQL production)]
    Store --> Events[Owner-scoped events + ticketed WebSocket replay]
    Result --> HITL[Idempotent admin action proposal]
    Result --> Memory[Security fingerprint + memory]
    Memory --> Campaign[Explainable campaign hypothesis]
    HITL --> Admin[Security Admin review / execute / audit]
    Campaign --> Admin
```

`POST /api/v4/analyses` hiện xử lý scope, investigation, trust enrichment và deterministic risk trong
request lifecycle, sau đó persist terminal snapshot và ba lifecycle event `queued/running/completed`
hoặc `failed`. Polling và WebSocket cung cấp owner-scoped replay; v4 chưa được chuyển sang durable worker
async khi feature flag và worker production được bật.

## 3. Security workflow và policy boundaries

```text
validate request/conversation version
→ scope decision + SecurityContextV4
→ terminal OUT_OF_SCOPE / NEED_MORE_INFO, hoặc investigation
→ local rules and policy-gated automatic external tools
→ brand/whitelist trust enrichment
→ deterministic risk and grounded explanation
→ terminal persistence
→ HITL proposal and Security Memory producers
```

Các invariant đang enforce:

- Out-of-scope kết thúc trước khi resolve investigation hoặc legacy analysis service.
- Planner chỉ nhận normalized target từ `SecurityContextV4`. Web product cấp lookup authorization qua disclosure cố định
  cho mỗi turn; executor vẫn revalidate request consent, purpose và target ngay trước external call.
- DNS/redirect/reputation dùng SSRF guard; redirect revalidate từng hop.
- Brand và whitelist record có provenance, lifecycle, reviewer và policy version.
- Risk/score/action là deterministic policy output; LLM không có quyền tự ghi verdict.
- Whitelist chạy trước negative scoring; mismatch, domain age, provider no-hit hoặc timeout đứng riêng
  không đủ tạo `MALICIOUS`.

## 4. Conversation, persistence và privacy

`SecurityAnalysisService` quản lý owner-scoped analysis, report, appeal và conversation. Analysis và
conversation có owner-scoped paginated API. Conversation dùng optimistic `conversation_version`, redacted structured summary
và retention interval. Raw private message không được persist trong Security v4 analysis/memory.

SQLite là durable local/dev store. PostgreSQL là production source of truth và có Alembic schema đến
`0018_remove_vector_compat`. Redis chỉ phục vụ rate limit/notification/ticket ở deployment có cấu
hình; không phải source of truth.

Security Memory chỉ giữ canonical domain, query-free URL fingerprint, redirect domain, claimed brand,
scenario/action pattern, threat/risk/policy version, timestamps, report count, admin verdict và evidence
refs. Campaign v4 cluster theo named security signals trong time window, không đọc claim embeddings.

## 5. Human-in-the-loop và admin

Completed `HIGH_RISK`/`MALICIOUS` URL analysis có thể tạo idempotent `ADD_TO_BLACKLIST` proposal liên kết
bằng `security_analysis_id`. Action bắt buộc canonical target, evidence snapshot, reviewer identity và
review note. State machine là:

```text
pending_review → rejected
pending_review → approved attempt → executed | failed
```

Chỉ `ADD_TO_BLACKLIST` có execution sink thật và ảnh hưởng lookup sau đó. `BLOCK_DOMAIN` và
`PUBLISH_BROAD_WARNING` chưa có sink; approved attempt phải kết thúc `FAILED` với reason code, không được
giả là đã execute. Admin Copilot chỉ tạo grounded suggestion (`executed=false`) và không đi vào executor.

Admin API hiện có paginated/search/filter contracts cho brand, whitelist, Security Memory, campaign,
report/appeal queue, domain/threat intelligence và unified v4 audit. Bounded endpoint
`GET /api/v4/admin/analyses/{analysis_id}` cho phép `security_admin` đọc structured/privacy-minimized case
để review feedback mà không trả owner hoặc raw conversation. Endpoint POST Copilot cùng boundary lưu
snapshot hash/usage/audit nhưng không lưu prompt/raw completion và không đổi case/action state. Frontend đã consume history,
conversation, explorer, feedback, trust, unified audit và case-detail contracts trong case workspace,
Observatory, Review Room, Trust lifecycle và Audit. Reviewed-action detail/audit/decision dùng
`/api/v4/admin/actions`; metrics/source-discovery compatibility surface đã bị xóa.

User conversation dùng routing hai tầng. Lượt intake đầu luôn tạo Security v4 analysis và khóa composer trong lúc
pipeline chạy. Sau verdict, authenticated `POST /api/v4/chat` xử lý follow-up: không có tool call thì trả lời như chatbot
bình thường; có `check_scam` thì frontend tạo analysis v4 mới. Chỉ pipeline analysis mới được quyền lập investigation
plan và gọi DNS/redirect/RDAP/reputation provider theo context, SSRF guard và budget.

## 6. Legacy cleanup

Public v2/v3 routers, frontend clients/mocks/surfaces, legacy worker activation và vector search persistence
đã được gỡ. Migration `0018_remove_vector_compat` xóa fact-check embeddings, source discovery,
campaign vector observations và extension `vector`. Fresh install chạy trên PostgreSQL thường.
Một số pure-Python general-analysis utilities vẫn còn cho authenticated v4 follow-up chat và regression tests,
nhưng không có public v2/v3 route hoặc PostgreSQL vector consumer.

## 7. Trust boundaries cần giữ khi cutover

- Request log không ghi body/query/token; persisted URL loại query khi không cần thiết.
- User read luôn filter theo owner; admin route yêu cầu `security_admin`.
- OIDC validate issuer/audience/JWKS; production không dùng demo token.
- External provider errors được normalize, bounded retry/deadline và không tự tạo safe verdict.
- Admin decision, execution result và evidence snapshot được audit bất biến.
- Schema removal chỉ diễn ra sau telemetry, backup/export và rollback rehearsal.
