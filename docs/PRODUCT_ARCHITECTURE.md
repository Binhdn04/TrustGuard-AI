# Product and Architecture

Tài liệu canonical cho phạm vi, contract và kiến trúc TrustGuard AI. Xem trạng thái tại
[CURRENT_STATUS.md](CURRENT_STATUS.md).

## Product boundary

TrustGuard AI hỗ trợ đánh giá tin nhắn hoặc URL đáng ngờ trước khi người dùng chuyển tiền, đăng nhập,
cung cấp OTP/thông tin cá nhân hoặc thực hiện hành động có rủi ro.

In scope: phishing, credential/OTP theft, giả mạo thương hiệu, financial/recruitment/promotion scam,
URL investigation có consent, multi-turn case, report/appeal và Security Admin review.

Out of scope: general news/politics/sports/science/medical fact-check, deepfake detection, malware sandbox,
tư vấn đầu tư và wide action chưa có execution sink được duyệt. Yêu cầu ngoài phạm vi kết thúc bằng
`OUT_OF_SCOPE_GENERAL_FACT_CHECK`, không gọi provider và không tạo risk verdict.

## Public contract

Runtime public chỉ cung cấp `/api/v4`. `/api/v2`, `/api/v3` và vector compatibility đã deprecated và bị
gỡ khỏi FastAPI/OpenAPI/frontend.

```text
Scope: IN_SCOPE | NEED_MORE_INFO | OUT_OF_SCOPE_GENERAL_FACT_CHECK
Risk:  SAFE | LOW_RISK | SUSPICIOUS | HIGH_RISK | MALICIOUS | INSUFFICIENT_EVIDENCE
```

Analysis response gồm scope, conversation ID/version, structured context, investigation plan/status,
typed evidence, normalized errors, risk/confidence/threat type, policy version, recommendations, grounded
explanation và limitations. API v4 bao phủ analyses, conversations/chat, events/WebSocket, reports/appeals,
admin review/actions, brand/whitelist, Security Memory, campaigns, intelligence, audit và capabilities.

## Runtime architecture

```mermaid
flowchart TD
    UI[Next.js workspace] --> API[FastAPI /api/v4]
    API --> Auth[Demo auth local hoặc OIDC/JWKS]
    Auth --> Scope[Scope + structured context]
    Scope -->|Out of scope| Boundary[Terminal boundary]
    Scope -->|Need info| FollowUp[Focused follow-up]
    Scope -->|In scope| Planner[Allowlisted planner]
    Planner --> Local[Rules + approved blacklist]
    Planner --> Network[DNS + redirect + RDAP + reputation + consented domain ranking]
    Planner --> Trust[Brand + target identity + whitelist]
    Trust --> Familiarity[Reviewed first-party / shared-platform familiarity]
    Local --> Evidence[Typed evidence]
    Network --> Evidence
    Familiarity --> Evidence
    Evidence --> Risk[Deterministic risk v1-v5]
    Risk --> Response[Grounded response]
    Response --> Store[(SQLite local / PostgreSQL production)]
    Store --> Events[Polling/WebSocket replay]
    Store --> Memory[Reviewed memory + campaigns]
    Store --> Admin[HITL + immutable audit]
```

Inline là mặc định. Async chỉ được quảng bá khi PostgreSQL, durable worker và configuration đều ready.
PostgreSQL là source of truth; Redis phục vụ rate limit, ticket ngắn hạn và wake-up notification.

## Workflow and invariants

```text
validate request/version → scope/context → boundary hoặc investigation
→ local + consented external tools → trust enrichment → deterministic risk
→ grounded response → persistence → optional HITL/memory/campaign
```

- AI không trực tiếp đặt risk, score, consent, network target hoặc admin decision.
- Rule tạo scope candidate; grounded AI understanding được chạy trước quyết định scope cuối cùng (trừ greeting/capability cục bộ). AI không được hạ một deterministic security-positive signal xuống out-of-scope.
- AI chỉ liên kết entity với URL bằng index của URL đã trích xuất cục bộ. Reviewed target owner được đối chiếu riêng; whitelist không chứng minh URL thuộc entity đang được claim.
- AI planner chỉ sắp thứ tự candidate đang runnable; policy quyết định coverage và AI không được skip evidence step.
- Chat follow-up gửi conversation ID/version và chỉ nhận owner-scoped structured summary đã làm sạch cùng assessment
  hiện tại. Context được đưa cho model dưới dạng untrusted JSON, không gồm raw chat, score/confidence hay evidence ID;
  stale version bị từ chối và chat thường không làm tăng version hoặc persist nội dung mới.
- Frontend chỉ render Markdown giới hạn trong phản hồi chatbot (nhấn mạnh, danh sách, inline code và HTTP(S) link)
  thành React element; không dùng raw HTML. Nội dung người dùng không được diễn giải như Markdown.
- External lookup cần consent của request hiện tại; consent không kế thừa qua conversation.
- SSRF guard chặn private/local/metadata target và revalidate từng redirect.
- Page capture tự chạy ở frontend cho URL cuối cùng (URL mới nhất) sau khi case có kết quả, owner-scoped theo URL
  index và gửi consent mới cho từng request. Chromium dùng context tạm không cookie/download/service worker,
  không vượt CAPTCHA hoặc access denial, chặn private/local target, popup, active stream và URL tải tệp phổ biến.
  API chỉ trả ảnh viewport với `Cache-Control: no-store`; frontend chỉ giữ Blob mới nhất trong RAM, thu hồi Blob
  trước đó và ảnh không đi vào evidence, conversation hay database.
- Whitelist có provenance và chạy trước negative scoring.
- Provider no-hit/error/timeout, domain age hoặc mismatch riêng lẻ không đủ tạo `MALICIOUS`.
- Domain familiarity là trục riêng với publisher và exact resource. Reviewed platform chỉ xác nhận platform owner;
  popularity chỉ mô tả usage. Hai nguồn này không bao giờ trực tiếp tạo `SAFE`, không giảm threat/context score và
  shared platform không xác minh form/video/post/file do người dùng tạo.
- User reads luôn owner-scoped; admin routes yêu cầu `security_admin`.
- Không lưu raw private message, URL query token, OTP hoặc credential trong memory/audit.
- Admin Copilot chỉ suggestion; action thật cần reviewer, note, evidence và audit.

Identity discovery là phần mở rộng provider-neutral của official-link verification, không phải pipeline mới.
Official-link verification đã được triển khai hoàn chỉnh trong runtime `/api/v4`; trạng thái release và
hosted validation được theo dõi tại `CURRENT_STATUS.md`, `DEPLOYMENT.md` và `TESTING.md`.
Khi reviewed registry thiếu/ambiguous hoặc chưa biết URL người dùng, coordinator có thể chạy tối đa ba query
được dẫn xuất từ tên entity và literal claim/title đã grounded. Candidate `discovered` không được coi là cache hit
hoàn tất. Riêng `endorsed_third_party_service`, một discovery source độc lập chứa entity/claim và exact link
(kể cả short-link qua guarded redirect) tới đúng URL người dùng đủ tạo association `verified` với confidence thấp
hơn; target không được tự endorse chính nó. Nếu target page independently khớp entity/claim thì confidence tăng.
Ownership của domain và parent relationship vẫn cần hai evidence family trên hai source host. Kết quả resource
được hiển thị `partially_verified`, có TTL 7 ngày, không ghi vào `BrandRecordV4` và không tự tạo kết luận `SAFE`.
Chỉ admin review mới promote thành immutable brand version; third-party endorsement luôn giới hạn ở exact
URL/resource.

## Persistence and lifecycle

- SQLite là local/test fallback; PostgreSQL/Alembic là production path.
- Conversation dùng optimistic version, redacted summary và retention.
- Durable jobs dùng encrypted payload, lease, idempotency key và transactional outbox.
- Memory ảnh hưởng risk phải reviewed, owner-scoped và không self-match analysis hiện tại.
- Campaign dùng named security signals, không dùng embeddings/vector database.
- Migration `0018_remove_vector_compat` xóa fact-check/source-discovery/vector storage cũ và không downgrade.
- Migration `0019_security_identity_discovery` thêm candidate versions, immutable typed observations và immutable
  reviewer decisions riêng cho Security v4; SQLite fallback có schema tương đương.

## Code map

| Area | Location |
|---|---|
| App/config/auth | `src/main.py`, `src/config.py`, `src/core/` |
| API v4 | `src/api/security_v4.py` |
| Scope/investigation/risk | `src/agents/security_*.py` |
| Services | `src/services/security_*.py` |
| Persistence | `src/repositories/`, `migrations/versions/` |
| AI/evaluation | `src/security_ai/`, `src/evaluation/` |
| Frontend/tests | `frontend/src/`, `tests/` |
