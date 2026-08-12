# TrustGuard AI — Architecture Entry Point

Tài liệu kiến trúc canonical nằm tại [docs/01-ARCHITECTURE.md](docs/01-ARCHITECTURE.md). File này
tóm tắt boundary quan trọng để README, slide và reviewer không nhầm kiến trúc đích với runtime hiện
tại.

## Kiến trúc hiện tại

```mermaid
flowchart TB
    UI[Next.js UI] --> API[FastAPI /api/v3]
    API --> Auth[OIDC/JWT or development token]
    API --> PG[(PostgreSQL + pgvector)]
    API -. development .-> SQLite[(SQLite)]
    PG --> Worker[Durable worker + outbox]
    Worker --> Redis[(Redis delivery)]
    Worker --> Agent[LangGraph workflow]
    Agent --> Risk[Deterministic Risk Engine]
    Agent --> Tools[Rules / blacklist / configured providers]
    API --> W2[Appeal / action / campaign / metrics / artifact]
    Agent -. optional .-> LLM[GPT-4o-mini]
```

Baseline hiện tại phát triển từ `7715ea0` và đã compose Wave 2 end-to-end. Frontend dùng HTTP v3;
API chỉ nhận/persist job còn worker chạy LangGraph, hybrid retrieval, conditional web fallback,
rerank/comparison, campaign detection và live event persistence. SQLite/in-process vẫn là development
fallback. Phần chưa hoàn thành là hosted rollout, live-provider smoke và release hardening Wave 3.

## Phần còn lại của kiến trúc đích

```mermaid
flowchart TB
    Chat[React chat + inline warning] <-->|HTTPS / WSS| API[FastAPI /api/v3]
    API --> DB[(PostgreSQL + pgvector)]
    API --> Redis[(Redis)]
    Worker[Durable LangGraph worker] --> DB
    Worker --> Redis
    Worker --> Rules[Rules + approved blacklist + cache]
    Worker --> Reputation[GSB / Web Risk / VirusTotal]
    Worker --> Domain[RDAP-first WHOIS + redirects]
    Worker --> Facts[Google Claim Search + FTS/pgvector]
    Facts -. evidence chưa đủ .-> Web[Tavily Search + source policy]
    Web --> Extract[Tavily Extract rerank]
    Facts --> LLM[GPT-4o-mini comparison]
    Extract --> LLM
    Worker -. advanced, consented .-> Shot[Sandbox screenshot renderer]
    Admin[Security Admin] --> API
    API --> Audit[Review + appeal + audit]
```

Đường URL ưu tiên local rule, approved blacklist và cached reputation để tạo cảnh báo sơ bộ. Đường
claim chạy Google Fact Check Claim Search và PostgreSQL FTS/pgvector trước; Google chỉ tìm các
ClaimReview đã tồn tại. Tavily Search và Extract chỉ chạy khi deterministic sufficiency gate cho
biết evidence chưa đủ. Extract dùng exact claim để chọn ba đoạn liên quan mỗi nguồn; GPT-4o-mini so sánh tối đa năm nguồn thành
stance có citation; Risk Engine vẫn quyết định score/verdict/action deterministic.

`/api/v3` là product contract hiện tại. `/api/v2` được giữ read-compatible trong release v3 đầu tiên.

## Trust boundaries

- User chỉ gửi message/URL đã chọn; hệ thống không đọc nền toàn bộ hội thoại và không phá E2E.
- URL/domain lookup và screenshot cần consent; dữ liệu gửi provider phải được tối thiểu hóa.
- Claim gửi embeddings/fact-check/comparison phải được redact và giới hạn ở phần text tối thiểu;
  raw message, OTP, secret và prompt không được ghi vào usage/log.
- Source Registry quyết định eligibility: Tier A/B có thể tạo kết luận, Tier C chỉ corroborate và
  Untrusted chỉ dùng discovery, bị loại trước fetch/comparator.
- Redirect/screenshot chạy sau SSRF guard, trong môi trường cô lập, không cookie hay credential.
- Individual warning được hiển thị ngay; domain block và broad warning luôn chờ admin phê duyệt.
- Redis là broker/cache/event fan-out, không phải source of truth; PostgreSQL giữ state và audit.

Xem tài liệu canonical để biết lifecycle, contract boundary, hiện trạng adapter và roadmap migration.
