# TrustGuard AI — P-068

AI Agent phát hiện liên kết độc và tuyên bố đáng ngờ trong nội dung chat do người dùng chủ động gửi.
TrustGuard AI lập kế hoạch điều tra, thu thập bằng chứng từ rule, blacklist và provider uy tín, chấm
điểm rủi ro deterministic rồi giải thích cảnh báo bằng ngôn ngữ dễ hiểu.

> **Trạng thái:** Wave 1 platform backend đã có PostgreSQL/Alembic, durable job + transactional
> outbox, v3 event replay/WebSocket ticket và OIDC/JWT. Dashboard, history và admin UI mặc định gọi
> API thật; screenshot, campaign detection và appeal thuộc các wave sau. `/api/v2` được giữ tương
> thích trong release v3 đầu tiên.

## Sản phẩm giải quyết gì?

Người dùng phổ thông khó tự đánh giá URL giả mạo, redirect, tuổi domain và độ xác thực của một
tuyên bố đang lan truyền. TrustGuard AI cung cấp:

- cảnh báo inline hai pha: cảnh báo sơ bộ nhanh từ rule/blacklist/cache, sau đó cập nhật kết luận khi
  tool và LLM hoàn tất;
- risk score, verdict, evidence, limitation và khuyến nghị rõ ràng;
- kiểm tra URL/domain qua adapter reputation và RDAP/WHOIS, cùng fact-check retriever cho claim;
- memory blacklist có nguồn gốc và audit;
- chuyển case nghiêm trọng cho Security Admin mà không trì hoãn cảnh báo cá nhân;
- Human-in-the-loop bắt buộc trước khi chặn domain hoặc phát cảnh báo diện rộng.

Hệ thống không đọc toàn bộ hội thoại, không phá mã hóa đầu cuối và không tự mở link trên thiết bị
người dùng. Chỉ nội dung được người dùng chủ động gửi mới được phân tích; external URL/domain lookup
cần consent rõ ràng.

## Luồng điều tra

```mermaid
flowchart LR
    A[User chọn message hoặc URL] --> B[Extract URL và claim]
    B --> C[Rule + blacklist + reputation cache]
    C --> D[Cảnh báo sơ bộ]
    C --> E[URL/domain scan]
    C --> F[Fact-check retrieval]
    E --> G[Risk Engine]
    F --> G
    G --> H[Giải thích grounded]
    H --> I[Cập nhật cảnh báo inline]
    G --> J{Cần tác động diện rộng?}
    J -->|Có| K[Security Admin review]
    K --> L[Blacklist / broad warning sau phê duyệt]
```

LLM `gpt-4o-mini` hỗ trợ hiểu ngữ cảnh, đề xuất thứ tự tool, review coverage và viết giải thích.
Score, verdict và action được quyết định từ structured evidence bằng Risk Engine; LLM không được tạo
evidence hoặc tự sửa kết luận.

## Công nghệ và kiến trúc

| Lớp | Lựa chọn | Trạng thái |
|---|---|---|
| LLM | OpenAI `gpt-4o-mini` | Đã có, optional theo API key |
| Orchestration | LangGraph: extract → scan → verify → score → warn/escalate | Đã có vertical slice |
| URL reputation | Google Web Risk primary, VirusTotal policy-gated secondary | Đã wire; fake adapters mặc định trong test |
| Domain intelligence | RDAP-first/WHOIS; guarded redirect | Đã wire lazy sau consent |
| Fact-check | Google Fact Check + fact-check corpus | Provider có; pgvector thuộc final scope |
| Backend | FastAPI `/api/v3` + `/api/v2` compatibility | Product path v3 đang hoạt động |
| Frontend | Next.js/React với warning banner | Dashboard/history/admin gọi API thật |
| Realtime | Persisted event polling + ticketed WebSocket | Wave 1 backend đã có |
| Data | PostgreSQL/pgvector source of truth + Redis delivery | Wave 1 core schema/job/outbox đã có |
| Deploy | Docker → Railway | Docker có; Railway thuộc final scope |

Chi tiết: [kiến trúc](docs/01-ARCHITECTURE.md), [yêu cầu sản phẩm](docs/00-PRODUCT_REQUIREMENTS.md),
[contract](docs/02-CONTRACT_AND_FIXTURES.md) và [kế hoạch triển khai](docs/03-IMPLEMENTATION_PLAN.md).

## Phạm vi final product

### Core product

- App deploy, đăng nhập và hai vai trò `user`/`security_admin`.
- Phân tích URL hoặc message được người dùng chủ động gửi.
- Rule, approved blacklist, URL reputation, RDAP/WHOIS và fact-check retrieval.
- Risk score deterministic; cảnh báo inline kèm lý do, evidence, limitation và khuyến nghị.
- Lịch sử, user report và admin-managed blacklist có audit.
- Theo dõi progress realtime, polling fallback và bảo vệ rate-limit/cost.

### Advanced intelligence

- Fact-check bằng corpus nguồn tin cậy trong pgvector.
- Screenshot renderer cô lập, không cookie/đăng nhập và chỉ chạy sau consent khi scan tĩnh chưa đủ.
- Phát hiện chiến dịch lan truyền theo cụm và dashboard xu hướng tin giả.
- Học có kiểm duyệt từ báo cáo người dùng; feedback không tự động đổi model/score.
- Dashboard chi phí API, quota/rate-limit và cơ chế appeal.

Core product và Advanced intelligence đều bắt buộc trước final release; cách gọi này chỉ phân nhóm
capability, không tạo một điểm dừng MVP. Việc triển khai được chia cho bốn coding agents tại
[Final Product Implementation Plan](docs/03-IMPLEMENTATION_PLAN.md).

## Chạy local

Yêu cầu Python 3.11+, Node.js 20+ và npm.

```bash
uv sync
cp .env.example .env
uv run uvicorn src.main:app --reload --port 8000
```

`.env.example` mặc định dùng SQLite để lệnh trên chạy ngay mà không cần Docker. Nếu chọn PostgreSQL,
hãy chạy PostgreSQL/Redis, thay `DATABASE_URL`, rồi chạy `uv run alembic upgrade head` trước khi mở API.

Nếu không dùng `uv`, có thể tạo virtualenv và cài `requirements.txt` bằng `pip` như trước.

Ở terminal khác:

```bash
cd frontend
npm ci
npm run dev
```

Đặt `NEXT_PUBLIC_API_URL=http://localhost:8000` và `NEXT_PUBLIC_USE_MOCK_API=false` trong
`frontend/.env.local` khi kiểm thử HTTP integration. Swagger UI: `http://localhost:8000/docs`.

Docker Compose chạy `alembic upgrade head` trước backend. Khi `DATABASE_URL` là PostgreSQL, API dùng
PostgreSQL làm source of truth và worker tự reclaim lease hết hạn; Redis chỉ đánh thức/phân phối
event. SQLite vẫn là default offline nếu cấu hình `DATABASE_URL=sqlite:///...`.

SQLite file thực tế lấy từ `SECURITY_DATABASE_PATH`. PostgreSQL hiện hỗ trợ durable analysis và
user-report review queue; v2 admin decision/approved blacklist vẫn chỉ hoàn chỉnh ở SQLite.

Import dữ liệu development SQLite sau khi đã chạy `alembic upgrade head` (head hiện tại là
`0004_review_queue`):

```bash
python scripts/import_sqlite_to_postgres.py ./data/security.db \
  --database-url "$DATABASE_URL" --encryption-key "$DATABASE_ENCRYPTION_KEY"
```

## Kiểm thử

```bash
ruff check src tests
pytest -q
cd frontend
npm run lint
npm run typecheck
npm test
npm run build
```

Test mặc định phải chạy offline bằng fake adapters/fixtures, không tiêu tốn quota provider hoặc LLM.

## Nguyên tắc an toàn

- Không coi provider no-hit, timeout hoặc thiếu evidence là bằng chứng “an toàn”.
- Không log secret, OTP, raw message hoặc raw provider response.
- Không gọi URL/domain provider khi chưa có consent và không truy cập private/local/metadata IP.
- Không biến URL đáng ngờ thành link bấm trực tiếp trong UI.
- Chặn domain, thêm blacklist và cảnh báo diện rộng phải có Security Admin phê duyệt cùng audit.

## Tài liệu

- [Product Requirements](docs/00-PRODUCT_REQUIREMENTS.md)
- [Architecture](docs/01-ARCHITECTURE.md)
- [Contract and Fixtures](docs/02-CONTRACT_AND_FIXTURES.md)
- [Implementation Plan](docs/03-IMPLEMENTATION_PLAN.md)
- [Gate 1 Brief](docs/gate1/brief.md)
- [Gate 1 PRD](docs/gate1/prd.md)
- [Gate 1 UI Flow](docs/gate1/UI_flow.md)
