# TrustGuard AI — AI Security Triage Assistant

Goal của TrustGuard AI là trợ lý hội thoại đánh giá message/URL đáng ngờ có dấu hiệu phishing, scam
hoặc giả mạo trước khi user thực hiện hành động rủi ro. [Product Scope](docs/scope.md) là nguồn sự
thật về goal.

> Security Triage v4 và frontend investigation workspace đã được triển khai. WP9 đã có deterministic
> evaluation, WP8 AI evaluation/rollout guard, cutover/freeze guard, compatibility checker và release
> runbook. Hosted OIDC/provider/PostgreSQL/Redis/load, restore rehearsal và zero-usage window vẫn chưa có evidence.
> Xem [Implementation Status](docs/implementation-status.md) để biết ranh giới chính xác.

## Trạng thái hiện tại

Đã implement và có thể tái sử dụng:

- FastAPI Security Triage `/api/v4` bên cạnh v2/v3 compatibility; auth demo/OIDC, owner isolation,
  Security Admin RBAC và rate limiting.
- Security scope gate, structured scam/threat context, multi-turn conversation và deterministic v4 risk.
- Text/URL analysis, URL normalization, local phishing rules, brand/whitelist và approved blacklist.
- Automatic URL/official lookup theo context dưới disclosure cố định; executor vẫn enforce request authorization,
  guarded redirect, RDAP, provider budget và SSRF protection.
- Typed evidence, bounded official verification, WebSocket + polling replay.
- SQLite local; PostgreSQL durable jobs/outbox, Redis delivery, retention và operations metrics.
- Paginated history/conversation/trust/memory/campaign API; report/appeal admin lifecycle, bounded admin
  case-detail, domain/threat intelligence, unified v4 audit và reviewed blacklist workflow.
- Next.js frontend gọi API thật, có Security v4 cho lượt kiểm tra đầu và chatbot router cho các lượt sau;
  hội thoại thường không mở analysis mới, còn `check_scam` chuyển về pipeline v4. Verdict gọn cho user, analyst detail theo yêu cầu,
  case history, Observatory, Security Review Room, Trust lifecycle,
  grounded suggestion-only Admin Copilot, Unified Audit và compatibility surface riêng cho v3 metrics/source discovery.
- AI roadmap WP8 có versioned AI quality report, hosted evidence validator và sequential feature-flag rollout/rollback checker.

Chưa đạt scope:

- `BLOCK_DOMAIN` và `PUBLISH_BROAD_WARNING` chưa có downstream sink thật; Admin Copilot chỉ đưa gợi ý,
  không thực thi hai action này.
- Legacy v2/v3 general fact-check/source-discovery writers chưa được freeze trên deployment thật hoặc cleanup;
  code đã có fail-fast cutover profile và legacy-write switch.
- Đã có versioned offline quality evaluation; chưa có compatibility zero-usage evidence và backup/restore rehearsal.
- Chưa có evidence hosted production/live-provider/backup-load-security validation.

## Runtime hiện tại

```mermaid
flowchart LR
    A[Message / URL / follow-up] --> B[Security scope + structured context]
    B --> C[Consent/policy-controlled investigation]
    C --> D[Trust + versioned deterministic risk v1/v2]
    D --> E[Grounded warning + recommendations]
    E --> F[Conversation/history/report/appeal]
    D --> G[Security Memory + campaign]
    D --> H[Reviewed admin action]
    D --> I[Admin Copilot suggestion only]
```

Legacy general fact-check pipeline không nằm trên Security v4 path nhưng vẫn tồn tại cho compatibility.
Kiến trúc và thứ tự cutover nằm tại [Architecture](docs/01-ARCHITECTURE.md) và
[Implementation Plan](docs/03-IMPLEMENTATION_PLAN.md).

## Chạy local

Yêu cầu Python 3.11+, Node.js 22+ và npm.

```bash
uv sync
uv run playwright install chromium
cp .env.example .env
uv run uvicorn src.main:app --reload --port 8000
```

Nếu không dùng `uv`:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
playwright install chromium
```

Chạy frontend:

```bash
cd frontend
npm ci
npm run dev
```

Đặt `NEXT_PUBLIC_API_URL=http://localhost:8000` và `NEXT_PUBLIC_USE_MOCK_API=false` trong
`frontend/.env.local`. Swagger UI ở `http://localhost:8000/docs`.

## Docker Compose

```bash
cp .env.example .env
docker compose up --build -d
docker compose ps
```

- Frontend: `http://localhost:3000`
- API docs: `http://localhost:8000/docs`
- Readiness: `http://localhost:8000/health/ready`

Compose gồm frontend, API, worker, PostgreSQL/pgvector và Redis. Development có thể dùng demo auth;
production phải tắt demo token và cấu hình OIDC, signing/encryption keys, CORS và provider secrets.
Frontend production dùng OIDC Authorization Code + PKCE tại `/auth/callback`; cấu hình tối thiểu
`NEXT_PUBLIC_OIDC_ISSUER`, `NEXT_PUBLIC_OIDC_CLIENT_ID`, `NEXT_PUBLIC_OIDC_AUDIENCE` và đăng ký callback/
logout/web origin ở Identity Provider. Danh sách override đầy đủ nằm trong `frontend/.env.example`.

```bash
docker compose down
```

`docker compose down -v` xóa named volumes và dữ liệu PostgreSQL/Redis.

## Kiểm thử

Quick backend gate từ repository root:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m alembic heads
```

AI roadmap WP8 offline evaluation/rollout gate (không cần credential hosted):

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_security_v4.py
.\.venv\Scripts\python.exe scripts\evaluate_security_memory_v2.py
.\.venv\Scripts\python.exe scripts\evaluate_security_ai.py
.\.venv\Scripts\python.exe scripts\check_security_ai_rollout.py --target-stage off
```

Frontend production gate:

```powershell
Push-Location frontend
npm.cmd test
npm.cmd run lint
npm.cmd run typecheck
npm.cmd run check:cutover
npm.cmd run build
npm.cmd run test:e2e
Pop-Location
```

Hosted rollout không nằm trong local gate; dùng observation thật và quy trình trong
[WP9 Release Runbook](docs/WP9_RELEASE_RUNBOOK.md), không bật flag chỉ dựa trên offline report.

Kết quả gần nhất 2026-08-15: backend 248 passed; Ruff pass; frontend 60 test/12 files,
lint/typecheck/cutover check, Next.js Turbopack + webpack standalone production build và Chromium E2E 2 pass.
Đây chưa phải hosted release evidence.

## Tài liệu canonical

- [Product Scope](docs/scope.md) — goal và boundary.
- [Implementation Status](docs/implementation-status.md) — code đã có, partial, deprecated và gap.
- [Architecture](docs/01-ARCHITECTURE.md) — kiến trúc hiện tại và kiến trúc đích.
- [Contract](docs/02-CONTRACT_AND_FIXTURES.md) — contract đang chạy và migration cần thiết.
- [Implementation Plan](docs/03-IMPLEMENTATION_PLAN.md) — thứ tự công việc để đạt scope.
- [WP9 Release Runbook](docs/WP9_RELEASE_RUNBOOK.md) — preflight, hosted smoke, restore, compatibility window và rollback.
- [Database Status](docs/04-POSTGRESQL_ALEMBIC_PLAN.md) — schema hiện tại và migration legacy.

## Safety invariants đang áp dụng

- Web product chỉ gọi URL/domain/official provider theo context sau disclosure; API executor vẫn yêu cầu authorization
  trong request, kiểm tra target allowlist và không cho AI tự tạo target.
- Lượt intake đầu luôn vào `/api/v4/analyses`. Sau verdict, `/api/v4/chat` chỉ trả lời hội thoại thường khi GPT không
  gọi tool; nếu có `check_scam`, frontend mở một lượt analysis v4 mới trước khi hiển thị kết luận bảo mật.
- SSRF guard chặn private/local/metadata target và revalidate redirect.
- Provider no-hit/error hoặc thiếu evidence không tự động tạo `SAFE`.
- LLM không trực tiếp ghi score/risk/action.
- URL đáng ngờ được hiển thị dạng text trong UI.
- Blacklist write qua flow hiện tại cần Security Admin decision và audit.
