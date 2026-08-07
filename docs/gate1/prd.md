# PRODUCT REQUIREMENTS DOCUMENT — TRUSTGUARD AI

## 1. Mục tiêu

Xây dựng AI Agent giúp người dùng đánh giá URL hoặc tin nhắn đáng ngờ bằng quy trình có bằng chứng,
cảnh báo inline hai pha và Human-in-the-loop cho mọi hành động ảnh hưởng nhiều người.

## 2. Persona

### User

- Chủ động chọn message/URL cần phân tích và cấp/từ chối consent external lookup.
- Xem cảnh báo sơ bộ, tiến trình, kết luận cuối, evidence và limitation.
- Xem lịch sử, gửi report và appeal khi cho rằng cảnh báo sai.

### Security Admin

- Review case, report, appeal, campaign hypothesis và evidence snapshot.
- Quản lý blacklist có provenance/lifecycle.
- Phê duyệt/từ chối block domain và broad warning với note/audit.

## 3. User flow

1. User đăng nhập, chọn nội dung cần kiểm tra và xem disclosure.
2. Agent extract URL, claim, brand, requested action và social-engineering signals.
3. Rule, approved blacklist và reputation cache tạo provisional warning có nhãn đang xác minh.
4. Policy planner gọi URL reputation, guarded redirect, RDAP-first WHOIS và fact-check theo consent,
   SSRF guard, deadline, quota và cost budget.
5. Risk Engine chấm điểm deterministic; GPT-4o-mini chỉ review coverage và viết giải thích grounded.
6. UI cập nhật final warning, evidence, limitation và recommendation.
7. Critical/conflicting/user-reported case vào admin queue; warning cá nhân vẫn hiện ngay.
8. Mọi blacklist/block/broad warning chỉ có hiệu lực sau admin approval và audit.

## 4. Functional requirements

### FR-01 — Authentication và RBAC

- Hai vai trò `user` và `security_admin`; production không dùng demo token.
- User chỉ đọc analysis/appeal của mình; admin endpoint yêu cầu role tương ứng.

### FR-02 — Consent và input privacy

- Nhận URL hoặc message 1–5.000 ký tự do user chủ động gửi.
- Consent riêng cho URL/domain lookup và screenshot; từ chối consent vẫn cho phép local analysis.
- Không đọc nền toàn bộ conversation, không phá E2E, không log raw message/OTP/secret.

### FR-03 — Extraction và plan

- Extract URL, claim, brand, requested action, urgency và scam indicators.
- Công khai plan/status ở mức task trace; không công khai chain-of-thought/prompt/model trace.
- Tool ngoài allowlist hoặc vượt consent/budget không được chạy dù LLM đề xuất.

### FR-04 — URL/domain investigation

- Normalize URL/IDNA, kiểm tra look-alike, blacklist, reputation và redirect.
- Dùng adapter GSB/Web Risk hoặc VirusTotal; no-hit là `inconclusive`, không phải `safe`.
- RDAP-first cho WHOIS metadata công khai; không lưu registrant entity/private record.
- Chặn private/local/metadata IP trước kết nối và revalidate mỗi redirect.

### FR-05 — Claim verification

- Fact-check qua provider và, ở pha nâng cao, trusted pgvector corpus có source/version/citation.
- Similarity chỉ dùng retrieval; stance/verdict không được suy ra từ embedding distance.
- Không có nguồn hoặc nguồn mâu thuẫn phải trả limitation/inconclusive phù hợp.

### FR-06 — Risk và warning

- Score/verdict/action được tính deterministic từ structured evidence và scoring version.
- Provisional warning từ local/blacklist/cache phải có nhãn đang xác minh.
- Final warning gồm score, risk level, verdict, confidence, reasons, evidence, limitations và action.
- URL đáng ngờ không là anchor bấm trực tiếp.

### FR-07 — Realtime

- Progress/final event qua WebSocket; polling endpoint là fallback/replay.
- Disconnect không hủy analysis; reconnect dedupe event bằng ID/cursor.

### FR-08 — History, report và appeal

- User xem lịch sử và gửi report.
- Pha nâng cao hỗ trợ appeal receipt, status, reviewer decision và notification.
- Feedback không tự thay đổi score/model/blacklist; chỉ vào evaluation/review workflow.

### FR-09 — Admin và Human-in-the-loop

- Admin xem evidence/audit trước decision.
- `add_to_blacklist`, `disable_blacklist`, `block_domain` và `publish_broad_warning` cần approved
  decision; overturn tạo corrective record, không xóa lịch sử.

### FR-10 — Campaign và operations

- Pha nâng cao cluster theo domain/redirect/claim/time-window và chỉ tạo admin hypothesis.
- Không lưu social graph hay suy diễn sender identity.
- Dashboard aggregate trend, false-positive, appeal, latency, cache, token/cost, quota và 429/timeout.

### FR-11 — Screenshot renderer

- Pha nâng cao, chỉ chạy khi consent và static evidence chưa đủ.
- Sandbox không cookie, login, credential hoặc persistent state; có SSRF, redirect, time, body và
  download limits.

## 5. Non-functional requirements

- Provisional warning p95 ≤ 1 giây khi local/cache có signal; final p95 ≤ 10 giây khi provider bình
  thường. Timeout trả result giới hạn trong deadline.
- Deterministic fallback khi LLM/provider lỗi; không bịa evidence hoặc trả 500 chỉ do LLM.
- Precision/recall/false-positive đo trên versioned evaluation set; release threshold được chốt sau
  baseline thay vì đặt số tùy ý.
- Tool/token/cost budget, bounded retries, cache và rate limiting áp dụng theo analysis/principal.
- PostgreSQL là source of truth; Redis chỉ làm broker/cache/event fan-out.
- Secret chỉ ở server; operational metrics không chứa raw private input.

## 6. Acceptance criteria

- URL/claim được extract và plan/tool routing đúng policy.
- Không consent thì không tạo external client/request; limitation vẫn rõ.
- Provider no-hit/timeout/429 không tạo verdict safe.
- Cùng evidence/scoring version luôn cho cùng score/verdict/action.
- User thấy provisional → progress → final qua WebSocket hoặc polling fallback.
- Cảnh báo cá nhân hiển thị ngay; wide action không thể bypass admin approval/audit.
- Fact-check có citation; screenshot/campaign chỉ bật khi đạt privacy/security gates.
- Report/appeal có ownership, receipt và immutable review history.
- Dashboard vận hành không lộ raw message, URL secret hoặc prompt.

## 7. Trạng thái triển khai final product

- **Đã có:** backend contract v2, LangGraph vertical slice, deterministic scoring, SQLite repository,
  report/admin-decision APIs và fake adapters offline.
- **Core workstream bắt buộc:** frontend HTTP integration, RDAP/redirect runtime wiring, production
  reputation cascade, live progress/WebSocket, PostgreSQL/Redis worker path, OIDC và Railway.
- **Intelligence workstream bắt buộc:** pgvector corpus, screenshot renderer, campaign detection,
  cost/trend dashboard, appeal và calibrated learning.
- **Contract migration:** `/api/v2` là baseline hiện tại; final frontend dùng `/api/v3`, đồng thời
  giữ v2 read-compatible trong release v3 đầu tiên.

Không release một bản MVP riêng. Final release chỉ qua gate khi cả hai workstream, privacy/security
tests và Human-in-the-loop backend gate đều hoàn tất.
