# PROJECT BRIEF — TRUSTGUARD AI

## Tên đề tài

**AI Agent Phát hiện & Cảnh báo Tin giả / Link độc trong Tin nhắn**

Mã dự án: **P-068** · Tên sản phẩm: **TrustGuard AI**

## Thực trạng và vấn đề

Tin nhắn giả mạo thương hiệu, khuyến mãi lừa đảo, yêu cầu OTP/chuyển tiền và claim sai lan truyền
nhanh qua chat. Người dùng phổ thông khó đọc cấu trúc URL, kiểm tra domain/redirect, đối chiếu nhiều
nguồn và hiểu output kỹ thuật từ công cụ bảo mật.

Người dùng cần một trợ lý có thể:

1. Nhận đúng message/URL họ chủ động chọn, không đọc nền toàn bộ hội thoại.
2. Trích xuất URL, thương hiệu, claim, hành động được yêu cầu và dấu hiệu gây áp lực.
3. Lập kế hoạch điều tra bằng rule, blacklist, reputation, RDAP/WHOIS và fact-check.
4. Chấm điểm từ evidence có cấu trúc và cảnh báo ngay trong hội thoại bằng ngôn ngữ dễ hiểu.
5. Không kết luận quá mức khi provider no-hit, lỗi hoặc thiếu dữ liệu.
6. Chuyển tác động diện rộng cho Security Admin phê duyệt.

## Giải pháp

TrustGuard AI dùng LangGraph điều phối luồng:

```text
extract-link → scan URL/domain → verify-claim → deterministic score → warn/escalate
```

Rule, approved blacklist và cached reputation chạy trước để tạo cảnh báo sơ bộ nhanh. External tools
chỉ chạy sau consent/policy; `gpt-4o-mini` hỗ trợ hiểu ngữ cảnh và viết giải thích grounded, không tự
tạo evidence hoặc sửa score/verdict/action.

Kết quả gồm risk score, mức rủi ro, verdict, lý do, evidence, limitation và khuyến nghị. Cảnh báo cá
nhân không chờ admin, nhưng blacklist/block domain/cảnh báo diện rộng luôn cần Human-in-the-loop và
audit.

## Công nghệ & kiến trúc

| Thành phần | Lựa chọn |
|---|---|
| LLM | GPT-4o-mini cho semantic context và grounded explanation |
| Tools | GSB/Web Risk hoặc VirusTotal, RDAP-first WHOIS, guarded redirect, fact-check retriever |
| Orchestration | LangGraph extract → scan → verify → score → warn/escalate |
| Vector DB | PostgreSQL + pgvector cho trusted fact-check corpus ở pha nâng cao |
| Realtime | WebSocket với polling replay/fallback |
| Backend / Frontend | FastAPI / Next.js React warning banner |
| Data / Cache | PostgreSQL source of truth / Redis broker-cache-event fan-out |
| Deploy | Docker, Railway target |

Hiện repository đã có backend contract v2, LangGraph vertical slice và SQLite persistence; frontend
integration, WebSocket và topology production vẫn thuộc kế hoạch triển khai.

## Phạm vi final product

### Core product

- App deploy; đăng nhập và vai trò user/security-admin.
- Phân tích URL/message được user chủ động gửi, có consent external lookup.
- Rule, blacklist, URL reputation, RDAP/WHOIS, redirect và fact-check provider.
- Cảnh báo inline hai pha, risk score deterministic, evidence/limitation/recommendation.
- History, report, admin review, audit và admin-managed blacklist.
- Rate limiting, tool/LLM budget và theo dõi chi phí/quota.

### Advanced intelligence

- Trusted fact-check corpus với pgvector và citation có version.
- Screenshot renderer sandboxed, không cookie/login, chỉ sau consent khi scan tĩnh chưa đủ.
- Campaign clustering và dashboard xu hướng tin giả.
- Học có kiểm duyệt từ report/appeal; không online-learn trực tiếp.
- Dashboard latency/API cost/rate-limit và appeal lifecycle đầy đủ.

Core product và Advanced intelligence đều phải hoàn tất trước final release. Việc chia nhóm chỉ thể
hiện dependency triển khai, không phải một mốc MVP; bốn thành viên thực hiện song song bằng bốn coding
agents theo các merge wave trong `../03-IMPLEMENTATION_PLAN.md`.

## Ràng buộc

- E2E-aware và data minimization: không đọc toàn bộ private chat, không log raw message/OTP/secret.
- False-positive control: deterministic scoring, `inconclusive` khi thiếu/mâu thuẫn evidence.
- Human-in-the-loop cho mọi hành động diện rộng.
- Provisional warning p95 ≤ 1 giây từ local/cache; final p95 ≤ 10 giây khi provider bình thường.

## Chỉ số

- Precision/recall/false-positive rate theo risk level trên evaluation set có version.
- URL extraction, tool routing và grounded-evidence coverage.
- Provisional/final latency, cache hit, provider timeout/429, token và cost mỗi analysis.
- Admin review time, appeal uphold rate và blacklist rollback.
