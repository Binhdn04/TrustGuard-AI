# Product Requirements — P-068

**Sản phẩm:** TrustGuard AI — Agent phát hiện tin giả và liên kết độc trong tin nhắn

**Bản tài liệu:** 2.2 — 2026-08-07

**Trạng thái:** Backend vertical slice đã chạy; final product đang được triển khai từ baseline hiện tại

> Contract đang chạy nằm ở `02-CONTRACT_AND_FIXTURES.md`; hiện trạng và kiến trúc đích ở
> `01-ARCHITECTURE.md`; thứ tự giao hàng ở `03-IMPLEMENTATION_PLAN.md`.

## 1. Vấn đề và mục tiêu

Link phishing, giả mạo thương hiệu và tuyên bố sai thường lan qua chat với ngôn ngữ khẩn cấp khiến
người dùng khó tự kiểm tra URL, domain, redirect và nguồn xác thực. TrustGuard AI phân tích đúng phần
nội dung người dùng chủ động chọn, lập kế hoạch điều tra, thu thập evidence, chấm điểm rủi ro và cảnh
báo ngay trong hội thoại bằng giải thích dễ hiểu.

Mục tiêu sản phẩm:

- phát hiện URL/claim đáng ngờ mà không cần đọc nền toàn bộ cuộc hội thoại;
- ưu tiên rule, approved blacklist và cached reputation để giảm độ trễ/chi phí;
- dùng URL scanner, RDAP/WHOIS, redirect resolver và fact-check retriever khi có consent/policy;
- dùng `gpt-4o-mini` cho phân tích ngữ cảnh và diễn giải, không giao quyền chấm điểm cho LLM;
- không biến no-hit, timeout hoặc thiếu evidence thành kết luận an toàn;
- cảnh báo cá nhân ngay, nhưng yêu cầu Security Admin duyệt block domain/cảnh báo diện rộng;
- cho phép report/appeal để đo và sửa false positive có kiểm soát.

## 2. Người dùng và quyền hạn

### User

- Đăng nhập, chọn một message/URL cần kiểm tra và quyết định consent cho external lookup.
- Nhận cảnh báo sơ bộ, theo dõi kế hoạch điều tra và xem kết luận cuối kèm evidence/limitation.
- Xem lịch sử của chính mình, gửi report hoặc appeal khi cho rằng kết quả sai.

### Security Admin

- Xem case `pending_review`, report, appeal, evidence, decision audit và blacklist.
- Phê duyệt/bác bỏ case, yêu cầu điều tra thêm và quản lý lifecycle blacklist.
- Phê duyệt riêng mọi hành động `block_domain` hoặc `publish_broad_warning`.

Auth hiện tại chỉ có demo bearer tokens; production phải dùng IdP/OIDC hoặc session auth tương đương.

## 3. Trải nghiệm hai pha

1. User chủ động gửi message/URL và đọc disclosure về dữ liệu có thể gửi tới provider.
2. API validate, persist analysis `queued` và trả `202`.
3. Agent extract URL, claim, thương hiệu, hành động được yêu cầu và dấu hiệu social engineering.
4. Local rule, approved blacklist và reputation cache tạo assessment sơ bộ; UI có thể hiển thị
   warning banner ngay, gắn nhãn **đang xác minh**.
5. LangGraph lập policy plan `extract-link → scan → verify-claim → score → warn/escalate`. Executor
   kiểm tra consent, SSRF, allowlist, deadline, quota và cost budget trước mỗi external call.
6. URL reputation và RDAP/WHOIS có thể chạy song song; redirect được kiểm tra từng hop. Fact-check
   chỉ chạy khi có claim đủ điều kiện. Screenshot chỉ thuộc pha nâng cao và chỉ chạy khi scan tĩnh
   chưa đủ evidence.
7. Risk Engine hợp nhất structured evidence thành score/verdict/action. LLM chỉ review coverage và
   tạo lời giải thích grounded theo evidence index.
8. UI cập nhật kết luận cuối, lý do, nguồn, thời điểm quan sát, limitation và hành động khuyến nghị.
9. Cảnh báo cá nhân không chờ admin. Hành động diện rộng tạo case và chỉ có hiệu lực sau phê duyệt
   có audit.

Mục tiêu SLO: provisional warning p95 không quá 1 giây khi local/cache có dữ liệu; final result p95
không quá 10 giây khi provider hoạt động bình thường. Timeout phải trả kết quả giới hạn trong budget.

## 4. Phạm vi

### 4.1 Core product

- App deploy, login và RBAC `user`/`security_admin`.
- Input URL hoặc message 1–5.000 ký tự do user chủ động gửi.
- Structured extraction, URL normalization, punycode/look-alike, brand-domain mismatch.
- Local rules, approved blacklist, URL reputation adapter, RDAP-first WHOIS, guarded redirects và
  fact-check provider.
- Deterministic risk score, confidence, verdict, evidence, limitation và inline warning hai pha.
- Investigation progress qua WebSocket, cùng polling fallback.
- History, user report, admin review, audit và admin-managed blacklist.
- Rate limiting, tool/LLM budget, cache và quan sát token/cost/provider quota.
- Docker deployment; production target dùng PostgreSQL, Redis và Railway.

### 4.2 Advanced intelligence

- pgvector fact-check corpus với nguồn tin cậy, version và ngày cập nhật.
- Screenshot renderer sandboxed, không cookie/credential/login, có consent và giới hạn tài nguyên.
- Phát hiện campaign theo cụm URL/domain/claim, không suy diễn danh tính người gửi.
- Feedback learning theo batch có evaluation và admin approval; không online-learn trực tiếp.
- Dashboard xu hướng, false-positive, API cost, cache hit, latency, quota và rate-limit.
- Appeal lifecycle đầy đủ, SLA review và thông báo kết quả cho user.

Core product và Advanced intelligence đều thuộc phạm vi bắt buộc của final release. Hai nhóm chỉ mô
tả dependency: capability advanced được merge sau khi contract, privacy, consent, SSRF và durable
runtime gates tương ứng đã xanh; không có release MVP ở giữa.

### 4.3 Ngoài phạm vi

- Đọc nền toàn bộ chat từ Zalo/Messenger/WhatsApp/SMS/email hoặc phá E2E encryption.
- Tự bấm link trên thiết bị user, chạy file, đăng nhập website hoặc sandbox malware đầy đủ.
- Thu thập registrant/private WHOIS data hay gửi raw private message cho provider không cần thiết.
- Tự block domain, tự phát cảnh báo diện rộng hoặc tự cập nhật model/score từ feedback.
- Khẳng định tuyệt đối một URL an toàn hoặc thay thế chuyên gia/phán quyết pháp lý.

## 5. Chính sách an toàn, riêng tư và độ chính xác

- **Data minimization:** external URL/domain lookup cần consent; LLM/fact-check chỉ nhận đoạn trích,
  claim hoặc metadata tối thiểu đã redact. Log không chứa raw message, OTP, secret hay provider body.
- **E2E-aware:** tích hợp chat phải do client/user chủ động chuyển nội dung sang TrustGuard; backend
  không được yêu cầu khóa giải mã hay quyền đọc lịch sử hội thoại.
- **False positive control:** score deterministic có version; recent domain hoặc tín hiệu LLM đơn lẻ
  không đủ kết luận malicious; evidence mâu thuẫn/thiếu phải trả `inconclusive` khi phù hợp.
- **Human-in-the-loop:** cảnh báo cá nhân có thể tự động; blacklist/block/broad warning cần reviewer,
  note, timestamp, evidence snapshot và audit.
- **Cost/latency:** local/cache trước, external tools chạy song song trong budget, LLM chỉ cho ca cần
  semantic context; retry có giới hạn và fallback deterministic.
- **Unsafe navigation:** URL đáng ngờ không hiển thị thành anchor trực tiếp; redirect/screenshot phải
  qua SSRF guard, DNS revalidation, hop/body/time limit.

## 6. Chỉ số thành công

- Precision, recall và false-positive rate theo risk level trên fixture/eval set có version; chốt
  release threshold sau khi có baseline, không đặt số tùy ý trước khi đo.
- Tỷ lệ analysis có evidence/limitation đầy đủ và tỷ lệ no-hit/timeout không bị diễn đạt thành safe.
- Provisional/final latency p50/p95, tool timeout, cache hit và số call mỗi analysis.
- Token và chi phí provider theo ngày/user/analysis; tỷ lệ 429 và budget-exhausted.
- Tỷ lệ critical case được review, thời gian review, appeal uphold rate và blacklist rollback.
- Campaign cluster precision phải được reviewer xác nhận trước khi dùng cho broad warning.

## 7. Acceptance criteria

| ID | Given / When | Then |
|---|---|---|
| AC-01 | User gửi input hợp lệ | Analysis được tạo, extract URL/claim và có plan quan sát được. |
| AC-02 | Input rỗng/quá dài | Trả validation error trước LLM/tool. |
| AC-03 | Có local/cache signal | UI nhận provisional warning có nhãn đang xác minh; không trình bày như verdict cuối. |
| AC-04 | User không consent URL lookup | Không tạo client/task/request external; local rule/blacklist vẫn chạy và ghi limitation. |
| AC-05 | User consent URL lookup | URL được normalize, SSRF-check và scan; evidence có source/timestamp. |
| AC-06 | URL redirect sang private/local/metadata IP | Chặn trước kết nối ở mọi hop. |
| AC-07 | Có claim kiểm chứng được | Retriever trả nguồn/stance; thiếu nguồn thì không tự suy diễn. |
| AC-08 | Provider no-hit/timeout/429 | Không trả safe chỉ vì thiếu dữ liệu; có limitation và retry/budget đúng policy. |
| AC-09 | Cùng evidence và scoring version | Score/verdict/action lặp lại giống nhau dù không có LLM. |
| AC-10 | LLM lỗi hoặc output sai schema | Workflow dùng deterministic fallback, không bịa evidence và không trả 500 chỉ vì LLM. |
| AC-11 | Analysis đang chạy | Owner nhận đúng progress qua WebSocket hoặc polling fallback. |
| AC-12 | Kết quả high/critical | Warning cá nhân hiển thị ngay; case phù hợp được tạo cho admin. |
| AC-13 | Cần block/broad warning | Không có hiệu lực trước admin approval và audit transaction thành công. |
| AC-14 | User báo false positive/appeal | Receipt được lưu, reviewer xử lý và kết quả không tự động sửa model/blacklist. |
| AC-15 | Screenshot advanced được yêu cầu | Chỉ chạy sau consent trong sandbox không cookie/login; lỗi không chặn fallback. |
| AC-16 | Campaign cluster được phát hiện | Chỉ hiện cho admin như hypothesis có evidence; broad warning vẫn chờ duyệt. |
| AC-17 | User thường gọi admin API hoặc đọc analysis người khác | Trả 403/404 phù hợp, không rò dữ liệu. |
| AC-18 | Dashboard vận hành | Hiển thị latency, cost, quota/429 và false-positive mà không chứa raw private message. |
