# Product Requirements — P-068

**Sản phẩm:** TrustGuard AI — Agent phát hiện tin giả và liên kết độc trong tin nhắn

**Bản tài liệu:** 2.4 — 2026-08-09

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
- ưu tiên rule, approved blacklist và cached reputation cho URL; dùng external model APIs thay model
  local cho claim extraction, embedding và evidence comparison;
- dùng URL scanner, RDAP/WHOIS, redirect resolver và fact-check retrieval khi có consent/policy;
- coi Google Fact Check Claim Search là index của các claim/review đã tồn tại, không phải dịch vụ
  Google tự xác minh; chỉ kết luận từ publisher/reviewer và evidence đủ điều kiện;
- dùng `gpt-4o-mini` cho claim extraction/evidence comparison/diễn giải và
  `text-embedding-3-small` cho semantic retrieval; không giao quyền chấm điểm cho LLM;
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
6. URL reputation và RDAP/WHOIS có thể chạy song song; redirect được kiểm tra từng hop. Với tối đa
   năm claim đủ điều kiện, agent redact/canonicalize rồi gọi một embeddings batch. Từng claim chạy
   song song Google Claim Search và PostgreSQL FTS/pgvector, sau đó áp evidence-sufficiency gate.
7. Chỉ khi evidence chưa đủ, Tavily tìm URL theo Source Registry; Jina Reader trích text,
   `langchain-text-splitters` tạo chunk và FlashRank multilingual chọn top 5. External LLM so sánh
   evidence và trả stance có schema/citation. Risk Engine hợp nhất structured
   evidence thành score/verdict/action deterministic; LLM không ghi trực tiếp ba trường này.
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

- Fact-check external-model-first với batch embedding, PostgreSQL FTS + pgvector, Google Fact Check
  Claim Search, conditional Tavily Search, Jina Reader, `langchain-text-splitters`, local CPU
  FlashRank multilingual và evidence comparison có citation.
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
- **False positive control:** score deterministic có version; LLM stance chỉ hợp lệ khi schema có
  evidence refs; evidence mâu thuẫn/thiếu phải trả `mixed`/`inconclusive` khi phù hợp.
- **Human-in-the-loop:** cảnh báo cá nhân có thể tự động; blacklist/block/broad warning cần reviewer,
  note, timestamp, evidence snapshot và audit.
- **Source Trust Policy:** Tier A là `*.gov.vn`; Tier B là báo chí được duyệt và trusted
  fact-checkers; Tier C là nguồn uy tín khác; blog không rõ nguồn, forum và social media là
  Untrusted. Tier A/B mới được hỗ trợ kết luận, Tier C chỉ corroborate, Untrusted chỉ discovery và
  bị loại trước comparator. Registry deny/disable luôn thắng suffix rule.
- **Temporal retrieval:** temporal claim phải mang claim date/range; evidence lưu publication,
  effective và retrieval date. Effective interval phù hợp được ưu tiên; thiếu effective date có thể
  dùng publication/update date làm proxy với penalty và limitation; không có ngày thì loại.
- **Cost/latency:** tối đa năm claim dùng một embeddings request, sau đó fan-out tối đa ba claim;
  chỉ gọi Tavily/Jina sau evidence-sufficiency gate; provider calls tuân deadline/quota/budget.
- **Model boundary:** embedding/comparison không fallback sang model local. FlashRank là ngoại lệ
  reranker local CPU, không sinh verdict. Khi embeddings lỗi, pipeline bỏ qua vector retrieval,
  tiếp tục Google/corpus lexical và conditional web, đồng thời ghi limitation.
- **Unsafe navigation:** URL đáng ngờ không hiển thị thành anchor trực tiếp; redirect/screenshot phải
  qua SSRF guard, DNS revalidation, hop/body/time limit.

## 6. Chỉ số thành công

- Precision, recall và false-positive rate theo risk level trên fixture/eval set có version; chốt
  release threshold sau khi có baseline, không đặt số tùy ý trước khi đo.
- Tỷ lệ analysis có evidence/limitation đầy đủ và tỷ lệ no-hit/timeout không bị diễn đạt thành safe.
- Provisional/final latency p50/p95, tool timeout, cache hit và số call mỗi analysis.
- Token và chi phí theo embedding/Google/Tavily/Jina/comparison; FTS/vector/cache hit, tỷ lệ tránh
  Tavily, temporal-incompatible evidence, FlashRank latency, stale rate, 429 và budget-exhausted.
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
| AC-07 | Có 1–5 claim kiểm chứng được | Chỉ tạo một embeddings batch; từng claim chạy Google Claim Search và corpus hybrid trước web. |
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
| AC-19 | Embedding API timeout/429 | Không tạo embedding fallback local; vẫn chạy Google/FTS và conditional web trong budget, có limitation. |
| AC-20 | Temporal claim tìm thấy bài semantic-relevant nhưng sai thời điểm | Evidence bị loại hoặc hạ hạng theo effective/publication proxy; semantic score không được lấn át temporal incompatibility. |
| AC-21 | Google Fact Check trả match | Match được ghi là ClaimReview của publisher/reviewer, không được trình bày như verdict do Google xác minh. |
| AC-22 | Một Tier A temporal-compatible, một trusted ClaimReview Tier B, hoặc hai Tier B độc lập | Evidence gate đủ; không gọi Tavily/Jina và chuyển thẳng comparator. |
| AC-23 | Chỉ có Tier C/Untrusted hoặc evidence chưa đủ | Tier C không tự đủ, Untrusted bị loại; Tavily chỉ tìm domain registry cho phép rồi Jina fetch tối đa 5 URL. |
| AC-24 | Web evidence mới hợp lệ | Deduplicate rồi cache ngay; chỉ bản Tier A/B đã validate/review mới được promote trusted corpus. |
| AC-25 | Jina/FlashRank lỗi | Trả evidence khả dụng kèm limitation hoặc `inconclusive`; không bịa citation và không trả safe. |
