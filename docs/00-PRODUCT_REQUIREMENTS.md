# Product Requirements — P-068

**Sản phẩm:** AI Agent phát hiện tin giả và link độc trong tin nhắn

**Giai đoạn:** MVP+ — hoàn thiện vertical slice hiện có và bổ sung domain intelligence

**Trạng thái:** Implementation-ready — 2026-08-06

> Tài liệu này định nghĩa **sản phẩm phải làm gì**. Schema, enum và fixture nằm tại `02-CONTRACT_AND_FIXTURES.md`; topology kỹ thuật nằm tại `01-ARCHITECTURE.md`; cách chia việc nằm tại `03-IMPLEMENTATION_PLAN.md`.

## 1. Vấn đề và mục tiêu

Tin nhắn giả mạo, link phishing và khuyến mãi lừa đảo thường được chia sẻ qua chat. Người dùng phổ thông khó tự kiểm tra domain, redirect và tính xác thực của claim trên nhiều nguồn.

MVP cho phép người dùng chủ động dán một URL hoặc tin nhắn để nhận đánh giá có bằng chứng trong vòng 60 giây ở điều kiện bình thường. Hệ thống phải:

- phát hiện dấu hiệu link độc, giả mạo thương hiệu và claim đáng ngờ;
- giải thích rủi ro và hành động nên làm bằng ngôn ngữ dễ hiểu;
- không biến thiếu dữ liệu thành kết luận “an toàn”;
- dùng scoring xác định từ structured evidence, không để LLM tự chấm điểm;
- dùng `gpt-4o-mini` để hiểu ngữ cảnh, kỹ thuật tác động cảm xúc và ý đồ có khả năng
  thuộc về người gửi; kết quả LLM không được xem là external evidence;
- yêu cầu Security Admin duyệt mọi thay đổi blacklist hoặc cảnh báo diện rộng;
- chỉ xử lý nội dung người dùng chủ động gửi.

### 1.1 Kết quả của lần mở rộng này

Codebase đã có graph phân tích URL/claim, Safe Browsing adapter, Google Fact Check adapter,
blacklist repository và deterministic scoring, nhưng API hiện mới tạo record `queued` và chưa nối
workflow/persistence thành một luồng end-to-end. Lần mở rộng phải hoàn thiện agent điều tra cho
**tin nhắn có URL và/hoặc tuyên bố**, đồng thời bổ sung domain intelligence:

- lập một `investigation_plan` có các bước quan sát được, nhưng policy engine có quyền phủ quyết;
- tra memory blacklist trước khi gọi provider để giảm độ trễ và chi phí;
- phân tích URL, redirect và thông tin đăng ký/tuổi domain;
- đối chiếu reputation/phishing database và truy xuất fact-check cho claim;
- hợp nhất evidence, chấm điểm deterministic và cảnh báo ngay trong kết quả hội thoại;
- tạo security case khi cần review, nhưng không trì hoãn cảnh báo cá nhân cho user.

## 2. Persona

### Người dùng

Dán nội dung đáng ngờ, theo dõi tiến trình, xem kết quả và lịch sử của mình, báo kết quả sai hoặc yêu cầu review.

### Security Admin

Xem hàng đợi case cần duyệt, kiểm tra evidence, xác nhận/bác bỏ kết luận, yêu cầu điều tra thêm và phê duyệt thay đổi blacklist có audit trail.

## 3. User flow

### 3.1 Phân tích

1. User đăng nhập, dán URL/tin nhắn, xem thông báo dữ liệu nào có thể được gửi tới LLM/fact-check
   provider, chọn đồng ý hoặc không đồng ý **external URL/domain lookup**, rồi bấm **Kiểm tra**.
2. Hệ thống validation, trích xuất URL/claim và dùng structured LLM output để phân tích
   ngữ cảnh, cảm xúc gây áp lực, ý đồ của người gửi và dấu hiệu lừa đảo; nếu input không
   hợp lệ thì dừng trước khi gọi model/tool.
3. LLM đề xuất kế hoạch điều tra và thứ tự tool trong allowlist; Agent lưu trạng thái từng bước và vẫn cưỡng chế consent, SSRF guard,
   retry và budget trước khi chạy rule nội bộ, blacklist và provider phù hợp.
4. Agent tra approved blacklist trước; nếu được consent, các lookup URL reputation và RDAP độc lập
   có thể chạy song song. Fact-check retriever chỉ chạy khi có claim đủ điều kiện và evidence còn thiếu.
5. Risk Engine tổng hợp evidence thành điểm/mức rủi ro deterministic. LLM chỉ review
   assessment và viết giải thích grounded, không được sửa score, verdict hay tạo evidence.
6. UI hiển thị tiến trình điều tra, verdict, mức/điểm rủi ro, lý do, evidence, limitations và hành động đề xuất ngay trong hội thoại.
7. Case cần hành động diện rộng được đưa vào hàng đợi admin; cảnh báo cho user không phải chờ admin.

### 3.2 Admin review

1. Admin mở case đã escalate và xem evidence/audit trail.
2. Admin chọn **phê duyệt**, **bác bỏ**, hoặc **yêu cầu thêm evidence** và nhập lý do.
3. Chỉ quyết định phê duyệt rõ ràng mới được tạo thay đổi blacklist; mọi quyết định đều được audit.

### 3.3 Tool lỗi hoặc thiếu dữ liệu

Agent retry trong budget. Khi LLM hoặc tool lỗi/hết budget, hệ thống trả kết quả giới hạn
với verdict `inconclusive` khi phù hợp, nêu model/tool/dữ liệu còn thiếu, dùng fallback
deterministic và không giả lập evidence.

## 4. Phạm vi MVP

- Đăng nhập và RBAC cho `user`, `security_admin`.
- Nhập một URL hoặc một tin nhắn tối đa 5.000 ký tự.
- Consent riêng cho external URL/domain lookup; UI phải nói rõ lookup có thể tiết lộ URL/domain cho provider.
- Phân tích URL/claim bằng rule, approved blacklist, một URL reputation adapter còn được hỗ trợ,
  một RDAP-over-HTTPS adapter và fact-check retriever.
- Kiểm tra URL an toàn gồm normalization, punycode/look-alike, redirect metadata và SSRF guard.
- Agent workflow có nhánh, retry và giới hạn tool/time/cost.
- Structured LLM reasoning bằng `gpt-4o-mini` cho semantic analysis, tool planning,
  assessment review và phản hồi grounded; có timeout, retry và deterministic fallback.
- Kết quả có evidence, limitations và nguồn/thời điểm quan sát.
- Lịch sử phân tích, báo kết quả sai, review queue và audit trail.
- Realtime progress bằng WebSocket, có polling fallback.
- Công khai `investigation_plan` và trạng thái bước ở mức an toàn; không công khai chain-of-thought, prompt hoặc raw provider response.
- Docker Compose cho API, PostgreSQL và Redis; worker tách riêng sau khi vertical slice đồng bộ đã
  chạy đúng. `pgvector` chỉ bật khi semantic retrieval chứng minh cần thiết.

## 5. Ngoài phạm vi MVP

- Tự đọc toàn bộ hội thoại từ Zalo/Messenger/WhatsApp/email.
- Tự mở link trên thiết bị user, tải/chạy file hoặc sandbox malware đầy đủ.
- WHOIS TCP fallback và thu thập thông tin registrant; MVP chỉ dùng dữ liệu domain công khai từ RDAP.
- Safe screenshot renderer và điều tra hình ảnh trang đích.
- Tự động quét nền mọi tin nhắn hoặc tích hợp trực tiếp nền tảng chat; UI hội thoại của MVP chỉ phân tích nội dung user chủ động gửi.
- Tự động chặn domain hoặc phát cảnh báo diện rộng không qua admin.
- Phát hiện chiến dịch lan truyền, dashboard xu hướng nâng cao, online learning.
- Native mobile app, browser extension hoặc tích hợp trực tiếp app chat.
- Cam kết thay thế chuyên gia an ninh hoặc kết luận pháp lý.

## 6. Chỉ số thành công

- 100% analysis hoàn tất trả đủ các trường bắt buộc theo contract v1.
- 100% tool call phải ánh xạ tới một bước trong `investigation_plan` và qua policy guard.
- 100% provider failure/thiếu evidence có limitation và không bị diễn đạt thành “safe”.
- 100% LLM output ảnh hưởng routing/response phải qua schema và safety guard; LLM
  failure không làm mất kết quả deterministic.
- 100% thay đổi blacklist có admin decision và audit record.
- Luồng phổ biến hoàn tất trong 60 giây; hết budget phải fail safely.
- Không có secret hoặc toàn bộ message trong operational log.
- Bộ fixture chuẩn chạy offline và deterministic trong CI.

## 7. Acceptance criteria

| ID | Given / When | Then |
|---|---|---|
| AC-01 | User hợp lệ gửi message 1–5.000 ký tự | Tạo analysis và bắt đầu workflow. |
| AC-02 | Input rỗng/quá dài/sai kiểu | Trả validation error; không gọi external tool. |
| AC-03 | Message chứa URL/claim | Trích xuất structured data; không bịa trường còn thiếu. |
| AC-04 | URL có consent external lookup | Normalize, kiểm tra blacklist/rule/reputation/RDAP; evidence có source và timestamp. |
| AC-05 | URL không có consent external lookup | Không gọi URL reputation hoặc RDAP provider; local rule/blacklist vẫn chạy và trả limitation phù hợp. |
| AC-06 | Claim cần xác minh | Chỉ kết luận theo nguồn truy xuất; không có nguồn thì `inconclusive`/limitation. |
| AC-07 | Cùng evidence và scoring version | Điểm, mức rủi ro và verdict lặp lại giống nhau, không cần LLM. |
| AC-08 | Workflow hoàn tất | UI hiển thị đầy đủ kết quả; URL đáng ngờ không là link bấm trực tiếp. |
| AC-09 | Provider timeout/hỏng | Dừng trong budget, ghi limitation, không bịa kết quả và không trả `safe` chỉ vì thiếu dữ liệu. |
| AC-10 | Evidence chưa đủ | Agent chỉ gọi tool allowlist và dừng theo điều kiện budget; không loop vô hạn. |
| AC-11 | Case đạt rule escalation | Cảnh báo user ngay và tạo case `pending_review`. |
| AC-12 | Admin ra quyết định | Lưu reviewer, timestamp, note; chỉ phê duyệt rõ ràng mới thay đổi blacklist. |
| AC-13 | User thường gọi API admin | Trả 403 và không thay đổi dữ liệu. |
| AC-14 | URL trỏ private/local/metadata IP, kể cả sau redirect | Chặn request trước kết nối và ghi evidence/limitation an toàn. |
| AC-15 | Workflow chuyển bước | Đúng user nhận progress qua WebSocket hoặc polling fallback. |
| AC-16 | Provider bình thường | Trả kết quả trong 60 giây; hết budget trả kết quả giới hạn. |
| AC-17 | Input hợp lệ và LLM khả dụng | Structured output mô tả ngữ cảnh, cảm xúc tác động và ý đồ có khả năng của người gửi; không quy kết ý đồ đó cho user đang kiểm tra. |
| AC-18 | LLM đề xuất tool | Chỉ tool trong allowlist được chạy; consent, SSRF và budget có quyền phủ quyết kế hoạch. |
| AC-19 | LLM review hoặc sinh phản hồi | Không sửa deterministic score/verdict/action, không thêm evidence và chỉ giải thích theo evidence index tồn tại. |
| AC-20 | LLM timeout/schema lỗi | Workflow tiếp tục bằng fallback deterministic, ghi limitation và không trả 500 chỉ vì LLM lỗi. |
| AC-21 | Registrable domain chưa có trong blacklist và user đã consent | Agent có thể lấy RDAP domain intelligence; evidence ghi source, thời điểm và trường dữ liệu thực sự có. |
| AC-22 | RDAP bị privacy-redacted/404/timeout | Không suy diễn chủ sở hữu hoặc coi dữ liệu thiếu là tín hiệu xấu; ghi limitation khi ảnh hưởng coverage và tiếp tục bằng evidence khác. |
| AC-23 | Domain nằm trong approved blacklist | Memory hit được dùng trước external provider, có provenance và không cần LLM để kết luận. |
| AC-24 | Analysis đang chạy | User thấy các bước điều tra ở trạng thái `pending/running/completed/skipped/failed` qua WebSocket hoặc polling. |
| AC-25 | Tin nhắn chỉ có claim, không có URL | Không gọi URL/RDAP tool; fact-check claim và trả `inconclusive` nếu không đủ nguồn. |
| AC-26 | Kết quả high/critical | Cảnh báo cá nhân hiển thị ngay; thao tác block domain/cảnh báo diện rộng vẫn chờ admin duyệt. |
| AC-27 | URL dùng subdomain, public suffix hoặc IP literal | RDAP chỉ tra registrable domain hợp lệ; bỏ qua IP/suffix không đăng ký được và không tốn tool budget. |
| AC-28 | Fact-check provider trả rating khác ngôn ngữ hoặc không map được | Giữ stance `unrated`; không suy ra refuted/supported bằng keyword trong prose. |
