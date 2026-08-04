# Product Requirements — P-068

**Sản phẩm:** AI Agent phát hiện tin giả và link độc trong tin nhắn  
**Giai đoạn:** MVP  
**Trạng thái:** Scope freeze — 2026-08-03

> Tài liệu này định nghĩa **sản phẩm phải làm gì**. Schema, enum và fixture nằm tại `02-CONTRACT_AND_FIXTURES.md`; topology kỹ thuật nằm tại `01-ARCHITECTURE.md`; cách chia việc nằm tại `03-IMPLEMENTATION_PLAN.md`.

## 1. Vấn đề và mục tiêu

Tin nhắn giả mạo, link phishing và khuyến mãi lừa đảo thường được chia sẻ qua chat. Người dùng phổ thông khó tự kiểm tra domain, redirect và tính xác thực của claim trên nhiều nguồn.

MVP cho phép người dùng chủ động dán một URL hoặc tin nhắn để nhận đánh giá có bằng chứng trong vòng 60 giây ở điều kiện bình thường. Hệ thống phải:

- phát hiện dấu hiệu link độc, giả mạo thương hiệu và claim đáng ngờ;
- giải thích rủi ro và hành động nên làm bằng ngôn ngữ dễ hiểu;
- không biến thiếu dữ liệu thành kết luận “an toàn”;
- dùng scoring xác định từ structured evidence, không để LLM tự chấm điểm;
- yêu cầu Security Admin duyệt mọi thay đổi blacklist hoặc cảnh báo diện rộng;
- chỉ xử lý nội dung người dùng chủ động gửi.

## 2. Persona

### Người dùng

Dán nội dung đáng ngờ, theo dõi tiến trình, xem kết quả và lịch sử của mình, báo kết quả sai hoặc yêu cầu review.

### Security Admin

Xem hàng đợi case cần duyệt, kiểm tra evidence, xác nhận/bác bỏ kết luận, yêu cầu điều tra thêm và phê duyệt thay đổi blacklist có audit trail.

## 3. User flow

### 3.1 Phân tích

1. User đăng nhập, dán URL/tin nhắn, chọn đồng ý hoặc không đồng ý quét URL bên ngoài, rồi bấm **Kiểm tra**.
2. Hệ thống validation, trích xuất URL và claim; nếu input không hợp lệ thì dừng trước khi gọi tool.
3. Agent chạy rule nội bộ, blacklist và các tool phù hợp trong giới hạn thời gian/lượt gọi.
4. Risk Engine tổng hợp evidence thành điểm và mức rủi ro; Agent tạo giải thích grounded.
5. UI hiển thị verdict, mức/điểm rủi ro, lý do, evidence, limitations và hành động đề xuất.
6. Case cần hành động diện rộng được đưa vào hàng đợi admin; cảnh báo cho user không phải chờ admin.

### 3.2 Admin review

1. Admin mở case đã escalate và xem evidence/audit trail.
2. Admin chọn **phê duyệt**, **bác bỏ**, hoặc **yêu cầu thêm evidence** và nhập lý do.
3. Chỉ quyết định phê duyệt rõ ràng mới được tạo thay đổi blacklist; mọi quyết định đều được audit.

### 3.3 Tool lỗi hoặc thiếu dữ liệu

Agent retry trong budget. Khi hết budget, hệ thống trả kết quả giới hạn với verdict `inconclusive` khi phù hợp, nêu tool/dữ liệu còn thiếu và không giả lập evidence.

## 4. Phạm vi MVP

- Đăng nhập và RBAC cho `user`, `security_admin`.
- Nhập một URL hoặc một tin nhắn tối đa 5.000 ký tự.
- Consent riêng cho external URL scanning.
- Phân tích URL/claim bằng rule, approved blacklist, ít nhất một URL reputation provider và fact-check retriever.
- Kiểm tra URL an toàn gồm normalization, punycode/look-alike, redirect metadata và SSRF guard.
- Agent workflow có nhánh, retry và giới hạn tool/time/cost.
- Kết quả có evidence, limitations và nguồn/thời điểm quan sát.
- Lịch sử phân tích, báo kết quả sai, review queue và audit trail.
- Realtime progress bằng WebSocket, có polling fallback.
- Docker Compose cho API, worker, PostgreSQL/pgvector và Redis.

## 5. Ngoài phạm vi MVP

- Tự đọc toàn bộ hội thoại từ Zalo/Messenger/WhatsApp/email.
- Tự mở link trên thiết bị user, tải/chạy file hoặc sandbox malware đầy đủ.
- Safe screenshot renderer và điều tra hình ảnh trang đích.
- Tự động chặn domain hoặc phát cảnh báo diện rộng không qua admin.
- Phát hiện chiến dịch lan truyền, dashboard xu hướng nâng cao, online learning.
- Native mobile app, browser extension hoặc tích hợp trực tiếp app chat.
- Cam kết thay thế chuyên gia an ninh hoặc kết luận pháp lý.

## 6. Chỉ số thành công

- 100% analysis hoàn tất trả đủ các trường bắt buộc theo contract v1.
- 100% provider failure/thiếu evidence có limitation và không bị diễn đạt thành “safe”.
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
| AC-04 | URL có consent scan | Normalize, kiểm tra blacklist/rule/reputation; evidence có source và timestamp. |
| AC-05 | URL không có consent scan | Không gọi external URL provider; trả limitation phù hợp. |
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

