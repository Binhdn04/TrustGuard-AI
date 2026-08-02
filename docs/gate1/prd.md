# PRODUCT REQUIREMENTS DOCUMENT

## 1. Mục tiêu

Xây dựng AI Agent giúp người dùng đánh giá nhanh một tin nhắn hoặc URL đáng ngờ trong dưới một phút bằng quy trình có bằng chứng, giải thích rõ lý do cảnh báo và hỗ trợ Human-in-the-Loop đối với các trường hợp rủi ro cao.

---

## 2. Persona

### User

- Dán tin nhắn hoặc URL cần kiểm tra.
- Xem kết quả phân tích và mức độ rủi ro.
- Xem lịch sử phân tích.
- Gửi phản hồi nếu AI cảnh báo sai.

### Security Admin

- Xem các trường hợp rủi ro cao.
- Xác nhận kết quả phân tích.
- Quản lý danh sách domain chính thức và blacklist.

---

## 3. User Stories

- Là người dùng, tôi muốn biết tin nhắn có dấu hiệu lừa đảo hay không.
- Là người dùng, tôi muốn biết AI dựa trên những bằng chứng nào để đưa ra cảnh báo.
- Là người dùng, tôi muốn biết giới hạn của kết quả thay vì khẳng định tuyệt đối.
- Là người dùng, tôi muốn báo cáo khi AI cảnh báo sai.
- Là Security Admin, tôi muốn xem các trường hợp nghiêm trọng để xác nhận và xử lý.

---

## 4. User Flow

1. Người dùng đăng nhập.
2. Nhập tin nhắn hoặc URL cần kiểm tra.
3. AI phân tích nội dung và trích xuất các thông tin cần thiết.
4. AI kiểm tra độ uy tín của URL, domain và đối chiếu với các nguồn xác thực.
5. AI đánh giá mức độ rủi ro và tạo báo cáo.
6. Hiển thị cảnh báo cùng lời giải thích.
7. Nếu rủi ro rất cao hoặc kết quả chưa đủ chắc chắn, hệ thống chuyển sang Security Admin xem xét.
8. Lưu lịch sử và cho phép người dùng gửi phản hồi.

---

## 5. Functional Requirements

### FR-01 Authentication

- Hỗ trợ hai vai trò:
  - User
  - Security Admin

### FR-02 Input Analysis

- Cho phép nhập văn bản hoặc URL.
- Không chấp nhận dữ liệu rỗng.

### FR-03 Information Extraction

AI tự động trích xuất các thông tin quan trọng như:

- URL
- Thương hiệu được nhắc đến
- Hành động được yêu cầu (đăng nhập, chuyển tiền...)
- Dấu hiệu khẩn cấp
- Nội dung cần xác minh

### FR-04 URL & Domain Verification

Hệ thống kiểm tra:

- URL Reputation
- Domain Information
- Domain chính thức của thương hiệu
- URL rút gọn hoặc đáng ngờ

### FR-05 Risk Assessment

AI tổng hợp các tín hiệu để:

- Chấm điểm rủi ro
- Phân loại mức cảnh báo
- Giải thích nguyên nhân

### FR-06 Grounded Report

Báo cáo phải bao gồm:

- Mức độ rủi ro
- Các dấu hiệu phát hiện
- Bằng chứng từ các nguồn kiểm tra
- Khuyến nghị cho người dùng
- Giới hạn của kết quả

### FR-07 Fact-check

- Nếu nội dung là một tuyên bố có thể kiểm chứng, AI sẽ tìm kiếm kết quả fact-check từ các nguồn tin cậy.
- Nếu không có đủ dữ liệu, hệ thống phải trả về trạng thái **chưa đủ bằng chứng** thay vì tự suy diễn.

### FR-08 History

- Người dùng có thể xem lại lịch sử các lần phân tích.

### FR-09 Feedback

Người dùng có thể gửi phản hồi:

- Cảnh báo hữu ích
- Cảnh báo sai
- Xác nhận lừa đảo
- Chưa đủ kết luận

### FR-10 Escalation

Hệ thống chuyển sang Security Admin khi:

- Mức rủi ro rất cao.
- Kết quả giữa các nguồn mâu thuẫn.
- Người dùng báo cáo.
- Chưa đủ bằng chứng nhưng có nhiều tín hiệu nguy hiểm.

### FR-11 Admin Review

Security Admin có thể:

- Xác nhận lừa đảo.
- Đánh dấu cảnh báo sai.
- Đánh dấu chưa đủ kết luận.
- Quản lý danh sách domain chính thức và blacklist.

---

## 6. Non-functional Requirements

- Thời gian phản hồi dưới **10 giây**.
- Không lưu hoặc hiển thị thông tin nhạy cảm như mật khẩu hoặc OTP.
- Người dùng chỉ xem được lịch sử của mình.
- Mỗi cảnh báo phải kèm theo lý do và giới hạn của kết quả.
- Không khẳng định một URL hoặc nội dung **an toàn tuyệt đối**.
- Hệ thống có cơ chế xử lý khi các dịch vụ bên ngoài không phản hồi.

---

## 7. Acceptance Criteria

- AI phát hiện được URL và các dấu hiệu đáng ngờ.
- Kiểm tra được độ uy tín của URL và domain.
- Sinh được báo cáo có giải thích rõ ràng.
- Hiển thị khuyến nghị phù hợp với từng mức rủi ro.
- Các trường hợp rủi ro cao được chuyển cho Security Admin để xem xét.
- Phân quyền User và Security Admin hoạt động đúng.
- Lưu được lịch sử phân tích và phản hồi người dùng.
- Demo hoàn chỉnh luồng từ nhập dữ liệu đến hiển thị cảnh báo và xử lý Human-in-the-Loop.