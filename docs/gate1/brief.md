## Tên đề tài
**AI Agent Phát hiện & Cảnh báo Tin giả / Link độc trong Tin nhắn**

Tên sản phẩm: **TrustGuard AI**

## Thực trạng
Tin nhắn giả mạo thương hiệu, khuyến mãi lừa đảo, yêu cầu OTP, chuyển tiền và link phishing lan truyền qua chat/SMS. Người dùng phổ thông khó phân biệt domain thật–giả, không hiểu kết quả từ công cụ bảo mật và dễ bị thao túng bởi ngôn ngữ khẩn cấp.

## Vấn đề
Người dùng cần một hệ thống:
1. Hiểu nội dung tin nhắn.
2. Trích xuất URL, thương hiệu, claim và hành động được yêu cầu.
3. Kiểm tra URL bằng nguồn uy tín.
4. Giải thích rủi ro bằng ngôn ngữ dễ hiểu.
5. Không kết luận quá mức khi thiếu bằng chứng.
6. Chuyển case nghiêm trọng cho con người.

## Giải pháp
TrustGuard AI:
- phân tích tín hiệu social engineering;
- chuẩn hóa URL/domain;
- gọi URL reputation;
- tra cứu thông tin domain;
- kiểm tra brand-domain mismatch;
- tính risk score bằng rule;
- tạo báo cáo có evidence, limitation và recommendation;
- escalation cho admin/security reviewer khi cần.

## Người dùng
- Người dùng phổ thông.
- Nhân viên doanh nghiệp.
- Security reviewer/admin.

## MVP 3 tuần
### Must-have
- Login User/Admin.
- Nhập tin nhắn hoặc URL.
- Structured extraction.
- URL normalization.
- Reputation lookup qua API hoặc mock.
- Domain lookup.
- Rule-based risk score.
- Báo cáo rủi ro.
- Lịch sử.
- Feedback.
- Admin escalation.

### Should-have
- Brand verification.
- Fact-check lookup đã tồn tại.
- Dashboard thống kê cơ bản.

### Ngoài phạm vi
- Tích hợp trực tiếp Zalo/Messenger/SMS.
- Realtime scanning.
- Browser extension.
- Tự render website.
- Ảnh/video/deepfake.
- Tự block domain.
- Tự khẳng định mọi claim là thật/giả.

## Chỉ số
- URL extraction accuracy.
- Tool routing accuracy.
- Precision/recall trên bộ test.
- Tỷ lệ báo cáo có evidence.
- Tỷ lệ không kết luận quá mức.
- Độ trễ trung bình.
- Feedback hữu ích.