# Nhật Ký Báo Cáo Hàng Tuần (Weekly Logs) — Team T-068 / P-068

## Thông Tin Chung
- **Mã nhóm / Dự án:** T-068 / P-068
- **Repository / Demo:**
  - GitHub: [AI20K-Build-Phase-Cohort-3/P-068](https://github.com/AI20K-Build-Phase-Cohort-3/P-068)
  - Demo Web: [Railway Frontend Application](https://frontend-production-3dd5.up.railway.app/)

---

## 📅 Tuần 1 (Nộp lúc 21:19 - 31/07/2026)

| Hạng mục | Nội dung chi tiết |
| :--- | :--- |
| **Done** (Đã hoàn thành) | Tìm dữ liệu cho bài toán của team, bao gồm dữ liệu về chính sách nghỉ phép và chính sách công tác phí của các công ty. |
| **Doing** (Đang thực hiện) | Thảo luận về scope của bài toán, định hướng mở rộng so với đề bài ban đầu (do đề bài tương đối đơn giản). |
| **Blocked** (Khó khăn / Vấn đề) | Cả team chưa có nhiều thời gian gặp nhau để tổ chức buổi họp chốt quy tắc làm việc chung và scope của sản phẩm. |
| **Kế hoạch tuần trước** | Làm rõ requirement của đề tài, clear các yêu cầu của MVP, thiết kế kiến trúc của agent. |
| **Câu hỏi cho Coach** | *"Em muốn hỏi tính năng tự động kiểm tra lịch nhân viên nghỉ có xung đột với dự án và thông báo cho quản lý có khác biệt so với các phần mềm HRM hiện tại?"* |
| **Link Code / Demo** | [https://github.com/AI20K-Build-Phase-Cohort-3/P-068](https://github.com/AI20K-Build-Phase-Cohort-3/P-068) |

---

## 📅 Tuần 2 (Nộp lúc 11:56 - 08/08/2026)

| Hạng mục | Nội dung chi tiết |
| :--- | :--- |
| **Done** (Đã hoàn thành) | Họp bàn và chốt xong phương án triển khai chi tiết cho các tính năng mới; tập trung vào hệ thống fact-check phát hiện tin giả. |
| **Doing** (Đang thực hiện) | Tiến hành viết code và phát triển các tính năng bám sát theo kế hoạch đã thống nhất. |
| **Blocked** (Khó khăn / Vấn đề) | Hiện tại không có khó khăn gì. |
| **Kế hoạch tuần trước** | Họp để thống nhất bản MVP của agent cần những tính năng gì và chia việc cho từng người. |
| **Câu hỏi cho Coach** | Nhóm chưa có câu hỏi nào thêm. |
| **Link Code / Demo** | [https://github.com/AI20K-Build-Phase-Cohort-3/P-068/](https://github.com/AI20K-Build-Phase-Cohort-3/P-068/) |

---

## 📅 Tuần 3 (Nộp lúc 10:02 - 15/08/2026)

| Hạng mục | Nội dung chi tiết |
| :--- | :--- |
| **Done** (Đã hoàn thành) | Hoàn thành 90% sản phẩm MVP để chuẩn bị cho deadline Gate 2 (Chủ Nhật tuần này); giới hạn scope của sản phẩm. |
| **Doing** (Đang thực hiện) | Các thành viên tập trung làm việc với tiến độ nhanh để hoàn thiện MVP. |
| **Blocked** (Khó khăn / Vấn đề) | Bộ test cho agent chưa hoàn thành. |
| **Kế hoạch tuần trước** | Thử nghiệm crawl dữ liệu thật về database hoặc search dữ liệu online để agent chạy thật. |
| **Câu hỏi cho Coach** | *"Từ thực tế triển khai, nhóm em nhận thấy fact-check tổng quát cho tất cả các lĩnh vực là không khả thi nên nhóm em đã giới hạn scope thành chỉ fact check tin giả mạo tổ chức tập đoàn và lừa đảo. Điều chỉnh này có phù hợp với người dùng không ạ?"* |
| **Link Code / Demo** | [https://github.com/AI20K-Build-Phase-Cohort-3/P-068](https://github.com/AI20K-Build-Phase-Cohort-3/P-068) |

---

## 📅 Tuần 4 (Nộp lúc 08:51 - 22/08/2026)

| Hạng mục | Nội dung chi tiết |
| :--- | :--- |
| **Done** (Đã hoàn thành) | Triển khai trang web lên Railway và chuyển đổi database từ SQLite sang PostgreSQL để đảm bảo khả năng scale. |
| **Doing** (Đang thực hiện) | Họp nhóm rà soát lại các tính năng hiện có xem đã hoạt động tốt chưa, đồng thời lên kế hoạch triển khai tính năng mới. |
| **Blocked** (Khó khăn / Vấn đề) | Các thành viên cùng "vibecode" tạo nên codebase lớn, tiềm ẩn nhiều tính năng thừa / không dùng tới nhưng vẫn giữ lại. |
| **Kế hoạch tuần trước** | Kiểm tra rà soát lại codebase để xóa các phần không được sử dụng nữa, đồng thời tối ưu flow hiện có. |
| **Câu hỏi cho Coach** | *"Bọn em muốn xin lời khuyên của anh về cách cân bằng giữa chatbot thông thường hỏi đáp (cho trải nghiệm người dùng) và agent chuyên dụng có khả năng check và gọi tool."* |
| **Link Code / Demo** | [https://frontend-production-3dd5.up.railway.app/](https://frontend-production-3dd5.up.railway.app/) |

---

## 📅 Tuần 5 (Nộp lúc 08:51 - 29/08/2026)

| Hạng mục | Nội dung chi tiết |
| :--- | :--- |
| **Done** (Đã hoàn thành) | Cả nhóm đọc hiểu các vấn đề trong code do Mentor chỉ ra, tìm nguyên nhân và cách giải quyết. Đã đóng (close) toàn bộ issue trên GitHub. |
| **Doing** (Đang thực hiện) | Rà soát và fix các lỗi hiển thị trên trang web tránh ảnh hưởng trải nghiệm người dùng; nghiên cứu áp dụng streaming cho câu trả lời. |
| **Blocked** (Khó khăn / Vấn đề) | Đánh giá agent bằng các metrics và ước lượng cost gặp nhiều khó khăn do bộ test còn ít. |
| **Kế hoạch tuần trước** | Họp team các thành viên thảo luận cách fix logic check hiện tại để giảm thiểu false positive. |
| **Câu hỏi cho Coach** | *"Em muốn xin kinh nghiệm của anh trong việc ước lượng cost thực tế và áp dụng các kỹ thuật tối ưu cost như prompt caching cho agent."* |
| **Link Code / Demo** | [https://frontend-production-3dd5.up.railway.app/](https://frontend-production-3dd5.up.railway.app/) |