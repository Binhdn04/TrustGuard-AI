# Weekly Journal — TrustGuard AI (P-068)

Nhật ký này được tổng hợp từ lịch sử Git của repository. Các kết quả chỉ được ghi nhận khi có commit hoặc tài liệu hiện hành làm bằng chứng; các kiểm chứng production chưa thực hiện được ghi rõ là còn pending.

## Tuần 1: 2026-07-23 – 2026-07-29

### Mục tiêu

- Khởi tạo repository và quy trình ghi nhận hoạt động AI.
- Xác lập nền tảng ban đầu cho sản phẩm.

### Đã hoàn thành

- Khởi tạo cấu trúc repository P-068.
- Thử nghiệm cơ chế lưu AI log phục vụ truy vết quá trình phát triển.

### Khó khăn và giải pháp

| Khó khăn | Giải pháp | Kết quả |
|---|---|---|
| Chưa có lịch sử phát triển và quy ước làm việc | Tạo repository nền và thử nghiệm AI log | Có điểm bắt đầu có thể truy vết bằng Git |

### Bài học

- Nhật ký kỹ thuật cần được cập nhật cùng quá trình phát triển, không để nguyên template đến cuối dự án.

## Tuần 2: 2026-07-30 – 2026-08-05

### Mục tiêu

- Hoàn thiện yêu cầu sản phẩm và kiến trúc ban đầu.
- Xây dựng agent, API, công cụ và giao diện phiên bản đầu.

### Đã hoàn thành

- Cập nhật README, tài liệu Gate 1, product requirements và architecture.
- Tạo agent skeleton, sau đó triển khai agent version 0 với mô hình được cấu hình tại thời điểm đó.
- Bổ sung tool/data version 0, API/platform tests và các thử nghiệm frontend.
- Thiết lập CI bước đầu và sửa các lỗi lint được phát hiện.

### Khó khăn và giải pháp

| Khó khăn | Giải pháp | Kết quả |
|---|---|---|
| Contract và module ownership còn thay đổi nhanh | Cập nhật implementation plan và tài liệu kiến trúc theo từng mốc | Các phần agent, API, tool và frontend có ranh giới rõ hơn |
| Lint và test chưa ổn định | Bổ sung test API/platform và sửa lỗi theo CI/review | Tạo nền kiểm thử cho các wave sau |

### Bài học

- Contract cần ổn định trước khi mở rộng nhiều agent và provider.
- CI hữu ích nhất khi kiểm tra cùng tiêu chuẩn mà lập trình viên chạy ở local.

## Tuần 3: 2026-08-06 – 2026-08-12

### Mục tiêu

- Mở rộng agent qua các wave và cải thiện công cụ điều tra.
- Đồng bộ API, frontend và deployment runtime.

### Đã hoàn thành

- Phát triển agent/API qua các wave 1–2 và contract v3.
- Bổ sung resource management, domain intelligence, blacklist, redirect validation và SSRF policy.
- Cải thiện frontend cho các wave, luồng fact-check đa ngôn ngữ và xử lý ngân sách/polling.
- Tối ưu Docker và thu hẹp workflow provider để giảm lỗi nguồn dữ liệu.

### Khó khăn và giải pháp

| Khó khăn | Giải pháp | Kết quả |
|---|---|---|
| Nhiều nhánh phát triển gây xung đột | Merge theo từng wave và sửa contract/lint sau tích hợp | Agent, API và frontend tiếp tục chạy trên cùng contract |
| Provider và redirect làm tăng rủi ro mạng | Thêm validated target, SSRF policy và giới hạn nguồn | Giảm bề mặt gọi mạng ngoài ý muốn |

### Bài học

- Kiểm soát SSRF và redirect phải nằm trước provider call.
- Mỗi wave cần có test contract và regression đi kèm, không chỉ code runtime.

## Tuần 4: 2026-08-13 – 2026-08-19

### Mục tiêu

- Chuyển trọng tâm sản phẩm sang Security Triage v4.
- Loại bỏ các bề mặt fact-check/vector cũ và chuẩn bị deployment.

### Đã hoàn thành

- Triển khai scope gate, security context, planner/evidence và các work package Security Triage.
- Xây dựng Admin Copilot theo hướng suggestion-only và tiếp tục hoàn thiện frontend.
- Loại bỏ public v2/v3 cùng runtime vector/pgvector đã deprecated.
- Cấu hình Railway backend/worker, sửa các lỗi deploy và cải thiện điều kiện chạy CI.

### Khó khăn và giải pháp

| Khó khăn | Giải pháp | Kết quả |
|---|---|---|
| Legacy fact-check và vector làm lệch product boundary | Thu hẹp runtime về `/api/v4` và xóa wiring deprecated | Runtime tập trung vào Security Triage |
| Deployment backend/worker gặp lỗi cấu hình | Tách cấu hình service và sửa lần lượt các lỗi Railway | Có cấu hình deploy riêng cho backend và worker |

### Bài học

- Product boundary phải được bảo vệ bằng route/test, không chỉ bằng tài liệu.
- Xóa dependency cũ cần giữ migration và rollback concern tách biệt với runtime mới.

## Tuần 5: 2026-08-20 – 2026-08-26

### Mục tiêu

- Hoàn thiện Official Link Verification và các luồng review/trust.
- Tăng khả năng quan sát, RBAC và độ an toàn của kết luận.

### Đã hoàn thành

- Hoàn thành các checkpoint Official Link Verification và bộ evidence offline tương ứng.
- Bổ sung organization discovery, screenshot flow, Langfuse tracing/logging và CI cleanup job.
- Hoàn thiện RBAC user/admin, giao diện trust/review, popular-domain checks và immutable security dataset.
- Sửa các false positive, grounding, domain checks, hội thoại AI và thu hẹp dữ liệu nhạy cảm trong log.

### Khó khăn và giải pháp

| Khó khăn | Giải pháp | Kết quả |
|---|---|---|
| Provider no-hit có thể bị diễn giải thành an toàn | Grounding lại kết luận và giữ trạng thái không chắc chắn khi thiếu bằng chứng | Giảm nguy cơ kết luận `SAFE` sai |
| Cần tách quyền user/admin và giữ audit | Thêm RBAC, review workflow và immutable audit/data | Các hành động nhạy cảm yêu cầu vai trò và bước review rõ ràng |

### Bài học

- Không được suy rộng brand/domain trust thành xác minh nội dung cụ thể.
- Observability phải redact dữ liệu nhạy cảm trước khi phát log hoặc trace.
