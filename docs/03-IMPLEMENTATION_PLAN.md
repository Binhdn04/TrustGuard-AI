# Implementation Plan — P-068

> Mục tiêu triển khai của MVP là tạo được **một luồng Agent chạy thật end-to-end**: người dùng gửi tin nhắn hoặc URL, Agent tự chọn bước kiểm tra, gọi ít nhất một provider thật, tổng hợp evidence, tính điểm rủi ro, trả cảnh báo và chuyển case cần thiết sang Security Admin review.
>
> Mọi module phải tuân thủ contract v1 trong `02-CONTRACT_AND_FIXTURES.md`. Fake adapters được sử dụng để phát triển và kiểm thử, nhưng không thay thế cho demo luồng thật.

## 2. Luồng MVP bắt buộc phải chạy thật

```text
User nhập tin nhắn hoặc URL
        ↓
POST /api/v1/analyses
        ↓
Classify input
        ↓
Extract URL và claim
        ↓
GPT-4o-mini phân tích ngữ cảnh, cảm xúc tác động và ý đồ người gửi
        ↓
Normalize URL
        ↓
Rule check + approved blacklist
        ↓
GPT-4o-mini đề xuất kế hoạch và thứ tự tool trong allowlist
        ↓
Gọi URL reputation provider thật
        ↓
Fact-check claim nếu có
        ↓
Chuẩn hóa evidence
        ↓
Risk Engine tính score và verdict
        ↓
GPT-4o-mini review assessment theo evidence
        ↓
Sinh phản hồi grounded, giữ nguyên score/verdict/action
        ↓
Lưu analysis
        ↓
UI hiển thị kết quả và limitation
        ↓
Nếu đạt ngưỡng escalation
        ↓
Tạo case trong Admin Review Queue
        ↓
Admin xác nhận, bác bỏ hoặc yêu cầu thêm evidence
```

Một luồng được xem là “chạy thật” khi evidence từ provider thật được đưa vào AgentState,
ảnh hưởng đến deterministic scoring và hiển thị được trên UI; đồng thời structured output
từ `gpt-4o-mini` phải tham gia semantic analysis, tool prioritization, assessment review và
phản hồi cuối. LLM output không được tính như evidence hoặc tự thay đổi score/verdict.

## 3. Phạm vi kỹ thuật MVP

### 3.1. Bắt buộc

* FastAPI API cho tạo và xem analysis.
* LangGraph hoặc workflow graph có conditional routing.
* `gpt-4o-mini` structured output cho semantic analysis, tool planning, assessment review
  và grounded response; có timeout/retry/fallback và fake LLM cho CI.
* Trích xuất URL và claim từ input thật.
* URL normalization và URL safety rules.
* Approved blacklist nội bộ.
* Một URL reputation provider thật.
* Một fact-check source hoặc corpus nhỏ có provenance.
* Risk Engine deterministic có version.
* PostgreSQL hoặc database tương đương để lưu analysis, evidence, review và blacklist.
* User UI: submit, trạng thái, result và history tối thiểu.
* Admin UI: review queue, detail và decision.
* Consent, SSRF guard, timeout, retry và limitation.
* Fake adapters và offline fixtures cho CI.
* Docker Compose chạy được toàn bộ luồng local.

### 3.2. Có thể giản lược trong vertical slice đầu

* Xử lý analysis đồng bộ trong API trước khi tách worker.
* Polling trước khi hoàn thiện WebSocket.
* Auth seed hoặc demo account trước auth production-grade.
* Fact-check corpus nhỏ dạng JSON/PostgreSQL search trước pgvector.
* Một provider thật thay vì nhiều provider.
* Logging cơ bản có redaction trước observability stack đầy đủ.

### 3.3. Chưa nằm trên đường găng

* Phát hiện chiến dịch lan truyền.
* Dashboard xu hướng.
* Nhiều provider dự phòng.
* Online learning từ feedback.
* Screenshot renderer phức tạp.
* Browser extension hoặc tích hợp ứng dụng chat.
* Auto scaling và production monitoring hoàn chỉnh.

## 4. Module ownership

| Thành viên         | Module sở hữu                                                           | Deliverable chính                                                                      | Reviewer chính |
| ------------------ | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | -------------- |
| Bình — Agent       | `src/agents/{state,graph,nodes/**}`, risk engine                        | Graph, semantic LLM nodes, guarded tool planning, extraction, planning loop, deterministic scoring, grounded explanation/response | Duc, Hiếu      |
| Duc — Tools/Data   | `src/agents/tools/**`, `src/repositories/**`, provider integration      | Fake adapters, provider thật, SSRF guard, blacklist và fact-check repositories         | Bình, Hải      |
| Hải — API/Platform | `src/api/**`, `src/services/**`, `src/models/**`, `src/core/**`, deploy | API v1, persistence orchestration, demo auth/RBAC, Docker và deployment                | Bình, Hiếu     |
| Hiếu — Frontend/QA | frontend/API client, `tests/**`, `eval/**`                              | User/admin UI, fixtures, contract/integration/eval runner và demo script               | Bình, Hải      |
