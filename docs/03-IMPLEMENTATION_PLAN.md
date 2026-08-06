# Implementation Plan — P-068

> Mục tiêu triển khai của MVP là tạo được **một luồng Agent chạy thật end-to-end**: người dùng gửi tin nhắn hoặc URL, Agent tự chọn bước kiểm tra, gọi ít nhất một provider thật, tổng hợp evidence, tính điểm rủi ro, trả cảnh báo và chuyển case cần thiết sang Security Admin review.
>
> Mọi module phải tuân thủ wire contract v2 trong `02-CONTRACT_AND_FIXTURES.md`; v1 chưa production
> nên không triển khai compatibility layer. `domain_registration` được server phát từ `/api/v2`
> sau khi consumer/UI v2 đã được deploy.
> Fake adapters được sử dụng để phát triển và kiểm thử, nhưng không thay thế cho demo luồng thật.

## 1. Baseline và mục tiêu thay đổi

- **Baseline đã có:** `src/agents` graph xử lý URL/claim, structured LLM nodes, local rules,
  deterministic scoring, Google Safe Browsing v4, Google Fact Check, SQLite approved blacklist,
  SSRF guard và API in-memory. API create hiện chỉ lưu `queued`, chưa có processor chạy graph;
  admin decision chưa ghi audit decision vào cùng repository trước blacklist write.
- **Mục tiêu lần này:** nối các thành phần thành vertical slice end-to-end, thêm observable
  investigation plan và RDAP domain intelligence, rồi mới tối ưu worker/realtime.
- Không viết lại luồng URL đang chạy. Mỗi PR phải giữ contract test cũ xanh và bổ sung fixture mới.

## 2. Luồng MVP bắt buộc phải chạy thật

```text
User nhập tin nhắn hoặc URL
        ↓
POST /api/v2/analyses
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
Executor hard-gate consent cho từng target trước khi tạo external work
        ↓
Gọi URL reputation provider được hỗ trợ ∥ RDAP khi cần
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

Một luồng được xem là “chạy thật” khi task plan và trạng thái bước quan sát được trên UI,
evidence từ provider thật được đưa vào AgentState,
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
* Một URL reputation provider còn được hỗ trợ và một RDAP-over-HTTPS adapter thật.
* Một fact-check source hoặc corpus nhỏ có provenance.
* Risk Engine deterministic có version.
* Một persistence boundary nhất quán để lưu analysis, evidence, review và blacklist; SQLite cho
  vertical slice, PostgreSQL là đích deployment.
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
| Hải — API/Platform | `src/api/**`, `src/services/**`, `src/models/**`, `src/core/**`, deploy | API v2, persistence orchestration, demo auth/RBAC, Docker và deployment | Bình, Hiếu     |
| Hiếu — Frontend/QA | frontend/API client, `tests/**`, `eval/**`                              | User/admin UI, fixtures, contract/integration/eval runner và demo script               | Bình, Hải      |

## 5. Trạng thái Tools/Data (Duc)

Phần Tools/Data hiện dùng profile triển khai sau:

- Fake URL scanner, claim retriever và blacklist repository chạy hoàn toàn offline cho CI.
- Provider hiện có gồm deprecated Google Safe Browsing v4 và Google Fact Check Tools API, được inject vào graph
  khi có `GOOGLE_SAFE_BROWSING_API_KEY` hoặc `GOOGLE_FACT_CHECK_API_KEY`.
- Google Safe Browsing no-hit trả `inconclusive`; hệ thống không dùng thiếu hit làm bằng chứng
  `safe`.
- `SsrfGuard` kiểm tra scheme, credential, port và toàn bộ DNS answers. `GuardedHttpClient` kiểm
  tra lại từng redirect và giới hạn redirect/response size.
- Blacklist vertical slice dùng SQLite. Ghi blacklist yêu cầu trước đó phải lưu audit decision
  `approved + add_to_blacklist`; domain được chuẩn hóa IDNA.
- Fact-check repository offline dùng corpus JSON có provenance và ranking deterministic. Đây là
  fallback/công cụ CI, không thay thế provider thật trong demo production.
- Cấu hình provider nằm server-side; browser và AgentState không nhận API key hoặc raw provider
  response.
- URL reputation production phải chuyển sang Web Risk/provider được hỗ trợ nếu sản phẩm có mục
  đích thương mại; giữ Safe Browsing v4 chỉ như compatibility adapter trong lúc migration.
- Domain intelligence dùng RDAP-over-HTTPS, IANA bootstrap, Public Suffix List versioned, cache có
  TTL và không lưu RDAP entity/vCard/registrant PII.

Các lựa chọn trên cụ thể hóa wire contract v2. V2 phát `domain_registration` với provenance RDAP.
Rollout theo thứ tự: deploy consumer/UI v2, kiểm thử contract v2, rồi bật producer/endpoint v2.
Không triển khai endpoint hoặc serializer v1. PostgreSQL vẫn là đích deployment chung; SQLite là
database tương đương được cho phép cho vertical slice Tools/Data.

## 7. Task chi tiết theo module

### 7.1 Agent — Bình

1. Giữ `assess_risk` pure/deterministic; thêm scoring signals RDAP dưới evidence type v2
   `domain_registration`, có trần tổng điểm (ví dụ ≤20) và không cho tuổi domain đơn độc tạo verdict
   `malicious`.
2. Thay heuristic dò từ khóa trong `ClaimEvidence.finding` bằng `stance` chuẩn hóa; Fact Check API
   không được tự biến thành `official_source`.
3. Tạo `InvestigationStep` và executor đổi trạng thái idempotent.
4. Planner chỉ sinh tool + target + reason code; blacklist lookup do code luôn chèn trước external tools.
5. Chạy song song reputation/RDAP chỉ sau hard gate của executor: với từng target, xác nhận
   `consent_to_scan_urls is true`, policy/SSRF hợp lệ và budget còn trước khi tạo task, request,
   provider client hoặc fan-out. Fact-check có thể chạy song song nếu claim độc lập.
6. Dừng khi evidence đủ, không còn tool, hoặc chạm `max_tool_calls`, deadline hay retry budget.

### 7.2 Tools/Data — Duc

1. Thêm protocol/model/fake fixture cho domain intelligence.
2. Implement RDAP-over-HTTPS từ IANA bootstrap; lookup eTLD+1, skip IP/public suffix, normalize
   nullable fields và không parse entity/vCard.
3. Cache theo `(registrable_domain, provider/schema_version)`; positive/not-found TTL riêng, không
   cache timeout/429/error như kết quả an toàn.
4. Blacklist `get()` trả provenance; write vẫn chỉ qua approved admin decision.
5. Bổ sung fact-check provider/corpus có source URL và observed time.
6. Map rating provider sang `stance` bằng bảng versioned; unknown rating là `unrated`.

### 7.3 API/Platform — Hải

1. Trước hết tạo `AnalysisProcessor` chạy graph và persist kết quả; API không được dừng mãi ở `queued`.
2. Migration lưu task plan/evidence/errors; event giữ `step` và thêm optional `step_id/step_status`.
3. Dedupe bằng `(analysis_id, step_id, target, provider)`; transaction/outbox trước khi tách worker.
4. Sửa admin flow để `record_decision` và `add_approved` dùng cùng transaction/repository; hiện tại
   gọi thẳng `add_approved` sẽ thất bại khi repository thực được cấu hình.

### 7.4 Frontend/QA — Hiếu

1. Input một message, consent rõ ràng và progress theo từng bước.
2. Warning card hiển thị score/level/verdict/action, evidence citation, limitation và thời điểm scan.
3. Không cho click trực tiếp URL bị nghi ngờ; có nút report/appeal.
4. Admin detail hiển thị evidence và audit trước decision.
5. Thêm contract/integration/eval fixtures, không assert nguyên văn văn phong LLM.

## 8. Definition of Done

- `make lint`, unit, contract và integration test xanh khi không có API key/network.
- Smoke test thật xử lý được: URL độc, tin nhắn URL+claim, claim-only và provider timeout.
- UI hiển thị task progress và cảnh báo trong ≤60 giây ở điều kiện bình thường.
- Evidence trên UI truy được source + `observed_at`; không có raw provider response/PII.
- Cùng evidence + `scoring_version` luôn cho cùng score/verdict/action khi tắt LLM.
- Không external URL/domain lookup nếu thiếu consent: executor phải chặn trước khi tạo task,
  fan-out, request hoặc provider client; RDAP bootstrap endpoint và redirect cũng qua network guard.
- High/critical cảnh báo user ngay và tạo pending review; blacklist chỉ đổi sau admin approval.
- Demo README ghi rõ env vars, quota/rate limit, lệnh chạy và fallback khi provider thiếu key.

## 9. Bộ test tối thiểu trước demo

1. Unit: URL normalization, IDNA/eTLD+1, redirect SSRF, RDAP normalize/redaction, cache TTL,
   fact-check stance mapping và scoring.
2. Contract: schema response/event/task plan v2 và strict enum `domain_registration` ở mọi
   producer/consumer.
3. Integration: message → plan → fake tools → score → persisted result → escalation.
4. Failure: no consent (assert không tạo task/fan-out/request/provider client), reputation no-hit,
   RDAP 404/429/timeout, fact-check empty, LLM schema error.
5. Eval: false-positive set cho domain chính thức/mới đăng ký; claim-only; brand look-alike.
6. Manual smoke: provider thật với secrets server-side; lưu request/result đã redaction làm demo evidence.
