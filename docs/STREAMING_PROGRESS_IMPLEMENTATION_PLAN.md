# Controlled Progress Streaming Implementation Plan

## Trạng thái và phạm vi

- Trạng thái hiện tại: **planned**.
- Phạm vi: backend coarse-grained progress events, durable event delivery và frontend presentation cho `/api/v4`.
- Không triển khai token streaming, chain-of-thought hoặc reasoning summary mới.
- Không đánh dấu checklist hoàn tất nếu chưa có implementation và bằng chứng kiểm thử hiện tại.
- `CURRENT_STATUS.md` chỉ được cập nhật sau khi các gate tương ứng thực sự đạt.

## Quyết định kiến trúc

Triển khai progress theo hai lớp:

1. Backend phát event `started/completed/skipped/degraded` cho các stage lớn của pipeline.
2. Frontend map stage/state qua allow-list và hiển thị progress tạm thời.

Progress là observer của luồng check, không phải một bước quyết định. Nó không được thay đổi request, pipeline state,
provider/tool calls, risk, evidence, action hoặc final response.

Không phát event theo từng tool trong work package này. Các event như `url_reputation.started` hoặc
`redirect_check.completed` làm tăng write amplification, làm UI nhiễu và mở rộng failure surface mà chưa cần thiết cho
trải nghiệm MVP.

## Mục tiêu sản phẩm

- Phản hồi ngay sau khi analysis async được nhận.
- Cho người dùng biết hệ thống đang ở stage lớn nào bằng câu ngắn, an toàn và không mang tính kết luận.
- Giữ câu trả lời hội thoại ngắn gọn như hiện tại.
- Giữ technical detail, evidence, risk và actions trong các panel hiện hành.
- WebSocket là đường realtime; cursor polling vẫn là fallback authoritative.
- Event thiếu hoặc lỗi không được làm analysis thất bại.

## Ngoài phạm vi

- Raw chain-of-thought, hidden reasoning hoặc model draft.
- Streaming từng token của assistant response.
- Reasoning summary mới trong bubble hội thoại.
- Event cho từng tool/provider call.
- Hiển thị raw prompt, tool arguments, provider response hoặc exception.
- Thay đổi scope, consent, investigation policy, deterministic risk hoặc grounding policy.
- Dùng progress event làm evidence hoặc đầu vào cho final result.
- Public v2/v3 compatibility hoặc vector-store dependency.
- Thay đổi `/api/v4/chat` trong work package đầu tiên.

## Baseline hiện tại

- API `POST /api/v4/analyses` đã có async response `202 + analysis_id` khi capability async truthful.
- API đã persist queued và provisional event khi enqueue.
- Durable worker đã phát `running` và các progress milestone từ callback hiện hành.
- Pipeline hiện phát milestone sau một số stage: understanding, investigation, official verification, memory lookup,
  risk assessment và assistant response.
- `append_security_analysis_event` ghi event và transactional outbox; PostgreSQL cấp sequence authoritative.
- Final response, final event, payload cleanup và job completion được commit atomically.
- Worker đã có heartbeat gia hạn lease trong khi handler chạy.
- WebSocket đọc replay từ PostgreSQL và dùng notifier để wake; polling cursor là fallback.
- Frontend đã subscribe, deduplicate theo event ID, sắp xếp theo sequence và fetch final analysis khi nhận terminal event.
- Busy card hiện chỉ hiển thị trạng thái chung, chưa trình bày stage progress.

## Kiến trúc mục tiêu

```text
Frontend
   │
   │ POST /api/v4/analyses (execution_mode=async)
   ▼
API
   ├─ validate request/version/consent
   ├─ local scope candidate
   ├─ tạo analysis_id
   ├─ persist queued/provisional event
   └─ enqueue immutable encrypted job
          │
          ▼
Durable Worker + lease heartbeat
   ├─ running
   ├─ understanding.started
   │      └─ understanding hiện hành
   ├─ understanding.completed | degraded
   │
   ├─ scope_gate
   │      ├─ out-of-scope / need-more-info -> terminal path
   │      └─ in-scope -> tiếp tục
   │
   ├─ investigation.started
   │      └─ plan/tools hiện hành, không đổi
   ├─ investigation.completed | degraded | skipped
   │
   ├─ official_link_verification.started/completed (khi applicable và có consent)
   ├─ security_memory_lookup.started/completed (khi applicable)
   ├─ risk_assessment.started/completed
   ├─ assistant_response.started/completed | degraded
   │
   ├─ quiesce progress reporter
   └─ atomic final result commit
          │
          ▼
PostgreSQL
Analysis + Events + Transactional Outbox
          │
     ┌────┴────┐
     ▼         ▼
 WebSocket   GET /api/v4/analyses/{id}/events
 realtime    cursor polling fallback
     │         │
     └────┬────┘
          ▼
       Frontend
```

Mọi progress event được persist trước khi WebSocket/polling nhìn thấy. PostgreSQL tiếp tục là source of truth;
WebSocket không trở thành authority mới.

## Invariant không thay đổi kết quả check

1. Progress observer không được mutate `request`, `scoped`, runtime budget, investigation plan hoặc provider result.
2. Không branch pipeline dựa trên kết quả phát event.
3. Progress publish lỗi, timeout hoặc queue đầy phải fail-open và không làm job retry.
4. Bật/tắt progress phải tạo final `SecurityScopeResponseV4` deep-equal, ngoại trừ timestamp runtime vốn đã biến đổi.
5. Số lượng, thứ tự, arguments và consent gate của provider/tool calls phải giống nhau khi bật/tắt progress.
6. Out-of-scope và need-more-info tiếp tục kết thúc trước investigation/external provider calls.
7. AI không được đặt risk, score, consent, targets hoặc action thông qua progress.
8. Provider no-hit/error/timeout không được biến thành `SAFE` hoặc message ngụ ý an toàn.
9. Progress không được tiêu tốn `TurnBudget`, network units hoặc provider cost budget.
10. Final commit không phụ thuộc việc mọi progress event đã delivery thành công.
11. Không persist raw private message, credential, OTP, token, unnecessary URL query hoặc provider payload trong event.
12. User event reads vẫn owner-scoped; WebSocket ticket vẫn single-use và analysis-bound.

Không thể coi backend instrumentation là zero-overhead tuyệt đối. Mục tiêu bắt buộc là không đổi semantic result,
provider/tool execution và failure decision; telemetry overhead phải bounded, đo được và không nằm trên provider/tool I/O
critical path.

## Event contract

### Trường mới

Bổ sung enum và trường optional, backward-compatible:

```python
class SecurityProgressStateV4(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    DEGRADED = "degraded"

class SecurityAnalysisEventV4(...):
    progress_state: SecurityProgressStateV4 | None = None
```

Quy tắc validation:

- `kind=progress` có thể có `progress_state`.
- Event cũ không có trường này vẫn đọc/replay được.
- `kind=final` không dùng `progress_state`; terminal authority vẫn là `status` và `kind=final`.
- `step` public tiếp tục là string để không phá event cũ; progress reporter nội bộ chỉ nhận enum/allow-list stage.
- Payload JSONB hiện hành cho phép bổ sung field mà không dự kiến cần migration; phải xác nhận bằng contract và
  PostgreSQL integration tests.

### Stage allow-list

| Stage | Khi phát | Ghi chú an toàn |
|---|---|---|
| `running` | Worker đã load payload và sở hữu lease | Không ngụ ý provider đã chạy |
| `understanding` | Trước/sau understanding hiện hành | Không hiển thị model reasoning |
| `scope_gate` | Sau scope decision | Không công bố risk |
| `incident_response` | Nhánh exposure applicable | Không thay investigation branching |
| `investigation` | Trước/sau investigation hiện hành | Không liệt kê tool ở simple mode |
| `official_link_verification` | Chỉ khi applicable, policy và consent cho phép | Không ngụ ý verified trước final |
| `security_memory_lookup` | Chỉ khi lookup hiện hành chạy | Không lộ memory content/owner |
| `risk_assessment` | Trước/sau deterministic risk | Không stream risk class như final |
| `assistant_response` | Trước/sau grounded composer | Không stream model draft |

Không thêm stage con cho DNS, RDAP, redirect, reputation, familiarity hoặc web search trong work package này.

### Nội dung event

- Message lấy từ registry tĩnh trong application code.
- `started`: câu đang làm, không dự báo kết quả.
- `completed`: chỉ nói stage đã kết thúc, không tuyên bố evidence tốt/xấu.
- `degraded`: nói dữ liệu của stage bị giới hạn; chi tiết authoritative nằm trong final limitations/errors.
- `skipped`: chỉ dùng khi stage applicable nhưng policy/consent/budget hiện hành đã quyết định không chạy.
- `evidence_refs` chỉ gồm normalized refs đã tồn tại; simple progress UI không hiển thị chúng.
- `risk_hint` không được dùng cho progress UI; provisional warning giữ flow riêng hiện hành.

## Progress reporter fail-open

Không nhân đôi cách callback hiện tại đang `await` PostgreSQL trực tiếp cho mọi event mới. Thiết kế reporter:

```text
pipeline await observer.emit(update)
                 │
                 └─ validate + queue.put_nowait (không database I/O)
                                      │
                                      ▼
                             single background writer
                                      │
                                      └─ append event + outbox tuần tự
```

Yêu cầu:

- Queue bounded; coarse stage count phải nằm dưới giới hạn bình thường.
- `emit` không chờ pool/SQL/network và không được raise lỗi telemetry vào pipeline.
- Một writer duy nhất giữ đúng enqueue order; PostgreSQL tiếp tục cấp sequence cuối cùng.
- Queue full hoặc append failure: drop progress, ghi metric/log code không nhạy cảm, tiếp tục check.
- Không retry progress vô hạn và không biến progress failure thành durable job retry.
- Reporter không dùng chung AI/network/cost budget.
- Writer chạy dưới lifecycle của handler và được giám sát rõ ràng; không tạo orphan task.
- Trước atomic final commit, reporter ngừng nhận event và quiesce có timeout ngắn, bounded.
- Nếu quiesce timeout, hủy/drop progress còn lại rồi mới final commit; không append progress sau final.
- Heartbeat hiện hành tiếp tục bảo vệ lease trong handler. Quiesce không được tắt heartbeat hoặc thay terminal ownership check.
- Final transaction hiện hành không được chuyển vào reporter và không được fail-open.

Progress event loss được chấp nhận; final analysis loss hoặc sai lệch thì không.

## Frontend presentation

### Allow-list label

Frontend không render trực tiếp arbitrary backend `message`. Nó map `step + progress_state` sang label cố định.

Ví dụ:

| Stage/state | Label |
|---|---|
| `running` | Đang chuẩn bị phiên kiểm tra |
| `understanding.started` | Đang phân tích ngữ cảnh bảo mật |
| `investigation.started` | Đang kiểm tra các tín hiệu liên quan |
| `official_link_verification.started` | Đang đối chiếu với nguồn chính thức |
| `risk_assessment.started` | Đang tổng hợp đánh giá rủi ro |
| `assistant_response.started` | Đang chuẩn bị hướng dẫn ngắn gọn |
| unknown | Đang tiếp tục kiểm tra nội dung |

Label không được chứa URL, entity, provider, risk class hoặc raw user content.

### Hội thoại và panel

- Busy bubble hiển thị progress hợp lệ mới nhất.
- Progress là trạng thái tạm thời, không thêm vào `SecurityCaseTurn` và không persist như assistant message.
- Simple mode chỉ hiển thị stage mới nhất.
- Analyst mode có thể hiển thị timeline stage lớn từ lifecycle events.
- Provisional warning tiếp tục có presentation riêng và luôn mang nhãn tạm thời.
- Khi nhận final event, frontend fetch analysis authoritative theo flow hiện hành, dừng subscription và thay busy bubble
  bằng assistant response ngắn hiện hành.
- Không thêm `top_reasons`, technical reasoning hoặc evidence refs vào bubble hội thoại.
- Event thiếu, malformed, duplicate hoặc out-of-order dùng fallback và không chặn terminal fetch.

## Checklist triển khai

### Phase 0 — Baseline và parity harness

- [x] Ghi lại result fixtures cho các nhánh in-scope, out-of-scope, need-more-info và incident exposure.
- [x] Ghi lại provider/tool call trace: thứ tự, arguments, consent và call counts.
- [x] Ghi lại event sequence hiện hành của async worker.
- [x] Xác nhận inline và worker result parity hiện hành.
- [x] Chốt coarse stage allow-list và label product/UI.
- [x] Chốt queue bound và quiesce timeout bằng constant trong code; không thêm environment flag nếu runtime không cần.

### Phase 1 — Contract và internal update type

- [x] Thêm `SecurityProgressStateV4` và optional `progress_state` vào `SecurityAnalysisEventV4`.
- [x] Giữ khả năng validate/replay event cũ không có `progress_state`.
- [x] Regenerate/cập nhật TypeScript v4 type từ contract.
- [x] Tạo internal `SecurityProgressUpdate` chỉ nhận allowlisted stage/state và static message code.
- [x] Không cho internal update chứa prompt, raw provider content hoặc exception.
- [x] Xác nhận Alembic vẫn một head và không cần migration.

File dự kiến:

- `src/models/security_v4.py`
- `src/models/__init__.py`
- module progress mới dưới `src/services/`
- `frontend/src/types/generated/api-v4.ts`

### Phase 2 — Fail-open progress reporter

- [ ] Tạo bounded queue và single writer.
- [ ] `emit` chỉ validate/enqueue, không chờ PostgreSQL/network.
- [ ] Queue full drop event và ghi metric code; không raise vào pipeline.
- [ ] Append failure drop event và ghi metric code; không raise vào pipeline/job retry.
- [ ] Writer giữ enqueue order và dùng repository append hiện hành.
- [ ] Reporter có lifecycle start/stop/quiesce rõ ràng.
- [ ] Quiesce timeout hủy/drop pending event và không append sau final.
- [ ] Cancellation của worker/lease vẫn được truyền đúng; không nuốt task cancellation hệ thống.
- [ ] Final transaction không đi qua fail-open reporter.

File dự kiến:

- module progress mới dưới `src/services/`
- `src/services/durable_worker.py`
- `src/repositories/postgres.py` chỉ sửa nếu test chứng minh cần API append idempotent/bounded; không đổi final transaction.

### Phase 3 — Pipeline coarse stage instrumentation

- [ ] Thay callback string rời rạc bằng internal typed update hoặc adapter tương thích.
- [ ] Phát `understanding.started` ngay trước stage và `completed|degraded` ngay sau stage.
- [ ] Phát `scope_gate` mà không mở investigation/provider cho terminal scope.
- [ ] Nhánh out-of-scope/need-more-info giữ zero investigation/external-provider calls.
- [ ] Phát `incident_response` đúng nhánh exposure hiện hành.
- [ ] Phát `investigation.started/completed|degraded|skipped` quanh stage hiện hành.
- [ ] Chỉ phát official verification khi stage hiện hành thật sự applicable và consent/policy cho phép.
- [ ] Chỉ phát memory lookup khi stage hiện hành thật sự chạy.
- [ ] Phát risk assessment quanh deterministic risk hiện hành; không đưa risk class vào progress display.
- [ ] Phát assistant response quanh composer/grounding hiện hành; không phát model draft.
- [ ] Không thêm event cho từng tool.
- [ ] Không branch, retry hoặc sửa `scoped` dựa trên observer result.
- [ ] Result và provider/tool trace bật/tắt observer phải parity.

File dự kiến:

- `src/services/security_pipeline.py`
- `src/services/durable_worker.py`
- test doubles đang implement progress callback.

### Phase 4 — Repository, ordering và retry correctness

- [ ] Xác minh PostgreSQL sequence tăng đơn điệu khi writer và final commit cạnh tranh.
- [ ] Xác minh không có progress append sau final event.
- [ ] Xác minh outbox idempotency và replay không tạo duplicate UI.
- [ ] Xác định semantics khi durable job retry: stage có thể chạy lại nhưng final side effect vẫn idempotent.
- [ ] Không trình bày event của attempt cũ như final result.
- [ ] Xác minh progress append không giữ analysis row lock đủ lâu để ảnh hưởng heartbeat/final commit.
- [ ] Xác minh event store lỗi nhưng final store phục hồi vẫn cho phép terminal commit.
- [ ] Xác minh mất lease vẫn hủy handler/reporter đúng cách.

### Phase 5 — Frontend selector và presentation

- [ ] Tạo pure selector cho latest progress theo active analysis ID và sequence.
- [ ] Dedupe replay và không lùi state khi event đến lệch thứ tự.
- [ ] Map stage/state qua allow-list; unknown dùng generic fallback.
- [ ] Không dùng `risk_hint` để tạo verdict text.
- [ ] Không dùng `evidence_refs` để tạo reasoning text.
- [ ] Truyền derived progress vào `ConversationPanel`.
- [ ] Mở rộng busy card hoặc tạo `ControlledProgressCard`.
- [ ] Simple mode chỉ hiển thị latest stage.
- [ ] Analyst timeline chỉ hiển thị coarse stages, không giả lập tool execution.
- [ ] Không thêm progress vào turns/history.
- [ ] Final event/fetch semantics, retry, reset và follow-up chat giữ nguyên.
- [ ] `aria-live="polite"`, tránh announce replay và tôn trọng reduced motion.

File dự kiến:

- `frontend/src/lib/hooks/use-security-case.ts`
- selector/view model mới dưới `frontend/src/lib/`
- `frontend/src/components/analysis/conversation-panel.tsx`
- `frontend/src/components/analysis/case-workspace.tsx`
- component progress mới nếu cần.

### Phase 6 — Backend verification

- [ ] Contract test event mới và event cũ không có `progress_state`.
- [ ] Test queue order, queue full, append error và quiesce timeout.
- [ ] Test progress failure không làm job retry hoặc analysis fail.
- [ ] Test không append progress sau final.
- [ ] Test worker cancellation/lost lease dọn reporter task.
- [ ] Test stage order cho in-scope, OOS, need-more-info và incident response.
- [ ] Test OOS/need-more-info zero investigation/provider calls.
- [ ] Test no-consent zero external lookup và progress không nói đang lookup.
- [ ] Test provider no-hit/error/timeout không tạo message ngụ ý safe.
- [ ] Test result deep-equality và provider/tool trace parity khi observer on/off.
- [ ] Test event payload không chứa raw message, credential, OTP, token, tool args hoặc exception.
- [ ] PostgreSQL integration test event/outbox/sequence/final transaction/lease.

Lệnh gate:

```bash
uv run ruff check .
uv run pytest -q
uv run alembic heads
```

Chạy PostgreSQL integration suite trên database disposable theo `TESTING.md`.

### Phase 7 — Frontend verification

- [ ] Unit test selector với empty, unknown, malformed, duplicate và out-of-order events.
- [ ] Test latest stage được render khi busy.
- [ ] Test không có event vẫn dùng generic busy state.
- [ ] Test provisional warning vẫn mang nhãn tạm thời.
- [ ] Test WebSocket replay và polling fallback cho cùng UI sequence.
- [ ] Test reconnect không làm UI quay về stage cũ.
- [ ] Test final result thay progress bằng assistant response hiện hành.
- [ ] Test progress không đi vào turns/history.
- [ ] Test reset/new analysis loại progress cũ.
- [ ] Test presentation error không chặn terminal fetch.
- [ ] Test accessibility live region và reduced motion.
- [ ] Xác nhận API mock calls của submit, polling và final fetch không đổi ngoài event contract mới.

Lệnh gate:

```bash
cd frontend
npm test
npm run lint
npm run typecheck
npm run check:cutover
npm run build
npm run test:e2e
```

### Phase 8 — Deployment và rollout

- [ ] Deploy backend backward-compatible trước hoặc cùng frontend hiểu field optional.
- [ ] Xác minh backend readiness và Alembic head.
- [ ] Xác minh worker cùng artifact/version, heartbeat ổn định và không duplicate claim.
- [ ] Xác minh Redis notifier; PostgreSQL cursor polling vẫn hoạt động khi Redis/WebSocket lỗi.
- [ ] Chạy hosted smoke owner isolation, ticket single-use, disconnect/reconnect và final fetch.
- [ ] Đo event count/payload size, time-to-first-progress và gap giữa stages.
- [ ] Chỉ bật `SECURITY_ASYNC_EXECUTION_ENABLED=true` khi toàn bộ async prerequisites trong `DEPLOYMENT.md` ready.
- [ ] Việc bật async production là rollout riêng có phê duyệt; không tự bật chỉ vì code đã merge.
- [ ] Không ghi token, raw private message, OTP, credential hoặc URL query nhạy cảm vào log/screenshot evidence.
- [ ] Cập nhật `DEPLOYMENT.md`, `TESTING.md`, `CURRENT_STATUS.md` từ evidence thực tế, không sao chép test count cũ.

## Acceptance criteria

- Sau `202`, UI có queued/running state và tiếp tục nhận coarse stage progress.
- Stage-start event đến trước tác vụ dài tương ứng khi event store khỏe.
- Progress store lỗi không thay đổi final result và không trực tiếp gây durable job retry.
- Bật/tắt observer cho cùng fixture tạo final response parity và provider/tool call trace parity.
- Out-of-scope và need-more-info không có investigation/external-provider event hoặc call.
- External lookup vẫn cần request-scoped consent và SSRF/redirect validation hiện hành.
- Provider no-hit/error/timeout không tạo hoặc ám chỉ `SAFE`.
- Không có raw chain-of-thought, model draft, provider payload hoặc dữ liệu nhạy cảm trong progress event.
- Không có progress event được append sau final.
- WebSocket reconnect và polling replay không tạo duplicate hoặc state regression trên UI.
- Simple mode chỉ hiển thị một label ngắn; technical detail vẫn ở panel riêng.
- Final event làm frontend tải response authoritative và thay progress bằng assistant response hiện hành.
- Inline path vẫn giữ hành vi hiện tại khi async capability không sẵn sàng.

## Quan sát vận hành

Theo dõi tối thiểu bằng metadata không nhạy cảm:

- time từ `202` đến event đầu tiên;
- time từ worker claim đến `running`;
- duration theo coarse stage;
- event queue depth, dropped events và append failures;
- progress events trung bình/tối đa mỗi analysis;
- WebSocket connect/reconnect và polling fallback rate;
- analysis queued/running quá deadline;
- job lease renewal/loss và retry rate;
- final completion rate và time-to-final.

Không log user message hoặc provider payload để tính metric.

## Rollback

- Frontend unknown/missing `progress_state` phải fallback được, nên có thể rollback backend hoặc frontend độc lập.
- Tắt presentation progress không được tắt analysis event transport/final monitoring.
- Nếu reporter gây tải hoặc contention, có thể disable coarse observer ở worker code/deployment rollback; final pipeline vẫn chạy.
- Không rollback bằng cách xóa event/history hoặc thay đổi final result.
- Không dùng destructive migration; contract field optional nên rollback không cần data rewrite.

## Definition of done

- [ ] Coarse progress hoạt động qua WebSocket và polling fallback.
- [ ] Reporter fail-open, bounded và không append sau final.
- [ ] Result/provider/tool parity gates đạt.
- [ ] Safety invariants và owner isolation được kiểm chứng.
- [ ] Backend, PostgreSQL integration và frontend gates đều đạt bằng evidence hiện tại.
- [ ] Không có tool-level event, chain-of-thought hoặc response token streaming.
- [ ] Canonical docs phản ánh đúng runtime và rollout state thực tế.
