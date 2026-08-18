
  # Kế hoạch nâng TrustGuard thành AI Security Assistant

  ## 1. Tóm tắt kiến trúc đích

  Message + conversation
          ↓
  Rule extraction + AI semantic understanding
          ↓
  Validated hybrid security context
          ├─ Thiếu dữ liệu → adaptive follow-up
          ├─ Đã bị lộ tài khoản/tiền → incident-response mode
          └─ Đủ dữ liệu → policy-constrained investigation
                                  ↓
                      Deterministic risk engine
                                  ↓
                      Grounded AI explanation
                                  ↓
              Reviewed Memory / Admin AI Copilot

  Nguyên tắc xuyên suốt:

  - AI hiểu ngữ cảnh, hỏi, ưu tiên tool và giải thích.
  - Deterministic policy vẫn sở hữu score, risk và recommended action.
  - AI không tạo URL/tool target mới, không đánh dấu SAFE, không thực thi admin action.
  - Rule signal đã xác nhận không được AI xóa; AI chỉ bổ sung field có source span hợp lệ.
  - LLM lỗi, timeout, hết budget hoặc thiếu API key phải fallback rules-only, không làm analysis trả 500.
  - API tiếp tục dùng /api/v4; mọi thay đổi contract đều additive.
  - Mỗi work package dưới đây chỉ bắt đầu sau khi package trước đạt gate test và merge hoàn chỉnh.

  ## 2. Work package tuần tự

  ### WP0 — Contract và AI runtime foundation

  **Status:** `DONE` — repository implementation và automated gate tests; production rollout vẫn theo WP8.

  Mục tiêu: tạo extension point ổn định để các package sau không cùng sửa model/config/dependency wiring.

  - Tạo interface provider-agnostic SecurityAssistantModel với bốn operation typed:
      - understand(message, conversation_summary)
      - prioritize_plan(context, candidate_steps)
      - synthesize(result)
      - draft_admin_review(case_detail)

  - OpenAI là adapter đầu tiên; test dùng deterministic fake adapter.
  - Mọi structured output dùng Pydantic extra="forbid", timeout, retry, token/cost accounting và schema validation.
  - Thêm feature flags độc lập:
      - SECURITY_AI_UNDERSTANDING_ENABLED
      - SECURITY_AI_PLANNING_ENABLED
      - SECURITY_AI_EXPLANATION_ENABLED
      - SECURITY_ASYNC_EXECUTION_ENABLED
      - SECURITY_MEMORY_RETRIEVAL_ENABLED
      - SECURITY_ADMIN_COPILOT_ENABLED

  - Budget mặc định mỗi turn:
      - Tối đa 4 LLM calls.
      - Extraction và planning dùng model nhỏ.
      - Chỉ một synthesis call.
      - Inline final p95 mục tiêu dưới 15 giây.

  - Không log/persist prompt, raw completion hoặc chain-of-thought. Chỉ lưu provider, model/version, operation, latency,
    token, cost, status và normalized error.

  - Mở rộng /api/v4/capabilities bằng các flag AI/async đang thực sự bật.

  Gate hoàn thành:

  - Fake adapter pass schema, timeout, malformed output, budget và fallback tests.
  - Khi toàn bộ AI flag tắt, response v4 byte-compatible với behavior hiện tại.
  - Production không bật AI nếu provider configuration không hợp lệ.

  ———

  ### WP1 — Hybrid semantic understanding

  **Status:** `DONE` — hybrid merge, grounding/source-span validation và rules-only regression đã có test.

  Mục tiêu: AI hiểu nội dung vượt khỏi regex nhưng không làm yếu safety invariant.

  Thêm assistant_context optional vào SecurityScopeResponseV4 và conversation summary:

  - processing_mode: hybrid | rules_only | fallback
  - sender_intent
  - social_engineering_techniques
  - exposure_state:
      - PRE_ACTION
      - LINK_OPENED
      - CREDENTIAL_SHARED
      - OTP_SHARED
      - PAYMENT_SENT
      - UNKNOWN

  - missing_information
  - field_confidences
  - source_spans: field name + start/end offset; không persist raw excerpt
  - understanding_version
  - model_version

  Merge policy:

  - URL chỉ lấy từ local URL extractor; AI không được tạo hoặc sửa URL.
  - Boolean signal true từ rules là sticky.
  - AI được bổ sung entity, scenario, requested action, exposure và security signal khi confidence ≥ 0.80 và source span
    trỏ đúng input.

  - AI không được suy ra SAFE.
  - Rule/AI conflict tạo limitation và cap confidence cuối ở 0.65.
  - Explicit general fact-check vẫn terminal out-of-scope.
  - Ambiguous scope được AI phân loại; nếu rule và AI xung đột về boundary thì trả NEED_MORE_INFO.
  - Merged SecurityContextV4 mới là input duy nhất của investigation/risk; risk engine không đọc prose LLM.

  Gate hoàn thành:

  - Evaluation bổ sung typo, không dấu, slang, yêu cầu gián tiếp, cài app, chia sẻ màn hình, QR/payment và prompt
    injection.

  - AI-added signals có thể ảnh hưởng deterministic score; malformed hoặc ungrounded signals bị loại.
  - Rules-only fallback giữ nguyên toàn bộ regression hiện tại.

  ———

  ### WP2 — Adaptive conversation và incident response

  **Status:** `DONE` — adaptive slot, monotonic exposure, immediate recovery và redacted memory đã có test.

  Mục tiêu: biến multi-turn storage thành hội thoại điều tra thực sự.

  - Thay câu hỏi follow-up cố định bằng missing-slot selector.
  - Mỗi turn chỉ hỏi một câu có information gain cao nhất theo ưu tiên:
      1. User đã thực hiện hành động chưa.
      2. Họ yêu cầu credential/OTP/payment gì.
      3. URL/contact/domain.
      4. Claimed organization.
      5. Amount/deadline/channel.

  - LLM chỉ diễn đạt câu hỏi từ slot đã được policy chọn; template deterministic là fallback.
  - Conversation summary lưu assistant context đã redact, exposure state cao nhất và unresolved slots.
  - Nếu exposure state từ LINK_OPENED trở lên, chuyển sang incident-response mode trước investigation bổ sung.
  - Bổ sung recommended action enum:
      - CLOSE_PAGE_AND_DO_NOT_RETURN
      - CHANGE_PASSWORD_FROM_TRUSTED_DEVICE
      - REVOKE_ACTIVE_SESSIONS
      - CONTACT_BANK_OR_PAYMENT_PROVIDER
      - PRESERVE_MESSAGE_FOR_REPORTING

  - Các action trên do deterministic policy ánh xạ từ exposure state; LLM chỉ giải thích.
  - Giữ optimistic conversation_version; turn khác case tiếp tục trả conflict.

  Gate hoàn thành:

  - Multi-turn test chứng minh câu hỏi thay đổi theo dữ liệu thiếu.
  - User đã nhập OTP/chuyển tiền nhận immediate recovery steps dù provider timeout.
  - Consent không được kế thừa giữa các turn.
  - Không persist raw message, OTP, query token hoặc credential.

  ———

  ### WP3 — Policy-constrained adaptive planner

  **Status:** `DONE` — AI chỉ ưu tiên candidate allowlist; consent/dependency/SSRF/budget vẫn do executor kiểm soát.

  Mục tiêu: investigation theo scenario thay vì chỉ theo URL.

  - Deterministic planner tạo toàn bộ candidate step và canonical target trước.
  - AI chỉ được rank, skip hoặc yêu cầu thêm một candidate step đã có trong allowlist.
  - Executor revalidate consent, dependency, SSRF, deadline, retries, quota và cost ngay trước call.
  - Scenario routing:
      - Phishing URL: local rules, blacklist, DNS, redirect, RDAP, reputation, brand match.
      - Recruitment: brand/career domain matching.
      - Promotion/prize: brand/domain and reputation checks.
      - Impersonation không URL: brand/contact registry và official channel verification.
      - Payment/OTP không URL: context-based risk; không gọi URL provider.
      - Incident response: ưu tiên recovery guidance; investigation không trì hoãn warning.

  - AI planning failure dùng deterministic plan hiện tại.
  - Event timeline ghi lý do step chạy, skip hoặc bị policy từ chối; không lộ prompt/chain-of-thought.

  Gate hoàn thành:

  - AI không thể bypass consent hoặc tạo hostname/tool ngoài candidate plan.
  - Unnecessary provider call rate không tăng so với baseline.
  - Payment-only và impersonation-without-URL có plan phù hợp, không sinh URL call giả.
  - Prompt injection trong message không thay đổi system policy.

  ———

  ### WP4 — Grounded assistant response và frontend experience

  **Status:** `DONE` — grounding verifier, phản hồi hội thoại policy-grounded và simple/analyst frontend đã có test.

  Mục tiêu: kết quả đọc như trợ lý bảo mật, không như raw tool report.

  Thêm assistant_response optional:

  - summary
  - top_reasons[]: text + evidence refs
  - uncertainties[]
  - immediate_steps[]: action enum + policy ref
  - follow_up_offer
  - response_version
  - generation_mode: ai | policy_grounded (`template_fallback` chỉ được đọc để tương thích dữ liệu cũ)

  Validation:

  - Mỗi factual reason phải tham chiếu evidence hiện hữu.
  - Procedural advice phải tham chiếu deterministic action/policy.
  - Không cho phép citation hoặc signal không tồn tại.
  - Không render URL đáng ngờ thành clickable anchor.
  - Synthesis failure giữ câu trả lời hội thoại được dựng trực tiếp từ verdict, evidence và action đã kiểm chứng;
    không chuyển sang template.

  Frontend:

  - Lượt intake đầu luôn chạy Security v4; trong lúc đang kiểm tra, conversation composer được ẩn và chỉ hiện lại sau
    verdict. Các lượt sau đi qua authenticated `/api/v4/chat`: hội thoại thường được trả lời trực tiếp, còn
    `check_scam` mở lượt Security v4 mới trong cùng `conversation_id`/version.
  - Web product bỏ checkbox lookup từng lượt; thao tác gửi dưới disclosure cố định cấp authorization cho automatic
    URL lookup. Executor vẫn quyết định call theo context và enforce target/SSRF/budget.
  - Simple mode dùng layout hai vùng: chat và `Kết luận và hướng dẫn`; summary, ba lý do/hành động quan trọng nhất hiển thị
    trước, investigation/evidence/report/appeal nằm trong disclosure mở rộng.
  - Analyst mode hiển thị plan, source, confidence, limitation và version.
  - Disclosure chung nêu rõ nội dung có thể được xử lý bởi AI/security provider; không thêm checkbox consent
    riêng trong composer theo lựa chọn sản phẩm.

  Gate hoàn thành:

  - Grounding verifier từ chối hallucinated evidence refs.
  - Accessibility, responsive, simple/analyst mode và retry/fallback tests pass.
  - User có thể hiểu kết luận và hành động chính mà không cần mở evidence detail.

  ———

  ### WP5 — Durable Security v4 và realtime thật

  **Status:** `DONE` — repository implementation; async capability mặc định tắt cho tới hosted rollout gate WP8.

  Mục tiêu: provisional → progress → final hoạt động thật, không chỉ replay sau khi request hoàn tất.

  Để giữ compatibility:

  - SecurityTriageCreateRequestV4 thêm execution_mode: inline | async, mặc định inline.
  - Frontend mới gửi async khi capability cho phép.
  - Inline tiếp tục trả 200 SecurityScopeResponseV4.
  - Async trả 202 SecurityAnalysisAcceptedResponseV4.
  - Hỗ trợ Idempotency-Key cho mỗi turn; cùng owner/key/payload trả lại analysis cũ, payload khác trả 409.
  - Mở rộng event additive bằng kind, step_id, message, evidence_refs và optional risk_hint.

  Persistence:

  - Migration 0016_security_v4_durable_jobs tạo job/payload/outbox/idempotency records riêng cho v4.
  - Raw message trong durable payload phải được mã hóa bằng application encryption key.
  - Payload được xóa ngay khi terminal; abandoned payload bị retention worker xóa tối đa sau 24 giờ.
  - Conversation version được reserve atomically khi enqueue; worker xử lý immutable context snapshot.
  - Worker retry phải idempotent cho evidence, memory, campaign và HITL proposal.
  - PostgreSQL là source of truth; Redis chỉ notify/fan-out.
  - Local SQLite giữ inline mode.

  Runtime sequence:

  1. Validate auth, rate limit, conversation version.
  2. Chạy scope/local signal đủ để tạo provisional warning.
  3. Persist queued analysis, encrypted payload và first events atomically.
  4. Worker chạy understanding → investigation → risk → synthesis.
  5. Persist terminal result/outbox atomically.
  6. WebSocket stream event mới; cursor polling vẫn authoritative fallback.

  Gate hoàn thành:

  - Lease loss, duplicate delivery, restart, Redis outage và WebSocket reconnect không tạo duplicate side effect.
  - Provisional warning xuất hiện trước external provider completion.
  - Disconnect không hủy job.
  - Encrypted payload được purge ở success, failure và retention recovery.
  - Inline compatibility suite vẫn pass.

  Bằng chứng implementation:

  - `SecurityTriageCreateRequestV4.execution_mode` giữ mặc định `inline`; async trả `202` và yêu cầu `Idempotency-Key`.
  - Migration `0016_security_v4_durable_jobs` tạo bảng job, encrypted payload, outbox và idempotency riêng.
  - Shared AI runtime áp dụng một budget/deadline xuyên suốt understanding → planning → synthesis.
  - PostgreSQL lease worker phát progress/final event, purge payload ở terminal/retry exhaustion/retention và dùng outbox để notify.
  - WebSocket theo dõi event mới tới terminal; cursor polling tiếp tục là nguồn authoritative khi Redis/WebSocket lỗi.
  - Frontend chỉ gửi async khi `/api/v4/capabilities` công bố `security_async_execution=true` và giữ cùng key khi retry.
  - Gate tests: `tests/unit/test_security_ai_wp5.py`, `tests/test_api/test_security_ai_wp5.py` và frontend Security workspace/event-stream tests.

  ———

  ### WP6 — Reviewed Security Memory retrieval

  **Status:** `DONE` — repository implementation và automated gate tests; feature flag mặc định tắt tới hosted rollout gate WP8.

  Mục tiêu: dùng tri thức đã review để tạo khác biệt sản phẩm mà không khuếch đại false positive.

  - Thêm tool local security_memory_lookup và evidence type reviewed_security_memory.
  - Chỉ retrieve:
      - Memory có admin verdict malicious, safe hoặc false_positive.
      - Campaign có reviewer status confirmed.

  - Không dùng record unreviewed hoặc campaign pending làm risk evidence.
  - Match bằng named security signals hiện có: domain, redirect, claimed brand, scenario, action pattern và threat; không
    cần embeddings trong phase đầu.

  - User response chỉ nhận privacy-minimized pattern summary, verdict, review time và provenance; không lộ owner, raw
    message hoặc member analysis IDs.

  - Reviewed malicious match có thể đóng góp risk qua policy version mới security-risk-v2.
  - Reviewed false-positive/safe match chỉ giảm weak heuristic contribution; không override approved blacklist hoặc
    malicious provider hit.

  - Rollout scoring v2 bằng versioned evaluation và feature flag; các analysis cũ giữ policy version cũ.

  Gate hoàn thành:

  - Không self-match analysis đang chạy.
  - Tenant/owner/private data isolation pass.
  - False-positive memory thực sự ngăn weak domain-age/lookalike signal bị nâng quá mức.
  - Risk v1 regression giữ nguyên khi memory flag tắt.

  Bằng chứng implementation:

  - Tool local `security_memory_lookup` chỉ nhận named signals đã chuẩn hóa, không nhận raw message; evidence mới dùng type
    `reviewed_security_memory`.
  - SQLite/PostgreSQL lookup join qua owner của analysis, loại analysis hiện tại, loại memory `unreviewed`/`suspicious`
    và campaign chưa `confirmed`; campaign khác owner không được retrieve.
  - Evidence public chỉ có pattern category, verdict, review time và provenance memory/campaign; không có owner, raw content
    hoặc member analysis IDs.
  - `security-risk-v2` cộng điểm có giới hạn cho malicious/confirmed match. Safe/false-positive chỉ bỏ contribution yếu từ
    local URL/RDAP/brand; approved blacklist và malicious reputation vẫn buộc `MALICIOUS`.
  - Flag tắt không thêm plan/evidence và tiếp tục dùng `security-risk-v1`; lookup lỗi tạo limitation rồi hoàn tất analysis.
  - Versioned 5-case rollout evaluation ở `tests/eval/security_memory_v2_v1.jsonl`; report có dataset hash tại
    `docs/evidence/security-memory-v2-v1-report.json`.
  - Gate tests: `tests/unit/test_security_ai_wp6.py`, `tests/test_api/test_security_ai_wp6.py` và OpenAPI contract test.

  ———

  ### WP7 — Admin AI Copilot

  **Status:** `DONE` — grounded suggestion-only API/UI, migration `0017`, RBAC/rate-limit/audit gates và
  prompt-injection/non-mutation tests đã có; production rollout vẫn theo WP8.

  Mục tiêu: hỗ trợ Security Admin review, không triển khai sink block-domain/broad-warning.

  Public API additive:

  - POST /api/v4/admin/analyses/{analysis_id}/copilot
  - Response gồm:
      - evidence summary
      - conflicts
      - missing information
      - related reviewed campaigns
      - proposed disposition
      - proposed existing admin action
      - grounded rationale/evidence refs
      - model/version

  - Migration 0017_security_admin_copilot lưu suggestion, usage metadata, evidence snapshot hash, reviewer và timestamps;
    không lưu prompt/raw completion.

  - Chỉ Security Admin được gọi.
  - Copilot không gọi action executor và không tự điền reviewer note khi submit.
  - Admin phải tự chọn decision, nhập note và đi qua HITL endpoint hiện tại.
  - UI hiển thị rõ AI suggestion — not executed và cho phép refresh có rate limit.
  - BLOCK_DOMAIN và PUBLISH_BROAD_WARNING tiếp tục báo sink chưa cấu hình.

  Hiện thực trong repository:

  - `SecurityAdminCopilotService` chỉ nhận structured/redacted case evidence và confirmed campaign có liên quan;
    prompt coi toàn bộ case data là untrusted và output phải qua allowlist + evidence-ref grounding.
  - `POST /api/v4/admin/analyses/{analysis_id}/copilot` chỉ cho Security Admin, có refresh rate limit riêng,
    deterministic fallback và response luôn `executed=false`.
  - Migration `0017_security_admin_copilot` lưu typed suggestion, usage metadata, SHA-256 evidence snapshot,
    reviewer/requested/completed timestamps và audit; không lưu prompt/raw completion.
  - Review Room hiển thị panel `AI suggestion — not executed`; suggestion không điền decision/reviewer note và
    không gọi v3 action executor.
  - Gate tests: `tests/unit/test_security_ai_wp7.py`, `tests/test_api/test_security_ai_wp7.py` và
    `frontend/src/test/admin-review-room.test.tsx`.

  Gate hoàn thành:

  - RBAC, rate limit, audit và evidence grounding pass.
  - Prompt injection trong case evidence không thể khiến copilot gọi tool/action.
  - Copilot suggestion không thay đổi case, blacklist, campaign hoặc report state.

  ———

  ### WP8 — Evaluation, rollout và cleanup gate

  **Status:** `REPOSITORY DONE / HOSTED ROLLOUT PENDING` — ba tầng evaluation và sequential rollout checker
  đã có code/test; tier hosted chưa được đánh dấu pass vì repository không có OIDC/PostgreSQL/Redis/live-provider evidence.

  Mở rộng evaluation thành ba tầng:

  1. Deterministic security regression.
  2. AI understanding/conversation/grounding.
  3. Hosted reliability/cost/latency.

  Release metrics:

  - Field-level extraction precision/recall theo scenario.
  - Scope routing accuracy.
  - Exposure-state accuracy.
  - Follow-up completion và số turn tới verdict.
  - Grounded reason rate phải đạt 100%.
  - Hallucinated evidence/action rate phải bằng 0.
  - Unnecessary provider call rate không vượt baseline.
  - Malicious precision và false-positive rate không được regression.
  - LLM fallback success rate.
  - p95 latency, tokens và cost mỗi turn.
  - Report/appeal overturn rate sau rollout.

  Rollout production theo thứ tự flag:

  1. Understanding + fallback.
  2. Adaptive follow-up/incident response.
  3. Grounded explanation.
  4. Adaptive planning.
  5. Async execution.
  6. Reviewed memory.
  7. Admin copilot.

  Mỗi flag chỉ bật sau hosted smoke với OIDC, PostgreSQL, Redis và live provider; rollback bằng tắt flag, không downgrade
  dữ liệu. Legacy v2/v3 cleanup không nằm trong roadmap này và chỉ thực hiện sau zero-usage window hiện có.

  Hiện thực trong repository:

  - Tier 1: `security-v4-eval-v1` có 24 category và `security-memory-v2-eval-v1` có 5 scoring/poisoning gate;
    grounded explanation bắt buộc 100%, malicious precision/FPR/provider-call không được regression.
  - Tier 2: `security-ai-eval-v1` chạy production merge/conversation/grounding code trên 9 category, đo field
    precision/recall theo scenario, scope/exposure, follow-up/turns-to-verdict, hallucination, fallback và p95.
    Report version/hash nằm tại `docs/evidence/security-ai-v1-report.json`.
  - Tier 3: `evaluate_security_ai_hosted.py` chỉ validate observation thật về OIDC/PostgreSQL/Redis/live provider,
    reliability, latency/token/cost và report/appeal overturn; tool không tự tạo hoặc giả lập hosted evidence.
  - `check_security_ai_rollout.py` fail closed nếu thiếu report đầy đủ do hosted evaluator tạo ra,
    provider/durable readiness hoặc bật flag vượt thứ tự. Kết quả local `target-stage=off` chỉ có
    `rollout_status=disabled` và `production_rollout_complete=false`; rollback luôn chỉ dẫn tắt flag hiện tại và
    `database_action=none`.
  - Audit WP1–WP7 trước WP8 đã siết WP7: rationale phải có evidence hợp lệ và proposed disposition không được
    xung đột với deterministic risk. Toàn bộ flag vẫn mặc định tắt.

  Local gate commands:

  ```powershell
  .\.venv\Scripts\python.exe scripts\evaluate_security_v4.py
  .\.venv\Scripts\python.exe scripts\evaluate_security_memory_v2.py
  .\.venv\Scripts\python.exe scripts\evaluate_security_ai.py
  .\.venv\Scripts\python.exe scripts\check_security_ai_rollout.py --target-stage off
  ```

  Để rollout một stage, operator phải thu observation theo template
  `docs/templates/security-ai-hosted-evidence.example.json`, validate thành hosted report rồi chạy rollout checker với
  `--hosted-report`. Không xóa legacy v2/v3 trong WP8.

  ## 3. Quy tắc chống conflict khi implement

  - WP0 là package duy nhất tạo AI interface, config và capability contract.
  - WP1–WP4 chỉ dùng interface WP0; không tự tạo provider client hoặc budget logic riêng.
  - Durable schema chỉ xuất hiện ở migration 0016; không trộn migration async với AI context.
  - Copilot schema chỉ xuất hiện ở migration 0017.
  - Mỗi WP phải giữ toàn bộ tests của WP trước xanh trước khi bắt đầu WP kế tiếp.
  - Feature flag mặc định tắt ở production cho đến gate rollout tương ứng.

  ## 4. Assumptions đã khóa

  - Phạm vi là assistant hoàn chỉnh cho user và admin copilot.
  - API giữ /api/v4 với thay đổi additive.
  - Hosted LLM processing nằm trong disclosure chung, không có consent checkbox riêng.
  - Provider abstraction độc lập; OpenAI là adapter đầu tiên.
  - AI output được dùng ngay khi hợp lệ, không chạy shadow-only.
  - Merge theo monotonic safety và confidence threshold 0.80.
  - Budget profile balanced, tối đa 4 LLM calls mỗi turn.
  - Durable async được triển khai sau AI core.
  - Deterministic fallback luôn khả dụng.
  - Không triển khai downstream sink thật cho block-domain hoặc broad-warning trong roadmap này.
