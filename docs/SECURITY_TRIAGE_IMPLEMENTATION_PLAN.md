# Kế hoạch triển khai AI Security Triage Assistant

**Cập nhật:** 14/08/2026

**Trạng thái:** WP0–WP8, API/frontend WP9 và local evaluation/cutover tooling hoàn tất; hosted release/cutover đang triển khai

**Nguồn yêu cầu:** [scope.md](scope.md)  
**Tài liệu hiện trạng:** [implementation-status.md](implementation-status.md), [01-ARCHITECTURE.md](01-ARCHITECTURE.md), [02-CONTRACT_AND_FIXTURES.md](02-CONTRACT_AND_FIXTURES.md), [04-POSTGRESQL_ALEMBIC_PLAN.md](04-POSTGRESQL_ALEMBIC_PLAN.md)

Tài liệu này là kế hoạch thực thi, không lặp lại toàn bộ nội dung audit hoặc product scope. Khi tài liệu
và runtime khác nhau, phải kiểm tra code/test hiện tại rồi cập nhật lại kế hoạch trước khi implement.

---

## 1. Mục tiêu và ranh giới

Chuyển luồng chính từ general fact-check sang Security Triage cho tin nhắn hoặc URL có dấu hiệu:

- phishing và đánh cắp credential/OTP;
- giả mạo thương hiệu/tổ chức;
- lừa chuyển tiền, tuyển dụng, khuyến mãi hoặc trúng thưởng;
- social engineering yêu cầu thông tin cá nhân hoặc hành động nguy hiểm.

Luồng đích:

```text
message / URL / follow-up
→ security scope decision
→ structured security context
→ policy-controlled investigation
→ evidence
→ deterministic security risk
→ warning / recommendation
→ admin review khi cần
```

Không biến sản phẩm thành công cụ xác minh mọi phát biểu trên Internet. General news, politics,
medical/science, sports, deepfake và malware sandbox vẫn ngoài scope theo `scope.md`.

### Nguyên tắc bắt buộc

- LLM có thể extract context, đề xuất ưu tiên tool và viết giải thích; LLM không quyết định final
  score/risk, whitelist/blacklist approval hoặc wide action.
- `provider no-hit != SAFE`; `provider timeout != SAFE`.
- `official NOT_FOUND != FALSE`.
- Domain mismatch hoặc domain mới, nếu đứng riêng, không đủ để kết luận `MALICIOUS`.
- External URL/domain lookup cần consent; official-source lookup có consent/purpose riêng.
- Không dùng URL/target do LLM tự sinh để gọi network tool.
- Giữ SSRF guard, redirect revalidation, ownership, RBAC, safe logging, durable job, idempotency,
  outbox và realtime lifecycle.
- Không drop legacy schema trước khi ngừng reader/writer, đo usage, backup/export và verify restore.

---

## 2. Nguồn trạng thái hiện tại

Trạng thái code, capability partial/deprecated và test gần nhất nằm tại
[implementation-status.md](implementation-status.md). Tài liệu này chỉ giữ thứ tự WP, quyết định kỹ thuật và
release gate; không duy trì thêm một bản audit source riêng dễ lỗi thời.

---

## 3. Chiến lược triển khai

### Boundary vNext

Tạo contract/route vNext riêng theo convention của repository; không nhồi field nullable vào v2/v3 cũ.
Trước khi code WP1, chốt đúng một cơ chế cutover:

- route/version mới cho Security Triage;
- frontend mới chỉ gọi contract này;
- legacy v2/v3 được giữ riêng trong compatibility window;
- settings chỉ dùng để bật/tắt capability thực sự cần vận hành, không tạo ba flag chồng chéo.

Tại thời điểm WP0, source chỉ có các flag source-discovery/provisional/auto-promotion; chưa có general
fact-check/security-vNext flag. Tên setting mới phải theo snake_case của `src/config.py` và env alias tự
động của Pydantic Settings.

### Thứ tự và dependency

| WP | Kết quả | Phụ thuộc để bắt đầu | Phụ thuộc để hoàn tất |
|---|---|---|---|
| WP0 | Baseline + boundary vNext | — | — |
| WP1 | Scope gate + SecurityContext + contract | WP0 | WP0 |
| WP2 | Security planner + evidence | WP1 | WP1 |
| WP3 | Deterministic risk + single-turn API | WP2 | WP2 |
| WP4 | Brand/whitelist/official verification | WP1 | WP2, WP3 |
| WP5 | Multi-turn conversation/case memory | WP1 | WP3 |
| WP6 | Security Chat frontend | Có draft contract WP1 | WP3, WP5 |
| WP7 | HITL/admin action | WP3 | WP4 |
| WP8 | Security memory/campaign | WP3 | WP4, WP7 |
| WP9 | Cutover/evaluation/cleanup | Có thể chuẩn bị fixture sớm | WP0–WP8 hoàn tất hoặc scope deviation được duyệt rõ ràng |

WP4, WP5, phần khung WP6 và WP7 không cần chờ nhau hoàn toàn. Không dùng bảng trên để ép mọi công
việc thành một chuỗi tuần tự.

### Definition of Done chung

Một WP chỉ `DONE` khi:

- contract/migration liên quan đã có test;
- safety invariants và owner/RBAC được test tại boundary;
- provider failure/no-hit có limitation đúng;
- không làm legacy path đổi ngoài chủ ý;
- phần “Progress” cuối file ghi test thực tế và deviation còn lại.

---

## 4. WP0 — Baseline & Migration Safety

**Status:** `DONE`

### Đã hoàn thành

- Audit source, API, migrations và frontend hiện tại.
- Chạy backend test/lint, frontend unit/lint/typecheck; kết quả ở mục 2.
- Xác nhận `/api/v2` và `/api/v3` đều đang tồn tại; v3 chưa phải security contract.
- Chốt boundary vNext tại `/api/v4`; endpoint đầu tiên của WP1 là `/api/v4/analyses`, model mới dùng
  `contract_version="v4"` và hậu tố `V4`, không kế thừa model v2/v3.
- Thêm `src/core/product_boundary.py` làm source of truth cho prefix/contract và phân loại usage.
- Bổ sung structured request-log fields an toàn: `api_contract`, `product_profile`,
  `compatibility_usage`; không log query/body/token.
- Thêm unit/integration test cho boundary và request telemetry.

### Cutover, telemetry và rollback đã chốt

- Trong compatibility window, server mount `/api/v4` additive bên cạnh `/api/v2` và `/api/v3`.
- WP1–WP5 không đổi route/model v2/v3 tại chỗ. WP6 tạo API adapter v4 riêng; cutover là chọn adapter
  v4 ở frontend/deployment, không route security request qua legacy graph.
- Chưa thêm feature flag backend ở WP0: khi route v4 chưa tồn tại, một flag vNext chỉ tạo trạng thái
  cấu hình giả. Nếu rollout sau này cần gradual enablement, flag phải gate router/adapter v4 thật.
- Rollback trước destructive cleanup: chuyển frontend/deployment về adapter v3 và ngừng nhận v4 write;
  dữ liệu/migration additive được giữ nguyên. Không rollback bằng drop table hoặc downgrade phá dữ liệu.
- Legacy API read/write được đo từ `compatibility_usage=legacy_read|legacy_write` trong structured logs.
- Provider usage/cost tiếp tục đo từ `tool_usage` theo `provider`, `operation`, `observed_at`; dashboard
  hoặc release query phải tách Google Fact Check, Tavily, embeddings/corpus khỏi security providers.
- Legacy schema writer phải được freeze trước; reader/writer evidence lấy từ application telemetry và
  database statement/audit telemetry nếu môi trường có. Nếu không có bằng chứng đo được thì không được
  suy ra zero usage và không chạy destructive migration.

### Hoàn thành khi

Boundary vNext, compatibility window, telemetry và rollback đã có quyết định/test đủ rõ để WP1 không
sửa trực tiếp contract cũ.

**File/symbol đã thay đổi:** `src/core/product_boundary.py`, `src/api/middleware.py`,
`src/core/logging.py`, `tests/unit/test_product_boundary.py`.

---

## 5. WP1 — Scope Gate, Security Context & Contract

**Status:** `DONE`

### Contract tối thiểu

```text
ScopeDecision
  IN_SCOPE
  NEED_MORE_INFO
  OUT_OF_SCOPE_GENERAL_FACT_CHECK

SecurityContext
  claimed_entity
  scenario
  requested_action
  amount
  urgency
  urls
  credential_request
  otp_request
  payment_request
  impersonation_signals
  potential_threat
  schema_version
```

Giữ `scenario` (recruitment, promotion, refund, account verification, payment...) tách khỏi
`potential_threat` (PHISHING, BRAND_IMPERSONATION, FINANCIAL_SCAM...). Không mở taxonomy rộng hơn
fixture/evaluation cần thiết.

### Flow

```text
validate/redact
→ scope gate
   ├─ OUT_OF_SCOPE → boundary response → END
   ├─ NEED_MORE_INFO → focused question → END
   └─ IN_SCOPE → SecurityContext → WP2
```

OOS và NEED_MORE_INFO phải terminal trước investigation planner. Với OOS rõ ràng, dùng local signals
nếu có thể. Nếu case mơ hồ cần LLM scope classifier, telemetry/test phải tách scope-classifier call khỏi
investigation provider call; invariant là **zero investigation calls**, không phải luôn zero LLM calls.

Khi context extraction lỗi, giữ URL/local indicators, tạo partial context + limitation và chỉ trả
NEED_MORE_INFO nếu thiếu dữ liệu thật sự cản trở triage.

### Không đi vào security path

- `FactCheckOrchestrator`, Google Fact Check, Tavily general fact-check, corpus và claim comparator;
- source-discovery flow;
- screenshot capture mặc định, trừ khi scope được mở rộng riêng.

Chưa xóa code/route legacy trong WP1; chỉ bảo đảm route vNext không gọi chúng.

### Test bắt buộc

| Input | Kỳ vọng chính |
|---|---|
| “Tây Ban Nha vô địch World Cup đúng không?” | OOS; zero investigation call |
| general news/politics/medical/sports | OOS; zero investigation call |
| “Tôi nhận được tin nhắn lạ” | NEED_MORE_INFO; một câu hỏi tập trung |
| “HR yêu cầu đóng 500k phí hồ sơ” | recruitment + payment + RECRUITMENT_SCAM |
| “Ngân hàng yêu cầu gửi OTP...” | `otp_request=true` |
| “Chuyển tiền ngay để mở khóa...” | payment + urgency + FINANCIAL_SCAM |
| “Trúng voucher, đăng nhập link này...” | promotion + credential/login signal |

### Hoàn thành khi

Route v4 có contract versioned; OOS/NEED_MORE_INFO terminal; in-scope tạo `SecurityContextV4`; security
path không gọi general fact-check.

### Đã triển khai

- Thêm `POST /api/v4/analyses` với auth/rate-limit boundary hiện có.
- Thêm contract v4 độc lập: consent, `ScopeDecisionV4`, `SecurityContextV4` và response transition được
  Pydantic validate; request v4 từ chối field legacy/screenshot.
- Thêm deterministic scope gate cho security signals, URL-only, impersonation và các nhóm OOS
  sports/politics/medical-science/news.
- Thêm taxonomy tối thiểu cho scenario, requested action và potential threat; scenario không bị đồng
  nhất với threat.
- OOS và NEED_MORE_INFO trả `terminal=true`, `next_step=END`; IN_SCOPE trả
  `next_step=INVESTIGATION` nhưng chưa gọi planner/provider/risk.
- Extraction failure trả partial context + limitation thay vì làm request fail.
- Legacy `/api/v2`, `/api/v3`, graph, persistence và frontend không đổi.

### Tests và giới hạn có chủ ý

- 22 test mới cho schema/OpenAPI, auth, terminal routing, zero legacy-service resolution, telemetry v4,
  recruitment/payment/OTP/promotion, impersonation, URL-only, OOS fixtures và fallback extraction.
- Scope classifier hiện deterministic/local; chưa có LLM fallback cho case mơ hồ. Đây không phải scope
  deviation vì WP1 đã bao phủ fixture bắt buộc; có thể bổ sung classifier call sau nếu evaluation yêu cầu.
- Consent được nhận trong contract nhưng chưa dùng, vì WP1 không có external lookup. WP2/WP4 phải
  enforce từng consent ngay trước provider call.
- V4 chưa persist analysis/lifecycle và chưa có GET/events; đó là đầu ra của WP3, không được route tạm
  sang legacy `AnalysisService`.

**File/symbol đã thay đổi:** `src/models/security_v4.py`, `src/agents/security_scope.py`,
`src/services/security_triage.py`, `src/api/security_v4.py`, `src/api/dependencies.py`, `src/main.py`,
`src/agents/nodes/extraction.py` và các test v4 tương ứng.

---

## 6. WP2 — Security Planner & Evidence

**Status:** `DONE`

V4 dùng planner/executor deterministic riêng, tái sử dụng stable `step_id_for`, local URL rules,
`ToolExecutionLedger` và các adapter chuẩn hóa hiện có. Legacy `planning_loop` không bị sửa tại chỗ nên
contract v2/v3 vẫn đóng băng; budget, deadline, retry, consent và SSRF được enforce trong executor v4.

### Planner policy

- Planner deterministic chọn tool theo `SecurityContext`, consent, target đã normalize và tool budget.
- WP2 không nhận target hoặc plan từ LLM. Nếu thêm LLM priority sau này, đầu ra chỉ được chọn tool trong
  allowlist; executor vẫn phải tự derive target từ `SecurityContext`.
- Không tiếp tục behavior hiện tại là tự thêm mọi required tool/claim retriever.
- No URL: không chạy network URL/domain tools.
- No consent: chỉ chạy normalization, local rules/SSRF classification, local blacklist và local scam
  analysis.
- Consent URL không tự động cấp consent cho official-source lookup.
- Blacklist hit hoặc blocked target phải short-circuit network work phù hợp.

Ví dụ:

```text
phishing + URL
→ local rules/blacklist → DNS safety → redirect → reputation + RDAP

recruitment không URL
→ structured social-engineering/payment rules; không gọi URL provider
```

### Evidence contract

```text
InvestigationPlan
Evidence[]       # type, source/provenance, target/ref, finding, observed_at, confidence nếu có
Errors[]
Limitations[]
```

Có thể adapter từ `Evidence` hiện tại, nhưng vNext không expose claim stance như product verdict và
không persist raw provider response, OTP, password hoặc token.

### DNS

WP2 đã chọn phương án 1: `SafeDnsEvidenceResolver` dùng `SsrfGuard.validate`, chỉ trả domain và số lượng
IPv4/IPv6 public; không expose địa chỉ IP đã resolve. DNS failure dùng envelope v4 riêng để không thay đổi
enum `ToolName` thuộc contract v3 đã đóng băng.

Redirect adapter tiếp tục revalidate DNS tại từng hop ngay trước network call.

### Test bắt buộc

Consent true/false, private/local/metadata target, Unicode/punycode, blacklist hit, credential path,
reputation no-hit/timeout, redirect revalidation, deadline, retry, budget exhaustion, LLM-supplied target
bị bỏ qua, no-URL không gọi network và DNS behavior nếu được implement.

### Hoàn thành khi

Mỗi provider call giải thích được từ plan; consent/SSRF được enforce ngay trước network call; lỗi được
normalize; general fact-check không quay lại route vNext.

**File/symbol đã triển khai:** `SecurityInvestigationService`, `build_security_investigation_plan`,
`SafeDnsEvidenceResolver`, DNS tool protocol/models, v4 investigation/evidence/error models,
`get_security_investigation_service` và `/api/v4/analyses`.

---

## 7. WP3 — Security Risk Engine & Single-turn API

**Status:** `DONE`

### Risk contract

```text
SAFE
LOW_RISK
SUSPICIOUS
HIGH_RISK
MALICIOUS
INSUFFICIENT_EVIDENCE
```

Policy phải versioned, ví dụ `security-risk-v1`. Risk class, score và recommended actions phải
deterministic. LLM chỉ được viết grounded explanation từ evidence refs.

Xóa khỏi vNext rule `ClaimStance.REFUTES → +70 → MALICIOUS`. Strong evidence cho malicious có thể là
confirmed threat-intelligence hit, approved blacklist/admin verdict hoặc nhiều security indicator độc
lập có độ tin cậy cao. Threshold cụ thể phải được fixture/evaluation khóa lại.

### Response tối thiểu

```json
{
  "scope": "IN_SCOPE",
  "risk": "HIGH_RISK",
  "score": 82,
  "confidence": 0.84,
  "threat_type": "PHISHING",
  "policy_version": "security-risk-v1",
  "evidence": [],
  "recommended_actions": [],
  "limitations": []
}
```

Giữ `AnalysisService`, queued/running/completed/failed, persistence, events, WebSocket và polling; thêm
contract/persistence vNext theo migration additive. Không đổi v2/v3 thành security contract tại chỗ.

### Test bắt buộc

Phishing credential, recruitment fee, OTP impersonation, financial scam, promotion scam, blacklist
hit, provider timeout/no-hit, domain mismatch only, new-domain only, insufficient evidence,
determinism cùng policy version và persistence/event round-trip.

### Hoàn thành khi

Single-turn chạy end-to-end từ API → scope → context → plan/tools → evidence → risk → explanation →
persistence/realtime, và không còn fact-check semantics trong output vNext.

### Đã triển khai

- Thêm policy thuần deterministic `security-risk-v1` trong `assess_security_risk`; score cao từ một
  security context vẫn chỉ là `HIGH_RISK`, còn `MALICIOUS` yêu cầu approved blacklist hoặc confirmed
  threat-intelligence evidence. V4 không import/consume `ClaimStance`.
- Thêm risk class, score, confidence, threat type, recommended actions và explanation chỉ dựa trên
  evidence refs. Provider no-hit/timeout tiếp tục là limitation và không tạo `SAFE`.
- `POST /api/v4/analyses` chạy trọn scope → investigation → risk trong một turn; OOS và
  NEED_MORE_INFO vẫn terminal trước investigation.
- Thêm owner-scoped `GET /api/v4/analyses/{id}`, cursor polling `/events`, single-use WebSocket ticket
  và replay stream. Lifecycle `queued/running/completed/failed` được persist riêng khỏi v2/v3.
- Thêm SQLite tables và PostgreSQL migration `0009_security_triage_v4` cho security analysis, event và
  v4 tool-execution ledger; không persist raw message/OTP/password/token. PostgreSQL final event có
  transactional outbox notification.
- Legacy `risk-v2`, `AnalysisService`, route/model v2/v3 và fact-check path không đổi.

**File/symbol đã triển khai:** `src/agents/security_risk.py`, `src/services/security_analysis.py`,
`src/models/security_v4.py`, `src/api/security_v4.py`, `src/api/dependencies.py`,
`src/repositories/blacklist.py`, `src/repositories/postgres.py`,
`migrations/versions/0009_security_triage_v4.py` và test WP3 tương ứng.

---

## 8. WP4 — Brand, Whitelist & Official Verification

**Status:** `DONE`

### Brand registry/matcher

Schema đề xuất (tên cuối cùng theo convention migration): brand entity, aliases, official
domain/contact, provenance, effective interval, lifecycle/reviewer. Không hard-code registry trong
prompt.

Matcher nhận claimed entity + observed domain/contact và trả official match, lookalike/typosquat/
homograph signals cùng provenance. `official_match=false` chỉ là evidence, không tự thành malicious.

### Whitelist

First-class table/repository/API với canonical indicator, scope, provenance, version, effective
interval, lifecycle và audit. Whitelist chạy trước negative scoring nhưng không phải global
`safe=true`: official domain không được suppress confirmed compromise signal độc lập.

### OfficialClaimVerifier

Capability riêng, không đổi tên/prompt của `FactCheckOrchestrator`:

```yaml
max_claims_per_case: 1
max_search_queries: 2
max_sources: 5
allowed_purposes:
  - verify_official_campaign
  - verify_brand_announcement
  - verify_recruitment_program
  - verify_official_domain
  - verify_official_contact
```

Output: `OFFICIAL_CONFIRMED`, `OFFICIAL_CONTRADICTED`, `NOT_FOUND`,
`INSUFFICIENT_EVIDENCE`. Chỉ truy xuất official/allowed sources, có consent riêng và luôn giữ
`NOT_FOUND != FALSE`.

### Test bắt buộc

Official domain/contact, alias, lookalike, homograph, mismatch-only, whitelist precedence, whitelist
không che malicious evidence, effective interval, unauthorized mutation, official confirmed/
contradicted/not-found và forbidden general fact request.

### Hoàn thành khi

Brand/whitelist evidence có provenance; official verifier bị bound theo purpose/budget; risk engine
consume trust evidence đúng false-positive policy.

### Đã triển khai

- Thêm brand registry versioned gồm aliases, official domains/contacts, provenance, effective interval,
  lifecycle và reviewer; matcher deterministic tạo `official_match`, `official_contact_match`,
  `lookalike_domain`, `homograph_domain` hoặc `domain_mismatch` cùng provenance ref.
- Thêm whitelist first-class cho domain/URL/contact với canonicalization, effective interval,
  lifecycle, reviewer và immutable audit. URL/contact evidence chỉ persist target đã privacy-minimize.
- Thêm admin API v4 create/list/disable cho brand và whitelist, bắt buộc security-admin role.
- Thêm `OfficialClaimVerifier` riêng với đúng purpose allowlist, tối đa 1 claim, 2 query và 5 source;
  local allowlist filter loại source ngoài official domains. Consent official-source tách khỏi URL consent.
- Thêm HTTP adapter cấu hình bằng `OFFICIAL_VERIFIER_API_URL`/`OFFICIAL_VERIFIER_API_KEY`; khi không
  cấu hình hoặc provider lỗi, kết quả là `INSUFFICIENT_EVIDENCE`/limitation, không suy ra phủ định.
- Trust steps xuất hiện trong investigation plan và official query tính vào external-call budget.
- Risk policy chạy whitelist trước weak domain/URL signals, nhưng approved whitelist/official match
  không che approved blacklist hoặc confirmed threat-intelligence hit.
- Thêm SQLite schema và PostgreSQL migration `0010_security_trust_registry` cho brand, whitelist và
  audit; legacy source registry/fact-check contract không đổi.

**File/symbol đã triển khai:** `src/agents/security_trust.py`, `src/services/security_trust.py`,
`src/models/security_v4.py`, `src/agents/security_risk.py`, `src/api/security_v4.py`,
`src/api/dependencies.py`, `src/repositories/blacklist.py`, `src/repositories/postgres.py`,
`migrations/versions/0010_security_trust_registry.py` và test WP4 tương ứng.

---

## 9. WP5 — Multi-turn Conversation & Case Memory

**Status:** `DONE`

Conversation tối thiểu cần owner, status, active investigation/analysis link, redacted structured
summary, context version, timestamps và retention. Có thể dùng `conversations` + FK/link trên analysis
hoặc turn table riêng; chốt theo access pattern trước migration, không mặc định chỉ một row là đủ.

Request vNext nhận optional `conversation_id`. Mỗi turn:

- kiểm tra owner trước khi đọc context;
- merge có version/conflict policy;
- reuse entity/scenario/action/known URLs/evidence refs cần thiết;
- không lưu raw OTP/password/token; không dùng làm private-chat archive;
- không âm thầm kế thừa consent của turn trước cho external lookup;
- không trộn unrelated case.

Test: create/continue, same owner, other owner denied, concurrent update/version conflict, unrelated
case, redaction, retention và follow-up từ NEED_MORE_INFO.

### Hoàn thành khi

`conversation_id` hoạt động end-to-end, context được redacted/versioned/retained và không có cross-user
hoặc cross-case leakage.

### Đã hoàn thành

- Request/response v4 có `conversation_id` và optimistic `conversation_version`; continuation bắt buộc
  gửi cả hai để stale/concurrent turn trả `409 CONFLICT` thay vì ghi đè context.
- Conversation/turn được lưu owner-scoped, liên kết active analysis, có structured summary, evidence
  refs, timestamps, version và expiry; thêm owner-checked `GET /api/v4/conversations/{id}`.
- Merge chỉ reuse structured entity/scenario/action/URL/security flags; case khác rõ ràng bị từ chối.
  Consent không nằm trong summary và luôn lấy từ request của turn hiện tại.
- URL trong case memory bị bỏ user-info, query và fragment; raw message, OTP/password/token không được
  ghi vào conversation/turn. PostgreSQL và SQLite đều có cleanup theo expiry; retention worker gọi
  cleanup PostgreSQL.
- Thêm PostgreSQL migration `0011_security_conversations`; schema SQLite additive tương đương.

**File/symbol đã triển khai:** v4 request/response/conversation models, `SecurityAnalysisService`,
`src/api/security_v4.py`, SQLite/PostgreSQL repositories, `RetentionWorker`,
`migrations/versions/0011_security_conversations.py` và test WP5 tương ứng.

---

## 10. WP6 — Security Chat Frontend

**Status:** `DONE`

Tái sử dụng HTTP client, ticketed WebSocket, cursor replay/polling fallback, progress, history, report,
appeal và auth. Thay semantics/component fact-check bằng composer/chat turns, risk summary, threat
evidence, recommended actions, technical details và follow-up.

UI phải render riêng:

```text
OUT_OF_SCOPE_GENERAL_FACT_CHECK
NEED_MORE_INFO
RUNNING
PROVISIONAL_WARNING
COMPLETED
FAILED
```

Ẩn source registry/general fact-check entry point và screenshot khỏi Security Triage product profile;
chưa xóa component legacy trước cutover. Copy không hướng user sang news/medical/general claims.

Test unit + E2E: multi-turn, owner session, OOS, NEED_MORE_INFO, no consent, realtime reconnect/cursor,
polling fallback, report/appeal và responsive/accessibility states.

### Hoàn thành khi

Main user flow dùng contract security vNext, chat nhiều lượt và không còn claim-stance semantics; các
boundary realtime/auth/report/appeal không regression.

### Đã hoàn thành

- Main workspace và history dùng adapter/type v4 riêng; legacy v3 adapter/component vẫn tách biệt cho
  compatibility/admin flow, không còn claim-stance hoặc general fact-check semantics trên main flow.
- Chat composer hỗ trợ multi-turn `conversation_id`/version, focused follow-up, consent URL và consent
  official-source riêng từng lượt; không còn screenshot consent/panel trong Security Triage profile.
- Render riêng OOS, NEED_MORE_INFO, RUNNING, PROVISIONAL_WARNING, COMPLETED và FAILED; kết luận risk,
  recommended actions, limitations, evidence và technical detail dùng security contract.
- Realtime v4 dùng single-use WebSocket ticket, cursor replay/reconnect và polling fallback; history
  owner-scoped chỉ hiển thị structured security context, không dựng lại raw private conversation.
- Thêm v4 owner-scoped history/report/appeal API và persistence để các control tái sử dụng không gửi
  security analysis ID sang legacy tables; PostgreSQL migration `0012_security_feedback` là additive.
- Cập nhật browser fixture/E2E cho login → provisional → polling fallback → final → history và axe
  accessibility; layout responsive giữ mobile-first breakpoints hiện có.

**File/symbol đã triển khai:** `analysis-workspace.tsx`, security composer/risk/technical components,
v4 generated types/API/event-stream, history/app-shell, report/appeal adapter, v4 feedback/history API,
SQLite/PostgreSQL repositories, `migrations/versions/0012_security_feedback.py` và test WP6 tương ứng.

---

## 11. WP7 — HITL & Security Admin Actions

**Status:** `DONE`

Không viết lại hạ tầng review đã có. Nối runtime producer vào v3/vNext admin action flow và hoàn thiện
ít nhất `ADD_TO_BLACKLIST` trước:

```text
high-risk analysis
→ proposal có target + evidence snapshot
→ admin review approve/reject
→ idempotent execution
→ executed/failed state + immutable audit
→ kết quả blacklist ảnh hưởng analysis sau
```

State machine đã chốt: `PENDING_REVIEW → REJECTED` hoặc approval đi qua trạng thái nội bộ
`APPROVED → EXECUTED/FAILED` trong cùng review/execution transaction. API trả trạng thái cuối; không còn
trả `APPROVED` khi blacklist side effect đã chạy. Memory/dev executor gọi audited SQLite sink trước khi
đánh dấu `EXECUTED`; standalone memory test double có deterministic in-memory blacklist.

Không cho action chạy nếu thiếu approved decision, reviewer/note, evidence snapshot hoặc canonical
target. Test unauthorized access, reject, duplicate decision/execution, transaction rollback và audit.

Sau action tối thiểu, bổ sung whitelist/domain/threat/audit views. `BLOCK_DOMAIN`,
`PUBLISH_BROAD_WARNING` và AI Security Copilot chỉ được đánh dấu done khi có sink/behavior thật; nếu
hoãn phải ghi scope deviation.

### Đã hoàn thành

- V4 `HIGH_RISK`/`MALICIOUS` có URL tạo `ADD_TO_BLACKLIST` proposal idempotent theo
  `security_analysis_id + action + canonical target`; analysis đã có approved-blacklist evidence không
  tạo proposal lặp. Target bắt buộc là domain IDNA/registrable hợp lệ.
- Evidence snapshot chỉ lấy evidence ref đã dùng bởi risk explanation, đổi URL thành origin domain và
  không lưu query/token hoặc raw private conversation.
- Approval `ADD_TO_BLACKLIST` thực thi audited blacklist write rồi trả `EXECUTED`; reject không có side
  effect; duplicate review trả conflict. Sink/transaction lỗi trả `FAILED` với execution code và không
  ghi blacklist một phần.
- PostgreSQL lưu immutable execution status/error trên `review_decisions`, liên kết action với
  `security_analyses` mà không dùng nhầm FK legacy; migration `0013_security_hitl_actions` thêm constraint,
  index idempotency và execution-state invariant.
- Admin API có action audit view; UI hiển thị security-analysis link, canonical domain, threat evidence,
  execution failure, immutable audit trail và brand/whitelist trust views. Tất cả vẫn yêu cầu
  security-admin role.

**Scope deviation:** `BLOCK_DOMAIN`, `PUBLISH_BROAD_WARNING` và AI Security Copilot chưa có external
sink/behavior thật. Approval các action này kết thúc `FAILED/ACTION_SINK_NOT_CONFIGURED`; chúng không
được tuyên bố đã triển khai. `DISABLE_BLACKLIST` có PostgreSQL executor cũ nhưng chưa được đưa vào v4
runtime producer nên không tính là deliverable WP7.

**File/symbol đã triển khai:** `propose_security_admin_actions`, `propose_admin_action`,
`decide_admin_action`, `AdminActionRecordV3`, `AdminActionAuditRecordV3`, PostgreSQL/memory repositories,
`migrations/versions/0013_security_hitl_actions.py`, v4 runtime producer, v3 audit API và admin UI.

---

## 12. WP8 — Security Memory & Campaign

**Status:** `DONE`

Security memory lưu structured intelligence có provenance: canonical domain/URL fingerprint, brand,
threat type, risk/policy version, first/last seen, report count, admin verdict và evidence refs. Không
lưu raw private conversation.

Thay claim embeddings bằng security fingerprint giải thích được, ví dụ:

- registrable domain và redirect target;
- claimed brand;
- scenario/requested action;
- contact/payment pattern;
- credential/OTP pattern;
- URL lexical features và time window.

Campaign vẫn chỉ là hypothesis cần reviewer; LLM có thể tóm tắt nhưng không tự xác nhận malicious hoặc
publish warning.

Test repeated domain, shared redirect, same brand/different domain, similar recruitment/payment
pattern, unrelated cases không cluster, time window, admin correction và provenance/version.

### Hoàn thành khi

Security path không phụ thuộc claim embeddings để cluster; cluster giải thích được bằng security
signals; admin verdict/correction phản ánh trong memory mà không xóa audit history.

**File/symbol thuộc phạm vi:** `src/agents/campaign.py`, campaign contracts/store, PostgreSQL/SQLite
schema và admin campaign views.

### Đã triển khai

- Security v4 terminal producer tạo `SecurityMemoryRecordV4` idempotent từ context/risk/evidence đã
  chuẩn hóa. Record chỉ giữ domain, URL hash đã bỏ query, redirect domain, claimed brand, scenario,
  requested action, credential/OTP/payment flags và lexical feature; không giữ message, query token
  hoặc raw conversation.
- `security-fingerprint-v1` và `security-clustering-v1` cluster theo named signal. Security path không
  gọi claim encoder/embedding; repeated domain, shared redirect, brand và scenario/action pattern đều
  có aggregate signal giải thích được. SAFE/LOW_RISK/INSUFFICIENT_EVIDENCE và admin verdict
  SAFE/FALSE_POSITIVE không tham gia hypothesis mới.
- Campaign luôn bắt đầu ở `pending_review`. Confirm/reject yêu cầu Security Admin và reviewer note;
  campaign audit giữ snapshot version/evidence. Không có broad-warning side effect trong WP8.
- Memory correction cho phép reviewer cập nhật verdict nhiều lần; mỗi correction append audit chứa
  previous/current verdict, reviewer, note, policy/fingerprint version và evidence refs. Lịch sử cũ
  không bị ghi đè. Report v4 tăng `report_count` theo transaction.
- SQLite và PostgreSQL có schema/store riêng cho security memory, campaign members và immutable audit;
  migration head là `0014_security_memory_campaigns`. API admin v4 cung cấp memory list/correction và
  campaign list/detail/decision/audit,
  frontend hiển thị memory provenance, named cluster signals và review controls.
- Legacy `campaign_claim_features` chỉ còn phục vụ compatibility path trước cutover; Security v4 producer
  và clustering hoàn toàn không đọc bảng/vector này. Việc xóa legacy path thuộc WP9.

**File/symbol đã triển khai:** `SecurityCampaignConfig`, `build_security_memory_record`,
`cluster_security_memory`, `SecurityMemoryService`, security memory/campaign v4 contracts và admin API,
PostgreSQL/SQLite repositories, `migrations/versions/0014_security_memory_campaigns.py`, admin platform UI.

---

## 13. WP9 — Cutover, Evaluation & Cleanup

**Status:** `IN_PROGRESS`

### WP9A — API readiness và contract freeze — `DONE`

Hoàn tất additive API surface để đợt thay frontend không phải phụ thuộc vào legacy fact-check contract:

- `GET /api/v4/capabilities` công bố đúng release profile `pre_cutover`, action contract v3 đang tái sử
  dụng, sink thật và các action/Copilot còn deferred;
- thêm owner-scoped paginated analysis history và conversation listing, giữ nguyên list response cũ để
  không phá frontend hiện tại;
- thêm paginated/filter/search contracts cho brand, whitelist, Security Memory và campaign;
- thêm admin report/appeal queue và atomic terminal decision với RBAC, conflict protection, reviewer/note;
- thêm domain/threat intelligence explorer và unified v4 audit cho trust, memory, campaign, report/appeal;
- PostgreSQL/SQLite persistence và revision `0015_security_api_readiness`; contract/OpenAPI, owner/RBAC,
  lifecycle, audit và SQLite reopen đều có automated test.

`/api/v3/admin/actions` tiếp tục là reviewed-action execution contract trong compatibility window; WP9A
không giả lập v4 sink cho `BLOCK_DOMAIN`, `PUBLISH_BROAD_WARNING` hoặc Copilot. Các API cũ không đổi kiểu
response, không có destructive migration và không sửa frontend.

### Frontend investigation workspace — `DONE`

Frontend dùng typed v4 client cho chat-to-case workspace, history/resume, evidence/timeline, Observatory,
Review Room, Trust và Audit. Reviewed-action cùng metrics/source discovery v3 được cô lập trong compatibility
surface. Responsive, accessibility, polling/WebSocket fallback, production build và Chromium E2E đã qua.

### Evaluation/release gate

Versioned dataset tối thiểu: phishing, credential/OTP, financial, recruitment, promotion/prize, brand
impersonation, safe official, mismatch-only, new-domain-only, provider timeout/no-hit, OOS,
NEED_MORE_INFO, multi-turn, no-consent và wide action.

Đo scope/tool-routing accuracy, unnecessary-provider-call rate, precision/recall, false-positive/
false-negative, malicious precision, high-risk recall, latency/cost và grounded explanation quality.

Security/reliability gate: SSRF, redirect revalidation, Unicode/homograph, prompt injection, ownership,
RBAC, rate limit, provider failure, lease loss, idempotency, PostgreSQL/Redis readiness, backup/restore
và hosted provider smoke nếu có môi trường.

Không được tuyên bố “đạt full scope” nếu DNS, multi-turn, whitelist, HITL execution, Security Memory
hoặc AI Security Copilot bị hoãn; phải ghi rõ scope deviation/release profile.

### Cutover và cleanup

1. Chuyển frontend/worker sang security route mặc định.
2. Freeze legacy API writers, fact-check/source-discovery jobs và provider calls.
3. Đo legacy API/provider/DB read/write usage trong compatibility window.
4. Backup/export dữ liệu cần retention và verify restore.
5. Xóa application code/route legacy không còn consumer.
6. Chạy destructive Alembic revision riêng; verify upgrade từ DB trống và DB `0008`.

Candidate cleanup sau khi đủ gate:

```text
FactCheckOrchestrator, Google Fact Check, Tavily general fact-check, claim comparator
/api/v2/chat và các analysis write route/contract legacy ở cả /api/v2, /api/v3
fact_check_sources, fact_check_records, fact_check_embeddings
fact_check_results, fact_check_result_embeddings
fact_check_evidence_snapshots, fact_check_chunks
source_discoveries, source_discovery_observations, source_discovery_decisions
campaign_claim_features
```

Chỉ drop pgvector khi không còn consumer. Không dùng `git` hoặc destructive migration như một phần
tự động của việc “đánh dấu WP done”; operator thực hiện theo runbook/approval riêng.

---

## 14. Progress

Chỉ cập nhật bảng này và ghi test/deviation ngắn gọn; không lặp một block “Chưa có” trong từng WP.

| WP | Status | Evidence/Tests | Còn lại hoặc deviation |
|---|---|---|---|
| WP0 | DONE | Backend 203 pass/1 skip; Ruff pass; frontend 30 pass + lint/typecheck pass | Không có; hosted/PostgreSQL/Redis/E2E vẫn là release evidence WP9 |
| WP1 | DONE | 22 test v4 mới; full backend 225 pass/1 skip; Ruff + frontend regression pass | Không có; planner/persistence/risk tiếp tục ở WP2/WP3 |
| WP2 | DONE | 12 test WP2 mới; targeted 42 pass; full backend 237 pass/1 skip; Ruff + frontend 30 test/lint/typecheck pass | Không có; DNS dùng safe resolver và privacy-minimized counts; risk/persistence cấp analysis tiếp tục ở WP3 |
| WP3 | DONE | 12 test risk/lifecycle mới; full backend 249 pass/1 skip; Ruff pass | Không có; hosted PostgreSQL/Redis/WebSocket smoke vẫn là release evidence WP9 |
| WP4 | DONE | 17 test trust/admin mới; full backend 266 pass/1 skip; Ruff pass | Không có; hosted official-verifier/PostgreSQL/Redis smoke vẫn là release evidence WP9 |
| WP5 | DONE | 6 test conversation mới; full backend 272 pass/1 skip; Ruff pass | Không có; hosted PostgreSQL/retention-worker smoke vẫn là release evidence WP9 |
| WP6 | DONE | Frontend 37 test/9 files + lint/typecheck; Chromium E2E 2 pass (gồm axe user flow); webpack production build pass; backend 273 pass/1 skip + Ruff | Default Turbopack build không chạy trong sandbox vì internal process không được bind port; webpack build đã verify production output |
| WP7 | DONE | 6 test WP7 mới; full backend 279 pass/1 skip; Ruff; frontend 37 test/lint/typecheck + webpack production build pass | Scope deviation: BLOCK_DOMAIN, PUBLISH_BROAD_WARNING, Copilot chưa có sink; DISABLE_BLACKLIST chưa có v4 producer |
| WP8 | DONE | 9 test WP8 mới; full backend 288 pass/1 skip; Ruff; frontend 37 test/lint/typecheck + webpack production build pass; Alembic 0014 head | Không có; legacy claim-vector compatibility path được giữ đến cleanup WP9 nhưng Security v4 không phụ thuộc embeddings |
| WP9 | IN_PROGRESS | API/frontend readiness; `scope_decision` filter; hardened production env; versioned 16-category offline evaluation + 5 reviewed-memory risk-v2 gate; AI roadmap WP0–WP7; durable Security v4 revision 0016; Admin Copilot revision 0017; v4 live-smoke; legacy freeze/cutover guard; compatibility checker và release runbook. Active suite: backend 217 pass; frontend 59 pass/12 files; Ruff/lint/typecheck/build pass; Alembic 0017 head | Chưa có hosted OIDC/PostgreSQL/Redis/provider/load, durable lease-loss, reviewed-memory hoặc Admin Copilot rollout evidence, restore rehearsal, API/provider/job/DB zero-usage window hay legacy cleanup; async, memory và admin-copilot flags mặc định tắt nên profile đúng là `pre_cutover` |

Trạng thái hợp lệ: `NOT_STARTED`, `IN_PROGRESS`, `BLOCKED`, `DONE`.

Khi cập nhật:

- ghi command/test và kết quả thực tế, không ghi “pass” nếu chỉ suy ra từ code;
- ghi file/symbol đã thay đổi ở WP tương ứng nếu khác danh sách gợi ý;
- ghi scope/plan deviation và lý do;
- không ghi lịch sử commit/PR/merge;
- không coi tên model/table ví dụ trong tài liệu là symbol đã tồn tại trước khi search repository.

### Ưu tiên khi thời gian hạn chế

Milestone dùng được tối thiểu: WP0 → WP1 → WP2 → WP3 → phần cốt lõi WP4 → UI cơ bản WP6 →
`ADD_TO_BLACKLIST` của WP7. WP5, DNS, Copilot hoặc advanced campaign nếu hoãn vẫn phải được ghi là
scope deviation; một bản single-turn ổn định có thể là release profile giới hạn, nhưng không phải hoàn
thành toàn bộ `scope.md`.
