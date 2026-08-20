# Official Source and Third-party Link Verification

**Status:** Proposed implementation plan  
**Target runtime:** Security Triage `/api/v4`  
**Delivery model:** Sequential work packages with mandatory checkpoints

Tài liệu này mô tả phần mở rộng xác minh nguồn chính thức và liên kết bên thứ ba cho TrustGuard AI.
Đây không phải trạng thái đã triển khai. `PRODUCT_ARCHITECTURE.md`, `CURRENT_STATUS.md`, `DEPLOYMENT.md`
và `TESTING.md` vẫn là tài liệu canonical cho runtime hiện tại.

## 1. Mục tiêu và ranh giới

Pipeline mới trả lời bốn câu hỏi độc lập:

1. Publisher có đúng là tổ chức được nhắc tới không?
2. Claim hoặc thông báo có xuất hiện trên nguồn chính thức không?
3. URL hành động của người dùng có trỏ tới đúng resource được nguồn chính thức liên kết không?
4. Các bằng chứng trên ảnh hưởng thế nào tới security risk hiện tại?

Tính năng chỉ chạy trong Security Triage v4. Không khôi phục general fact-check, public v2/v3, corpus,
embedding, reranker, vector database, browser automation hoặc cơ chế tự động promote nguồn.

Các invariant bắt buộc:

- Out-of-scope kết thúc trước mọi AI, provider hoặc network call.
- Incident/exposure đang diễn ra ưu tiên recovery và bỏ qua online verification.
- Mọi external operation cần consent của request hiện tại; consent không kế thừa qua conversation.
- AI không đặt risk, score, consent, URL fetch target, official identity hoặc admin decision.
- Provider no-hit, error, timeout và thiếu consent không tạo `SAFE` hoặc scam signal.
- Không persist raw private message, credential, OTP, token, raw HTML hoặc URL query không cần thiết.
- User read luôn owner-scoped; admin operation yêu cầu `security_admin` và immutable audit.

## 2. Quyết định kiến trúc đã chốt

### 2.1 Scope và applicability

Một turn được đưa vào Security Triage khi có ít nhất một trong các điều kiện sau:

- người dùng yêu cầu kiểm tra an toàn/lừa đảo/giả mạo;
- có URL cần kiểm tra;
- có yêu cầu đăng nhập, chia sẻ OTP/credential/thông tin cá nhân, thanh toán hoặc chuyển tiền;
- có yêu cầu mở link, quét QR, chia sẻ màn hình, cài ứng dụng, tải tệp, điền form hoặc đăng ký/ứng tuyển
  kèm security concern, impersonation, urgency hoặc dấu hiệu hành động nhạy cảm.

Chỉ nhắc tới tuyển dụng, khóa học, sự kiện, khảo sát, form hoặc khuyến mãi không đủ để vào scope. Rule
không được coi mọi recruitment/promotion keyword là security signal độc lập.

URL trần vẫn đi qua URL-safety triage. Nếu không xác định được organization, claim hoặc action để đối
chiếu, `official_verification` là `None` với applicability reason nội bộ; không ép thành `UNVERIFIED`.

### 2.2 Verification status

Mỗi component có `applicable: bool`, `status` và `reason_code`. Khi `applicable=false`, `status=None`.
Status chỉ nhận:

- `VERIFIED`
- `PARTIALLY_VERIFIED`
- `UNVERIFIED`
- `CONFLICTING`

`NOT_APPLICABLE` không được biểu diễn bằng `UNVERIFIED`. `resource_verification` không áp dụng khi không
có user/action URL. Toàn bộ report là `None` khi official verification không áp dụng hoặc rollout chưa
expose report.

### 2.3 Deadline, request budget và cost

Một `TurnExecutionContext` request-scoped được dùng chung bởi understanding, planning, investigation,
verification, risk preparation và synthesis:

- end-to-end deadline: tối đa 30 giây;
- AI call budget: tối đa 4 provider attempts, retry cũng tính một attempt;
- external network budget khi verification bật: tối đa 16 network units;
- một direct HTTP request hoặc redirect hop là một network unit;
- một search/extract provider API request là một network unit; request nội bộ do provider thực hiện không
  thể quan sát được phải được ghi rõ trong limitation/telemetry;
- estimated total provider cost: tối đa US$0.05 mỗi analysis.

Stage deadline chỉ là phần còn lại của end-to-end deadline, không phải các deadline 30 giây độc lập. Khi
budget hoặc deadline hết, inline trả bounded partial result. Inline không tự chuyển thành async sau khi đã
bắt đầu side effect/network call. Async chỉ được nhận trước khi xử lý, theo request contract, idempotency key
và capability hiện có.

### 2.4 URL representation

Không dùng cùng một chuỗi cho fetch và matching:

- `fetch_url`: URL đã validate nhưng giữ nguyên path/query order và tham số mang nghĩa để gọi mạng;
- `display_url`: URL đã bỏ credential, fragment và sensitive/tracking query; chỉ hiển thị plain text;
- `canonical_url`: biểu diễn ổn định để dedupe;
- `match_key`: biểu diễn versioned dùng để so resource identity.

Việc sort query hoặc bỏ tracking key chỉ áp dụng cho canonical/match representation. Không rewrite
`fetch_url`, đặc biệt với signed URL hoặc duplicate query parameter.

### 2.5 Official identity

Nguồn chỉ được coi là official khi thỏa một trong các điều kiện:

- exact identity nằm trong Brand Registry đã review và còn hiệu lực;
- exact entity-bound entry nằm trong Source Registry đã review, có source type phù hợp;
- social/sub-organization identity được cross-link trực tiếp từ official page đã chấp nhận trong cùng
  analysis.

Wildcard rộng như `*.gov.vn`, source tier, search rank, snippet, generic social domain, self-claim hoặc nhiều
bài báo giống nhau không chứng minh identity của một tổ chức cụ thể. Chúng chỉ tạo corroboration và không
đưa component vượt quá `PARTIALLY_VERIFIED`.

Identity phát hiện online chỉ tồn tại trong report hiện tại. Không tự động ghi Brand Registry, whitelist hoặc
Source Registry.

### 2.6 Persistence và audit

- Bounded verification report được lưu trong analysis response JSON.
- Official identity descriptors được lưu trong Brand record JSON; PostgreSQL columns hiện có vẫn được duy
  trì để tương thích.
- `security_tool_executions` tiếp tục chỉ làm execution/idempotency ledger với target hash, status và attempt.
- Latency, request units, cost và error code đi qua redacted telemetry/usage records. Nếu cần query bền vững
  trực tiếp trên các trường này, phải tạo migration riêng; không tuyên bố “không cần migration”.
- Admin không sửa identity tại chỗ. Thay đổi tạo Brand version mới, liên kết `supersedes`, rồi disable version
  cũ trong cùng transaction/audit boundary.

### 2.7 Provider và rollout

Transport mới dùng interface provider-neutral `WebSearchProvider.search_one()` và
`WebExtractProvider.extract()`. Tavily là adapter ban đầu, không phải contract của coordinator. Pipeline mới
không gọi `FactCheckOrchestrator`, corpus, embedding, reranker hoặc source promotion.

Rollout dùng một flag mới:

```text
SECURITY_OFFICIAL_VERIFICATION_MODE=off|shadow|visible|enforced
```

- `off`: giữ nguyên Security v4 hiện tại; không có “old official verifier”.
- `shadow`: chạy coordinator nhưng không gắn report vào public/persisted analysis response và không đổi risk;
  chỉ phát redacted aggregate telemetry.
- `visible`: expose report/UI; risk vẫn dùng v1/v2.
- `enforced`: expose report/UI; deterministic risk v3 được phép dùng verified evidence.

`visible`/`enforced` không bắt buộc Tavily nếu exact reviewed identity và direct verification đủ dùng.
Capabilities phải phản ánh riêng `official_link_verification` và `official_web_search_ready`. Thiếu search
provider làm kết quả partial/unverified, không làm application fail startup. OpenAI cũng không phải điều kiện
bắt buộc của risk v3; semantic comparison có deterministic fallback và không được tự nâng lên `VERIFIED`.

## 3. Target flow

```text
request/version validation
  -> deterministic scope gate
  -> OOS/need-info terminal, hoặc shared SecurityTriagePipeline
  -> semantic understanding
  -> recovery-first short circuit nếu incident/exposure
  -> investigation (local + consented external tools)
  -> trust enrichment
  -> official-link verification coordinator
  -> deterministic fusion
  -> deterministic risk v1/v2/v3 theo rollout
  -> grounded response
  -> persistence/events/optional HITL-memory
```

## 4. Work package rules

- Chỉ bắt đầu work package tiếp theo khi checkpoint trước đã merge và toàn bộ gate xanh.
- Mỗi package giữ thay đổi trong phạm vi file đã nêu; thay đổi contract ngoài phạm vi phải quay lại review.
- Không sửa eval set `security-v4-v1`; tạo dataset version mới.
- Không ghi test count vào tài liệu. Handoff ghi commit SHA, command, environment và link/log evidence.
- Không khôi phục file đang bị xóa hoặc revert thay đổi không thuộc package.
- Migration mới phải có backup/restore và staging rehearsal plan; không downgrade migration `0018`.

Mẫu handoff bắt buộc cho mọi checkpoint:

```text
WP/Checkpoint:
Commit SHA:
Contract/schema changes:
Migration/head:
Commands run and result:
Known limitations:
Next WP entry conditions satisfied: yes/no
```

Ownership được chốt theo vai trò để không phụ thuộc tên hoặc lịch làm việc của một cá nhân:

| Package | Primary owner role | Required reviewer role |
|---|---|---|
| WP0 | Tech lead | Security lead |
| WP1 | Backend/platform | Backend reviewer |
| WP2 | API contract/backend | Frontend contract reviewer |
| WP3 | Security scope/AI | Security policy reviewer |
| WP4 | Trust registry/backend | Security admin reviewer |
| WP5 | Network security/backend | SSRF/security reviewer |
| WP6 | Verification backend | Network security reviewer |
| WP7 | Orchestration/backend | Risk policy reviewer |
| WP8 | Risk/platform | Security lead |
| WP9 | Frontend | Backend contract reviewer |
| WP10 | QA/DevOps | Tech lead and security lead |

Mỗi package chỉ có một primary owner tại một thời điểm. Reviewer không tự approve package do chính mình
thực hiện. Tên thành viên và link issue/PR được điền trong handoff của package, không hard-code vào plan.

## 5. Sequential work packages

### WP0 - Baseline và contract freeze

**Mục tiêu:** Chốt behavior trước khi thay code và tạo baseline có thể so sánh.

**Công việc:**

- Xác nhận scope/applicability, consent matrix, component status và rollout semantics trong tài liệu này.
- Ghi OpenAPI baseline, capability response và representative v4 JSON fixtures.
- Chạy backend/frontend baseline; phân loại failure có sẵn, không sửa ngoài phạm vi.
- Chốt ownership từng WP và quy tắc handoff.

**Checkpoint CP0:**

- Không còn decision mở ảnh hưởng schema hoặc migration.
- Có baseline evidence cho `uv run pytest -q`, `uv run ruff check .`, `uv run alembic heads`, frontend test,
  lint, typecheck và `check:cutover`.
- Working tree changes của từng thành viên được ghi nhận để tránh overwrite.

### WP1 - Shared orchestration và end-to-end execution context

**Mục tiêu:** Loại bỏ khác biệt inline/worker trước khi thêm coordinator.

**Công việc:**

- Chuyển inline `/api/v4/analyses` sang cùng `SecurityTriagePipeline` mà durable worker đang dùng.
- Tạo request-scoped `TurnExecutionContext` chứa monotonic deadline, AI attempts, network units và estimated
  cost; chưa bật verification behavior.
- Giữ nguyên scope, evidence, risk, events, persistence, memory/HITL side effects và error normalization.
- Bảo đảm OOS kết thúc trước pipeline stages có provider.

**Checkpoint CP1:**

- Inline/async parity tests pass với cùng fixtures.
- OOS AI/provider/network calls bằng 0.
- Retry/idempotency/event ordering không regression.
- Public OpenAPI và risk output chưa thay đổi.

### WP2 - Additive contracts và backward compatibility

**Mục tiêu:** Thêm contract mới nhưng vẫn đọc được analysis/brand v4 cũ.

**Công việc:**

- Thêm `SUBMIT_FORM`, `REGISTER_OR_APPLY`, `DOWNLOAD_FILE` vào `RequestedActionV4` theo lower-snake value.
- Thêm versioned `VerificationIntentV4`, `VerificationTopicV4`, `LinkRoleV4`, identity/resource/report models,
  component applicability và verification status.
- Cho `SecurityContextV4` đọc `security-context-v1`, phát mới `security-context-v2`; field mới optional/defaulted.
- Cho understanding contract đọc v1, phát mới v2 với source spans và derived-query provenance.
- Thêm `official_verification: OfficialLinkVerificationReportV4 | None` vào response.
- Thêm `official_source_lookup: bool = false` vào consent; giữ `external_url_lookup`.
- Mở policy version để đọc risk v1/v2 và phát risk v3 khi enforced.
- Thêm optional capabilities fields; không expose khi mode `off`.

**Checkpoint CP2:**

- OpenAPI contract tests pass.
- Old/new SQLite và PostgreSQL JSON round-trip tests pass.
- Persisted v1 context/risk/brand fixtures vẫn parse được.
- `official_verification` không xuất hiện trong response khi `None`.
- Alembic vẫn một head; migration decision được ghi rõ.

### WP3 - Scope, semantic intent và safe query builder

**Mục tiêu:** Chỉ tạo verification work từ grounded security intent.

**Công việc:**

- Sửa scope để recruitment/promotion/form/event/course context đơn lẻ không tự động in-scope.
- Nhận diện các action mới bằng rule và grounded semantic output.
- Bare URL vẫn in-scope cho URL safety nhưng official verification không applicable nếu thiếu entity/claim/action.
- Incident/exposure tiếp tục short-circuit trước online verification.
- Mọi accepted entity/claim/action có confidence và source span hợp lệ.
- Tách user-grounded organization khỏi English name/alias được suy ra; derived value có provenance và không
  được coi là source span.
- Query builder deterministic tạo tối đa 6 variants, thực thi tối đa 4 attempts tuần tự.
- Trước provider: bỏ URL, email, OTP, password/token-like value; giới hạn 300 ký tự; dedupe; không gửi toàn
  bộ raw message.

**Checkpoint CP3:**

- Unit/property tests pass cho tiếng Việt, không dấu, slang, ambiguity và query redaction.
- OOS external/AI calls bằng 0 cho các category được deterministic gate xác định.
- Không query nào chứa fixture secret, email, OTP hoặc URL.
- AI output không thể tạo URL hoặc network target.

### WP4 - Versioned official identity registry

**Mục tiêu:** Tạo nguồn sự thật reviewed cho organization identity.

**Công việc:**

- Mở rộng Brand record bằng `official_identities` gồm type, canonical value, match scope, relationship,
  provenance, policy version, effective interval và optional `supersedes`.
- Runtime chuyển `official_domains` cũ thành `PRIMARY_WEBSITE` identities.
- Cho `official_domains=[]` chỉ khi có ít nhất một valid official identity.
- Resolution order: exact canonical name -> exact alias -> bounded phrase match.
- Nhiều brand cùng match tạo ambiguous result và không tạo implicit allowlist.
- Source Registry chỉ xác nhận identity với exact entity-bound reviewed entry; wildcard/tier rộng chỉ
  corroborate.
- Admin API tạo version mới/supersede/disable; không update record tại chỗ.

**Checkpoint CP4:**

- Tests pass cho exact alias, accent folding, ambiguous brand, social, careers và sub-organization identity.
- Old Brand records vẫn đọc được và có runtime primary identity tương đương.
- Mọi admin mutation yêu cầu `security_admin` và có immutable audit event.
- Không có online-discovered identity nào được auto-persist/promote.

### WP5 - Provider-neutral search, guarded fetch và shared network budget

**Mục tiêu:** Tạo online transport độc lập với legacy fact-check path.

**Công việc:**

- Định nghĩa `WebSearchProvider.search_one()` và `WebExtractProvider.extract()` với normalized envelopes.
- Bọc Tavily hiện có bằng adapters mới; không gọi `FactCheckOrchestrator`.
- Thêm `GuardedHtmlFetcher` trên `GuardedHttpClient`; chỉ chấp nhận HTML/XHTML, tối đa 1 MB và 5 redirects.
- Enforce shared `TurnExecutionContext` ở mọi provider request và từng direct redirect hop.
- Revalidate DNS/SSRF sau mỗi redirect, giữ DNS pinning, port policy, timeout và bounded response.
- Provider search/extract failure trả normalized limitation; không sinh citation thay thế.

**Checkpoint CP5:**

- Network tests pass cho private IP, metadata, DNS rebinding, private redirect, redirect loop, invalid port,
  timeout, 429, oversized và non-HTML response.
- Budget test chứng minh request thứ 17 không được gửi.
- `tool_calls_used`/telemetry phân biệt adapter attempt và actual network units.
- Tavily không cấu hình vẫn cho phép local/exact-registry verification path chạy bounded.

### WP6 - HTML extraction, URL normalization và resource identity

**Mục tiêu:** Trích official outbound links và so đúng resource, không suy từ domain.

**Công việc:**

- Thêm `beautifulsoup4>=4.12,<5`, dùng `html.parser`; không thêm browser runtime.
- Parse `<a href>` deterministic với first valid `<base>`, relative và protocol-relative URL.
- Bỏ `javascript:`, `data:`, `mailto:` và URL chứa credentials.
- Lưu bounded link ref, source page ref, display URL, anchor tối đa 200 ký tự, context tối đa 500 ký tự,
  canonical URL, extraction method, evidence strength và content hash; không lưu raw HTML.
- Sau redirect, phân loại lại final page identity trước khi tin nội dung.
- Direct fetch failure/anti-bot chỉ cho provider fallback khi URL xuất hiện rõ trong extract; cap result ở
  `PARTIALLY_VERIFIED`.
- Tạo versioned `ResourceIdentity` và match result `EXACT_RESOURCE`, `EXACT_CANONICAL_URL`,
  `DIFFERENT_RESOURCE`, `UNRESOLVED`.
- Hỗ trợ Google Forms và Microsoft Forms theo provider ID; Bitly chỉ là redirect hop; provider khác chỉ
  exact canonical URL. Cùng domain không đủ để match resource.

**Checkpoint CP6:**

- Property tests pass cho malformed HTML, `<base>`, relative link, percent encoding, duplicate query,
  tracking keys và signed URL không bị rewrite khi fetch.
- Resource fixtures pass cho LinkedIn -> Bitly -> forms.gle -> Google Forms và Microsoft Forms aliases.
- Different form luôn tạo conflict/unresolved đúng policy, không match theo domain.
- Không có raw HTML, credentials hoặc sensitive query trong persisted report/log.

### WP7 - Verification coordinator và deterministic fusion

**Mục tiêu:** Tạo report grounded sau trust enrichment và trước risk.

**Công việc:**

- Thêm `OfficialLinkVerificationCoordinator` vào shared pipeline.
- Policy `official-link-verification-v1`: tối đa 4 search attempts, 5 results/attempt, 8 deduped candidates,
  fetch 3 official candidates với concurrency 2 và resolve 3 outbound action links.
- Early stop khi đủ publisher + claim + exact resource hoặc có strong official contradiction.
- Consent matrix:
  - local Brand/Source Registry lookup không cần external consent;
  - search/extract/fetch official page cần `official_source_lookup`;
  - user URL và third-party redirects cần `external_url_lookup`;
  - thiếu consent chỉ skip operation tương ứng và ghi limitation.
- Optional comparison AI chỉ nhận numbered source/link IDs như untrusted data và chỉ trả ID, relation,
  matched dimensions, link role. Validator loại unknown ID/URL.
- Fusion deterministic:
  - publisher verified chỉ từ reviewed exact identity hoặc accepted official cross-link;
  - claim verified khi publisher verified và organization/topic/action khớp, cùng time/audience nếu claim có;
  - resource verified khi official page chứa action-relevant link và user/official chains có cùng resource ID;
  - thiếu dimension, external corroboration, provider fallback hoặc incomplete chain tạo partial;
  - strong official contradiction, official disagreement sau freshness resolution hoặc different resource tạo
    conflicting;
  - no-hit, error, timeout, thiếu consent hoặc thiếu evidence tạo unverified, không tạo scam signal.

**Checkpoint CP7:**

- Evidence-reference closure đạt 100%; fabricated source/link/URL ID bằng 0.
- Tests cover cả bốn statuses và non-applicable components.
- No-hit/error/timeout không thay risk trong `shadow`/`visible`.
- Coordinator không chạy trong recovery-first incident path.

### WP8 - Risk v3, rollout và observability

**Mục tiêu:** Chỉ cho verification ảnh hưởng risk sau khi visible behavior ổn định.

**Công việc:**

- Thêm deterministic `security-risk-v3` chỉ dùng khi mode `enforced`.
- `VERIFIED` chỉ suppress weak mismatch/lookalike-style contributions có cùng target/evidence provenance.
- Không suppress credential, OTP, payment, personal-data, malicious reputation, blacklist, incident recovery
  hoặc strong indicators.
- `CONFLICTING` thêm tối đa 25 điểm nhưng một mình không tạo `MALICIOUS`.
- `UNVERIFIED`, no-hit và not-applicable thêm 0 điểm.
- `SAFE` yêu cầu complete applicable verification, không có sensitive-action risk, tool error hoặc residual
  strong indicator.
- Implement `off|shadow|visible|enforced`, capabilities và startup validation theo mục 2.7.
- Log/metrics chỉ chứa analysis ID, stage, provider, operation, counts, latency, cost, status, strength,
  target hash và error code; không chứa raw query/message/URL/context.

**Checkpoint CP8:**

- Risk regression chứng minh verified không che malicious reputation hoặc sensitive action.
- Conflicting-only và not-found không tạo malicious.
- `off`, `shadow`, `visible` giữ risk v1/v2 byte-compatible trên fixtures.
- `enforced` fallback an toàn khi search/AI provider không sẵn sàng.
- Rollback `enforced -> visible -> off` không cần database downgrade.

### WP9 - Frontend và admin trust workflow

**Mục tiêu:** Expose report rõ ràng mà không biến URL đáng ngờ thành link có thể click.

**Công việc:**

- Cập nhật generated v4 types sau khi CP8 contract ổn định.
- Simple view hiển thị overall conclusion và safe next actions.
- Analyst view hiển thị publisher, claim, resource, identity, source refs, outbound refs, redirect/canonical
  chain, strength và limitations.
- Signal graph chỉ nối risk với evidence refs thực sự được risk policy sử dụng.
- Suspicious/user URL luôn plain text và copy-safe, không auto-link.
- Admin trust UI tạo identity version mới/supersede; không có in-place edit không audit.
- Giữ layout hiện tại, responsive constraints và accessibility behavior của workspace.

**Checkpoint CP9:**

- Frontend unit tests pass cho simple/analyst, limitations, all statuses và non-applicable state.
- E2E pass cho user analysis, admin versioning và rollback capability visibility.
- Không có suspicious URL nào render thành clickable anchor.
- `npm test`, `npm run lint`, `npm run typecheck`, `npm run check:cutover`, `npm run build` và
  `npm run test:e2e` pass.

### WP10 - Evaluation, hosted verification và release

**Mục tiêu:** Chứng minh safety, quality, latency, cost và rollback trước khi enforced.

**Công việc:**

- Tạo immutable dataset `security-v4-v2`; không sửa `security-v4-v1`.
- Bắt buộc hard case: Vietnamese input -> English derived query -> official social announcement -> short URL
  -> third-party form, chạy bằng offline fakes và hosted smoke.
- Contract/integration tests cho consent matrix, OpenAPI, persistence, async/inline parity, retries,
  idempotency, events, owner/RBAC và capabilities.
- Chạy PostgreSQL/Redis/worker, OIDC/RBAC, backup/restore, SSRF, prompt injection, provider failure, load và
  rollback rehearsal theo canonical deployment/testing docs.
- Rollout tuần tự `shadow -> visible -> enforced`; mỗi stage có observation window và rollback evidence.

**Checkpoint CP10 / release gate:**

- OOS provider/network/AI calls = 0.
- Fabricated URL/evidence ref = 0; evidence-reference closure = 100%.
- Labeled resource-match precision = 100% trên release dataset.
- Not-found -> malicious = 0; SSRF bypass = 0.
- Scope accuracy >=95%; component-status accuracy >=90%; grounded explanations = 100%.
- Tổng estimated provider cost <= US$0.05/analysis.
- End-to-end p95 <=30 giây; budget exhaustion trả bounded partial result.
- Backend: `uv run ruff check .`, `uv run pytest -q`, `uv run alembic heads` pass.
- Frontend: toàn bộ commands trong `docs/TESTING.md` pass.
- Hosted smoke, backup/restore, load/failure và rollback evidence đã được review.

## 6. Dependency map

```text
CP0 baseline
  -> CP1 shared pipeline/execution context
  -> CP2 contracts
  -> CP3 scope/query intent
  -> CP4 identity registry
  -> CP5 provider/fetch/network budget
  -> CP6 extraction/resource identity
  -> CP7 coordinator/fusion
  -> CP8 risk/rollout/telemetry
  -> CP9 frontend/admin UI
  -> CP10 evaluation/release
```

Không thực hiện song song các package thay đổi cùng public contract hoặc pipeline. Sau CP2, test fixture và
frontend type preparation có thể được nghiên cứu riêng, nhưng chỉ merge theo thứ tự checkpoint ở trên.
