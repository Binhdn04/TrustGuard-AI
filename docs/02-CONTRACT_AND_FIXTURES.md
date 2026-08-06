# Contract and Fixtures — P-068

**Document revision:** `v2.0` (wire field `contract_version: "v2"`, API path `/api/v2`)
**Freeze date:** 2026-08-06

> Đây là nguồn sự thật duy nhất cho API schema, AgentState, enum, tool interface, fixture và safety invariant.

## 1. Quy ước và enum

- JSON `snake_case`; timestamp UTC ISO 8601; ID là UUID do backend sinh.
- Field kết quả chưa có khi analysis đang chạy dùng `null`/omitted theo schema; string có mặt không
  được rỗng. Dữ liệu RDAP không có dùng `null`, không dùng chuỗi rỗng hoặc giá trị suy đoán.
- Risk score là integer `[0,100]`. `domain_registration` là một giá trị bắt buộc của enum v2;
  mọi consumer/UI của dự án phải dùng contract `/api/v2` và validate enum này trước khi server
  phát domain-registration evidence. Vì v1 chưa production, không duy trì endpoint, payload hay
  lớp tương thích v1.

```python
InputType = Literal["text", "url", "text_with_url"]
AnalysisStatus = Literal["queued", "running", "completed", "failed"]
RiskLevel = Literal["low", "medium", "high", "critical"]
Verdict = Literal["safe", "suspicious", "malicious", "inconclusive"]
EvidenceType = Literal[
    "url_rule", "domain_reputation", "redirect", "blacklist",
    "domain_registration", "fact_check", "official_source", "user_report"
]
InvestigationStepStatus = Literal["pending", "running", "completed", "skipped", "failed"]
InvestigationTool = Literal[
    "local_rules", "blacklist_lookup", "url_scanner", "redirect_resolver",
    "domain_intelligence", "claim_retriever"
]
CaseStatus = Literal["not_required", "pending_review", "approved", "rejected"]
RecommendedAction = Literal["allow", "show_caution", "do_not_open", "escalate_for_review"]
```

| Score | Level | Default action |
|---:|---|---|
| 0–29 | `low` | `allow` |
| 30–59 | `medium` | `show_caution` |
| 60–84 | `high` | `do_not_open` |
| 85–100 | `critical` | `escalate_for_review` |

`verdict` biểu diễn kết luận từ evidence; `risk_level` chỉ là bucket của điểm. Provider failure có thể dẫn đến `inconclusive`, không tạo thêm risk level.

## 2. Public API v2

Đây là public contract duy nhất. Client dùng domain intelligence gọi `/api/v2`; không dùng content
negotiation hay feature flag để phát schema/enum khác nhau cho cùng endpoint.

### `POST /api/v2/analyses` — `202 Accepted`

```json
{"message":"Tập đoàn X tặng quà tại https://example.com/claim","consent_to_scan_urls":true}
```

Validation: `message` dài 1–5.000 ký tự. Response:

```json
{
  "contract_version":"v2",
  "analysis_id":"550e8400-e29b-41d4-a716-446655440000",
  "status":"queued",
  "created_at":"2026-08-03T13:00:00Z"
}
```

### `GET /api/v2/analyses/{analysis_id}` — `200 OK`

```json
{
  "contract_version":"v2",
  "analysis_id":"550e8400-e29b-41d4-a716-446655440000",
  "status":"completed",
  "input_type":"text_with_url",
  "normalized_urls":["https://example.com/claim"],
  "claims":["Tập đoàn X đang tặng quà"],
  "investigation_plan":[{
    "step_id":"step-1",
    "tool":"blacklist_lookup",
    "target":"example.com",
    "reason_code":"url_present",
    "depends_on":[],
    "status":"completed"
  }],
  "risk_score":78,
  "risk_level":"high",
  "verdict":"suspicious",
  "recommended_action":"do_not_open",
  "confidence":0.74,
  "summary":"Liên kết có dấu hiệu mạo danh và chưa được nguồn chính thức xác nhận.",
  "reasons":["Tên miền không thuộc danh sách chính thức."],
  "evidence":[{
    "type":"domain_registration",
    "source":"iana-rdap",
    "title":"Thông tin đăng ký domain",
    "url":null,
    "finding":"Domain được đăng ký 12 ngày trước; dữ liệu registrant bị redacted.",
    "observed_at":"2026-08-03T13:00:00Z"
  }],
  "limitations":["Chưa đủ bằng chứng để kết luận chắc chắn là lừa đảo."],
  "case_status":"not_required",
  "scoring_version":"risk-v2",
  "created_at":"2026-08-03T13:00:00Z",
  "completed_at":"2026-08-03T13:00:09Z"
}
```

`investigation_plan` có mặt cho mọi analysis. Khi `queued`/`running`, các trường kết quả nullable.
User chỉ đọc analysis của mình; admin đọc case đã escalate.

### Các endpoint còn lại

- `GET /api/v2/analyses`: lịch sử của user hiện tại.
- `POST /api/v2/analyses/{analysis_id}/reports`: `{reason, comment?}`; chỉ tạo report.
- `GET /api/v2/admin/cases`: review queue, role `security_admin`.
- `POST /api/v2/admin/cases/{analysis_id}/decision`: `{decision: approved|rejected, action: add_to_blacklist|none, note}`.
- `GET /api/v2/analyses/{analysis_id}/events`: polling fallback; WebSocket phát cùng event schema
  `{analysis_id,status,step,occurred_at,step_id?,step_status?}`. Các field task-plan được áp dụng
  nhất quán cho mọi producer và consumer v2.

`investigation_plan` là task trace có cấu trúc để UI giải thích agent đang làm gì; không chứa
chain-of-thought. `tool` chỉ nhận giá trị trong `InvestigationTool`.
Mỗi `step_id` ổn định trong một analysis; `depends_on` là danh sách `step_id`, không phải tên tool.

Error envelope:

```json
{"error":{"code":"VALIDATION_ERROR","message":"message must contain 1 to 5000 characters","retryable":false,"details":{}}}
```

Mã tối thiểu: `VALIDATION_ERROR` 422, `FORBIDDEN` 403, `NOT_FOUND` 404, `RATE_LIMITED` 429, `PROVIDER_TIMEOUT` 503, `INTERNAL_ERROR` 500.

## 3. AgentState và node contract

```python
class AgentState(TypedDict, total=False):
    analysis_id: str
    message: str
    consent_to_scan_urls: bool
    input_type: InputType
    extracted_urls: list[str]
    normalized_urls: list[str]
    claims: list[str]
    investigation_plan: list[InvestigationStep]
    url_findings: list[UrlScanResult]
    domain_findings: list[DomainIntelligenceResult]
    claim_findings: list[ClaimEvidence]
    evidence: list[Evidence]
    tool_calls_used: int
    errors: list[ToolError]
    risk_score: int
    risk_level: RiskLevel
    verdict: Verdict
    confidence: float
    recommended_action: RecommendedAction
    reasons: list[str]
    limitations: list[str]
    case_status: CaseStatus
    scoring_version: str
```

`InvestigationStep` gồm `step_id: str`, `tool: InvestigationTool`, `target: str`,
`reason_code: str`, `depends_on: list[str]`, `status: InvestigationStepStatus`. Không có field
rationale tự do hoặc prompt/model trace.

| Node | Đọc | Ghi | Cấm |
|---|---|---|---|
| `classify_input` | message | input_type | External call |
| `extract_indicators` | message | URLs, claims | Chấm điểm cuối |
| `analyze_message` | message, extracted indicators | context, emotion, sender intent, scam indicators, claims | Quy kết ý đồ cho user; tạo evidence |
| `normalize_and_check_rules` | URLs | normalized URLs, rule evidence | Truy cập URL đích |
| `plan_tools` | semantic state, indicators | ordered task plan + reason codes | Lưu chain-of-thought; vượt allowlist/consent/SSRF/budget |
| `plan_next_tool` | state/budget + proposal | route | Chọn tool ngoài allowlist |
| `scan_urls` | URL + consent | findings/evidence/errors | Scan khi thiếu consent hoặc trước executor hard gate |
| `inspect_domains` | registrable domains + consent | domain findings/evidence/errors | Tạo provider work trước hard gate; tra IP/public suffix; suy diễn field RDAP bị thiếu; bypass network guard/budget |
| `verify_claims` | claims | findings/evidence/errors | Khẳng định không có nguồn |
| `assess_risk` | structured evidence | score/level/verdict/confidence | Ghi blacklist, dùng LLM tự do làm điểm |
| `review_assessment` | deterministic assessment/evidence | narrative, missing information, evidence indexes | Sửa score/verdict; thêm evidence |
| `explain_result` / `generate_response` | assessment/evidence | summary/reasons/limitations | Thêm evidence không tồn tại; sửa action |
| `route_action` | assessment | action/case status | Tự chặn domain |

## 4. Tool interfaces

```python
class UrlScanner(Protocol):
    async def scan(self, normalized_url: str) -> UrlScanResult: ...

class RedirectResolver(Protocol):
    async def resolve(self, normalized_url: str) -> RedirectResult: ...

class ClaimRetriever(Protocol):
    async def search(self, claim: str, limit: int = 5) -> list[ClaimEvidence]: ...

class DomainIntelligence(Protocol):
    async def lookup(self, domain: str) -> DomainIntelligenceResult: ...

class BlacklistRepository(Protocol):
    async def get(self, domain: str) -> BlacklistEntry | None: ...
    async def add_approved(self, domain: str, decision_id: str) -> None: ...
```

Adapter trả model nội bộ, không truyền raw response. `UrlScanResult` tối thiểu có provider,
normalized URL, verdict, signals, observed_at; field `redirect_chain` hiện có được giữ để tương
thích nhưng provider reputation được phép trả rỗng. `RedirectResult` mới là nguồn sự thật cho
redirect metadata. `ClaimEvidence` có source/title/url/finding/relevance/observed_at và
`stance: supports|refutes|mixed|unrated`; scoring dùng stance đã chuẩn hóa,
không dò keyword trong `finding`. `DomainIntelligenceResult` có `provider`, `domain`, nullable
`registered_at`, nullable `expires_at`, nullable `registrar`, nullable `country`,
`status`, `privacy_redacted`, `signals` và `observed_at`. `BlacklistEntry` tối thiểu có `domain`,
`decision_id`, `source`, `added_at`, `active`. Không lưu RDAP entity/vCard, registrant
name/email/phone/address hoặc raw response.

### 4.1 Adapter profile hiện tại

- URL reputation adapter hiện tại là Google Safe Browsing v4. Vì v4 đã deprecated, nó chỉ là
  compatibility adapter tạm thời. Replacement giữ nguyên `UrlScanner` protocol:
  `GoogleSafeBrowsingV5Scanner` gọi `GET /v5/urls:search` cho non-commercial;
  `GoogleWebRiskScanner` gọi `GET /v1/uris:search` cho commercial. Threat match thành `malicious`;
  no-hit luôn thành `inconclusive`, không phải `safe`, bất kể ví dụ provider gọi empty response là safe.
- Cache phải theo response provider: Safe Browsing v5 áp dụng `cacheDuration` cho cả match/no-match;
  Web Risk không giữ positive match quá `expireTime`. Cache key gồm provider + API version +
  normalized URL; không dùng cache v4 sau cutover.
- Fact-check production adapter: Google Fact Check Tools API. Chỉ các review có provenance được
  chuyển thành `ClaimEvidence`; rating được map bằng bảng provider/versioned sang `stance`. Rating
  không biết thành `unrated`, không đoán bằng chuỗi tự do. Mọi review từ API có type `fact_check`;
  chỉ nguồn nằm trong official-source registry mới được type `official_source`. Adapter dùng
  endpoint [`claims.search`](https://developers.google.com/fact-check/tools/api/reference/rest/v1alpha1/claims/search).
- Offline fact-check adapter: corpus JSON gồm các bản ghi hợp lệ theo `ClaimEvidence`, tìm kiếm từ
  khóa và xếp hạng deterministic.
- Provider timeout/lỗi HTTP/lỗi payload được chuyển thành `ToolError`; message lỗi không chứa API
  key, query string nhạy cảm hoặc raw response.
- Domain intelligence MVP chỉ dùng RDAP-over-HTTPS với IANA bootstrap; WHOIS TCP không nằm trong
  MVP. Target là registrable domain được suy ra bằng Public Suffix List đóng gói/versioned; IP
  literal và public suffix bị skip. Tuổi domain được tính deterministic từ registration event;
  dữ liệu thiếu/redacted không thành tín hiệu xấu. Timeout mặc định 5 giây; cache positive và
  `not_found` bằng TTL riêng, không cache timeout/429/provider error như kết quả hợp lệ.
- RDAP base URL lấy từ bootstrap vẫn là external target: chỉ HTTPS, validate DNS/public IP và
  revalidate redirect. Response giới hạn kích thước và chỉ parse field allowlist.
- URL reputation provider có endpoint cố định không fetch URL đích, nên không resolve DNS target.
  `RedirectResolver` mới dùng `GuardedHttpClient`: URL tuyệt đối `http`/`https`, không credential,
  port 80/443, mọi DNS answer public/global, revalidate từng hop, tối đa 5 redirect và 1 MB response.
- Blacklist repository chuẩn hóa **registrable domain** bằng IDNA. `get()` phải trả provenance để
  evidence không dựa vào boolean vô danh. `add_approved(domain,
  decision_id)` chỉ thành công nếu repository đã có audit decision tương ứng với
  `decision=approved` và `action=add_to_blacklist`.

### 4.2 LLM contract

- Production model baseline: `gpt-4o-mini` (hiện vẫn supported, không nằm trong deprecation list tại
  ngày freeze); temperature `0`, timeout 15 giây và tối đa một retry. Model ID/snapshot được inject
  từ config, không hard-code trong node và không lưu object model trong AgentState/checkpoint.
- Mọi call dùng Pydantic structured output. Bốn output nội bộ là `MessageAnalysis`,
  `ToolPlan`, `AssessmentReview` và `GroundedResponse`. `ToolPlan` tối đa ba tool; planner không
  sinh local rule/blacklist step.
- `sender_intent` mô tả ý đồ có khả năng của người tạo/gửi nội dung được dán, không phải
  ý đồ của user đang yêu cầu kiểm tra.
- `ToolPlan.tools` chỉ nhận `url_scanner|domain_intelligence|claim_retriever`. Blacklist lookup
  luôn do code lập lịch trước provider. Với mọi URL/domain lookup, executor phải kiểm tra
  `consent_to_scan_urls is true` **trước** khi tạo task, fan-out, request hoặc provider client;
  target sau đó vẫn phải qua SSRF, retry và budget. Khi không có consent, chỉ local
  rules/blacklist và limitation được phép chạy. Code có thể bổ sung tool cần thiết bị model bỏ sót.
- `AssessmentReview` tham chiếu evidence bằng zero-based index. Mỗi reason của
  `GroundedResponse` là cặp `{evidence_index, text}`. Index không tồn tại bị loại bỏ;
  response có evidence nhưng không còn reason hợp lệ sẽ bị thay bằng fallback.
- Các field orchestration như `llm_context`, `llm_emotion`, `llm_sender_intent`,
  `llm_tool_plan`, `llm_assessment`, `llm_*_evidence_indexes` và `llm_errors` là private
  `WorkflowState`, không mở rộng public `AgentState` contract v2.

## 5. Fixture chuẩn

```text
tests/fixtures/
├── analyses.jsonl
├── tool_responses/{url_scanner,domain_intelligence,claim_retriever,blacklist}.json
└── README.md
```

Một dòng `analyses.jsonl`:

```json
{
  "id":"phishing_brand_001",
  "request":{"message":"Nhận quà tại https://tapdoanx-qua.example/login","consent_to_scan_urls":true},
  "mocks":{"url_scanner":"url_phishing_001","domain_intelligence":"domain_new_001","claim_retriever":"claim_none_001","blacklist":"domain_not_listed_001"},
  "expected":{"input_type":"text_with_url","verdict":"malicious","risk_level":"critical","risk_score_min":85,"risk_score_max":100,"recommended_action":"escalate_for_review","case_status":"pending_review","required_evidence_types":["domain_reputation","url_rule"],"required_limitation":false}
}
```

Không assert nguyên văn summary/reasons. Assert enum, khoảng điểm, evidence bắt buộc và invariant.

| Fixture ID | Tình huống | Expected chính |
|---|---|---|
| `safe_official_001` | Domain chính thức | safe, low, allow |
| `phishing_brand_001` | Look-alike + login | malicious, critical, pending review |
| `short_url_redirect_001` | Redirect tới domain xấu | malicious, high/critical |
| `suspicious_claim_001` | Khuyến mãi chưa xác nhận | suspicious, medium/high |
| `false_claim_001` | Fact-check bác bỏ | malicious, high |
| `no_url_or_claim_001` | Text không kiểm chứng được | inconclusive, không scan URL |
| `no_consent_001` | URL, không consent | không external scan, có limitation |
| `provider_timeout_001` | Scanner timeout | không 500/safe, có limitation |
| `unicode_domain_001` | IDN/homograph | normalize an toàn, suspicious+ |
| `ssrf_private_ip_001` | Private/metadata target | request bị chặn |
| `empty_message_001` | Input rỗng | HTTP 422 |
| `admin_review_001` | Approved review | audit + blacklist write |
| `new_domain_001` | Domain mới đăng ký + brand look-alike | `domain_registration` evidence có provenance RDAP; riêng tuổi domain không đủ high+ |
| `rdap_redacted_001` | RDAP ẩn thông tin | không suy diễn owner, có limitation nếu coverage bị ảnh hưởng |
| `rdap_timeout_001` | Domain intelligence timeout | không 500/safe, workflow tiếp tục và không cache lỗi |
| `rdap_subdomain_001` | URL có nhiều subdomain | chỉ lookup registrable domain một lần |
| `rdap_ip_or_suffix_001` | URL host là IP/public suffix | skip RDAP, không tiêu tool call |
| `claim_only_false_001` | Tin nhắn chỉ có claim đã bị bác bỏ | không gọi URL tool, fact-check evidence |
| `blacklist_memory_hit_001` | Domain có approved blacklist entry | lookup-first, provenance đúng, có thể bỏ provider tốn phí |

## 6. Safety invariants

- Không external URL reputation/RDAP lookup khi consent là false; executor không được tạo task,
  fan-out, request hoặc provider client trước khi kiểm tra hard gate này. Local rules/blacklist
  vẫn chạy.
- Không trả `safe` chỉ vì provider timeout, no-hit hoặc không có dữ liệu.
- Không ghi blacklist nếu thiếu authenticated admin decision và audit record.
- Chặn SSRF trước request và sau redirect/DNS resolution.
- External evidence phải có source và `observed_at`; URL nguồn nếu loại evidence hỗ trợ citation.
- Evidence ảnh hưởng điểm phải truy được tới signal và scoring version.
- Fact-check score dùng normalized `stance` + relevance threshold; không phân loại nguồn/rating bằng keyword prose.
- Log không chứa full message, token/API key, credential hoặc sensitive query string.
- Unit/integration/eval mặc định không gọi provider thật.
- Unit/integration/eval inject fake LLM hoặc `llm=None`; không gọi OpenAI thật.
- LLM output không được trực tiếp tăng/giảm risk score, đổi verdict/action, tạo evidence,
  bỏ qua consent/SSRF hoặc chọn tool ngoài allowlist.
- LLM failure phải ghi limitation khi LLM đã được cấu hình và tiếp tục bằng extraction,
  planning, scoring và explanation deterministic.
- Không lưu hoặc trả chain-of-thought; chỉ trả kế hoạch tác vụ, reason code và trạng thái bước.
- RDAP không lưu entity/vCard/PII registrant hoặc raw response; field thiếu/redacted không được coi là risk signal.
- Mọi blacklist hit dùng để chấm điểm phải trỏ tới approved entry và audit decision còn hiệu lực.
