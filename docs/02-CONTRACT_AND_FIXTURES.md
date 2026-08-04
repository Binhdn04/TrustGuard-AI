# Contract and Fixtures — P-068

**Contract version:** `v1`  
**Freeze date:** 2026-08-03

> Đây là nguồn sự thật duy nhất cho API schema, AgentState, enum, tool interface, fixture và safety invariant.

## 1. Quy ước và enum

- JSON `snake_case`; timestamp UTC ISO 8601; ID là UUID do backend sinh.
- Không có dữ liệu dùng `null`, không dùng chuỗi rỗng.
- Risk score là integer `[0,100]`; thêm optional field là compatible, đổi/xóa field hoặc enum cần `v2`.

```python
InputType = Literal["text", "url", "text_with_url"]
AnalysisStatus = Literal["queued", "running", "completed", "failed"]
RiskLevel = Literal["low", "medium", "high", "critical"]
Verdict = Literal["safe", "suspicious", "malicious", "inconclusive"]
EvidenceType = Literal[
    "url_rule", "domain_reputation", "redirect", "blacklist",
    "fact_check", "official_source", "user_report"
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

## 2. Public API v1

### `POST /api/v1/analyses` — `202 Accepted`

```json
{"message":"Tập đoàn X tặng quà tại https://example.com/claim","consent_to_scan_urls":true}
```

Validation: `message` dài 1–5.000 ký tự. Response:

```json
{
  "contract_version":"v1",
  "analysis_id":"550e8400-e29b-41d4-a716-446655440000",
  "status":"queued",
  "created_at":"2026-08-03T13:00:00Z"
}
```

### `GET /api/v1/analyses/{analysis_id}` — `200 OK`

```json
{
  "contract_version":"v1",
  "analysis_id":"550e8400-e29b-41d4-a716-446655440000",
  "status":"completed",
  "input_type":"text_with_url",
  "normalized_urls":["https://example.com/claim"],
  "claims":["Tập đoàn X đang tặng quà"],
  "risk_score":78,
  "risk_level":"high",
  "verdict":"suspicious",
  "recommended_action":"do_not_open",
  "confidence":0.74,
  "summary":"Liên kết có dấu hiệu mạo danh và chưa được nguồn chính thức xác nhận.",
  "reasons":["Tên miền không thuộc danh sách chính thức."],
  "evidence":[{
    "type":"official_source",
    "source":"official-domain-registry",
    "title":"Tên miền chính thức của Tập đoàn X",
    "url":"https://official.example/security",
    "finding":"example.com không nằm trong danh sách chính thức.",
    "observed_at":"2026-08-03T13:00:00Z"
  }],
  "limitations":["Chưa đủ bằng chứng để kết luận chắc chắn là lừa đảo."],
  "case_status":"not_required",
  "scoring_version":"risk-v1",
  "created_at":"2026-08-03T13:00:00Z",
  "completed_at":"2026-08-03T13:00:09Z"
}
```

Khi `queued`/`running`, các trường kết quả nullable. User chỉ đọc analysis của mình; admin đọc case đã escalate.

### Các endpoint còn lại

- `GET /api/v1/analyses`: lịch sử của user hiện tại.
- `POST /api/v1/analyses/{analysis_id}/reports`: `{reason, comment?}`; chỉ tạo report.
- `GET /api/v1/admin/cases`: review queue, role `security_admin`.
- `POST /api/v1/admin/cases/{analysis_id}/decision`: `{decision: approved|rejected, action: add_to_blacklist|none, note}`.
- `GET /api/v1/analyses/{analysis_id}/events`: polling fallback; WebSocket phát cùng event schema `{analysis_id,status,step,occurred_at}`.

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
    url_findings: list[UrlScanResult]
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

| Node | Đọc | Ghi | Cấm |
|---|---|---|---|
| `classify_input` | message | input_type | External call |
| `extract_indicators` | message | URLs, claims | Chấm điểm cuối |
| `normalize_and_check_rules` | URLs | normalized URLs, rule evidence | Truy cập URL đích |
| `plan_next_tool` | state/budget | route | Chọn tool ngoài allowlist |
| `scan_urls` | URL + consent | findings/evidence/errors | Scan khi thiếu consent |
| `verify_claims` | claims | findings/evidence/errors | Khẳng định không có nguồn |
| `assess_risk` | structured evidence | score/level/verdict/confidence | Ghi blacklist, dùng LLM tự do làm điểm |
| `explain_result` | assessment/evidence | summary/reasons/limitations | Thêm evidence không tồn tại |
| `route_action` | assessment | action/case status | Tự chặn domain |

## 4. Tool interfaces

```python
class UrlScanner(Protocol):
    async def scan(self, normalized_url: str) -> UrlScanResult: ...

class ClaimRetriever(Protocol):
    async def search(self, claim: str, limit: int = 5) -> list[ClaimEvidence]: ...

class BlacklistRepository(Protocol):
    async def contains(self, domain: str) -> bool: ...
    async def add_approved(self, domain: str, decision_id: str) -> None: ...
```

Adapter trả model nội bộ, không truyền raw response. `UrlScanResult` tối thiểu có provider, normalized URL, verdict, redirect chain, signals, observed_at; `ClaimEvidence` có source/title/url/finding/relevance/observed_at.

## 5. Fixture chuẩn

```text
tests/fixtures/
├── analyses.jsonl
├── tool_responses/{url_scanner,claim_retriever,blacklist}.json
└── README.md
```

Một dòng `analyses.jsonl`:

```json
{
  "id":"phishing_brand_001",
  "request":{"message":"Nhận quà tại https://tapdoanx-qua.example/login","consent_to_scan_urls":true},
  "mocks":{"url_scanner":"url_phishing_001","claim_retriever":"claim_none_001","blacklist":"domain_not_listed_001"},
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

## 6. Safety invariants

- Không external-scan URL khi consent là false.
- Không trả `safe` chỉ vì provider timeout, no-hit hoặc không có dữ liệu.
- Không ghi blacklist nếu thiếu authenticated admin decision và audit record.
- Chặn SSRF trước request và sau redirect/DNS resolution.
- External evidence phải có source và `observed_at`; URL nguồn nếu loại evidence hỗ trợ citation.
- Evidence ảnh hưởng điểm phải truy được tới signal và scoring version.
- Log không chứa full message, token/API key, credential hoặc sensitive query string.
- Unit/integration/eval mặc định không gọi provider thật.

