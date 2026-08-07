# Contract and Fixtures — P-068

**Document revision:** 2.1 — 2026-08-07

**Wire contract:** `contract_version: "v2"`, base path `/api/v2`

**Source of truth in code:** `src/models/schemas.py`

> Đây là mô tả contract đang được backend và TypeScript client triển khai. Nếu tài liệu và Pydantic
> model khác nhau, model cùng contract tests thắng. v1 chưa production nên không có compatibility
> layer.

## 1. Quy ước chung

- JSON dùng `snake_case`; ID public là UUID; timestamp phải là UTC ISO 8601.
- Pydantic contract dùng `extra="forbid"`; field ngoài schema bị từ chối.
- String có mặt không được rỗng hoặc chỉ có whitespace, kể cả field optional khi được gửi.
- Kết quả chưa có ở trạng thái `queued/running/failed` dùng `null`; `investigation_plan` mặc định
  là mảng rỗng.
- Completed response phải có đủ mọi result field và `risk_level` phải khớp `risk_score`.
- Score là integer 0–100; confidence là number 0–1.
- External evidence có `source`, `title`, `finding`, `observed_at`; `url` có thể `null`.

## 2. Enum v2

```text
InputType               text | url | text_with_url
AnalysisStatus          queued | running | completed | failed
RiskLevel               low | medium | high | critical
Verdict                 safe | suspicious | malicious | inconclusive
EvidenceType            url_rule | domain_reputation | redirect | blacklist |
                        domain_registration | fact_check | official_source | user_report
InvestigationStepStatus pending | running | completed | skipped | failed
InvestigationTool       local_rules | blacklist_lookup | url_scanner | redirect_resolver |
                        domain_intelligence | claim_retriever
ClaimStance             supports | refutes | mixed | unrated
CaseStatus              not_required | pending_review | approved | rejected
RecommendedAction       allow | show_caution | do_not_open | escalate_for_review
ReviewDecision          approved | rejected
ReviewAction            add_to_blacklist | none
```

| Score | Risk level | Default action |
|---:|---|---|
| 0–29 | `low` | `allow` |
| 30–59 | `medium` | `show_caution` |
| 60–84 | `high` | `do_not_open` |
| 85–100 | `critical` | `escalate_for_review` |

`verdict` là kết luận từ evidence, không phải tên khác của risk bucket. Ví dụ score thấp vẫn có thể
`inconclusive` khi không có đủ dữ liệu.

## 3. Public analysis API

Tất cả endpoint dưới đây yêu cầu `Authorization: Bearer <token>`. Dev defaults là
`dev-user-token` và `dev-admin-token`; chúng không phải production credentials.

### `POST /api/v2/analyses` — 202

Request:

```json
{
  "message": "Tập đoàn X tặng quà tại https://example.com/claim",
  "consent_to_scan_urls": true
}
```

`message` dài 1–5.000 ký tự sau khi áp dụng invariant không-whitespace. Response:

```json
{
  "contract_version": "v2",
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "created_at": "2026-08-07T09:00:00Z"
}
```

Response chỉ xác nhận enqueue vào background task trong process; không có nghĩa workflow đã hoàn
tất hoặc có durable queue.

### `GET /api/v2/analyses/{analysis_id}` — 200

Completed example:

```json
{
  "contract_version": "v2",
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "input_type": "text_with_url",
  "normalized_urls": ["https://example.com/claim"],
  "claims": ["Tập đoàn X đang tặng quà"],
  "investigation_plan": [
    {
      "step_id": "step-15f2f4fdd850",
      "tool": "blacklist_lookup",
      "target": "example.com",
      "reason_code": "url_present",
      "depends_on": ["step-5b94155dab48"],
      "status": "completed"
    }
  ],
  "risk_score": 78,
  "risk_level": "high",
  "verdict": "suspicious",
  "recommended_action": "do_not_open",
  "confidence": 0.74,
  "summary": "Liên kết có dấu hiệu đáng ngờ và chưa được nguồn chính thức xác nhận.",
  "reasons": ["Tên miền không thuộc nguồn chính thức đã biết."],
  "evidence": [
    {
      "type": "domain_registration",
      "source": "iana-rdap/rdap-v1/psl-2026-08-06",
      "title": "Thông tin đăng ký domain",
      "url": null,
      "finding": "registered_at=2026-07-26T09:00:00+00:00",
      "observed_at": "2026-08-07T09:00:00Z"
    }
  ],
  "limitations": ["Chưa đủ bằng chứng để kết luận chắc chắn."],
  "case_status": "not_required",
  "scoring_version": "risk-v2",
  "created_at": "2026-08-07T09:00:00Z",
  "completed_at": "2026-08-07T09:00:09Z"
}
```

`step_id` là opaque, ổn định trong một analysis và hiện được derive deterministic từ tool/target.
Consumer không được tự tính hoặc phụ thuộc vào giá trị hash cụ thể.

### Các endpoint user khác

| Method | Path | Response/behavior |
|---|---|---|
| GET | `/api/v2/analyses` | Danh sách analysis của principal hiện tại, mới nhất trước. |
| GET | `/api/v2/analyses/{id}/events` | Mảng `AnalysisEvent` để polling. |
| POST | `/api/v2/analyses/{id}/reports` | Tạo report; body `{reason, comment?}`, trả 201 receipt. |

`AnalysisEvent`:

```json
{
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "step": "url_scanner",
  "occurred_at": "2026-08-07T09:00:04Z",
  "step_id": "step-opaque",
  "step_status": "completed"
}
```

`step_id` và `step_status` là nullable. Hiện không có WebSocket endpoint. Processor phát step event
sau khi graph trả plan cuối, nên event contract đúng nhưng timing chưa phải realtime transition.

## 4. Admin API

Tất cả endpoint yêu cầu role `security_admin`.

| Method | Path | Contract |
|---|---|---|
| GET | `/api/v2/admin/cases` | Các analysis đang `pending_review`, cũ nhất trước. |
| GET | `/api/v2/admin/reports?limit=50&offset=0` | `AnalysisReportRecord[]`; limit 1–100. |
| GET | `/api/v2/admin/decisions?limit=50&offset=0` | `AdminDecisionAudit[]`; limit 1–100. |
| GET | `/api/v2/admin/blacklist?query=&limit=50&offset=0` | `BlacklistEntry[]`; query tối đa 253 ký tự. |
| POST | `/api/v2/admin/cases/{id}/decision` | Review case và optional blacklist write. |

Decision request:

```json
{
  "decision": "approved",
  "action": "add_to_blacklist",
  "note": "Evidence is sufficient."
}
```

`add_to_blacklist` chỉ hợp lệ với `approved`. Analysis phải đang `pending_review`; trường hợp khác
trả 409. SQLite implementation commit decision audit, case state, event, outbox và blacklist trong
cùng transaction. Các domain hiện được lấy từ hostname trong `normalized_urls` của result và được
IDNA-normalize; service chưa quy mọi subdomain về registrable domain/eTLD+1.

## 5. Error contract

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed.",
    "retryable": false,
    "details": {}
  }
}
```

Các code public đã định nghĩa:

```text
VALIDATION_ERROR | FORBIDDEN | NOT_FOUND | RATE_LIMITED |
PROVIDER_TIMEOUT | INTERNAL_ERROR
```

FastAPI request validation trả 422 envelope. `PlatformError` được map theo status do service cung
cấp. Exception bất ngờ trong background processor không lộ raw detail; analysis chuyển `failed`.
Legacy `/api/v2/chat` vẫn có thể trả FastAPI `detail` khi lỗi và không thuộc contract này.

## 6. Public AgentState và private WorkflowState

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

`WorkflowState` bổ sung summary, route, target, attempt/budget/deadline, blocked/blacklisted target và
các field `llm_*`. Những field riêng này không đi vào `AnalysisResponse`.

`InvestigationStep` gồm đúng sáu field: `step_id`, `tool`, `target`, `reason_code`, `depends_on`,
`status`. Không thêm free-form rationale hoặc model trace.

## 7. Tool contracts

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
    async def get(self, domain: str) -> BlacklistLookupEntry | None: ...
    async def add_approved(self, domain: str, decision_id: str) -> None: ...
```

Important model rules:

- `UrlScanResult`: provider, normalized URL, verdict, redirect chain, signals, observed time.
- Provider no-hit phải là `inconclusive`, không phải `safe`.
- `ClaimEvidence`: source/title/url/finding/relevance/stance/observed time; scoring dùng stance.
- `DomainIntelligenceResult`: registration/expiry/registrar/country nullable, status, redaction,
  signals và observed time; không có registrant entity/vCard/raw response.
- `BlacklistLookupEntry`: domain, decision provenance, source, added time và active flag.
- Adapter exception được normalize thành private `ToolError`; không trả raw provider payload.

Redirect protocol có trong contract nhưng executor hiện đánh dấu `redirect_resolver` là unsupported
vì chưa có adapter mapping.

## 8. Scoring invariants

- `SCORING_VERSION = "risk-v2"`.
- Score chỉ dùng structured rule/tool findings, không dùng prose LLM.
- RDAP signals bị cap tổng cộng 20 điểm; recent registration một mình giữ verdict inconclusive.
- Privacy redaction không tăng điểm.
- Fact-check chỉ ảnh hưởng điểm khi stance đã normalize và relevance đạt threshold.
- Blacklist/malicious provider evidence có thể tạo malicious verdict và escalation theo rule.
- Provider unavailable/no-hit/empty result phải tạo limitation khi làm giảm coverage.

## 9. Fixture contract hiện tại

```text
tests/fixtures/
├── analyses.jsonl                         # 12 scenarios
├── tool_responses/url_scanner.json        # 6 records
├── tool_responses/claim_retriever.json    # 3 records
├── tool_responses/domain_intelligence.json# 3 records
├── tool_responses/blacklist.json          # 2 records
└── README.md
```

12 analysis fixtures đang freeze:

| Fixture | Ý nghĩa chính |
|---|---|
| `safe_official_001` | Official domain, low/safe. |
| `phishing_brand_001` | Look-alike/login, critical malicious. |
| `short_url_redirect_001` | Redirect tới blacklist. |
| `suspicious_claim_001` | Claim chưa xác nhận. |
| `false_claim_001` | Fact-check refutes claim. |
| `no_url_or_claim_001` | Không có indicator; inconclusive. |
| `no_consent_001` | Không external URL work, có limitation. |
| `provider_timeout_001` | Timeout không thành safe/500. |
| `unicode_domain_001` | Punycode/homograph signal. |
| `ssrf_private_ip_001` | Private/metadata target bị chặn. |
| `empty_message_001` | API 422. |
| `admin_review_001` | Approved decision và blacklist write. |

Domain-intelligence fixture records đã có nhưng chưa được tham chiếu bởi 12 dòng
`analyses.jsonl`. Các scenario RDAP mới, claim-only, subdomain/public suffix và blacklist memory hit
hiện được kiểm tra chủ yếu bằng unit/agent tests, chưa phải frozen end-to-end fixture rows.

Fixture tests không assert nguyên văn summary/reasons; chúng assert typed schema, enum, score range,
evidence requirement và safety invariant. Unit/integration/eval mặc định phải inject fake hoặc
`None`, không gọi network/OpenAI thật.

## 10. Endpoint ngoài product contract

- `GET /health` → process health cơ bản.
- `POST /api/v2/chat` → starter/legacy graph.
- `GET /api/v2/status` → starter agent status.

Các endpoint này không được frontend product dùng và không có compatibility guarantee của analysis
contract v2.

## 11. Frozen contract v3 — Wave 0

Phần này là contract final product đã được freeze trong Wave 0. Pydantic source of truth nằm tại
`src/models/schemas.py`, OpenAPI được phát từ `src/main.py`, và schema/migration plan nằm tại
`docs/04-POSTGRESQL_ALEMBIC_PLAN.md`. Core analysis/report/read adapter đã có dưới `/api/v3` để client
tích hợp sớm. WebSocket ticket, appeal, reviewed action, campaign và metrics đã có đầy đủ request/
response schema và route trong OpenAPI nhưng chủ động trả 501 cho tới wave triển khai tương ứng;
không có dữ liệu giả được ghi. Release v3 đầu tiên giữ read path v2 tương thích; capability mới chỉ
xuất hiện dưới `/api/v3`.

### 11.0 Versioning và core routes

Response v3 dùng `contract_version: "v3"`. Các analysis field v2 được giữ nguyên semantics; v3 bổ
sung typed realtime/appeal/action/campaign/metrics resources thay vì nhét nullable field mới vào v2.

| Method | Path | Hành vi v3 |
|---|---|---|
| POST | `/api/v3/analyses` | Tạo durable analysis, trả `202` sau transactional enqueue. |
| GET | `/api/v3/analyses` | List analysis của principal hiện tại. |
| GET | `/api/v3/analyses/{id}` | Trả state/result cuối, gồm plan/evidence/limitation như v2. |
| GET | `/api/v3/analyses/{id}/events` | Poll/replay persisted typed events theo cursor. |
| POST | `/api/v3/analyses/{id}/reports` | Tạo user report và receipt. |
| POST | `/api/v3/ws-tickets` | Cấp ticket một lần, TTL ngắn, bound với principal/analysis. |

Frontend final product chỉ tạo analysis mới qua v3. Các GET v2 được giữ trong compatibility window;
v2 create được đánh dấu deprecated khi v3 production-ready và không nhận capability v3 mới.

### 11.1 Realtime và cảnh báo hai pha

Đích: `WS /api/v3/analyses/{analysis_id}/stream` dùng ticket ngắn hạn lấy từ
`POST /api/v3/ws-tickets`. Server chỉ stream analysis mà principal có quyền đọc. Polling
`GET /api/v3/analyses/{id}/events` vẫn là fallback và nguồn replay.

Event v3 dùng envelope có `event_id`, `analysis_id`, `sequence`, `event_type`, `occurred_at` và
payload typed. Event types đã freeze:

```text
analysis_status | step_transition | provisional_warning | final_result | case_update | limitation
```

`provisional_warning` bắt buộc có `risk_level`, `summary`, `evidence_refs` và
`is_provisional: true`; không dùng verdict `safe`. `final_result` chỉ tham chiếu response đã persist.
Sequence tăng đơn điệu trong một analysis; polling/reconnect gửi lại opaque `next_cursor` dưới query
`cursor`, và event delivery có thể at-least-once nên client dedupe bằng `event_id`.

### 11.2 Appeal và Human-in-the-loop

API đã freeze:

| Method | Path | Quyền/hành vi |
|---|---|---|
| POST | `/api/v3/analyses/{id}/appeals` | Owner tạo appeal với reason/comment; trả receipt. |
| GET | `/api/v3/appeals/{id}` | Owner hoặc admin xem trạng thái/kết quả. |
| GET | `/api/v3/admin/appeals` | Admin list queue có pagination/filter. |
| POST | `/api/v3/admin/appeals/{id}/decision` | Admin uphold/overturn/inconclusive kèm note. |
| GET | `/api/v3/admin/actions` và `/{id}` | Admin đọc proposal và immutable evidence snapshot. |
| POST | `/api/v3/admin/actions/{id}/decision` | Duyệt/từ chối blacklist, block hoặc broad warning. |

Reviewed action enum là `add_to_blacklist | disable_blacklist | block_domain |
publish_broad_warning | none`. Mọi action ngoài `none` cần approved decision, reviewer, evidence
snapshot, note, timestamp và audit. Overturn tạo record mới và giữ lịch sử, không xóa decision cũ.

### 11.3 Campaign và operations dashboard

Admin-only read APIs đã freeze:

- `GET /api/v3/admin/campaigns` và `/api/v3/admin/campaigns/{id}` trả cluster hypothesis, time window, aggregate
  signals, evidence refs và reviewer status; không trả sender social graph/raw private messages.
- `GET /api/v3/admin/metrics` trả aggregate latency, cache hit, token/cost, provider call/429/timeout,
  risk distribution, report/appeal và false-positive metrics theo time range.

Campaign cluster không tự tạo broad warning. Metrics usage chứa provider/model, units, estimated
cost, latency, cache status và outcome; target/raw prompt không thuộc public operations contract.

### 11.4 Advanced tool contract

`ScreenshotRenderer` chỉ được thêm vào allowlist khi có sandbox implementation và security tests.
Input là normalized public HTTP(S) URL đã consent; output chỉ gồm final URL, image/artifact reference,
visible-text hash, render signals và observed time. Không trả cookie, credential, DOM/raw page body
hoặc dữ liệu form. Renderer không đăng nhập, không tương tác và bị giới hạn redirect/time/body.

Fact-check corpus record v3 cần source URL, publisher, claim, stance, language, published/updated
time, embedding model/version và ingestion provenance. Vector similarity chỉ là retrieval score;
ClaimEvidence stance vẫn phải đến từ normalized source metadata/reviewer, không suy ra từ similarity.

### 11.5 Fixture additions trước final v3 release gate

- provisional → final upgrade, WebSocket reconnect/replay và duplicate event;
- no-consent chứng minh không tạo provider/renderer client;
- conflicting reputation/fact-check, timeout, 429 và exhausted cost budget;
- screenshot SSRF/redirect/download/cookie isolation;
- appeal uphold/overturn và blacklist disable có immutable audit;
- campaign cluster hypothesis không tự phát broad warning;
- metrics aggregate không chứa raw message, URL query secret hoặc prompt.
