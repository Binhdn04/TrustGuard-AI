# Implementation Status Against Product Scope

**Ngày đối chiếu:** 2026-08-13  
**Nguồn sự thật về goal:** [scope.md](scope.md)

Tài liệu này được lập từ code hiện tại, không suy ra từ roadmap cũ. `Implemented` nghĩa là có code và
test trong repository; không đồng nghĩa đã được xác minh trên hosted production hoặc provider thật.

## 1. Kết luận ngắn

Codebase hiện là một nền tảng phân tích URL + general fact-check khá hoàn chỉnh về hạ tầng, nhưng chưa
đúng product flow của scope mới. Hạ tầng reusable đã có: API, auth/RBAC, persistence, durable worker,
realtime, URL safety tools, risk engine, report/review/appeal, campaign và operations. Phần nghiệp vụ
cần chuyển đổi lớn nhất là bỏ general fact-check làm luồng chính, thêm security scope gate, structured
scam understanding, brand/organization verification, whitelist và multi-turn investigation.

## 2. Đã implement và có thể tái sử dụng

| Capability | Mức hiện tại | Bằng chứng code |
|---|---|---|
| Text, URL, text + URL input | Implemented, single-turn | `AnalysisCreateRequest`, `classify_input`, `extract_indicators` |
| URL normalization và local rules | Implemented | `src/agents/nodes/rules.py` |
| SSRF/private/local/metadata blocking | Implemented | `src/agents/nodes/rules.py`, `src/agents/tools/network.py` |
| Consent trước URL/domain external lookup | Implemented | executor gate trong `src/agents/graph.py` và tool nodes |
| URL reputation cascade | Implemented khi có key | Google Web Risk primary, VirusTotal secondary trong `src/agents/tools/reputation.py` |
| RDAP/domain metadata | Implemented | `src/agents/tools/rdap.py`, runtime wiring trong `integration.py` |
| Guarded redirect resolution | Implemented | `src/agents/tools/redirect.py` |
| Approved blacklist lookup/write | Implemented | SQLite/PostgreSQL repositories và admin decision v2 |
| Deterministic scoring | Implemented theo contract cũ | `src/agents/nodes/risk.py`, scoring version `risk-v2` |
| Grounded deterministic fallback | Implemented | `src/agents/nodes/explanation.py`; LLM failure không làm hỏng core result |
| Async analysis lifecycle | Implemented | queued/running/completed/failed trong `AnalysisService` |
| Durable PostgreSQL worker | Implemented | lease/retry/idempotency/outbox trong repository và `durable_worker.py` |
| Realtime progress | Implemented | persisted events, ticketed WebSocket, cursor replay và polling fallback |
| Auth, ownership, admin RBAC | Implemented | demo auth cho dev, OIDC/JWKS cho production, owner checks và admin dependency |
| Rate limiting và safe request logs | Implemented | Redis/memory limiter; middleware không log body/query/token |
| User history và report | Implemented | API v2/v3, PostgreSQL/SQLite, frontend |
| Report review queue | Implemented | persisted queue, start/review state và optimistic conflict handling |
| Appeal lifecycle | Implemented | create/list/admin decision/audit/notification trong v3 |
| Campaign hypothesis/review | Implemented, xem giới hạn bên dưới | domain/redirect/claim-vector clustering và admin review |
| Operations metrics | Implemented | latency, usage, feedback/appeal aggregates ở v3 |
| Retention và signed screenshot artifact | Implemented nhưng không thuộc scope mới | retention worker, signed access, guarded Playwright capture |
| Local Docker topology | Implemented | frontend, API, worker, PostgreSQL/pgvector và Redis trong Compose |

## 3. Implemented một phần hoặc sai semantics scope mới

| Scope capability | Hiện trạng thực tế | Gap |
|---|---|---|
| AI Security Chatbot | UI là form phân tích một lượt, mang nhãn “Fact-Check AI” | Đổi copy/component và hỗ trợ follow-up chat |
| Multi-turn investigation / case memory | Không có `conversation_id`, conversation model hay API | Thiết kế ownership, state summary và retention cho conversation |
| Security Scope Classifier | `classify_input` chỉ phân loại text/URL | Thêm `IN_SCOPE`, `NEED_MORE_INFO`, `OUT_OF_SCOPE_GENERAL_FACT_CHECK` trước tool routing |
| Message understanding | LLM extract emotion/intent/scam indicator/claim | Thiếu schema organization, scenario, action, amount, urgency, payment, credential/OTP |
| Threat taxonomy | Một số keyword/URL/provider signal nhận phishing | Chưa có classifier rõ cho financial/recruitment/promotion/OTP scam |
| Brand impersonation | Có punycode/lure tokens và có thể nhận provider `brand_lookalike` | Không có brand registry, official-domain mapping, typosquat/homograph matcher có provenance |
| Whitelist | Không có table/repository/admin lifecycle riêng | Thêm first-class whitelist và precedence trong Risk Engine |
| DNS analysis | DNS resolver đang phục vụ SSRF validation | Chưa expose DNS evidence/tool theo investigation plan |
| OfficialClaimVerifier | Source Registry và web retrieval cũ có thể tìm official source | Chưa có bounded verifier theo allowed purpose; hiện vẫn là general fact-check |
| Risk classification | Có `RiskLevel(low/medium/high/critical)` + `Verdict` cũ | Chưa khớp taxonomy `SAFE/LOW_RISK/.../INSUFFICIENT_EVIDENCE` của scope |
| False-positive policy | Domain age capped; provider no-hit/error không tự thành safe | Chưa có whitelist precedence; claim refuted hiện có thể tự tạo malicious, trái scope mới |
| Security memory | Có blacklist và campaign observations | Thiếu store chuẩn cho domain/fingerprint/brand/threat/report count/admin verdict |
| Security Admin product | Có case/report/appeal/action/campaign/source/metrics UI/API | Thiếu whitelist, domain/threat views và audit-log browser đầy đủ |
| Wide actions | Có enum/table/decision cho block và broad warning | Không có runtime caller tạo proposal; chưa có executor/sink hoàn chỉnh |
| Campaign clustering | Có domain, redirect và claim embeddings | Claim-vector path phụ thuộc pipeline fact-check deprecated; cần chuyển sang security fingerprint |
| Production readiness | Có OIDC, PostgreSQL, Redis, Compose, readiness | Chưa có evidence hosted rollout, live-provider smoke, backup/restore và load/security run |

## 4. Deprecated hoặc ngoài scope mới

Các phần sau vẫn có code nhưng không còn là product capability:

- General claim extraction/retrieval/comparison: `src/agents/fact_check.py`,
  `src/agents/tools/fact_check.py`, phần fact-check trong `nodes/tools.py` và `graph.py`.
- Google Fact Check Claim Search, Tavily Search/Extract, OpenAI claim embeddings và hybrid corpus.
- Fact-check Source Registry, source discovery/promotion và admin source UI/API.
- PostgreSQL tables `fact_check_*`, `source_discoveries`, `source_discovery_observations`,
  `source_discovery_decisions` và claim-vector campaign features.
- Frontend `FactCheckComposer`, `FactCheckSummary`, `ClaimResultCard`, claim-stance filters/history và
  admin “Fact-check Review”.
- `/api/v2/chat` starter endpoint và `/api/v2` compatibility contract sau khi v3/new contract migration
  hoàn tất.
- Screenshot capture/artifact UI: code có thật nhưng không được yêu cầu trong `scope.md`; nên disable
  khỏi product flow, giữ riêng nếu có quyết định scope mới.
- `CHROMA_PERSIST_DIR` và boilerplate/template không tham gia runtime product.

Không drop schema legacy ngay. Trước tiên phải ngừng routing/writer, đo zero usage, backup/export rồi
mới dùng Alembic migration có restore/downgrade plan.

## 5. Việc bắt buộc để đạt goal

### P0 — Chặn hành vi sai scope

1. Thêm `SecurityScopeClassifier` trước extraction/tool planning.
2. Out-of-scope request kết thúc mà không gọi Google Fact Check, Tavily, embeddings hoặc corpus.
3. Feature-gate general fact-check và source-discovery routes/UI.
4. Sửa Risk Engine để claim “bị bác bỏ” không tự động đồng nghĩa malicious security risk.
5. Đổi user-facing copy/examples khỏi news, medical và general claims.

### P1 — Hoàn thiện core security triage

1. Contract vNext cho scope decision, structured scam context và risk taxonomy mới.
2. Brand registry/matcher cùng official domain/contact provenance.
3. First-class whitelist repository, admin lifecycle và precedence trong scoring.
4. OfficialClaimVerifier bounded: một claim, hai query, năm official sources; `NOT_FOUND != FALSE`.
5. Threat-specific rules/evaluation cho phishing, financial, recruitment, promotion và OTP scam.
6. Multi-turn conversation/case memory có ownership và retention.
7. Chuyển frontend thành chatbot security triage với out-of-scope/need-more-info states.

### P2 — Admin, memory và migration

1. Security-memory schema/service và campaign fingerprints không phụ thuộc fact-check embeddings.
2. Hoàn tất create → review → execute cho block/global blacklist/broad warning.
3. Thêm whitelist/domain/threat/audit views cho admin.
4. Ngừng legacy writers, archive/drop fact-check/source-discovery schema và pgvector nếu không còn dùng.
5. Xóa v2/starter route, legacy frontend components, provider config và fixtures sau compatibility window.

### P3 — Release evidence

1. Versioned evaluation set theo threat và out-of-scope routing.
2. Precision/recall/false-positive, routing accuracy, grounded evidence và latency/cost report.
3. Hosted OIDC/PostgreSQL/Redis/provider smoke; backup/restore, load, SSRF và auth security tests.
4. Runbook cho provider disable, rollback scoring/schema và incident handling.

## 6. Test evidence tại thời điểm audit

- Backend: `PYENV_VERSION=myenv pytest -q` → **198 passed, 1 skipped**.
- Frontend unit: `npm test` → **30 passed trong 6 files**.
- Frontend lint và TypeScript: `npm run lint && npm run typecheck` → **pass**.
- Chưa chạy browser E2E, PostgreSQL integration có service thật hoặc live-provider smoke trong lần audit
  này; không được ghi chúng là verified.

Test hiện tại chủ yếu bảo vệ contract cũ. Chúng chứng minh code đang ổn định, không chứng minh sản phẩm
đã đạt scope mới. Fixture mới cho scope gate, multi-turn, whitelist, recruitment/payment/OTP và bounded
official verification vẫn chưa tồn tại.
