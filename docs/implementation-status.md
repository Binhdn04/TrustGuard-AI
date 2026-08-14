# Implementation Status Against Product Scope

**Ngày đối chiếu:** 2026-08-14

**Nguồn goal:** [scope.md](scope.md)

**Nguồn WP/release gate:** [SECURITY_TRIAGE_IMPLEMENTATION_PLAN.md](SECURITY_TRIAGE_IMPLEMENTATION_PLAN.md)

`Implemented` nghĩa là có code và automated test trong repository. Nó không đồng nghĩa đã được xác minh
trên hosted production, PostgreSQL/Redis thật hoặc live provider.

## 1. Kết luận ngắn

Security Triage v4 và frontend investigation workspace đã triển khai end-to-end: product boundary, scope gate, structured scam
context, consent-gated investigation, deterministic risk, brand/whitelist/official verification,
multi-turn Security Chat, owner persistence, report/appeal, HITL blacklist action, Security Memory và
explainable campaign hypotheses, paginated API, admin feedback lifecycle, intelligence explorer và unified audit.

Codebase vẫn giữ legacy `/api/v2`/`/api/v3`, general fact-check providers/corpus/source discovery,
claim-vector campaign và một số frontend compatibility code. Các phần này không nằm trên Security v4
analysis/memory path nhưng chưa được freeze/xóa trên deployment thật. WP9 đã thêm offline evaluation,
fail-fast cutover/freeze config, compatibility checker và release runbook; hosted evidence, restore rehearsal,
zero-usage window và cleanup vẫn còn lại.

## 2. Security v4 đã implement

| Capability | Trạng thái hiện tại | Bằng chứng chính |
|---|---|---|
| Product boundary | `/api/v4` tách khỏi legacy profile; route usage được phân loại read/write | `src/core/product_boundary.py`, middleware tests |
| API capabilities | Truthful `pre_cutover` profile; v3 action contract/sink limits được công bố rõ | `SecurityCapabilitiesResponseV4`, OpenAPI tests |
| Security scope gate | `IN_SCOPE`, `NEED_MORE_INFO`, `OUT_OF_SCOPE_GENERAL_FACT_CHECK`; terminal OOS không resolve investigation | `security_scope.py`, `security_triage.py`, API tests |
| Structured understanding | Entity, scenario, requested action, amount, urgency, URL, credential/OTP/payment/PII và threat | `SecurityContextV4`, scope tests |
| Investigation planner | Allowlisted local/external tools, consent, budget, retry, deadline và dependency status | `security_investigation.py` |
| URL/network safety | Canonical URL/domain, local rules, blacklist, DNS, redirect, RDAP, reputation và SSRF protection | security investigation/tool tests |
| Evidence/provenance | Typed evidence, normalized tool error, provider usage refs và grounded explanation refs | v4 models, investigation/risk tests |
| Risk classification | `SAFE/LOW_RISK/SUSPICIOUS/HIGH_RISK/MALICIOUS/INSUFFICIENT_EVIDENCE`, policy `security-risk-v1` | `security_risk.py` |
| False-positive policy | Whitelist precedence; mismatch/age/no-hit/timeout riêng lẻ không đủ malicious | trust/risk regression tests |
| Brand registry | Alias, official domains/contacts, provenance, effective interval, lifecycle và reviewer | `security_trust.py`, migration `0010` |
| Whitelist | Domain/URL/contact scope, provenance/version/lifecycle, SQLite/PostgreSQL và admin API | trust services/repositories |
| Official verifier | Allowed purpose, một claim, tối đa hai query/năm official sources; `NOT_FOUND != FALSE` | `OfficialClaimVerifier` tests |
| Multi-turn conversation | Owner-scoped ID/list, optimistic version, redacted summary, conflict isolation và retention | `SecurityAnalysisService`, migration `0011` |
| Analysis lifecycle | Terminal persistence, owner list/get/page/filter, queued/running/completed/failed events | v4 API/service/repositories |
| Realtime replay | Cursor polling, single-use WebSocket ticket và terminal event replay | v4 event/stream tests |
| Security Chat frontend | Multi-turn composer, OOS/need-more-info states, risk/evidence/recommendations, history/report/appeal | frontend components + tests/E2E |
| User feedback | V4 user create/list; admin page/decision, terminal conflict, reviewer/note và immutable audit | migrations `0012`/`0015`, API tests |
| HITL blacklist | High-risk URL producer, canonical target/evidence snapshot, approve/reject, idempotent execution và audit | `platform_wave2.py`, migration `0013` |
| Security Memory | Domain/URL fingerprint/redirect/brand/pattern/threat/risk/version/report count/admin verdict | `security_memory.py`, migration `0014` |
| Campaign v4 | Named security signals, 24h window, min-three hypothesis, reviewer decision/correction audit; no embeddings | `campaign.py`, WP8 tests |
| Intelligence API | Paginated/filterable domain/threat aggregation và unified trust/memory/campaign/feedback audit | API/repository tests |
| Admin UI | Threat Observatory; Review Room với structured case evidence, report/appeal decision và reviewed-action v3 detail/audit; Trust lifecycle; Unified Audit; compatibility v3 surface | admin frontend components + API tests |
| Local/production persistence | SQLite local and PostgreSQL/Alembic implementations through revision `0015` | repositories + migrations |

## 3. Hạ tầng dùng chung vẫn có thể tái sử dụng

| Capability | Trạng thái |
|---|---|
| Auth/RBAC | Demo token cho dev; frontend OIDC Authorization Code + PKCE/callback/per-tab session/refresh/logout; backend xác minh issuer/audience/JWKS và admin role |
| Ownership/privacy | Owner-scoped reads; logs không body/query/token; v4 persistence không raw private message |
| Rate limiting | Redis hoặc deterministic memory fallback |
| PostgreSQL durable jobs/outbox | Implemented cho legacy analysis worker; v4 hiện vẫn xử lý inline |
| Operations metrics | V3 latency, provider usage, quota/error và feedback aggregates |
| Report review/appeal infrastructure | Persisted queue/decision/audit/optimistic conflict paths có thể tái sử dụng |
| Retention/artifacts | Retention worker và guarded signed screenshot artifacts tồn tại; screenshot ngoài Security scope |
| Local topology | Frontend, API, worker, PostgreSQL/pgvector và Redis trong Compose |

## 4. Partial capability và gap thật còn lại

| Capability | Đã có | Còn thiếu / scope deviation |
|---|---|---|
| Wide admin actions | `ADD_TO_BLACKLIST` có producer + real sink; reject/failure/audit hoàn chỉnh | `BLOCK_DOMAIN`, `PUBLISH_BROAD_WARNING` và AI Copilot chưa có downstream sink; không được coi là executed |
| `DISABLE_BLACKLIST` | Legacy PostgreSQL executor tồn tại | Không có v4 runtime producer, không tính là WP7 deliverable |
| Admin exploration | Domain/threat Observatory, Review Room, Trust lifecycle và Unified Audit dùng contract thật; `/admin` redirect sang Review Room; v3 metrics/source discovery được cô lập trong compatibility surface | Không còn repository frontend gap; hosted release evidence vẫn thuộc WP9 |
| Security v4 execution model | Inline lifecycle và persisted replay hoạt động | Chưa chuyển sang durable PostgreSQL worker/lease path; cần hosted reliability decision/evidence |
| Official/live providers | Adapter, bounded policy và deterministic fakes có | Chưa có live-provider smoke trong môi trường được cấp credential |
| Evaluation | Versioned 16-category deterministic dataset/report đo routing, calls, risk, precision/recall, grounding, latency/cost | Offline fixture evidence không thay thế hosted provider/multi-turn transport/load evidence |
| Production readiness | Frontend OIDC PKCE, backend JWT/RBAC, hardened production validation, Security v4 live-smoke CLI và release/rollback runbook | Chưa verify với IdP/hosted PostgreSQL/Redis/provider thật, backup/restore và load |
| Cutover | Frontend dùng v4; route telemetry tách legacy/security/reviewed-action; cutover config freeze legacy writes và source discovery | Chưa kích hoạt freeze hoặc đạt API/provider/job/DB zero-usage window trên deployment thật |

## 5. Legacy/deprecated code vẫn tồn tại

Các phần sau không nằm trong Security v4 product path nhưng vẫn còn để compatibility/rollback:

- `/api/v2/chat`, `/api/v2` và general-analysis writers của `/api/v3`.
- Legacy LangGraph `classify_input → fact-check → risk-v2` workflow.
- Google Fact Check, Tavily, claim comparator, OpenAI claim embeddings và hybrid fact-check corpus.
- Source Registry discovery/promotion API, DB tables và admin source tab.
- `fact_check_*`, `source_discoveries*`, `campaign_claim_features` và legacy campaign tables.
- Claim-stance mapper/types/tests và old analysis frontend compatibility components.
- Screenshot capture/artifact flow, nếu không có quyết định scope mới giữ lại.
- pgvector extension/index sau khi mọi legacy vector consumer đã được chứng minh bằng zero usage.

Không drop các phần này trước compatibility telemetry, backup/export, restore rehearsal và rollback plan.

## 6. Việc còn lại để đạt release goal

Frontend đã hoàn tất chat-to-case workspace, history/resume, Observatory, Review Room, Trust/Audit,
responsive/accessibility và production E2E. Frontend không còn task riêng; phần còn lại đều thuộc WP9 release/cutover.

### Evaluation/reliability gate

1. Versioned deterministic dataset/report đã có; giữ dataset hash và report cùng release artifact.
2. Chạy hosted OIDC/PostgreSQL/Redis/security-provider smoke; quyết định và test v4 durable execution.
3. Chạy backup/restore, Alembic upgrade/downgrade, load, SSRF/redirect, RBAC, prompt injection,
   lease-loss/idempotency và retention tests.
4. Chạy theo runbook provider disable, scoring/schema rollback, incident response và retention đã có.

### Cutover/cleanup gate

1. Kích hoạt freeze legacy writers/source discovery bằng cutover config đã có sau khi drain job.
2. Đo zero `legacy_read/legacy_write` qua compatibility window đã định.
3. Export/archive dữ liệu cần giữ và kiểm chứng restore.
4. Xóa deprecated routes/providers/config/frontend fixtures.
5. Drop legacy tables/index/pgvector chỉ khi không còn consumer và rollback đã được rehearsal.

## 7. Test evidence hiện tại

- Backend: **194 passed** trong suite Security v4 và reviewed-action compatibility đang hoạt động.
- Ruff: **pass**.
- Alembic: **`0015_security_api_readiness` là head**.
- Frontend unit: **57 passed trong 12 files**, gồm OIDC state/nonce/PKCE/code exchange/per-tab session và refresh-token rotation.
- Frontend lint và TypeScript: **pass**.
- Chromium E2E: **2 passed**, gồm mobile/keyboard user report-appeal-resume và admin Review/Observatory/Trust/Audit;
  axe structural WCAG gate và computed theme contrast đạt yêu cầu.
- Next.js default Turbopack và webpack standalone production build: **pass**; `/admin` redirect sang Review Room.

Offline Security v4 evaluation 16 nhóm đã pass và có version/hash report. Chưa có bằng chứng hosted
PostgreSQL/Redis/OIDC/live-provider, backup/restore/load hoặc compatibility window. Vì vậy trạng thái đúng là
“Security v4, frontend và phần local WP9 đã implemented trong repository; WP9
release/evaluation/cutover tổng thể chưa hoàn tất”, không phải “full production scope complete”.
