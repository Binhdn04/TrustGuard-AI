# Implementation Status Against Product Scope

**Ngày đối chiếu:** 2026-08-13

**Nguồn goal:** [scope.md](scope.md)

**Nguồn WP/release gate:** [SECURITY_TRIAGE_IMPLEMENTATION_PLAN.md](SECURITY_TRIAGE_IMPLEMENTATION_PLAN.md)

`Implemented` nghĩa là có code và automated test trong repository. Nó không đồng nghĩa đã được xác minh
trên hosted production, PostgreSQL/Redis thật hoặc live provider.

## 1. Kết luận ngắn

Security Triage v4 đã triển khai end-to-end qua WP0–WP8: product boundary, scope gate, structured scam
context, consent-gated investigation, deterministic risk, brand/whitelist/official verification,
multi-turn Security Chat, owner persistence, report/appeal, HITL blacklist action, Security Memory và
explainable campaign hypotheses.

Codebase vẫn giữ legacy `/api/v2`/`/api/v3`, general fact-check providers/corpus/source discovery,
claim-vector campaign và một số frontend compatibility code. Các phần này không nằm trên Security v4
analysis/memory path nhưng chưa được freeze/xóa. WP9 chịu trách nhiệm evaluation, hosted evidence,
compatibility telemetry, backup/restore và cleanup.

## 2. Security v4 đã implement

| Capability | Trạng thái hiện tại | Bằng chứng chính |
|---|---|---|
| Product boundary | `/api/v4` tách khỏi legacy profile; route usage được phân loại read/write | `src/core/product_boundary.py`, middleware tests |
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
| Multi-turn conversation | Owner-scoped ID, optimistic version, redacted summary, conflict isolation và retention | `SecurityAnalysisService`, migration `0011` |
| Analysis lifecycle | Terminal persistence, owner list/get, queued/running/completed/failed events | v4 API/service/repositories |
| Realtime replay | Cursor polling, single-use WebSocket ticket và terminal event replay | v4 event/stream tests |
| Security Chat frontend | Multi-turn composer, OOS/need-more-info states, risk/evidence/recommendations, history/report/appeal | frontend components + tests/E2E |
| User feedback | V4 report và appeal create/list, owner checks và persistence | migration `0012`, API tests |
| HITL blacklist | High-risk URL producer, canonical target/evidence snapshot, approve/reject, idempotent execution và audit | `platform_wave2.py`, migration `0013` |
| Security Memory | Domain/URL fingerprint/redirect/brand/pattern/threat/risk/version/report count/admin verdict | `security_memory.py`, migration `0014` |
| Campaign v4 | Named security signals, 24h window, min-three hypothesis, reviewer decision/correction audit; no embeddings | `campaign.py`, WP8 tests |
| Admin UI | Actions/audit, brand, whitelist, memory correction, campaign review, appeals, metrics | `platform-operations.tsx` |
| Local/production persistence | SQLite local and PostgreSQL/Alembic implementations through revision `0014` | repositories + migrations |

## 3. Hạ tầng dùng chung vẫn có thể tái sử dụng

| Capability | Trạng thái |
|---|---|
| Auth/RBAC | Demo token cho dev; OIDC issuer/audience/JWKS và admin role cho production |
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
| Admin exploration | Brand/whitelist/memory/campaign và action audit views đã có | Chưa có dedicated domain/threat explorer và audit browser tổng hợp |
| Security v4 execution model | Inline lifecycle và persisted replay hoạt động | Chưa chuyển sang durable PostgreSQL worker/lease path; cần hosted reliability decision/evidence |
| Official/live providers | Adapter, bounded policy và deterministic fakes có | Chưa có live-provider smoke trong môi trường được cấp credential |
| Evaluation | Unit/API/integration-style fixtures rộng | Chưa có versioned release dataset và precision/recall/routing/cost report |
| Production readiness | OIDC/PostgreSQL/Redis/readiness/config code có | Chưa verify hosted rollout, backup/restore, load, migration rollback và incident runbook |
| Cutover | Frontend product path dùng v4; route telemetry phân biệt legacy/security | Chưa freeze legacy writer hoặc đạt zero-usage compatibility window |

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

## 6. Việc còn lại để đạt release goal — WP9

### Evaluation/reliability gate

1. Tạo versioned dataset bao phủ threat, safe official, mismatch-only, provider failure, OOS,
   need-more-info, no-consent, multi-turn và wide-action cases.
2. Đo routing/provider-call accuracy, precision/recall, false-positive/false-negative, grounding,
   latency và cost.
3. Chạy hosted OIDC/PostgreSQL/Redis/security-provider smoke; quyết định và test v4 durable execution.
4. Chạy backup/restore, Alembic upgrade/downgrade, load, SSRF/redirect, RBAC, prompt injection,
   lease-loss/idempotency và retention tests.
5. Hoàn thiện runbook provider disable, scoring/schema rollback, incident response và retention.

### Cutover/cleanup gate

1. Freeze legacy writers và provider calls trong product profile.
2. Đo zero `legacy_read/legacy_write` qua compatibility window đã định.
3. Export/archive dữ liệu cần giữ và kiểm chứng restore.
4. Xóa deprecated routes/providers/config/frontend fixtures.
5. Drop legacy tables/index/pgvector chỉ khi không còn consumer và rollback đã được rehearsal.

## 7. Test evidence hiện tại

- Backend: **288 passed, 1 skipped**; skipped test là PostgreSQL integration khi không có
  `TEST_DATABASE_URL`.
- Ruff: **pass**.
- Alembic: **`0014_security_memory_campaigns` là head**.
- Frontend unit: **37 passed trong 9 files**.
- Frontend lint và TypeScript: **pass**.
- Chromium E2E: **2 passed**, gồm user flow và axe accessibility check.
- Next.js webpack production build: **pass**, toàn bộ route được prerender thành công.

Chưa có bằng chứng hosted PostgreSQL/Redis/OIDC, live-provider smoke, backup/restore/load hoặc versioned
quality evaluation. Vì vậy trạng thái đúng là “WP0–WP8 implemented trong repository; WP9 release gate
chưa hoàn tất”, không phải “full production scope complete”.
