# Implementation Status Against Product Scope

**Ngày đối chiếu:** 2026-08-18

**Nguồn goal:** [scope.md](scope.md)

**Nguồn WP/release gate:** [SECURITY_TRIAGE_IMPLEMENTATION_PLAN.md](SECURITY_TRIAGE_IMPLEMENTATION_PLAN.md)

**Nguồn AI upgrade gate:** [AI_copilot.md](AI_copilot.md)

`Implemented` nghĩa là có code và automated test trong repository. Nó không đồng nghĩa đã được xác minh
trên hosted production, PostgreSQL/Redis thật hoặc live provider.

## 1. Kết luận ngắn

Security Triage v4 và frontend investigation workspace đã triển khai end-to-end: product boundary, scope gate, structured scam
context, policy-gated automatic investigation dưới disclosure, deterministic risk, brand/whitelist matching,
multi-turn Security Chat, owner persistence, report/appeal, HITL blacklist action, Security Memory và
explainable campaign hypotheses, paginated API, admin feedback lifecycle, intelligence explorer và unified audit.
AI Copilot roadmap WP0–WP8 đã implemented ở mức repository/local gate: shared provider runtime/budget,
hybrid understanding, adaptive incident conversation, constrained planning, grounded response, durable Security v4 async
và owner-isolated reviewed Security Memory retrieval, grounded Security Admin Copilot suggestion-only, versioned
AI evaluation và sequential rollout guard. Hosted WP8 rollout vẫn chưa có external evidence.

Public `/api/v2`/`/api/v3`, frontend compatibility clients/surface và pgvector persistence đã được xóa.
Reviewed actions đã chuyển sang `/api/v4/admin/actions`; migration `0018_remove_vector_compat` dọn fact-check
embeddings, source discovery, campaign vector observations và extension `vector`. Hosted evidence và
restore rehearsal vẫn còn lại trước production rollout.

## 2. Security v4 đã implement

| Capability | Trạng thái hiện tại | Bằng chứng chính |
|---|---|---|
| Product boundary | Chỉ `/api/v4` được mount; v2/v3 trả 404 và không có trong OpenAPI | `src/core/product_boundary.py`, route tests |
| API capabilities | Truthful `pre_cutover` profile; v4 action contract/sink limits được công bố rõ | `SecurityCapabilitiesResponseV4`, OpenAPI tests |
| Security scope gate | `IN_SCOPE`, `NEED_MORE_INFO`, `OUT_OF_SCOPE_GENERAL_FACT_CHECK`; terminal OOS không resolve investigation | `security_scope.py`, `security_triage.py`, API tests |
| Structured understanding | Entity, scenario, requested action, amount, urgency, URL, credential/OTP/payment/PII và threat | `SecurityContextV4`, scope tests |
| Investigation planner | Allowlisted local/external tools, consent, budget, retry, deadline và dependency status | `security_investigation.py` |
| URL/network safety | Canonical URL/domain, local rules, blacklist, DNS, redirect, RDAP, reputation và SSRF protection | security investigation/tool tests |
| Evidence/provenance | Typed evidence, normalized tool error, provider usage refs và grounded explanation refs | v4 models, investigation/risk tests |
| Risk classification | `SAFE/LOW_RISK/SUSPICIOUS/HIGH_RISK/MALICIOUS/INSUFFICIENT_EVIDENCE`; baseline `security-risk-v1`, reviewed-memory flag dùng `security-risk-v2` | `security_risk.py` |
| False-positive policy | Whitelist precedence; mismatch/age/no-hit/timeout riêng lẻ không đủ malicious | trust/risk regression tests |
| Brand registry | Alias, official domains/contacts, provenance, effective interval, lifecycle và reviewer | `security_trust.py`, migration `0010` |
| Whitelist | Domain/URL/contact scope, provenance/version/lifecycle, SQLite/PostgreSQL và admin API | trust services/repositories |
| Multi-turn conversation | Owner-scoped ID/list, optimistic version, redacted summary, conflict isolation và retention | `SecurityAnalysisService`, migration `0011` |
| Analysis lifecycle | Terminal persistence, owner list/get/page/filter, queued/running/completed/failed events | v4 API/service/repositories |
| Realtime replay | Cursor polling, single-use WebSocket ticket và terminal event replay | v4 event/stream tests |
| Security Chat frontend | Chatbot multi-turn với automatic lookup disclosure; Simple mode chat + grounded verdict, detail/report/appeal thu gọn; Analyst mode giữ plan/evidence; OOS/need-more-info/history/resume đầy đủ | frontend components + tests/E2E |
| User feedback | V4 user create/list; admin page/decision, terminal conflict, reviewer/note và immutable audit | migrations `0012`/`0015`, API tests |
| HITL blacklist | High-risk URL producer, canonical target/evidence snapshot, approve/reject, idempotent execution và audit | `platform_wave2.py`, migration `0013` |
| Security Memory | Domain/URL fingerprint/redirect/brand/pattern/threat/risk/version/report count/admin verdict | `security_memory.py`, migration `0014` |
| Campaign v4 | Named security signals, 24h window, min-three hypothesis, reviewer decision/correction audit; no embeddings | `campaign.py`, WP8 tests |
| Intelligence API | Paginated/filterable domain/threat aggregation và unified trust/memory/campaign/feedback audit | API/repository tests |
| Admin UI | Threat Observatory; Review Room với structured case evidence, report/appeal decision và reviewed-action v4 detail/audit; Trust lifecycle; Unified Audit | admin frontend components + API tests |
| Local/production persistence | SQLite local and PostgreSQL/Alembic implementations through revision `0018_remove_vector_compat` | repositories + migrations |
| AI assistant WP1–WP4 | Hybrid understanding, adaptive follow-up/incident recovery, policy-constrained planner và grounded response/frontend | `security_ai`, `security_understanding.py`, `security_pipeline.py`, AI WP tests |
| Durable Security v4 WP5 | Inline mặc định; PostgreSQL async 202/idempotency/encrypted payload/lease/outbox/realtime, SQLite giữ inline | migration `0016`, durable worker, WP5 tests |
| Reviewed Security Memory WP6 | Owner-scoped/non-self lookup chỉ dùng reviewed verdict/confirmed campaign; privacy-minimized evidence, poisoning controls và risk v2 | `security_memory_lookup`, repository joins, WP6 tests |
| Admin AI Copilot WP7 | Admin-only grounded suggestion, related reviewed campaign, typed disposition/existing action, dedicated rate limit, audit/snapshot hash và `executed=false` UI | migration `0017`, `security_admin_copilot.py`, WP7/API/frontend tests |
| AI evaluation/rollout WP8 | Ba tier evaluator, scenario metrics, 100% grounding/zero hallucination gate, hosted observation validator và sequential flag/rollback checker | `security_ai_v1.py`, `security_ai_hosted.py`, `security_ai_rollout.py`, versioned reports/tests |

## 3. Hạ tầng dùng chung vẫn có thể tái sử dụng

| Capability | Trạng thái |
|---|---|
| Auth/RBAC | Demo token cho dev; frontend OIDC Authorization Code + PKCE/callback/per-tab session/refresh/logout; backend xác minh issuer/audience/JWKS và admin role |
| Ownership/privacy | Owner-scoped reads; logs không body/query/token; v4 persistence không raw private message |
| Rate limiting | Redis hoặc deterministic memory fallback |
| PostgreSQL durable jobs/outbox | Isolated Security v4 worker; Redis chỉ notify, PostgreSQL giữ source of truth |
| Report review/appeal infrastructure | Persisted queue/decision/audit/optimistic conflict paths có thể tái sử dụng |
| Retention | Retention worker xóa nội dung đã tối giản và security payload hết hạn |
| Local topology | Frontend, API, worker, PostgreSQL thường và Redis trong Compose |

## 4. Partial capability và gap thật còn lại

| Capability | Đã có | Còn thiếu / scope deviation |
|---|---|---|
| Wide admin actions | `ADD_TO_BLACKLIST` có producer + real sink; Admin Copilot WP7 đã có suggestion-only API/UI | `BLOCK_DOMAIN`, `PUBLISH_BROAD_WARNING` chưa có downstream sink; Copilot không execute và không được coi là sink |
| `DISABLE_BLACKLIST` | Legacy PostgreSQL executor tồn tại | Không có v4 runtime producer, không tính là WP7 deliverable |
| Admin exploration | Domain/threat Observatory, Review Room, Trust lifecycle và Unified Audit dùng contract v4; `/admin` redirect sang Review Room | Không còn repository frontend gap; hosted release evidence vẫn thuộc WP9 |
| Security v4 execution model | Inline và durable PostgreSQL worker/lease/outbox path đều có; async chỉ được công bố khi config thật sự ready | Chưa có hosted lease-loss/load/Redis outage evidence trên deployment thật |
| Reviewed-memory rollout | Local tool, owner isolation, reviewed-only filtering, risk v2 và v1 fallback đã có; flag mặc định tắt | Chưa chạy hosted PostgreSQL fixture/poisoning/scoring evaluation trước khi bật flag |
| Live providers | URL reputation adapter, bounded policy và deterministic fakes có | Chưa có live-provider smoke trong môi trường được cấp credential |
| Evaluation | Versioned 24-category deterministic, 5-case memory và 9-category AI datasets/reports đo routing, field/scenario precision/recall, conversation, grounding, hallucination, fallback, p95 latency/token/cost | Offline fixture evidence không thay thế hosted provider/multi-turn transport/load evidence; hosted validator đã có nhưng chưa có input thật |
| Production readiness | Frontend OIDC PKCE, backend JWT/RBAC, hardened production validation, Security v4 live-smoke CLI và release/rollback runbook | Chưa verify với IdP/hosted PostgreSQL/Redis/provider thật, backup/restore và load |
| Cutover | Frontend và backend public surface chỉ dùng v4; vector/source-discovery storage đã có cleanup migration | Chưa áp dụng migration hoặc verify backup/restore trên deployment thật |

## 5. Legacy cleanup đã thực hiện

- FastAPI không còn mount `/api/v2` hoặc `/api/v3`; OpenAPI chỉ có product routes `/api/v4`.
- Reviewed actions đã chuyển sang `/api/v4/admin/actions`.
- Frontend compatibility pages, v2/v3 HTTP client, mocks, mapper và event stream đã bị xóa.
- Worker không claim legacy analysis/re-embedding jobs hoặc legacy outbox.
- Fresh Alembic history không tạo pgvector; migration `0018_remove_vector_compat` xóa vector/fact-check/source-discovery storage trên database cũ.
- Docker Compose và Railway dùng PostgreSQL thường.

Migration cleanup là destructive và không hỗ trợ downgrade; database đã có dữ liệu phải được backup trước khi deploy.

## 6. Việc còn lại để đạt release goal

Frontend đã hoàn tất chat-to-case workspace, history/resume, Observatory, Review Room, Trust/Audit,
responsive/accessibility và production E2E. Frontend không còn task riêng; phần còn lại đều thuộc WP9 release/cutover.

### Evaluation/reliability gate

1. Versioned deterministic dataset/report đã có; giữ dataset hash và report cùng release artifact.
2. Chạy hosted OIDC/PostgreSQL/Redis/security-provider smoke; quyết định và test v4 durable execution.
3. Chạy backup/restore, Alembic upgrade/downgrade, load, SSRF/redirect, RBAC, prompt injection,
   lease-loss/idempotency và retention tests.
4. Chạy theo runbook provider disable, scoring/schema rollback, incident response và retention đã có.

### Cleanup rollout gate

1. Export/archive dữ liệu legacy cần giữ và kiểm chứng restore.
2. Drain legacy jobs/outbox nếu production database từng chạy v2/v3.
3. Áp dụng `0018_remove_vector_compat` ở staging trước production.
4. Xác minh `/api/v4`, worker, backup/restore và rollback application image trên PostgreSQL thường.

## 7. Test evidence hiện tại

- Backend: **237 passed** trong suite Security v4, authenticated follow-up chat, AI WP0–WP8 và reviewed actions v4.
- Ruff: **pass**.
- Alembic: **`0018_remove_vector_compat` là head**.
- Frontend unit: **61 passed trong 12 files**, gồm automatic lookup/chat routing/continuation, Simple/Analyst presentation,
  Admin Copilot suggestion isolation, async capability/idempotency, OIDC state/nonce/PKCE/code exchange/per-tab session và refresh-token rotation.
- Frontend lint và TypeScript: **pass**.
- Chromium E2E: **2 passed**, gồm mobile/keyboard user report-appeal-resume và admin Review/Observatory/Trust/Audit;
  axe structural WCAG gate và computed theme contrast đạt yêu cầu.
- Next.js webpack standalone production build: **pass**; `/admin` redirect sang Review Room.

Offline Security v4 evaluation 24 category, reviewed-memory risk-v2 evaluation 5 gate và AI understanding/conversation/grounding
evaluation 9 category đều pass, có version/hash report. Chưa có bằng chứng hosted
PostgreSQL/Redis/OIDC/live-provider hoặc backup/restore/load. Vì vậy trạng thái đúng là
“Security v4, frontend và phần local WP9 đã implemented trong repository; WP9
release/evaluation/cutover tổng thể chưa hoàn tất”, không phải “full production scope complete”.
