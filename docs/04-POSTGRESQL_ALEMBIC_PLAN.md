# PostgreSQL/Alembic Status and Migration Plan

## 1. Migration hiện có

| Revision | Đã tạo |
|---|---|
| `0001_extensions` | PostgreSQL extension `pgcrypto` |
| `0002_analysis_core` | analyses, events, steps, evidence, reports |
| `0003_durable_jobs` | jobs, outbox, tool usage, schema imports |
| `0004_review_queue` | persisted report review queue |
| `0005_fact_check_corpus` | appeals, admin actions/decisions, blacklist và toàn bộ fact-check corpus |
| `0006_campaign_artifacts` | migration lịch sử cho campaign và bảng artifact đã ngừng sử dụng |
| `0007_runtime_integration` | campaign observations và claim-feature vectors |
| `0008_source_discovery` | source discovery/decision telemetry và bootstrap nguồn general fact-check |
| `0009_security_triage_v4` | Security v4 analyses/events và owner-scoped lifecycle |
| `0010_security_trust_registry` | brand registry, whitelist và trust audit |
| `0011_security_conversations` | multi-turn conversation summary/version/retention |
| `0012_security_feedback` | Security v4 reports và appeals |
| `0013_security_hitl_actions` | v4 action proposal/execution state và immutable decision audit |
| `0014_security_memory_campaigns` | explainable security memory, campaign members và correction/review audit |
| `0015_security_api_readiness` | report-review status/index và immutable v4 feedback audit |
| `0016_security_v4_durable_jobs` | isolated Security v4 job, encrypted payload, transactional outbox và per-owner idempotency |
| `0017_security_admin_copilot` | grounded admin suggestion, usage metadata, evidence snapshot hash, reviewer timestamps và audit |
| `0018_remove_vector_compat` | xóa fact-check/source-discovery/campaign-vector storage và extension `vector` trên database cũ |

Production repository có implementation cho durable analysis, owner reads, reports/review, appeals,
admin actions, blacklist, Security v4 memory/campaigns,
retention và operations metrics.

## 2. Schema phù hợp scope và nên giữ

- `analyses`, `analysis_events`, `investigation_steps`, `evidence`.
- `analysis_jobs`, `outbox`, `tool_usage`.
- `analysis_reports`, `review_queue_items`, `appeals`, `review_decisions`, `user_notifications`.
- `admin_actions` và `blacklist_entries`, sau khi chỉnh flow proposal/execution.
- `campaign_clusters`, `campaign_members`, `campaign_signals`, sau khi thay feature semantics.
- Bảng artifact lịch sử không còn application reader/writer; chỉ giữ migration để bảo toàn upgrade path.

## 3. Schema scope mới đã bổ sung

- `security_analyses`, `security_analysis_events` giữ output v4 và policy version tách khỏi legacy.
- `security_conversations` và turns giữ redacted context summary, optimistic version và retention.
- `security_whitelist`, `security_brands`, `security_trust_audit` giữ provenance/lifecycle/reviewer.
- `security_memory` giữ domain/fingerprint/brand/threat/risk/first-last seen/report count/admin verdict.
- `security_campaigns_v4`, members và audit giữ hypothesis/review history không dùng claim vectors.
- `security_feedback_audit_v4` giữ append-only report/appeal decision; report/appeal status có index phục vụ
  admin page/filter.
- Trust, action, memory, campaign và feedback đều có audit table/index riêng; unified v4 API chỉ tổng hợp,
  không ghi đè lịch sử reviewer. Reviewed action execution thuộc contract v4.

## 4. Legacy schema đã được remove bởi revision 0018

- `fact_check_sources`, `fact_check_records`, `fact_check_embeddings`.
- `fact_check_results`, `fact_check_result_embeddings`.
- `fact_check_evidence_snapshots`, `fact_check_chunks`.
- `source_discoveries`, `source_discovery_observations`, `source_discovery_decisions`.
- `campaign_claim_features` sau khi campaign dùng security fingerprint mới.
- extension `vector`.

## 5. Migration sequence

1. **Additive:** revisions `0009`–`0017` thêm Security v4 schema và runtime.
2. **Cutover:** frontend/API/reviewed actions chỉ dùng v4; legacy worker/provider bị tháo.
3. **Destructive:** revision `0018` drop legacy FK/index/table/extension.
4. **Verify:** upgrade từ database trống; backup/restore database hiện hữu trước khi chạy `0018`.

## 6. Invariants cần enforce ở DB/service

- Owner-scoped reads cho conversation/analysis/report/appeal.
- Monotonic unique event sequence và unique job/outbox idempotency key.
- Whitelist/blacklist mutations có approved decision và provenance.
- Wide action không thể executed nếu thiếu approved decision/evidence/reviewer/note.
- Evidence không chứa raw provider body, OTP, password, token hoặc raw private conversation.
- Corrective decision append record mới, không xóa immutable audit history.
- Report chỉ chuyển terminal một lần sang `processed`; appeal chỉ chuyển terminal một lần sang `resolved`;
  transition lặp lại trả conflict và không append audit thứ hai.

Migration `0018` không hỗ trợ downgrade. Production cần verified backup, restore rehearsal và operator approval.
