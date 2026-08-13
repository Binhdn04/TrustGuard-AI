# PostgreSQL/Alembic Status and Migration Plan

## 1. Migration hiện có

| Revision | Đã tạo |
|---|---|
| `0001_extensions` | PostgreSQL extensions, gồm pgvector |
| `0002_analysis_core` | analyses, events, steps, evidence, reports |
| `0003_durable_jobs` | jobs, outbox, tool usage, schema imports |
| `0004_review_queue` | persisted report review queue |
| `0005_fact_check_corpus` | appeals, admin actions/decisions, blacklist và toàn bộ fact-check corpus |
| `0006_campaign_artifacts` | retention, campaign clusters/members/signals và artifacts |
| `0007_runtime_integration` | campaign observations và claim-feature vectors |
| `0008_source_discovery` | source discovery/decision telemetry và bootstrap nguồn general fact-check |

Production repository có implementation cho durable analysis, owner reads, reports/review, appeals,
admin actions, blacklist, source/corpus, campaigns, artifacts, retention và operations metrics.

## 2. Schema phù hợp scope và nên giữ

- `analyses`, `analysis_events`, `investigation_steps`, `evidence`.
- `analysis_jobs`, `outbox`, `tool_usage`.
- `analysis_reports`, `review_queue_items`, `appeals`, `review_decisions`, `user_notifications`.
- `admin_actions` và `blacklist_entries`, sau khi chỉnh flow proposal/execution.
- `campaign_clusters`, `campaign_members`, `campaign_signals`, sau khi thay feature semantics.
- Retention/audit-safe artifact metadata chỉ giữ nếu capability liên quan còn được phê duyệt.

## 3. Schema thiếu cho scope mới

- `conversations`: owner, active investigation, redacted context summary, retention/version.
- Scope decision/reason và security-context version trên analysis hoặc structured child table.
- `whitelist_entries`: canonical indicator, provenance, lifecycle, reviewer/decision/version.
- `brand_entities` và official domain/contact mappings có provenance/effective interval.
- `security_memory`: domain/fingerprint/brand/threat/risk/first-last seen/report count/admin verdict.
- Audit browsing/index nếu `review_decisions` chưa đủ bao phủ mọi admin mutation.

## 4. Legacy schema cần freeze rồi remove

- `fact_check_sources`, `fact_check_records`, `fact_check_embeddings`.
- `fact_check_results`, `fact_check_result_embeddings`.
- `fact_check_evidence_snapshots`, `fact_check_chunks`.
- `source_discoveries`, `source_discovery_observations`, `source_discovery_decisions`.
- `campaign_claim_features` sau khi campaign dùng security fingerprint mới.
- pgvector extension nếu không còn bất kỳ feature mới nào cần vector.

## 5. Migration sequence

1. **Additive:** thêm scope decision, conversations, whitelist, brand mappings và security memory.
2. **Dual-read có giới hạn:** contract mới đọc security schema; legacy path vẫn riêng biệt dưới flag.
3. **Cutover:** frontend/API/worker chỉ dùng product path mới; ngừng legacy writer/job/provider.
4. **Observe:** đo zero reader/writer và hoàn tất retention/export decision.
5. **Destructive:** drop legacy FK/index/table/extension trong revision riêng.
6. **Verify:** upgrade từ database trống và database `0008`; backup/restore và downgrade/restore smoke.

## 6. Invariants cần enforce ở DB/service

- Owner-scoped reads cho conversation/analysis/report/appeal.
- Monotonic unique event sequence và unique job/outbox idempotency key.
- Whitelist/blacklist mutations có approved decision và provenance.
- Wide action không thể executed nếu thiếu approved decision/evidence/reviewer/note.
- Official verification `NOT_FOUND` được lưu đúng enum, không biến thành contradiction.
- Evidence không chứa raw provider body, OTP, password, token hoặc raw private conversation.
- Corrective decision append record mới, không xóa immutable audit history.

Không chạy migration destructive chỉ để làm docs khớp scope. Việc xóa schema cần telemetry, backup và
operator approval riêng.
