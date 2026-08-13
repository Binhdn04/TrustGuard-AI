# Implementation Plan to Reach `scope.md`

Backlog này chỉ chứa gap được xác nhận từ code audit. Chi tiết capability/status nằm tại
[implementation-status.md](implementation-status.md).

## Phase 0 — Stop scope leakage

- [ ] Thêm feature flags để tắt general fact-check orchestrator, Source Registry discovery và admin
  source UI/API khỏi product profile.
- [ ] Thêm Security Scope Classifier làm node đầu tiên có thể kết thúc graph.
- [ ] Test zero provider/tool calls cho news, politics, sports, science và medical fact-check.
- [ ] Bỏ medical/general claim markers và examples khỏi user-facing path.
- [ ] Bỏ scoring rule `REFUTES => +70/MALICIOUS`.

Exit: product không còn xử lý general fact-check dù legacy code/schema vẫn tồn tại.

## Phase 1 — Contract và core triage

- [ ] Tạo contract vNext với scope decision, structured security context và risk taxonomy mới.
- [ ] Implement scenario/threat extraction cho phishing, impersonation, financial, recruitment,
  promotion/prize và credential/OTP theft.
- [ ] Thêm `conversation_id`, owner-scoped case memory và retention.
- [ ] Thêm planner allowlist theo consent/budget/deadline; out-of-scope không vào planner.
- [ ] Giữ deterministic fallback khi LLM/provider lỗi.

Exit: text, URL, message + URL và multi-turn fixtures chạy end-to-end đúng scope.

## Phase 2 — Brand, whitelist và official verification

- [ ] Brand/organization registry với official domain/contact provenance.
- [ ] Typosquat/lookalike/homograph matcher trả structured signal, không tự tạo malicious.
- [ ] First-class whitelist table/repository/admin API/UI và precedence trong scoring.
- [ ] Bounded OfficialClaimVerifier theo allowed purposes; `NOT_FOUND != FALSE`.
- [ ] DNS evidence tool nếu vẫn giữ DNS trong product scope summary.

Exit: safe-official, domain-mismatch-only và official-not-found regression pass.

## Phase 3 — Risk, UI và Human-in-the-loop

- [ ] Security Risk Engine policy version mới với strong-evidence threshold cho malicious.
- [ ] Chat UI nhiều lượt; out-of-scope và need-more-info states.
- [ ] Thay claim stance/history/admin copy bằng threat/risk/evidence/recommendation.
- [ ] Hoàn tất proposal creation và execution adapter cho block/global blacklist/broad warning.
- [ ] Thêm whitelist, domains, threats và audit-log views.

Exit: individual warning không chờ admin; wide action không thể bypass review/audit.

## Phase 4 — Security memory, campaign và legacy removal

- [ ] Security-memory store cho domain/fingerprint/brand/threat/report count/admin verdict.
- [ ] Campaign clustering dùng security fingerprint thay claim embedding.
- [ ] Ngừng toàn bộ writer vào `fact_check_*` và source-discovery tables.
- [ ] Đo zero reader/writer qua một release window; backup/export dữ liệu cần giữ.
- [ ] Alembic migration drop legacy tables/index/pgvector nếu không còn consumer.
- [ ] Xóa deprecated providers/config, frontend components, v2 routes và fixtures.

Exit: production profile không import/configure general fact-check modules.

## Phase 5 — Release evidence

- [ ] Versioned evaluation set theo threat và out-of-scope routing.
- [ ] Báo cáo precision/recall/false-positive, routing accuracy, grounding, latency và cost.
- [ ] Hosted deployment với OIDC, PostgreSQL worker, Redis và real security-provider smoke.
- [ ] Backup/restore, migration rollback, load, SSRF, auth/RBAC và prompt-injection tests.
- [ ] Runbook provider disable, scoring rollback, incident response và retention.

## Dependency order

```text
Scope gate
  → contract vNext
  → structured security context
  → brand + whitelist + official verifier
  → risk-vNext
  → chat/admin UI
  → security memory/campaign migration
  → legacy removal
  → hosted release evidence
```

Không bắt đầu destructive schema removal trước khi product flow mới chạy, telemetry cho thấy zero
legacy usage và backup/restore đã được kiểm chứng.
