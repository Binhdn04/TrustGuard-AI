# Implementation Plan Summary

Tài liệu này là roadmap rút gọn. Trạng thái WP, command test và scope deviation chi tiết nằm tại
[SECURITY_TRIAGE_IMPLEMENTATION_PLAN.md](SECURITY_TRIAGE_IMPLEMENTATION_PLAN.md). Trạng thái code tổng
thể nằm tại [implementation-status.md](implementation-status.md).

**Hiện tại:** Security v4, frontend workspace và local WP9 evaluation/cutover tooling đã hoàn thành;
public v2/v3 và pgvector cleanup đã có trong revision `0018`; hosted release evidence và restore rehearsal còn lại.

## Phase 0 — Product boundary và scope gate — DONE FOR SECURITY V4

- [x] Tách `/api/v4` Security Triage khỏi `/api/v2`/`/api/v3` legacy profile.
- [x] Security Scope Classifier kết thúc sớm cho general fact-check/news/politics/sports/science/medical.
- [x] Test terminal out-of-scope không resolve investigation hoặc legacy analysis service.
- [x] Security frontend không hiển thị claim stance hoặc medical/news examples.
- [x] Security v4 risk không dùng legacy rule `REFUTES => MALICIOUS`.
- [x] Tháo public v2/v3, legacy worker activation và source-discovery runtime — WP9.

Exit hiện đạt: runtime và OpenAPI chỉ quảng bá Security v4.

## Phase 1 — Contract và core triage — DONE

- [x] Contract v4 có scope decision, structured security context và security risk taxonomy.
- [x] Scenario/threat extraction cho phishing, impersonation, financial, recruitment, promotion/prize
  và credential/OTP theft.
- [x] Owner-scoped conversation, optimistic version, redacted summary và retention.
- [x] Planner allowlist theo normalized target, consent, budget, retry và deadline.
- [x] DNS, redirect, RDAP, reputation và blacklist evidence với normalized provider error.
- [x] Deterministic risk/explanation fallback; provider failure không làm hỏng core result.

Exit: text, URL, text + URL, no-consent và multi-turn tests chạy đúng Security scope.

## Phase 2 — Brand và whitelist — DONE

- [x] Brand registry có alias, official domain/contact, provenance, lifecycle và reviewer.
- [x] Brand mismatch/lookalike signal không tự tạo malicious.
- [x] First-class whitelist SQLite/PostgreSQL/admin API/UI và precedence trong risk policy.
- [x] DNS là investigation evidence/tool riêng, vẫn dùng safe resolver/SSRF guard.

Exit: safe whitelist, domain mismatch only và Unicode/homograph regressions pass.

## Phase 3 — Risk, Security Chat và HITL — DONE WITH EXPLICIT SINK LIMITS

- [x] `security-risk-v1` với strong-evidence threshold và grounded evidence refs.
- [x] Feature-gated `security-risk-v2` cho reviewed Security Memory; safe/false-positive chỉ giảm weak heuristic.
- [x] Multi-turn Security Chat; out-of-scope và need-more-info có presentation riêng.
- [x] History/result/admin copy dùng threat/risk/evidence/recommendation semantics.
- [x] High-risk v4 producer tạo idempotent reviewed `ADD_TO_BLACKLIST` proposal.
- [x] Approve/reject/executed/failed state machine, rollback semantics và immutable action audit.
- [x] Admin views cho action audit, brand, whitelist, memory và campaign.
- [ ] Execution sink thật cho `BLOCK_DOMAIN`, `PUBLISH_BROAD_WARNING` — chỉ triển khai khi có downstream
  system thật; hiện approved attempt phải `FAILED/ACTION_SINK_NOT_CONFIGURED`.
- [x] Admin Copilot WP7 suggestion-only, grounded/audited/rate-limited và không gọi execution sink.
- [x] Dedicated domain/threat explorer và unified v4 audit API/browser.

Exit đạt cho individual warning và blacklist action: user warning không chờ admin; side effect không thể
bypass review/audit. Không tuyên bố wide-action coverage cho action chưa có sink.

### WP9A — API readiness và contract freeze — DONE

- [x] Truthful capabilities/release profile; action execution đã chuyển sang v4.
- [x] Owner-scoped analysis/conversation pages và resume contract.
- [x] Admin report/appeal queue, terminal review decision, RBAC/conflict protection và immutable audit.
- [x] Paginated/filter/search pages cho trust, memory, campaign; domain/threat explorer và unified v4 audit.
- [x] PostgreSQL/SQLite persistence, Alembic `0018`, OpenAPI/contract/repository regression tests.
- [x] Frontend dùng contract v4 cho chat/case workspace, history, Observatory, Review Room, Trust và Audit;
  không còn frontend compatibility surface hoặc v2/v3 client.

## Phase 4 — Security Memory, campaign và legacy removal — DONE LOCALLY

### Hoàn thành ở WP8

- [x] Structured Security Memory cho domain/URL fingerprint/brand/threat/risk/report count/admin verdict.
- [x] Privacy-minimized persistence: không raw conversation hoặc URL query token.
- [x] Explainable `security-fingerprint-v1`/`security-clustering-v1`, không dùng claim embeddings.
- [x] Reviewer-gated campaign hypothesis và immutable correction/review audit.
- [x] SQLite/PostgreSQL schema/store và admin Memory/Campaign views.

### Hoàn thành ở WP9

- [x] Public v2/v3 routes, telemetry và legacy worker activation đã bị xóa.
- [x] Frontend compatibility components, clients, mocks và mappers đã bị xóa.
- [x] Migration `0018_remove_vector_compat` xóa legacy fact-check/source-discovery/vector tables và extension.
- [x] Fresh migration history chỉ yêu cầu PostgreSQL thường.
- [ ] Backup/export/restore rehearsal cho deployment thật trước khi áp dụng migration phá hủy dữ liệu.

Exit chỉ đạt khi production profile không import/configure/call general fact-check modules và rollback
evidence đã được lưu.

## Phase 5 — Evaluation và release evidence — IN PROGRESS (WP9)

- [x] Versioned deterministic evaluation set theo threat, safe/mismatch/no-hit/OOS/multi-turn/wide-action.
- [x] Báo cáo routing accuracy, provider-call rate, precision/recall/false-positive, grounding,
  latency và cost.
- [ ] Hosted deployment smoke với OIDC, PostgreSQL worker/readiness, Redis và real security providers.
- [ ] PostgreSQL migration upgrade/downgrade, backup/restore và retention verification.
- [ ] Load, SSRF/redirect, auth/RBAC, prompt-injection, lease-loss và idempotency tests.
- [x] Runbook provider disable, scoring/schema rollback, incident response, retention, restore và migration cleanup.

## Dependency order còn lại

```text
WP0–WP8 complete
  → API readiness + frontend workspace complete
  → local versioned evaluation complete
  → legacy API/frontend/runtime cleanup complete
  → backup/restore and rollback rehearsal
  → apply migration 0018 on staging then production
  → final release evidence
```

Không áp dụng migration `0018` trên production trước backup/export và restore test.
