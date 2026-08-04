# Implementation Plan — P-068

> Tài liệu này chỉ định **ai làm gì, theo thứ tự nào và khi nào được coi là xong**. Mọi code phải tham chiếu contract v1 trong `02-CONTRACT_AND_FIXTURES.md`.

## 1. Nguyên tắc triển khai

1. Merge contract skeleton trước khi chia nhánh tính năng.
2. Phát triển trên fake adapters/fixtures; chỉ ghép provider thật sau khi contract test xanh.
3. Mỗi module có một owner kỹ thuật và reviewer chéo; owner không phải người duy nhất được code.
4. Thay đổi schema/enum/fixture expectation cần PR `contract-change` và review của các module bị ảnh hưởng.
5. Không sửa expected label chỉ để làm test xanh; thay scoring/prompt phải kèm lý do và eval result.

## 2. Module ownership

Thay `Member 1–4` bằng tên thật trước PR đầu tiên.

| Thành viên | Module sở hữu | Deliverable | Reviewer chính |
|---|---|---|---|
| Member 1 — Agent | `src/agents/{state,graph,nodes/**}`, risk engine | Graph, node routing, budget loop, deterministic scoring, node tests | Member 2, 4 |
| Member 2 — Tools/Data | `src/agents/tools/**`, `src/repositories/**`, migrations/ingestion | Protocol implementations, SSRF guard, fake + real adapters, fact-check/blacklist repositories | Member 1, 3 |
| Member 3 — API/Platform | `src/api/**`, `src/services/**`, `src/models/**`, `src/core/**`, deploy | API v1, auth/RBAC, persistence orchestration, WebSocket, audit, Docker | Member 1, 4 |
| Member 4 — Frontend/QA | frontend/API client, `tests/{contract,integration,eval,fixtures}/**`, `eval/**` | User/admin flows, fixtures, contract/regression/eval runner, demo script | Member 1, 3 |

Shared-file rules:

| Phạm vi | Owner | Review bắt buộc |
|---|---|---|
| `src/models/**` | Member 3 | Member 1 + 4 |
| `src/agents/state.py` | Member 1 | Member 2 + 3 |
| Tool protocols | Member 2 | Member 1 |
| `tests/fixtures/**` | Member 4 | Member 1 + 2 |
| Migration/Compose/env | Member 3 | Member 2 |

## 3. Thứ tự PR

### PR-0 — Contract freeze và project skeleton

**Lead:** Member 3; cả team review.

- Tạo package/repository layout theo Architecture.
- Khai báo Pydantic enum/schema, AgentState và tool protocols v1.
- Thêm 12 fixture skeleton, fake adapters và contract import tests.
- Thêm CI tối thiểu: lint, type check, unit/contract test; cập nhật `.gitignore` loại cache, `.env`, `.next`.

**Gate:** OpenAPI, AgentState và fixtures dùng cùng enum/tên trường; không còn contract song song.

### PR-1A đến PR-1D — Vertical modules chạy song song

| PR | Owner | Tasks | Gate riêng |
|---|---|---|---|
| PR-1A Agent core | Member 1 | classify/extract/normalize, planning loop, assessment, explanation boundary, fake-tool graph | Node tests; deterministic score; loop dừng đúng budget |
| PR-1B Tools/data | Member 2 | SSRF-safe URL client, reputation adapter, claim retriever, repositories, migrations | Adapter contract tests; timeout/no-hit/redirect/private-IP cases |
| PR-1C API/platform | Member 3 | create/get/list analysis, job queue, auth/RBAC, WebSocket/polling, reports/review/audit | API integration tests với fake agent; user isolation và 403 |
| PR-1D UI/eval | Member 4 | user form/progress/result/history; admin queue/detail/decision; fixture loader/eval runner | UI dùng generated contract; URL không clickable; offline fixture suite |

Các PR chỉ merge khi rebase trên PR-0 và không thay contract âm thầm.

### PR-2 — Integration trên fake dependencies

**Lead:** Member 4; Member 1 và 3 ghép luồng.

- Chạy end-to-end user analysis và admin review bằng fake adapters.
- Kiểm tra persistence, event ordering, retry/budget và audit transaction.
- Chạy toàn bộ fixture/safety invariant trong CI.

**Gate:** 12 fixture xanh; happy path, no-consent, timeout, SSRF và admin review chạy end-to-end.

### PR-3 — Provider thật và hardening

**Lead:** Member 2.

- Cấu hình một URL reputation provider và fact-check source thật sau feature flag.
- Thêm rate limit, cache, provider timeout/retry, redaction và observability metadata.
- Kiểm tra migration, container healthcheck và local Docker Compose.

**Gate:** provider smoke test thủ công trong môi trường test; CI vẫn offline; không lộ secret/raw payload.

### PR-4 — Evaluation, tuning và release candidate

**Lead:** Member 4; cả team sign-off.

- Chạy golden set và failure set; phân tích false positive/negative.
- Chỉ tinh chỉnh scoring/prompt sau khi ghi baseline và impact.
- Chạy security checklist, load/latency smoke test và demo rehearsal.
- Hoàn thiện README, `.env.example`, migration/rollback và demo seed.

**Gate:** toàn bộ acceptance criteria có automated test hoặc kịch bản nghiệm thu được lưu; không có blocker severity cao.

## 4. Task checklist theo thành viên

### Member 1 — Agent

- [ ] Implement state reducers và graph edges.
- [ ] Implement extraction fallback không bịa trường thiếu.
- [ ] Enforce tool allowlist, max calls/retries/time budget.
- [ ] Implement scoring `risk-v1`, verdict/confidence và grounded explanation.
- [ ] Test determinism, provider failure, no-consent và loop termination.

### Member 2 — Tools/Data

- [ ] Implement internal result models và fake adapters trước.
- [ ] Implement SSRF validation trước/sau DNS và redirect.
- [ ] Implement reputation/fact-check adapters với timeout, cache, rate limit.
- [ ] Implement analysis/evidence/review/blacklist repositories và migrations.
- [ ] Seed approved official domains/fact-check corpus có provenance.

### Member 3 — API/Platform

- [ ] Implement API v1, ownership checks và error envelope.
- [ ] Implement queue worker boundary, WebSocket và polling events.
- [ ] Implement auth/RBAC, report/review action và atomic audit write.
- [ ] Configure settings, redacted logging, Docker/Compose và healthchecks.
- [ ] Publish OpenAPI artifact cho frontend/contract tests.

### Member 4 — Frontend/QA

- [ ] Implement consent-aware submit/progress/result/history screens.
- [ ] Implement admin review queue/detail/decision screens.
- [ ] Disable direct navigation for suspicious URLs; render evidence/limitations.
- [ ] Complete fixtures, fake data loader, contract/integration/eval suites.
- [ ] Prepare two demo flows and record expected outputs.

## 5. Branch, review và merge policy

- Branch: `feat/<module>-<short-name>`; PR nhỏ, một mục tiêu, có test.
- Dependency order: PR-0 → PR-1* → PR-2 → PR-3 → PR-4.
- Không import ngược từ `agents/tools` hoặc repositories vào API; agent nodes không import provider SDK trực tiếp.
- CODEOWNERS theo bảng shared files; PR contract-change cần Member 1, 3 và 4 duyệt.
- Không commit `.env`, key, provider raw response thật, database dump, build/cache/log.

## 6. Definition of Done

Một task chỉ Done khi code, test và tài liệu liên quan cùng PR; lint/type/test xanh; error path được xử lý; không thêm secret/log nhạy cảm.

MVP Done khi:

- API và UI tuân thủ contract v1; frontend build được từ OpenAPI/fixtures.
- 12 fixtures chạy offline, deterministic; CI không gọi provider thật.
- Consent, SSRF, timeout, RBAC, user isolation, HITL, blacklist audit đều có test.
- Có thể thay provider mà không sửa graph hoặc public schema.
- Docker Compose khởi động API, worker, PostgreSQL/pgvector và Redis; migration chạy sạch.
- Demo chạy trọn hai flow: user phân tích và admin review.
- Mọi AC-01…AC-16 có test tự động hoặc evidence nghiệm thu được lưu.
- README mô tả setup, test, demo, cấu hình provider và giới hạn MVP.
