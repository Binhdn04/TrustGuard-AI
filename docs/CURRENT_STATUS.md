# Current Status

**Updated:** 2026-08-22

`Implemented` nghĩa là có code và automated coverage trong repository, không đồng nghĩa đã verify trên
hosted production với OIDC, PostgreSQL, Redis và provider thật.

## Summary

Security Triage v4 và frontend investigation workspace đã implement end-to-end trong repository. Runtime
public chỉ còn `/api/v4`. Official Link Verification đã được triển khai hoàn chỉnh và có
automated/offline evidence. Production release chưa hoàn tất vì CP10 chưa có reviewed hosted evidence,
backup/restore rehearsal, load/failure testing và live-provider smoke.

## Implemented

| Area | Current state |
|---|---|
| Boundary | `/api/v4` only; v2/v3 không mount/OpenAPI |
| Scope | structured context, focused follow-up, recovery-first incident path |
| Investigation | rules, blacklist, DNS, redirects, RDAP, VirusTotal, consent/budget/deadline/SSRF |
| Trust/risk | versioned brand/whitelist, target-owner resolution, deterministic risk v1-v4, false-positive policy |
| User flow | context-aware conversations, history/resume, reports, appeals, owner isolation, event replay |
| Durable flow | PostgreSQL lease, encrypted payload, idempotency, outbox; SQLite inline fallback |
| Admin/HITL | review, `ADD_TO_BLACKLIST`, trust, memory/campaign, intelligence, audit |
| AI | optional understanding/planning/explanation; suggestion-only Admin Copilot |
| Official verification | publisher/claim/resource verification plus identity discovery v2, literal-title search, one-source exact-resource endorsement, guarded redirects, 7-day terminal-aware cache, typed ownership evidence, reviewed promotion and rollout `off|shadow|visible|enforced` |
| Evaluation | versioned offline security, memory, AI, immutable `security-v4-v2` official-link dataset and additive `security-identity-discovery-v3` cases |
| Frontend | Security Chat với case-context follow-up, Markdown giới hạn an toàn, tự chụp URL mới nhất trong RAM; Simple/Analyst views, history, Observatory, Review Room, Trust candidate queue/Audit |
| Schema | Alembic through `0019_security_identity_discovery` (one head) |

## Partial and pending

- `BLOCK_DOMAIN` và `PUBLISH_BROAD_WARNING` chưa có execution sink.
- Understanding, planning, explanation và Admin Copilot mặc định bật với kill switch riêng; thiếu provider ở local/test fallback an toàn, production yêu cầu cấu hình AI hợp lệ. Async và reviewed-memory vẫn mặc định tắt.
- Official Link Verification đã hoàn thành; CP10 release approval vẫn pending hosted evidence và Tech Lead/Security Lead review.
- Identity discovery v2 đã có local automated coverage; PostgreSQL/provider thật, reviewer workflow và rollout
  observation vẫn cần hosted validation trước enforced production.
- Chưa có hosted OIDC/PostgreSQL/Redis/VirusTotal evidence với credential thật.
- Chưa có production backup/restore, load, lease-loss và Redis-outage rehearsal.
- `0018_remove_vector_compat` cần backup và staging rehearsal trên database cũ.
- `0019_security_identity_discovery` additive vẫn cần staging migration/persistence parity smoke trên PostgreSQL.

## Deprecated and removed

- public v2/v3 routes và frontend compatibility clients/mocks/surfaces;
- legacy worker activation và analysis/re-embedding jobs;
- Google Web Risk và Google Fact Check configuration/wiring;
- ChromaDB/pgvector runtime và vector persistence;
- fact-check corpus, source-discovery và campaign-vector storage;
- Jina và flash-model configuration.

Pure-Python legacy utilities hoặc migration history còn lại chỉ phục vụ upgrade/regression, không phải
public capability.

## Remaining release gates

1. Deploy production-like staging với OIDC, PostgreSQL, Redis và worker.
2. Chạy backup/restore rehearsal và migration `0018` trên bản sao dữ liệu.
3. Chạy hosted provider, RBAC, SSRF/redirect, prompt-injection, retention và failure smoke.
4. Chạy load/lease/idempotency/outbox/WebSocket fallback checks.
5. Chạy Official Link Verification theo `shadow -> visible -> enforced -> visible -> off`, lưu observation window
   và rollback evidence cho từng stage.
6. Validate reviewed CP10 evidence bằng tooling trong [TESTING.md](TESTING.md), sau đó Tech Lead và Security Lead review.
7. Validate identity candidate TTL/revalidation, PostgreSQL versioning, RBAC promotion và exact-resource endorsement
   trong cùng hosted rollout windows; không dùng auto-verified association để tự kết luận `SAFE`.

Không giữ test count cũ trong status. Lấy kết quả mới từ CI hoặc chạy lệnh trong [TESTING.md](TESTING.md).
