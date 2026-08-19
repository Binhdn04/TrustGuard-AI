# Current Status

**Updated:** 2026-08-19

`Implemented` nghĩa là có code và automated coverage trong repository, không đồng nghĩa đã verify trên
hosted production với OIDC, PostgreSQL, Redis và provider thật.

## Summary

Security Triage v4 và frontend investigation workspace đã implement end-to-end trong repository. Runtime
public chỉ còn `/api/v4`. WP0–WP8 và phần code/local của WP9 đã hoàn thành; các implementation plan cũ đã
được hợp nhất vào đây và deprecated. Production release chưa hoàn tất vì thiếu hosted evidence,
backup/restore rehearsal, load/failure testing và live-provider smoke.

## Implemented

| Area | Current state |
|---|---|
| Boundary | `/api/v4` only; v2/v3 không mount/OpenAPI |
| Scope | structured context, focused follow-up, recovery-first incident path |
| Investigation | rules, blacklist, DNS, redirects, RDAP, VirusTotal, consent/budget/deadline/SSRF |
| Trust/risk | versioned brand/whitelist, deterministic risk v1/v2, false-positive policy |
| User flow | conversations, history/resume, reports, appeals, owner isolation, event replay |
| Durable flow | PostgreSQL lease, encrypted payload, idempotency, outbox; SQLite inline fallback |
| Admin/HITL | review, `ADD_TO_BLACKLIST`, trust, memory/campaign, intelligence, audit |
| AI | optional understanding/planning/explanation; suggestion-only Admin Copilot |
| Evaluation | versioned offline security, memory and AI datasets/reports with rollout guard |
| Frontend | Security Chat, Simple/Analyst views, Observatory, Review Room, Trust/Audit |
| Schema | Alembic through `0018_remove_vector_compat` |

## Partial and pending

- `BLOCK_DOMAIN` và `PUBLISH_BROAD_WARNING` chưa có execution sink.
- Async, reviewed-memory và AI flags mặc định tắt, chỉ bật tuần tự sau gate tương ứng.
- Chưa có hosted OIDC/PostgreSQL/Redis/VirusTotal evidence với credential thật.
- Chưa có production backup/restore, load, lease-loss và Redis-outage rehearsal.
- `0018_remove_vector_compat` cần backup và staging rehearsal trên database cũ.

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
5. Lưu evidence, bật capability tuần tự và kiểm tra rollback sau mỗi stage.

Không giữ test count cũ trong status. Lấy kết quả mới từ CI hoặc chạy lệnh trong [TESTING.md](TESTING.md).

