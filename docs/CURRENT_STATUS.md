# Current Status

**Updated:** 2026-08-29

`Implemented` nghĩa là có code và automated coverage trong repository, không đồng nghĩa đã verify trên
hosted production với OIDC, PostgreSQL, Redis và provider thật.

## Summary

Security Triage v4 và frontend investigation workspace đã implement end-to-end trong repository. Runtime
public chỉ còn `/api/v4`. Official Link Verification đã được triển khai hoàn chỉnh và có
automated/offline evidence. Production release chưa hoàn tất vì CP10 chưa có reviewed hosted evidence,
backup/restore rehearsal, load/failure testing và live-provider smoke.

Streaming coarse progress đã có code và local verification cho event contract, reporter fail-open, pipeline,
PostgreSQL ordering/retry và frontend replay/presentation. Async production vẫn tắt; chưa có hosted evidence cho
backend/worker cùng artifact, Redis/WebSocket fallback, owner/ticket smoke hoặc operational metrics.

Chrome Extension Phase 0 repository-local/MVP đã `DONE` theo project-owner instruction của documentation task ngày
2026-08-29; đây không phải production/Store approval. Phase 1 và Phase 2 implementation đã `COMPLETE`, automated
verification `PASS`: Manifest V3 scaffold, đúng hai context menu, selection/link normalization, pending capture TTL trong
trusted `storage.session`, trusted runtime messaging và text-only Side Panel preview/cancel đã có. Extension không có host
permission, content script, network, OIDC hoặc API submission. Phase 1/2 exit gate còn
`PENDING MANUAL CHROME CAPTURE SMOKE`; Phase 3+ chưa bắt đầu. Delivery order đã chốt là hoàn tất unpacked extension với local
backend/frontend trước, sau đó mới setup Railway internal, rồi mới chuẩn bị Chrome Web Store/production GA.

Phạm vi UI của MVP đã hoàn tất trong workspace: một navigation/sidebar dùng chung, user có hai mục chính và
`security_admin` có thêm **Duyệt bảo mật** cùng **Tin cậy & chặn**. Login local vẫn hỗ trợ demo khi được cấu hình;
hosted dùng OAuth/OIDC. Bản code hiện tại chưa được deploy để chạy smoke OAuth bằng hai danh tính thật.

## Implemented

| Area | Current state |
|---|---|
| Boundary | `/api/v4` only; v2/v3 không mount/OpenAPI |
| Scope | structured context, focused follow-up, recovery-first incident path |
| Investigation | rules, blacklist, DNS, IANA RDAP + optional BKNS WHOIS v2 routing, VirusTotal, optional Cloudflare Radar domain ranking, consent/budget/deadline/SSRF |
| Trust/risk | versioned brand/whitelist, reviewed first-party/shared-platform familiarity, target-owner resolution, deterministic risk v1-v7 with action-intent assurance, false-positive policy |
| User flow | context-aware conversations, history/resume, reports, appeals, owner isolation, event replay |
| Durable flow | PostgreSQL lease, encrypted payload, idempotency, outbox; SQLite inline fallback |
| Streaming progress | coarse allow-listed stages, ordered fail-open reporter, PostgreSQL event replay/cursor and frontend WebSocket/polling presentation |
| Persistence | PostgreSQL facade tách feedback, jobs/outbox, trust và Wave 2 thành domain mixins; integration suite chạy trên PostgreSQL 16 disposable trong CI |
| Admin/HITL | review, `ADD_TO_BLACKLIST`, trust, memory/campaign, intelligence, audit |
| AI | optional understanding/planning/explanation; backend span candidates + model-selected IDs; per-candidate fail-soft grounding; suggestion-only Admin Copilot |
| Official verification | publisher/claim/resource compatibility plus URL-routed domain ownership/sender identity/action endorsement, resource-first identity discovery, bounded attribution, two-host ownership, guarded redirects, 7-day consent-gated cache, action-relevant SAFE policy, reviewed promotion and rollout `off|shadow|visible|enforced` |
| Evaluation | versioned offline security, memory, AI, immutable `security-v4-v2` official-link dataset and additive `security-identity-discovery-v3` cases |
| Frontend | UI MVP tiếng Việt; một navigation/sidebar; user có Kiểm tra/Lịch sử, còn Hồ sơ/Cài đặt nằm trong menu avatar; admin có thêm Duyệt bảo mật và Tin cậy & chặn; whitelist/blacklist thao tác trực tiếp với trạng thái/audit; route Observatory/Audit cũ redirect về Trust workspace |
| Chrome Extension | Phase 0 `DONE`; Phase 1/2 implementation `COMPLETE`, automated verification `PASS`, manual Chrome capture smoke `PENDING`; Phase 3+ `NOT STARTED` |
| Testing | `pytest-cov` gate `68%`, default offline suite và PostgreSQL integration job riêng; xem bằng chứng hiện hành trong `docs/TESTING.md` |
| Schema | Alembic through `0022_action_assurance_metadata` (one head) |

## Partial and pending

- `BLOCK_DOMAIN` và `PUBLISH_BROAD_WARNING` chưa có execution sink.
- Understanding, planning, explanation và Admin Copilot mặc định bật với kill switch riêng; thiếu provider ở local/test fallback an toàn, production yêu cầu cấu hình AI hợp lệ. Async và reviewed-memory vẫn mặc định tắt.
- Official Link Verification đã hoàn thành; CP10 release approval vẫn pending hosted evidence và Tech Lead/Security Lead review.
- Identity discovery v2 đã có local automated coverage; PostgreSQL/provider thật, reviewer workflow và rollout
  observation vẫn cần hosted validation trước enforced production.
- Domain familiarity mặc định `off`; reviewed-platform manifest/admin seed tooling đã có nhưng cần Security Admin
  review/apply trên staging. Radar cache/timeout/429 và inline/worker parity vẫn cần hosted smoke trước `enforced`.
- Chưa có hosted OIDC/PostgreSQL/Redis/VirusTotal evidence với credential thật.
- BKNS WHOIS v2 đã có adapter/routing/cache/privacy/error automated coverage; key là optional và vẫn cần live-provider
  smoke cho `.vn`, RDAP capability fallback, rate limit và timeout trước production rollout.
- Chưa có production backup/restore, load, lease-loss và Redis-outage rehearsal.
- `0018_remove_vector_compat` cần backup và staging rehearsal trên database cũ.
- `0019_security_identity_discovery` additive vẫn cần staging migration/persistence parity smoke trên PostgreSQL.
- `0020_report_audit_details` additive vẫn cần staging migration smoke trên PostgreSQL trước khi deploy luồng report remediation.
- `0021_security_blacklist_v4` đổi unique constraint của proposal pending và mở rộng audit resource; vẫn cần staging PostgreSQL migration/restart smoke.
- `0022_action_assurance_metadata` additive lưu `policy_metadata` riêng cho analysis và reserve
  `assurance_metadata` trên feedback audit. Runtime đã ghi analysis metadata; audit column hiện giữ default `{}` và
  vẫn cần staging migration cùng end-to-end write/read validation trước khi được dùng.
- PostgreSQL 16 disposable local đã migrate sạch đến `0022` và integration suite đạt 5 tests ngày 2026-08-28;
  điều này không thay thế staging/production persistence, worker hoặc Redis evidence.
- Streaming progress/async chưa có hosted readiness, worker artifact/heartbeat, Redis outage/cursor fallback,
  owner/ticket reconnect/final-fetch smoke hay latency/event-volume observation. Async production vẫn mặc định tắt
  và chỉ được bật theo approval gate trong `DEPLOYMENT.md`.
- Chrome Extension chỉ sẵn sàng cho local unpacked capture smoke. Capture boundary đã implement; OIDC, backend origin
  allow-list, submit, progress và web handoff chưa implement. Phase 3–8 sẽ được implement/verify với unpacked extension + local TrustGuard
  stack; local ID chỉ nằm trong untracked exact-origin config nếu cần. Stable Railway/internal ID cùng hosted OIDC/origin
  là Phase 9 gate; production Store ID, listing/review và GA approval là Phase 10 gate. Không mục nào là Phase 0/local
  implementation blocker.
- Luồng MVP report → admin resolution/remediation → phân tích lại → audit đã có automated integration coverage
  trên local SQLite, nhưng chưa có smoke production với hai phiên OAuth thật `user` và `security_admin`.

## MVP UI scope

- Bề mặt admin công khai trong MVP chỉ gồm **Duyệt bảo mật** (`/admin/review`) và **Tin cậy & chặn**
  (`/admin/trust`). Không tạo sidebar thứ hai hoặc thứ ba theo role.
- Hồ sơ và Cài đặt chỉ truy cập từ menu avatar góc phải; route `/profile` vẫn được giữ nhưng không lặp lại trong
  sidebar hoặc navigation di động.
- Whitelist cho phép admin tạo/vô hiệu hóa trực tiếp. Blacklist cho phép tạo/vô hiệu hóa proposal trên UI,
  nhưng thay đổi chỉ có hiệu lực sau một quyết định review rõ ràng và được ghi immutable audit.
- Khi report đề xuất blacklist, quyết định report chỉ tạo action `pending_review`; admin phải xác nhận hoặc từ chối
  action liên kết. Thất bại/từ chối giữ `admin_action_id` để truy vết và đặt remediation của report là `failed`.
- Brand, identity candidate, Security Memory, campaign, intelligence, Observatory và audit độc lập là các khả năng
  nâng cao vẫn còn ở API/component nội bộ khi cần vận hành hoặc phát triển tiếp, nhưng đã bị ẩn khỏi navigation MVP.
- Whitelist chỉ là ngoại lệ có provenance; reviewed platform familiarity chỉ mô tả platform quen thuộc; official
  identity kiểm tra domain ownership, sender identity và action endorsement riêng. Không nguồn nào được suy rộng
  để xác minh nội dung do người dùng tạo trên shared platform hoặc tự động kết luận `SAFE`.

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
7. Validate identity candidate TTL/revalidation, PostgreSQL versioning, RBAC promotion, exact-resource endorsement
   và action-relevant SAFE behavior trong cùng hosted rollout windows; auto-verified evidence chỉ áp dụng cho đúng
   resource/action đã kiểm chứng, không mở rộng thành brand trust.
8. Review/apply platform manifest, quan sát familiarity ở `visible`, rồi kiểm tra Radar coverage/cache/p95/429 và
   Google Forms/shared-content regressions trước khi bật `enforced`.
9. Deploy code MVP hiện tại, chạy smoke OAuth bằng user/admin thật và xác minh report → whitelist/blacklist →
   re-analysis → immutable audit trên PostgreSQL; rejected/unreviewed report không được ảnh hưởng risk.

Không giữ test count cũ trong status. Lấy kết quả mới từ CI hoặc chạy lệnh trong [TESTING.md](TESTING.md).
