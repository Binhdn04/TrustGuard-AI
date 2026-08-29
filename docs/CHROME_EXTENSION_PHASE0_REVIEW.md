# Chrome Extension Phase 0 — Product and Security Review

## Trạng thái

- Work package: Phase 0 của [Chrome Extension Implementation Plan](CHROME_EXTENSION_IMPLEMENTATION_PLAN.md).
- Phase 0 technical baseline: **DONE**.
- Phase 0 repository-local/MVP gate: **APPROVED FOR MVP / repository-local** theo project-owner instruction của
  documentation task ngày 2026-08-29.
- Approval scope: product scope, data-flow/minimization, permission budget, threat model, baseline consent/privacy/support
  copy và characterization evidence trong repository.
- Không phải approval cho production, hosted rollout, external security audit hoặc Chrome Web Store submission.
- Stable Railway internal/Chrome Web Store IDs: chưa reserve và được defer đúng sang Phase 9/10; không phải Phase 0
  hoặc local implementation blocker.
- Phase 1/2 local scaffold và capture boundary đã implement, automated verification đã pass; manual Chrome capture
  smoke vẫn pending.
- Runtime backend/frontend và AI pipeline: không thay đổi bởi Phase 0/1/2 local extension work.
- Automated evidence: `tests/unit/test_chrome_extension_phase0_baseline.py` và
  `tests/unit/test_streaming_progress_phase0_baseline.py`.
- Fixture version: `chrome-extension-phase0-v1` tại
  `tests/fixtures/chrome_extension/phase0_cases.json`.

Không dùng tài liệu này như bằng chứng hosted hoặc phê duyệt rollout. Phase 0 khóa product/security boundary và
characterization baseline cho repository-local MVP. Project-owner approval thay Product/Security review độc lập chỉ
trong phạm vi này; Railway hosted và production/Store vẫn cần các gate riêng ở Phase 9/10.

## Quyết định kỹ thuật

| ID | Quyết định | Lý do | Trạng thái |
|---|---|---|---|
| D0-01 | Chrome desktop 116+ | `sidePanel.open()` có thể mở từ context-menu user gesture; tránh fallback UI thứ hai | Chốt kỹ thuật |
| D0-02 | Chỉ hai capture type `selection` và `link` | Đủ cho MVP và tạo data boundary nhỏ, dễ giải thích | Chốt kỹ thuật |
| D0-03 | Context menu là capture path chính | Chrome cung cấp `selectionText`/`linkUrl`; không cần content script thường trực | Chốt kỹ thuật |
| D0-04 | Content Script chỉ inject on-demand nếu thêm toolbar/keyboard | Tránh `<all_urls>` và không đọc DOM nền | Chốt kỹ thuật |
| D0-05 | Extension là client mỏng của `/api/v4` | Giữ một pipeline, một contract, một owner boundary và một risk authority | Chốt kỹ thuật |
| D0-06 | Consent mặc định `false` và được xác nhận lại cho từng submit | Consent không kế thừa qua capture/request/conversation | Approved for MVP/repository-local |
| D0-07 | Không thu page URL/title/DOM/HTML/cookie/form/history/referrer | Những dữ liệu này không cần cho hai use case MVP | Chốt kỹ thuật |
| D0-08 | Raw capture chỉ tồn tại tạm trong `storage.session` | Service worker có thể restart nhưng raw content không được persist lâu dài | Chốt kỹ thuật |
| D0-09 | Final `/api/v4` response là authority | Progress không được tạo verdict hoặc thay đổi pipeline | Chốt kỹ thuật |
| D0-10 | Local unpacked ID không phải deployment identity; Railway internal và Store production dùng stable ID riêng + exact allow-list | Tách OIDC redirect/origin/revocation theo environment | Strategy chốt; reserve IDs ở Phase 9/10 |

Nguồn platform được dùng cho các quyết định trên:

- [Chrome Side Panel API](https://developer.chrome.com/docs/extensions/reference/api/sidePanel)
- [Chrome contextMenus API](https://developer.chrome.com/docs/extensions/reference/api/contextMenus)
- [The activeTab permission](https://developer.chrome.com/docs/extensions/develop/concepts/activeTab)
- [Extension service-worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)
- [Chrome manifest key](https://developer.chrome.com/docs/extensions/reference/manifest/key)
- [Chrome Extension storage](https://developer.chrome.com/docs/extensions/reference/api/storage)
- [Chrome Extension security guidance](https://developer.chrome.com/docs/extensions/develop/security-privacy/stay-secure)

## Stable extension ID registry

Strategy local-first đã chốt:

- Local dùng unpacked extension ID hiện Chrome cung cấp. Nếu auth/origin local cần ID, chỉ cấu hình exact value trong
  untracked local config; không wildcard, không commit và không coi đây là deployment identity.
- Railway internal dùng một stable ID từ developer-managed manifest public key hoặc Developer Dashboard draft item trước
  Phase 9 hosted OIDC/origin setup; không cần publish Store và private key không vào repository.
- Nếu sau này tạo Railway staging riêng thì staging có stable ID riêng trước staging smoke.
- Chrome Web Store production reserve Store item ID ở Phase 10, sau khi Railway internal đã đạt.

Không stable ID nào là điều kiện để đóng Phase 0 hoặc implement/verify local Phase 1–8.

| Environment | Extension identity | OIDC client | Backend allow-list | Owner/status |
|---|---|---|---|---|
| Local unpacked | Runtime ID; không ghi vào registry | Local-only/untracked khi cần | Exact local runtime ID; untracked | Không cần reserve |
| Railway internal | TBD stable ID | TBD | TBD exact origin | Reserve tại Phase 9 |
| Railway staging (optional) | TBD nếu environment được tạo | TBD | TBD exact origin | Không áp dụng hiện tại |
| Chrome Web Store production | TBD Store item ID | TBD | TBD exact origin | Reserve tại Phase 10 |

Không dùng local unpacked ID cho Railway/Store, không dùng wildcard `chrome-extension://*`, và không điền ID giả vào
registry.

## Capture và data-flow boundary

```text
User gesture
   ↓
contextMenus(selectionText | linkUrl)
   ↓
Background validates {captureId, kind, value, createdAt}
   ↓
storage.session pending draft (TTL 5 phút)
   ↓
Side Panel preview + request-scoped consent + Submit
   ↓
Background OIDC boundary → POST /api/v4/analyses
   ↓
Backend pipeline + event store
   ↓
Ticketed WebSocket / owner-scoped polling
   ↓
Side Panel final → fixed-host /cases/{analysisId}
```

### Dữ liệu được phép

| Stage | Dữ liệu | Retention đề xuất | Consumer |
|---|---|---|---|
| Capture draft | `captureId`, `kind`, selected text hoặc explicit link, `createdAt` | Tối đa 5 phút trong `storage.session`; xóa khi cancel/accepted/final | Background + Side Panel |
| Consent | Hai boolean của request hiện tại | Chỉ đi cùng request; không dùng làm default request sau | Background + backend |
| Auth transaction | state, nonce, PKCE verifier, redirect URI | Đến khi callback/timeout; session-only | Background |
| Access token | Token + expiry tối thiểu | Đến expiry/logout/browser restart; session-only | Background, không gửi Side Panel/Content Script |
| Active analysis | analysis ID, cursor, UI state, timestamps | Tối đa browser session và 24 giờ; không có raw capture | Background + Side Panel |
| Backend request | `SecurityTriageCreateRequestV4.message`, consent, execution mode | Theo retention/encryption hiện hành của `/api/v4` | Security Triage pipeline |
| Final UI | Scope/risk/summary/actions/limitations từ final response | In-memory/session presentation; backend là source of truth | Side Panel |

Backend retention hiện hành vẫn áp dụng: async request payload được mã hóa và có expiry; analysis/conversation chỉ giữ
structured/minimized content theo policy. Phase extension không được mở rộng retention hoặc tạo client history mới.

### Dữ liệu bị cấm trong capture envelope/telemetry

- page URL của tab nguồn, page title, favicon hoặc referrer;
- full DOM, HTML, screenshot hoặc surrounding text ngoài selection;
- cookie, website local/session storage, form value hoặc clipboard;
- browser history, request/response traffic hoặc tab list;
- bearer token, WebSocket ticket, OIDC raw claims hoặc provider payload;
- raw capture, domain/link query, OTP/credential trong log, metric, crash report hoặc analytics.

Link capture giữ exact HTTP(S) target do user chọn vì path/query có thể cần cho exact-resource investigation. Client loại
credentials và fragment; backend tiếp tục SSRF/redirect validation. Query không được copy sang telemetry hoặc durable
ledger không cần query.

## Consent và disclosure copy đề xuất

Copy dưới đây đã được project owner chấp nhận cho MVP/repository-local. Đây chưa phải approved Railway-hosted/Chrome
Web Store copy và vẫn phải được review lại ở Phase 9/10.

### Trước preview/submit

> TrustGuard chỉ phân tích nội dung hoặc liên kết bạn vừa chọn. Không gửi mật khẩu, OTP, token hoặc dữ liệu riêng tư
> không cần thiết.

### External URL lookup

Label:

> Cho phép kiểm tra liên kết bằng dịch vụ bảo mật bên ngoài cho lượt này.

Giải thích:

> Khi bật, TrustGuard có thể gửi domain hoặc liên kết cần thiết tới nhà cung cấp bảo mật. Quyền này không được ghi nhớ
> cho lượt kiểm tra sau.

### Official source lookup

Label:

> Cho phép đối chiếu tổ chức hoặc liên kết với nguồn công khai chính thức cho lượt này.

Giải thích:

> Khi bật, TrustGuard có thể tạo truy vấn tối thiểu từ nội dung đã chọn để tìm nguồn công khai. Quyền này không được
> ghi nhớ cho lượt kiểm tra sau.

### Support policy MVP

- Hỗ trợ Chrome desktop stable từ version 116.
- Hỗ trợ hai thao tác chủ động: selected text và link context menu.
- Không cam kết chạy trên trang đặc quyền `chrome://`, Chrome Web Store hoặc trang bị browser chặn extension.
- Không hỗ trợ background auto-scan, full-page capture, incognito workflow hoặc browser khác trong MVP.
- Auth/network/provider lỗi dùng error code và safe message; support không yêu cầu user gửi token, OTP hoặc raw private
  capture.
- Case đã accepted được tiếp tục xử lý ở backend dù Side Panel đóng; user mở lại từ web history/full-case route.

## Permission budget

Required cho MVP:

| Permission | Mục đích |
|---|---|
| `contextMenus` | Tạo hai user-gesture capture actions |
| `identity` | OIDC Authorization Code + PKCE flow |
| `sidePanel` | Draft/progress/final UI |
| `storage` | Session-only auth/capture/active-analysis state |
| API/OIDC exact host permissions | Authenticated API call và token exchange tới host đã cấu hình |

Không request trong MVP: `<all_urls>`, `tabs`, `cookies`, `history`, `webRequest`, `clipboardRead`,
`unlimitedStorage`, persistent content scripts hoặc externally-connectable wildcard. `activeTab` và `scripting` chỉ
được thêm khi toolbar/keyboard capture có implementation và review riêng.

## Threat model

| Threat | Security impact | Control bắt buộc | Verification/phase |
|---|---|---|---|
| Hostile page giả internal message | Arbitrary API call hoặc token exfiltration | Discriminated union, sender validation, không nhận arbitrary URL/header | Phase 1–2 unit/E2E |
| Content Script bị page thao túng | Privilege escalation | Không giữ token; chỉ gửi bounded capture; background revalidate | Phase 1–2 |
| Thu thừa page data | Privacy breach | Context-menu fields only; no persistent script/DOM read | Phase 0 fixture + manifest audit |
| User vô tình gửi secret | Credential/OTP exposure | Preview, warning, explicit submit; no telemetry; transient storage | Phase 2 UI/privacy tests |
| Malicious URL scheme/credential URL | Script execution hoặc credential leak | Chỉ absolute HTTP(S); reject credentials/fragment; backend SSRF guard | Phase 0 fixture schema + Phase 2 tests |
| Consent confusion/reuse | Unauthorized external lookup | Defaults false; consent stored only in current request body | Phase 0 baseline + Phase 5 tests |
| Token theft từ Side Panel/page | Account takeover | Background-only token; PKCE; session storage trusted contexts; exact CSP | Phase 3 local + Phase 9 hosted tests |
| XSS qua selection/provider text | Extension privilege compromise | Text/React nodes only; no raw HTML/remote code; exact CSP | Phase 1/7 CSP + UI tests |
| WebSocket ticket replay | Cross-user event access | Short TTL, single use, analysis/user binding, exact Origin | Existing v4 + Phase 6 local + Phase 9 hosted tests |
| Service worker restart | Duplicate case/lost state | Session state + stable `captureId` idempotency; authoritative replay | Phase 5/6 tests |
| Progress spoof/out-of-order | False warning/verdict | Validate analysis ID, dedupe event ID, monotonic sequence, final fetch authority | Existing progress + Phase 6 |
| Deep-link injection | Open arbitrary/phishing page | Fixed configured web host + validated UUID only | Phase 7 tests |
| Extension ID spoof/config drift | Unauthorized origin/OIDC redirect | Local ID untracked; Railway/Store stable IDs riêng; exact allow-list, no wildcard | Phase 4 local + Phase 9/10 hosted tests |
| Provider timeout/no-hit | False `SAFE` | Preserve `INSUFFICIENT_EVIDENCE`; deterministic risk authority | Phase 0 fixture baseline |
| OOS/need-info opens providers | Boundary/cost/privacy violation | Terminal scope before investigation/provider stage | Phase 0 fixture baseline |

Residual risks requiring explicit review:

- selected text may itself contain private data even when capture is user-initiated;
- exact link query can contain a secret needed for diagnosis but must not reach logs/telemetry;
- browser/extension compromise is outside application containment; short retention and narrow permissions reduce impact;
- async progress trên Railway/production remains dependent on hosted worker/Redis/PostgreSQL readiness and approval.

## Versioned characterization fixtures

| Fixture | Capture | Branch | Locked baseline |
|---|---|---|---|
| `selection_otp_in_scope` | Selection | In scope | `HIGH_RISK`, local context only, zero provider calls |
| `selection_general_fact_check` | Selection | Out of scope | Terminal, no tool plan/provider calls |
| `selection_need_more_info` | Selection | Need more info | Terminal, no tool plan/provider calls |
| `link_without_external_consent` | Link | No consent | External steps skipped, zero provider calls, not `SAFE` |
| `link_provider_error` | Link | Provider timeout/error | Exact tool order/targets/count; `INSUFFICIENT_EVIDENCE` |
| `link_provider_no_hit` | Link | Provider no-hit | Four planned provider calls; `INSUFFICIENT_EVIDENCE` |

Mỗi fixture chạy cả `execution_mode=inline` và `execution_mode=async` qua scope boundary. Test loại bỏ dynamic IDs/time và
yêu cầu structured security semantics deep-equal. Việc này không bật async production và không thay thế PostgreSQL/
worker hosted parity smoke.

## Review checklist

Approval record: project-owner instruction của documentation task ngày 2026-08-29 đóng vai Product và Security/Privacy
approval cho repository-local MVP theo scope ở đầu tài liệu. Các checkbox này không chứng minh external audit hay
production approval.

### Product

- [x] Duyệt Chrome 116+ và hai capture actions cho repository-local MVP.
- [x] Duyệt preview, warning, consent labels/explanations và support policy baseline cho repository-local MVP.
- [x] Duyệt việc no-consent là default cho từng request.
- [x] Duyệt full case handoff thay vì chat/report trong Side Panel MVP.

### Security/Privacy

- [x] Duyệt data inventory, retention và prohibited data list cho repository-local MVP.
- [x] Duyệt permission budget và không dùng `<all_urls>`.
- [x] Duyệt threat model, residual risks và exact-origin strategy.
- [ ] Xác nhận Railway-hosted disclosure/privacy owner trước Phase 9; không thuộc Phase 0/local exit.
- [ ] Xác nhận Chrome Web Store disclosure/privacy policy owner trước Phase 10; không thuộc Phase 0/local exit.

### Platform/Identity

- [x] Chốt local-first identity strategy: unpacked local ID không phải deployment identity; Railway/Store dùng stable
  identity riêng và exact allow-list, không wildcard.
- [ ] Reserve stable Railway/internal extension ID và ghi owner/OIDC/origin mapping trước Phase 9 hosted integration.
- [ ] Nếu tạo Railway staging riêng, reserve staging ID riêng trước staging smoke.
- [ ] Reserve production/Store item ID và ghi owner/OIDC/origin mapping trước Phase 10 submission.
- [x] Chốt không commit private signing key, OIDC secret, token hoặc local unpacked ID configuration; tiếp tục enforce
  bằng secret/bundle checks ở các phase sau.

**Phase 0 repository-local/MVP exit: DONE.** Phase 1/2 local scaffold và user-gesture capture được phép tồn tại trước
hosted governance vì manifest hiện dùng `connect-src 'none'`, không host permission/content script/OIDC/token/network,
không đọc page metadata/DOM và chưa có submit behavior. Phase 1/2 vẫn cần manual Chrome capture smoke. Phase 3–8 được
phép implement/verify local nhưng không được suy ra là hosted-approved. Phase 9 không bắt đầu hosted identity/origin integration khi Railway mapping còn
`TBD`; Phase 10 vẫn cần Store/production approvals tương ứng.
