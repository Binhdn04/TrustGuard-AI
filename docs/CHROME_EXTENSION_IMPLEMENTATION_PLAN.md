# TrustGuard Chrome Extension Implementation Plan

## Trạng thái và phạm vi

- Trạng thái hiện tại:
  - **Phase 0 repository-local/MVP: DONE** — technical baseline và project-owner instruction của documentation task
    ngày 2026-08-29 đã đóng repository-local review.
  - **Phase 1 implementation: COMPLETE; automated verification: PASS; exit gate: PENDING MANUAL CHROME SMOKE**.
  - **Phase 2 implementation: COMPLETE; automated verification: PASS; exit gate: PENDING MANUAL CHROME CAPTURE SMOKE**.
  - **Phase 3 implementation: COMPLETE; automated verification: PASS; exit gate: PENDING LOCAL OIDC CLIENT + CHROME SMOKE**.
  - **Phase 4+: NOT STARTED**.
  - Stable deployment ID, Railway OIDC/origin integration và external hosted review được giữ tại Phase 9; Chrome Web
    Store ID/submission/GA được giữ tại Phase 10. Không mục nào là blocker của local implementation.
- Mục tiêu: cho phép người dùng chủ động gửi đoạn text hoặc liên kết đang chọn từ Chrome vào Security Triage
  `/api/v4`, theo dõi coarse progress và xem cảnh báo ngắn trong Side Panel.
- Pipeline understanding → investigation/tools → deterministic risk → grounded synthesis giữ nguyên. Extension là một
  client mới của pipeline hiện tại, không phải một agent hoặc risk engine mới.
- Full case tiếp tục thuộc web TrustGuard tại `/cases/{analysisId}`.
- Kế hoạch này phụ thuộc [Controlled Progress Streaming Implementation Plan](STREAMING_PROGRESS_IMPLEMENTATION_PLAN.md).
  Code/local verification của progress đã hoàn tất, nhưng async production vẫn chưa được bật vì hosted rollout gates
  còn mở.
- Chỉ cập nhật `CURRENT_STATUS.md` khi từng phase có code và bằng chứng kiểm thử tương ứng.

## Kết quả sản phẩm mong muốn

```text
Người dùng bôi đen text hoặc chuột phải liên kết
        ↓
Chọn “Kiểm tra với TrustGuard”
        ↓
Side Panel hiển thị đúng nội dung sắp gửi + disclosure/consent của request này
        ↓
POST /api/v4/analyses
        ↓
understanding → scope gate → investigation/tools → risk assessment → synthesis
        ↓
WebSocket ticket + stream, fallback về owner-scoped cursor polling
        ↓
Side Panel hiển thị progress allow-listed rồi thay bằng kết quả authoritative
        ↓
Người dùng có thể mở /cases/{analysisId} trên web TrustGuard
```

Definition of success cho MVP:

- Hai entry context menu: kiểm tra text được chọn và kiểm tra đích liên kết.
- Không gửi dữ liệu trước khi người dùng nhìn thấy nội dung và xác nhận submit.
- Dùng đúng OIDC user identity với backend hiện tại; không dùng demo token trong hosted build.
- Async khi capability công bố sẵn sàng; inline fallback vẫn trả được kết quả khi async chưa sẵn sàng.
- Progress reconnect/replay không duplicate hoặc lùi stage; final analysis luôn là authority.
- Extension không đọc toàn trang, cookie, form field, browsing history hoặc request traffic.
- Full case mở đúng owner-scoped route hiện có.

## Ngoài phạm vi MVP

- Tự động quét mọi trang, mọi navigation hoặc mọi link mà không có user gesture.
- Đọc toàn bộ DOM, email, chat thread, clipboard, cookie, local storage của website hoặc browser history.
- Chụp màn hình/trang từ extension; page capture backend hiện hành là capability riêng và không được tự động gọi.
- Inject badge/cảnh báo vào DOM của website.
- Chat multi-turn, report/appeal hoặc admin workflow ngay trong Side Panel.
- Lưu lịch sử case riêng trong extension; PostgreSQL/backend và web TrustGuard tiếp tục là source of truth.
- Tool-level progress, token streaming, model draft, chain-of-thought hoặc provisional verdict mới.
- Public API v2/v3, general fact-check hoặc vector-store compatibility.
- Firefox/Safari trong work package đầu tiên.

## Baseline hiện tại

Các capability có thể tái sử dụng trực tiếp:

| Nhu cầu | Baseline `/api/v4` |
|---|---|
| Tạo lượt kiểm tra | `POST /api/v4/analyses` |
| Async acknowledgement | `202 + analysis_id + conversation_id/version` |
| Retry an toàn | `Idempotency-Key` bắt buộc cho async |
| Capability discovery | `GET /api/v4/capabilities` |
| Kết quả authoritative | `GET /api/v4/analyses/{analysis_id}` |
| Event replay | `GET /api/v4/analyses/{analysis_id}/events?cursor=...` |
| Realtime | `POST /api/v4/ws-tickets` rồi WebSocket `/analyses/{id}/stream` |
| Auth/RBAC | OIDC bearer token; mọi user read owner-scoped |
| Full case web | `/cases/{analysisId}` |
| Pipeline | scope, understanding, investigation, trust, deterministic risk và grounded response hiện hành |

Repository-local extension baseline đã có:

- Manifest V3 TypeScript workspace, pinned build, Side Panel, background service worker và hai context-menu captures.
- Phase 3 OIDC public-client/PKCE boundary; unconfigured build giữ `connect-src 'none'`, configured local build chỉ thêm
  exact issuer/token origin vào CSP và host permission.
- Strict internal message/capture/auth-state schemas, session-only capture/token state, generated v4 types/drift test và
  extension CI checks.

Khoảng trống còn cần triển khai:

- Chưa cấu hình OIDC public client/redirect thật cho unpacked local ID; cấu hình này phải ở untracked `.env.local` và
  provider dashboard, không commit vào repository.
- Backend production config hiện chỉ chấp nhận HTTPS CORS origins; chưa có allow-list rõ ràng cho
  `chrome-extension://<extension-id>` và WebSocket `Origin`.
- Chưa có browser E2E, Railway extension package/config hoặc Chrome Web Store package/listing.
- Async hosted prerequisites trong `DEPLOYMENT.md` chưa có đủ evidence và production vẫn tắt.

## Quyết định kiến trúc

### 1. Extension là adapter mỏng của `/api/v4`

MVP không tạo endpoint `/api/v4/extension/*` và không fork pipeline. Payload submit dùng
`SecurityTriageCreateRequestV4` hiện tại; response/event dùng contract v4 hiện tại. Không cần migration chỉ để ghi nhận
nguồn client khi pipeline không sử dụng thông tin đó.

Extension luôn:

1. gọi capabilities;
2. chọn `execution_mode=async` chỉ khi `security_async_execution=true`;
3. gửi `Idempotency-Key` ổn định cho retry của cùng một capture;
4. xử lý cả `202 accepted` và inline `200 final`;
5. coi final fetch là authoritative, không dựng verdict từ progress.

### 2. Context menu là capture path chính; Content Script chỉ on-demand

Chrome cung cấp `selectionText` và `linkUrl` ngay trong event context menu. Vì vậy không cần content script chạy thường
trực trên mọi website chỉ để hỗ trợ hai use case MVP.

Kiến trúc thực tế:

```text
Web page
   │ user gesture
   ├─ contextMenus: selectionText | linkUrl       ← MVP path
   └─ on-demand Content Script + activeTab        ← chỉ khi thêm toolbar/keyboard capture
                    │
                    ▼
Manifest V3 Background Service Worker
   ├─ validate capture envelope
   ├─ giữ pending capture ngắn hạn
   ├─ OIDC token boundary
   ├─ authenticated API calls
   └─ cấp WebSocket ticket cho Side Panel
                    │
                    ▼
TrustGuard API /api/v4
   └─ AI Agent + approved tools + PostgreSQL/event outbox
                    │
             ┌──────┴──────┐
             ▼             ▼
     WebSocket ticket   Cursor polling
             │             │
             └──────┬──────┘
                    ▼
             Extension Side Panel
```

Nếu phase sau cần nút toolbar/keyboard để lấy selection hiện tại, background chỉ inject content script sau user gesture
qua `activeTab + scripting`. Không thêm `<all_urls>` hoặc content script thường trực cho MVP.

### 3. Background giữ privilege; Side Panel giữ presentation

- Content Script/on-click capture không giữ token và không gọi backend.
- Background validate internal message, quản lý OIDC và thực hiện mọi HTTP request có bearer token.
- Side Panel yêu cầu background tạo WebSocket ticket, sau đó mở WebSocket trực tiếp bằng ticket ngắn hạn, single-use.
- Khi WebSocket lỗi, Side Panel yêu cầu background thực hiện owner-scoped cursor polling.
- Side Panel đóng không hủy analysis. Khi mở lại, nó lấy `analysis_id + cursor` tối thiểu từ session state và replay/fetch.
- Không giữ WebSocket lâu dài trong service worker vì lifecycle Manifest V3 có thể suspend/restart worker.

### 4. Data minimization mặc định

Capture envelope nội bộ chỉ gồm:

```ts
type CaptureEnvelope = {
  captureId: string; // UUID dùng cho idempotency
  kind: "selection" | "link";
  value: string;     // tối đa 5.000 ký tự sau normalize
  createdAt: string;
};
```

Không thu hoặc gửi `pageUrl`, page title, DOM snapshot, tab history, favicon, cookie, form values hay referrer. Quy tắc
normalize:

- Selection: trim, normalize line endings, giữ nguyên ngôn ngữ/ngữ cảnh, từ chối chuỗi rỗng, giới hạn 5.000 ký tự.
- Link: chỉ nhận absolute `http:` hoặc `https:` URL; từ chối `javascript:`, `data:`, `file:`, `chrome:` và URL chứa
  username/password; bỏ fragment.
- Query của chính link được người dùng chọn có thể cần cho exact-resource analysis, nên không tự ý bỏ trước pipeline.
  Tuy nhiên không ghi query vào log, progress, analytics hoặc client history; backend tiếp tục redaction khi ghi các
  durable ledger không cần query.
- Nếu nội dung có vẻ chứa OTP, credential hoặc token, Side Panel hiển thị cảnh báo trước submit; không copy nội dung đó
  sang telemetry hay error report.

Pending raw capture chỉ được giữ trong `chrome.storage.session`, thay thế capture cũ, có TTL ngắn và bị xóa ngay sau khi
request được accepted/final hoặc khi người dùng hủy. Không dùng `storage.local`/`storage.sync` cho raw capture hay token.

### 5. Consent là request-scoped

Context-menu click chỉ tạo draft và mở Side Panel, chưa gọi backend. Side Panel phải hiển thị:

- nội dung/URL sắp gửi;
- disclosure rằng TrustGuard có thể gửi domain/claim cần thiết tới dịch vụ bảo mật/nguồn công khai;
- hai consent tương ứng `external_url_lookup` và `official_source_lookup`;
- nút submit rõ ràng.

Consent không kế thừa từ request trước, browser session hay web TrustGuard. Nếu consent tắt, payload gửi `false` và
progress không được nói rằng external lookup đang chạy. Không được để extension tự đặt consent dựa trên AI hoặc nội dung
capture.

### 6. OIDC dành riêng cho extension

- Đăng ký một public OIDC client riêng cho Chrome Extension; không chia sẻ client secret và không đóng gói secret.
- Dùng Authorization Code + PKCE qua `chrome.identity.launchWebAuthFlow()` và redirect do
  `chrome.identity.getRedirectURL()` tạo.
- `state`, `nonce` và PKCE verifier tồn tại qua service-worker restart bằng `chrome.storage.session`, chỉ trusted
  extension contexts được truy cập.
- Access token chỉ nằm trong memory/session storage, không vào URL, log, DOM/content script, sync/local storage hoặc
  analytics. WebSocket chỉ nhận ticket single-use hiện hành, không nhận bearer token.
- MVP có thể yêu cầu đăng nhập lại sau browser restart thay vì persist refresh token. Nếu sau này dùng refresh token,
  phải có threat-model/revocation/rotation work package riêng.
- Web app và extension phải map về cùng OIDC `sub` để `/cases/{analysisId}` owner scope hoạt động nhất quán.

### 7. Progress là observer, final là authority

Side Panel dùng cùng stage allow-list với web:

`running`, `understanding`, `scope_gate`, `incident_response`, `investigation`,
`official_link_verification`, `security_memory_lookup`, `risk_assessment`, `assistant_response`.

Quy tắc:

- Map `step + progress_state` sang label tĩnh; không render arbitrary backend `message`.
- Không dùng `risk_hint`, `evidence_refs` hay progress message để tạo verdict.
- Dedupe theo `event_id`, chỉ tiến theo `sequence`, lưu `next_cursor` và bỏ event sai `analysis_id`.
- WebSocket reconnect lấy ticket mới và dùng cursor hiện tại; hết retry thì polling với bounded backoff.
- Khi có final event, dừng stream/poll và gọi `GET /analyses/{id}`. Nếu final event bị mất, polling status/final fetch
  vẫn phải hoàn tất flow.
- Progress/event transport lỗi không được biến analysis thành failed nếu final endpoint vẫn đọc được.

## Phân rã theo lớp kiến trúc

| Lớp | Trách nhiệm | Không được làm |
|---|---|---|
| Web page | Nơi user tạo gesture và selection/link target | Không bị quét nền hoặc inject cảnh báo tự động |
| Context menu / Content Script | Lấy đúng selection/link; Content Script chỉ on-demand khi feature cần | Không giữ token, gọi API, đọc toàn DOM/cookie/form/history |
| Background Service Worker | Validate message/capture, OIDC, API client, transient state, cấp WS ticket | Không tự đặt consent/risk, không fetch arbitrary target do page truyền |
| TrustGuard API | Auth/RBAC/rate limit, idempotency, scope boundary, enqueue/inline, owner-scoped reads | Không trust client source như security signal |
| AI Agent + Tools | Pipeline v4 hiện hành với consent, budget, deadline, SSRF/redirect guard | AI không trực tiếp đặt risk, score, target, consent hoặc admin action |
| PostgreSQL/Redis | Analysis/event source of truth, durable job/outbox; Redis chỉ wake/ticket/rate limit | Không persist raw content trong event/telemetry hoặc coi Redis là result authority |
| WebSocket / Polling | Replay ordered coarse events, reconnect và fallback | Không tạo verdict hoặc chặn final fetch khi transport lỗi |
| Side Panel | Draft/consent, progress allow-list, final summary, fixed-host web handoff | Không render raw HTML/message, provider payload hoặc provisional hint như final |

Critical path theo trạng thái và gate thực tế:

```text
Phase 0 technical baseline                       DONE
        ↓
Phase 1 local scaffold allowed                   COMPLETE
        ↓
Phase 0 MVP/project-owner review closure         DONE
        ↓
Phase 1 → 3 manual Chrome capture/OIDC smoke       PENDING
        ↓
Phase 4 → 7 local origin/API/progress/final
        ↓
Phase 8 local security/privacy hardening
        ↓
LOCAL END-TO-END GATE
        ↓
Phase 9 Railway internal deployment
        ↓
Phase 10 Chrome Web Store + production GA
```

Local Phase 1 được triển khai trước production governance vì không có network, OIDC/token, host permission, persistent
content script, page-data read hoặc capture/submit behavior. Phase 1/2 smoke có thể gộp với Phase 3 local OIDC smoke;
implementation tự động không thay thế manual Chrome/provider acceptance. Phase 2–8 được implement và verify trước với unpacked extension + local TrustGuard
stack. Local origin/OIDC config nếu cần phải dùng
đúng ID mà Chrome đang hiển thị và chỉ nằm trong local untracked config; không wildcard và không coi ID đó là deployment
identity. Stable ID, exact Railway OIDC redirect/backend origin allow-list và hosted approval trở thành hard gate ở Phase
9. Chrome Web Store identity/listing/review chỉ bắt buộc ở Phase 10. Async hosted readiness là dependency của trải nghiệm
progress trên Railway/production, không phải dependency của local inline submit/final MVP.

## Side Panel state machine

```text
EMPTY
  └─ capture → DRAFT
                 ├─ chưa auth → AUTH_REQUIRED → DRAFT
                 ├─ hủy → EMPTY
                 └─ submit → SUBMITTING
                                  ├─ inline 200 → COMPLETED
                                  ├─ async 202 → QUEUED/RUNNING
                                  │                  ├─ final fetch → COMPLETED
                                  │                  └─ terminal error → FAILED
                                  └─ request error → RETRYABLE_ERROR | FAILED

COMPLETED ── “Mở hồ sơ đầy đủ” → https://<web-host>/cases/{analysisId}
```

Một Side Panel chỉ theo dõi một active capture. Capture mới không hủy job cũ; job cũ vẫn thuộc lịch sử backend/web.
Retry trước khi backend accepted phải dùng cùng `captureId` và cùng body. Nếu user sửa nội dung hoặc consent, tạo
`captureId` mới để không vi phạm idempotency hash.

## UI scope của MVP

### Draft

- Loại capture: “Đoạn văn bản” hoặc “Liên kết”.
- Preview bounded, text-only; không dùng raw HTML/Markdown.
- Disclosure/consent của request hiện tại.
- Cảnh báo không gửi mật khẩu, OTP, token hoặc dữ liệu riêng tư không cần thiết.
- `Đăng nhập` hoặc `Kiểm tra` tùy auth state.

### Running

- Trạng thái queued/running và đúng một coarse progress label mới nhất.
- Nút đóng panel chỉ đóng presentation, không ngụ ý hủy backend job.
- Transport reconnect/polling không hiển thị như risk signal.
- `aria-live="polite"`, không announce lại event replay và tôn trọng reduced motion.

### Final

- Scope/boundary hoặc risk badge từ final response.
- Grounded summary ngắn, top reasons/immediate actions đã có trong final contract và limitations quan trọng.
- Với `NEED_MORE_INFO`, chỉ hiển thị câu hỏi cần bổ sung và CTA mở full case; MVP không tự tạo chat flow thứ hai.
- Với out-of-scope, hiển thị terminal boundary, không hiển thị risk giả.
- Nút “Mở hồ sơ đầy đủ” chỉ tạo URL từ frontend base URL cố định + UUID đã validate; không mở arbitrary URL do model
  hoặc page cung cấp.
- Không render provider payload, technical evidence dump, raw exception hoặc model draft.

## Cấu trúc code đề xuất

```text
extension/
├─ manifest.json
├─ package.json
├─ tsconfig.json
  ├─ vite.config.ts
├─ src/
│  ├─ background/
│  │  ├─ service-worker.ts
│  │  ├─ auth.ts
│  │  ├─ api-client.ts
│  │  └─ capture-controller.ts
│  ├─ content/
│  │  └─ capture-selection.ts       # chỉ build/inject on-demand nếu toolbar/keyboard được bật
│  ├─ sidepanel/
│  │  ├─ index.html
│  │  ├─ main.tsx
│  │  ├─ app.tsx
│  │  └─ components/
│  ├─ lib/
│  │  ├─ internal-messages.ts
│  │  ├─ capture-validation.ts
│  │  ├─ progress-selector.ts
│  │  ├─ event-stream.ts
│  │  └─ session-state.ts
│  └─ types/
│     └─ api-v4.ts                  # generated/subset từ cùng OpenAPI v4
├─ tests/
│  ├─ unit/
│  ├─ integration/
│  └─ e2e/
└─ public/icons/
```

Không import trực tiếp Next.js component vào extension. Có thể tái sử dụng contract semantics và fixtures, nhưng bundle
extension phải self-contained và tuân thủ Manifest V3 CSP. Type v4 của extension phải được generate hoặc drift-check
từ cùng backend OpenAPI; không duy trì một contract viết tay không có test.

Manifest permission budget cho MVP:

```json
{
  "manifest_version": 3,
  "minimum_chrome_version": "116",
  "permissions": ["contextMenus", "identity", "sidePanel", "storage"],
  "host_permissions": [
    "https://<trustguard-api-host>/*",
    "https://<oidc-host>/*"
  ]
}
```

`activeTab` và `scripting` chỉ thêm khi phase toolbar/keyboard capture thực sự được triển khai. Không yêu cầu
`tabs`, `cookies`, `history`, `webRequest`, `clipboardRead`, `<all_urls>` hoặc `unlimitedStorage` cho MVP.

## Backend/config changes tối thiểu

Pipeline và response model không cần đổi. Backend work package chỉ gồm boundary/hardening cần thiết cho client mới:

1. Cho phép cấu hình exact production extension IDs/origins, không wildcard.
2. Validate HTTP CORS origin và WebSocket `Origin` theo frontend HTTPS origins + approved
   `chrome-extension://<id>` origins. CORS/origin check không thay thế bearer/ticket auth.
3. Giữ `POST /analyses`, events, final fetch và ticket endpoint owner-scoped như hiện tại.
4. Không log `Authorization`, ticket, raw capture, URL query hoặc internal message payload.
5. Nếu cần client telemetry, chỉ nhận enum allow-listed như `chrome_extension_v1`; không cho field này ảnh hưởng scope,
   plan, risk, consent hoặc persistence. Không thêm field/flag khi runtime chưa thực sự consume nó.
6. Không bật async capability chỉ để phục vụ extension. Capability chỉ truthful khi PostgreSQL, worker, lease,
   Redis/notifier và deployment gates hiện hành đều ready.

Config dự kiến nếu origin hardening cần tách khỏi web CORS:

```text
TRUSTED_BROWSER_EXTENSION_IDS=<comma-separated exact deployed IDs>
```

Validator chỉ nhận Chrome extension ID đúng format. Local unpacked ID chỉ nằm trong untracked local environment;
Railway/Store chỉ dùng stable ID đã ghi registry. Không đưa wildcard vào bất kỳ environment nào.

## Internal extension message boundary

Background chỉ nhận một discriminated union allow-listed, ví dụ:

```ts
type ExtensionRequest =
  | { type: "capture.claim" }
  | { type: "auth.login" }
  | { type: "auth.logout" }
  | { type: "analysis.create"; captureId: string; consent: SecurityConsentV4 }
  | { type: "analysis.get"; analysisId: string }
  | { type: "analysis.events"; analysisId: string; cursor: string | null }
  | { type: "analysis.wsTicket"; analysisId: string };
```

Mỗi handler phải validate schema, `sender.id`, UUID, length và ownership-by-backend. Content script không được truyền API
URL, authorization header, WebSocket path, arbitrary fetch target hoặc tab-open target. Background không gửi token hay
private state ngược lại content script.

## Kế hoạch triển khai

### Phase 0 — Product decisions, threat model và parity fixtures

- [x] Chốt technical baseline Chrome 116+ vì programmatic Side Panel open cần user gesture và API tương ứng.
- [x] Chốt hai capture type MVP: `selection`, `link`.
- [x] Chốt environment identity strategy: local unpacked ID không phải deployment identity; Railway internal và Chrome
  Web Store production dùng stable ID riêng, exact allow-list và không wildcard.
- [x] Chốt consent copy, privacy disclosure, retention và support policy cho MVP/repository-local qua project-owner
  review. Đây không phải production, external security hay Chrome Web Store approval.
- [x] Threat-model hostile page → content script/background messages, token theft, XSS trong Side Panel, ticket replay,
  malicious URL scheme, service-worker restart và deep-link injection.
- [x] Tạo fixtures cho in-scope, out-of-scope, need-more-info, no-consent, URL error/no-hit và inline/async scope parity.
- [x] Ghi baseline stable scope/threat/risk projection, tool plan và provider trace từ backend contract/pipeline
  `/api/v4` mà web client hiện hành sử dụng cho cùng fixtures.
- [x] Chốt không thu page URL/title/full DOM trong MVP.

Phase 0 technical evidence và review checklist nằm tại
[CHROME_EXTENSION_PHASE0_REVIEW.md](CHROME_EXTENSION_PHASE0_REVIEW.md).

**Phase 0 repository-local/MVP exit gate: DONE.** Technical baseline, scope, data-flow/minimization, permission budget,
threat model, fixtures và baseline copy đã được chấp nhận cho MVP trong repository theo project-owner instruction của
documentation task ngày 2026-08-29. Stable ID reservation và hosted/external approvals là
`NOT APPLICABLE TO PHASE 0 EXIT`; Railway identity được defer sang Phase 9 và Store identity sang Phase 10.

Deferred environment gates, không thuộc Phase 0 checklist:

- [ ] Reserve một stable Railway/internal extension ID trước khi cấu hình hosted OIDC redirect/origin ở Phase 9.
- [ ] Nếu tạo Railway staging riêng, reserve stable staging ID riêng trước staging smoke; không bắt buộc khi chưa có
  staging environment.
- [ ] Reserve production/Chrome Web Store ID trước Phase 10 submission; không cần để hoàn tất local hoặc Railway
  internal rollout.

### Phase 1 — Extension scaffold và CI

Status: **implementation COMPLETE · automated verification PASS · exit gate PENDING MANUAL CHROME SMOKE**.

- [x] Tạo `extension/` Manifest V3 TypeScript workspace, pinned lockfile và deterministic build.
- [x] Thêm Side Panel entry, background service worker và CSP không cho remote executable code; local scaffold dùng
  `connect-src 'none'`; local environment config thuộc Phase 4, Railway host allow-list/activation thuộc Phase 9.
- [x] Thêm schema validation cho internal message và capture envelope.
- [x] Generate/subset type v4 từ backend OpenAPI; thêm drift test cho capabilities, request, accepted/final, event page
  và ticket.
- [x] Thêm lint, typecheck, unit test, build và package checks vào CI.
- [x] Xác minh bundle không có remote executable code, source map, bearer credential hoặc demo token.

Manual exit evidence bắt buộc, không được thay bằng unit/build test:

```text
npm run build
→ chrome://extensions
→ Developer mode
→ Load unpacked extension/dist
→ extension load thành công
→ Side Panel mở thành công trên Chrome 116+
```

Exit gate: **PENDING MANUAL CHROME SMOKE**. Local Phase 2–8 không bị chặn bởi stable deployment ID. Railway integration
bị chặn đúng tại stable-ID/OIDC/origin và hosted approval gate của Phase 9; Store/GA bị chặn tại Phase 10.

### Phase 2 — Capture boundary

- Status: **implementation COMPLETE · automated verification PASS · exit gate PENDING MANUAL CHROME CAPTURE SMOKE**.
- [x] Đăng ký đúng hai context-menu items cho `selection` và `link`.
- [x] Validate/normalize `selectionText`/`linkUrl`; từ chối scheme, credential URL và oversize input không hợp lệ.
- [x] Lưu một pending capture TTL 5 phút trong trusted `storage.session`; không dùng local/sync.
- [x] Gọi mở Side Panel trực tiếp từ context-menu user gesture và chuyển draft qua trusted internal message.
- [x] Side Panel preview bằng `textContent`, cho phép hủy và xóa đúng pending capture hiện hành.
- [x] Không bổ sung toolbar/keyboard capture ở Phase 2; không cần `activeTab`, injected content script hoặc persistent script.
- [x] Test iframe selection contract, Unicode, whitespace, 5.000 Unicode-character boundary, malicious scheme,
  TTL/malformed storage, stale cancel, trusted sender và rapid consecutive captures.

Automated gate: **PASS** — bundle không có `fetch`/WebSocket/EventSource/XMLHttpRequest, CSP vẫn `connect-src 'none'`,
manifest không có host permission/content script và chỉ thêm `contextMenus` + `storage` vào permission budget.

Manual gate còn lại trên Chrome 116+: reload `extension/dist`, xác nhận đúng hai menu, selection trong top frame/iframe,
link preview, cancel/clear và capture liên tiếp. Có thể gộp bằng chứng này vào manual Phase 3 Chrome acceptance.

### Phase 3 — OIDC Authorization Code + PKCE

- Status: **implementation COMPLETE · automated verification PASS · exit gate PENDING LOCAL OIDC CLIENT + CHROME SMOKE**.
- [x] Implement local auth flow cho OIDC public client riêng và exact redirect do `chrome.identity.getRedirectURL("oidc")`
  trả về cho unpacked extension hiện tại; không dùng client secret trong extension.
- [x] Build fail-closed: khi chưa cấu hình giữ `connect-src 'none'`; khi cấu hình chỉ mở CSP + host permission cho exact
  OIDC issuer/token origin, không thêm Railway/production host và không dùng wildcard.
- [x] Giữ unpacked extension ID/redirect chỉ trong untracked `.env.local` và provider dashboard. Khi ID thay đổi, cập nhật
  local OIDC callback; không đưa ID tạm vào shared Railway/production allow-list.
- [x] Implement `launchWebAuthFlow`, state/nonce, PKCE S256, exact callback validation, code exchange, access/ID token
  expiry/issuer/audience/subject validation và logout/revocation flow.
- [x] Giữ auth transaction/access/refresh/ID token trong trusted `storage.session`; clear khi logout, extension
  update/reload hoặc auth error terminal.
- [x] Background cung cấp `getValidAccessToken()` để tự refresh trước API call; khi không refresh được thì clear session
  và yêu cầu interactive reauth. Side Panel chỉ nhận `AuthPublicState`, không nhận raw token/claim/user object.
- [x] Backend tiếp tục validate access-token signature, issuer, audience, expiry, subject và roles như web; runtime backend
  không bị sửa và targeted auth/config suite đạt.
- [x] Test state/nonce mismatch, redirect mismatch, expired token, canceled login, service-worker restart giữa flow,
  wrong client/API audience, refresh/revoke, exact manifest policy và token non-disclosure.
- [ ] Tạo/cấu hình local OIDC public client thật với exact callback của unpacked ID, điền untracked `.env.local` và chạy
  Chrome login/logout smoke; cần owner/provider credentials nên không thể commit hoặc đóng bằng automated test.

Automated gate: **PASS**. Manual Phase 3 gate: Chrome login/logout/refresh với local provider client phải pass. Việc chứng
minh extension và web cùng user đọc cùng owner-scoped case được đóng ở Phase 5/7 integrated smoke, khi API submit/read đã
được implement. Railway OIDC client, stable ID và hosted smoke vẫn thuộc Phase 9.

### Phase 4 — Backend origin hardening và deployment config

- [ ] Thêm exact extension ID/origin configuration với fail-closed validation; local config có thể dùng ID unpacked hiện
  tại nhưng không dùng wildcard.
- [ ] Validate WebSocket `Origin` trước accept, song song với single-use ticket + owner check hiện hành.
- [ ] Tách local web/extension origins khỏi Railway/Store origins; local values ở untracked config, deployed values ở
  managed environment configuration.
- [ ] Test unapproved extension ID, arbitrary website origin, missing/expired/reused ticket và mismatched analysis ID.
- [ ] Xác minh structured logs/error envelope không chứa bearer, ticket, raw capture hoặc URL query.
- [ ] Cập nhật `.env.example` và `DEPLOYMENT.md` khi runtime thực sự consume config mới.

Local exit gate: chỉ exact local web origin và exact unpacked extension ID hiện tại đi qua transport boundary;
auth/RBAC vẫn là authorization authority. Railway exact-origin/config validation và hosted smoke được đóng ở Phase 9.

### Phase 5 — Submit và idempotency

- [ ] Side Panel hiển thị disclosure và lấy consent mới cho từng submit.
- [ ] Background gọi capabilities và chọn async/inline đúng capability.
- [ ] Map `CaptureEnvelope.value` trực tiếp vào `message`; không tự thêm page title/referrer hoặc prompt instruction.
- [ ] Dùng `captureId` làm `Idempotency-Key` cho cùng body; sửa content/consent thì tạo key mới.
- [ ] Xử lý inline final, async accepted, 401/403, validation, rate limit, conflict, timeout và offline.
- [ ] Xóa raw pending capture khỏi session sau accepted/final; chỉ giữ analysis ID, cursor, state và timestamp tối thiểu.
- [ ] Test request body/consent/tool trace parity với web cho cùng fixture.

Exit gate: duplicate click/network retry không tạo duplicate case; observer/client source không làm đổi kết quả pipeline.

### Phase 6 — WebSocket, polling và resume

- [ ] Background tạo ticket qua `/api/v4/ws-tickets`; Side Panel không nhìn thấy bearer token.
- [ ] Side Panel connect ticketed WebSocket với cursor hiện tại.
- [ ] Dedupe event ID, sort/advance sequence, reject wrong analysis ID và map progress qua allow-list.
- [ ] Reconnect bằng ticket mới; fallback cursor polling qua background sau bounded retries.
- [ ] Khi Side Panel mở lại, resume bằng session `analysisId/cursor`, fetch current state và replay events.
- [ ] Terminal event kích hoạt authoritative final fetch rồi stop transport.
- [ ] Test malformed/duplicate/out-of-order event, expired/reused ticket, panel close/reopen, worker suspend/restart,
  WebSocket outage, Redis notifier outage và polling recovery.

Exit gate: transport loss không làm mất final result, duplicate UI hoặc state regression.

### Phase 7 — Final result và web handoff

- [ ] Render scope/boundary/risk từ final response, không từ progress.
- [ ] Render bounded summary/actions/limitations bằng text/React nodes an toàn; không dùng raw HTML.
- [ ] Hiển thị đúng state cho `NEED_MORE_INFO`, out-of-scope, insufficient evidence và provider degraded/error.
- [ ] Tạo CTA cố định `${TRUSTGUARD_WEB_URL}/cases/${validatedAnalysisId}`.
- [ ] Web auth callback giữ return target để deep link tiếp tục sau login.
- [ ] Test owner isolation khi mở full case, invalid UUID, wrong account, deleted/expired case và auth redirect.
- [ ] Accessibility: keyboard flow, focus, screen reader live region, contrast và reduced motion.

Exit gate: Side Panel đủ dùng cho cảnh báo nhanh, web tiếp quản đúng full case mà không copy raw content qua query string.

### Phase 8 — Local security, privacy và end-to-end hardening

- [ ] Chạy dependency/SAST/secret scan, CSP test và manual permission audit.
- [ ] Xác minh không có remote executable code, `eval`, unsafe `innerHTML` hoặc externally-connectable wildcard.
- [ ] Pentest hostile page/internal-message spoofing, XSS payload, OAuth redirect/state, token exfiltration và deep-link
  injection.
- [ ] Xác minh local logs/storage/build artifact không chứa capture content, token, ticket, OTP, credential, URL query
  nhạy cảm hoặc demo token.
- [ ] Test unpacked install/reload/remove, browser restart, service-worker suspend/restart và incognito policy.
- [ ] Chạy local end-to-end unpacked extension → local backend/frontend cho capture → consent → submit → progress/final
  → web handoff, gồm inline fallback và failure cases.
- [ ] Ghi local test evidence không nhạy cảm; không coi local evidence là Railway/production approval.

Exit gate: local end-to-end và security/privacy regression suite đạt. Từ đây mới bắt đầu setup Railway. Chrome Web Store
listing, Store ID, signed publication artifact và Store policy review chưa thuộc gate này.

### Phase 9 — Railway internal deployment

- [ ] Reserve một stable Railway/internal extension ID bằng developer-managed manifest public key hoặc Chrome Developer
  Dashboard draft item. Không cần publish Store; ghi public ID/owner mapping và giữ private key ngoài repository.
- [ ] Tạo Railway OIDC public client cho exact Chromium redirect của stable internal ID; không dùng local unpacked ID.
- [ ] Cấu hình extension Railway build với exact HTTPS API/OIDC host và WSS host trong CSP; không wildcard.
- [ ] Cấu hình backend/WebSocket exact `chrome-extension://<railway-internal-id>` origin cùng web origin; giữ JWT/RBAC,
  owner check và single-use ticket là authorization authority.
- [ ] Hoàn tất toàn bộ hosted Phase 8 của streaming plan trước khi quảng bá progress realtime.
- [ ] Deploy backend + worker cùng artifact; verify PostgreSQL/Alembic, Redis, lease/heartbeat và readiness.
- [ ] Giữ inline fallback; chỉ bật `SECURITY_ASYNC_EXECUTION_ENABLED=true` sau approval hiện hành.
- [ ] Phân phối unpacked/internal package cho nhóm thử nghiệm đã kiểm soát; không quảng bá là Chrome Web Store release.
- [ ] Smoke hai Railway OIDC users: submit, owner isolation, ticket single-use, reconnect, polling fallback, final fetch
  và web handoff.
- [ ] Induce Redis/WebSocket failure và xác minh cursor polling từ PostgreSQL vẫn hoàn tất.
- [ ] Theo dõi metric không nhạy cảm: auth success, submit accepted/final, time-to-first-progress, time-to-final,
  reconnect/fallback rate, dropped UI events và error code distribution.
- [ ] Không log capture content, URL query, token, ticket, OTP, credential hoặc provider payload.

Exit gate: Railway internal observation window đạt SLO, exact identity/origin/OIDC smoke và failure recovery đạt;
Product + Security + Operations duyệt internal deployment. Gate này không phải Chrome Web Store hoặc public GA approval.

### Phase 10 — Chrome Web Store và production GA

- [ ] Chốt production publisher ownership và reserve production/Chrome Web Store item ID riêng; không tái sử dụng local
  hoặc Railway internal identity.
- [ ] Tạo production OIDC client và exact backend origin allow-list cho Store ID; chạy lại owner/RBAC/ticket smoke.
- [ ] Hoàn thiện privacy policy, Limited Use disclosure, retention/deletion description và single-purpose store listing.
- [ ] Chuẩn bị icon/screenshot không chứa user data, production case, token hoặc internal environment detail.
- [ ] Test Store install/update/uninstall, browser restart, incognito policy và managed enterprise restrictions.
- [ ] Tạo signed release artifact, checksum, versioning, rollback package và bảo vệ publisher/update ownership.
- [ ] Hoàn tất Chrome Web Store submission/review rồi canary theo trusted testers → small production cohort → general
  availability.
- [ ] Quan sát production SLO/security/privacy và diễn tập revoke Store ID/OIDC client + rollback extension version.

Exit gate: Chrome Web Store review cùng Product + Security + Privacy + Operations approval đạt, production observation
window không có regression và rollback evidence đầy đủ trước public GA.

## Verification matrix

| Layer | Kiểm thử bắt buộc |
|---|---|
| Capture | selection/link, iframe, Unicode, empty/oversize, scheme/credential URL, rapid replacement |
| Internal boundary | sender validation, schema reject, no arbitrary fetch/open, no token to content script |
| Auth | PKCE/state/nonce, expiry, wrong audience, cancel/restart/logout, same-sub web handoff |
| API | capability truthfulness, inline/async, idempotency, rate limit, validation, owner isolation |
| Progress | replay, sequence, dedupe, reconnect, ticket reuse, WS/Redis outage, polling fallback |
| Pipeline parity | result deep-equality và provider/tool call trace parity với web client |
| Safety | OOS/need-info zero provider calls; no-consent zero external lookup; no-hit/error không thành SAFE |
| UI | draft disclosure, allow-listed labels, final authority, NEED_MORE_INFO/OOS/degraded, accessibility |
| Privacy | no page metadata/history/cookies, transient raw capture, no sensitive log/storage/build artifact |
| Handoff | fixed-host UUID route, login return target, current owner success, other owner denied |

Lệnh gate dự kiến:

```bash
uv run ruff check .
uv run pytest -q
uv run alembic heads

cd frontend
npm test
npm run lint
npm run typecheck
npm run check:cutover
npm run build

cd extension
npm test
npm run lint
npm run typecheck
npm run build
npm run test:e2e
npm run package
```

Local Phase 2–8 evidence là gate bắt buộc trước Railway nhưng không thay thế Railway
OIDC/PostgreSQL/Redis/worker/provider/failure smoke. Railway internal evidence cũng không thay thế Chrome Web Store
review hoặc production GA observation.

## Acceptance criteria

- Context-menu action tạo draft đúng text/link và không thu page data ngoài dữ liệu người dùng chủ động chọn.
- Không có API/provider call trước submit và request-scoped consent.
- Extension không bao giờ quyết định scope, risk, score, consent, target hoặc action bằng AI/client logic.
- Async request có idempotency; retry cùng body không tạo case trùng.
- Inline fallback hoạt động khi capability async không được công bố.
- OOS/need-more-info kết thúc trước investigation/provider calls như pipeline hiện hành.
- External lookup vẫn cần consent và backend SSRF/redirect validation hiện hành.
- Provider no-hit/error/timeout không tạo hoặc ám chỉ `SAFE`.
- Progress chỉ là coarse allow-listed presentation; không có chain-of-thought, model draft hay tool-level event.
- WebSocket reconnect/polling replay không duplicate hoặc lùi state; final fetch là authority.
- Token không vào content script, URL, log, local/sync storage hoặc bundle; WebSocket ticket vẫn single-use và bound với
  analysis/user.
- Raw capture không tồn tại trong extension sau accepted/final và không vào client analytics/history.
- Full case chỉ mở fixed web host + validated analysis UUID và vẫn owner-scoped sau OIDC login.
- Manifest không có broad permissions không cần thiết; production chỉ trust exact extension IDs.

## Quan sát vận hành

Chỉ thu metadata allow-listed, không nhạy cảm:

- extension version, browser major version và environment;
- auth success/failure code, không có token/claims thô;
- capture kind (`selection|link`) và size bucket, không có content/domain;
- inline/async selection, accepted/final/error code;
- time-to-first-progress, time-to-final;
- WebSocket connect/reconnect, ticket failure và polling fallback rate;
- resume-after-panel-reopen success;
- web-handoff click/success ở mức aggregate, không chứa analysis ID.

Không dùng browsing activity/capture cho quảng cáo, profiling hoặc mục đích ngoài security triage đã công bố.

## Rollback

- Có thể unpublish/rollback extension version độc lập vì backend contract giữ backward-compatible.
- Có thể disable exact extension ID ở backend origin allow-list để chặn client bị compromise; web TrustGuard vẫn chạy.
- Có thể tắt presentation WebSocket và giữ polling/final fetch.
- Có thể giữ async tắt và dùng inline fallback; không công bố progress realtime trong trạng thái này.
- Không rollback bằng cách xóa case/event/history hoặc nới wildcard origin/permission.
- Nếu extension artifact/token boundary bị nghi compromise: revoke OIDC client/session, disable extension ID, dừng rollout,
  rotate credentials liên quan và điều tra audit đã redacted.

## Definition of done

### Local implementation done

- [ ] Phase 0–8 có code, automated coverage và local security/privacy evidence.
- [ ] Phase 1 manual Chrome smoke đạt trên unpacked build.
- [ ] Manifest permission budget đạt; không có `<all_urls>` hay content script thường trực cho MVP.
- [ ] Capture → submit → local pipeline → progress/final → local web handoff hoạt động end-to-end.
- [ ] Local OIDC/token/session và exact current unpacked-origin checks đạt; không wildcard và không commit local ID/token.
- [ ] Result/provider trace parity, safety invariants, owner isolation, consent và SSRF/redirect gates không regression.

### Railway internal deployment done

- [ ] Phase 9 stable internal ID, Railway OIDC redirect, CSP và backend/WebSocket exact origin checks đạt hosted smoke.
- [ ] PostgreSQL/Redis/worker/provider/failure recovery và inline fallback có evidence đã làm sạch.
- [ ] Streaming hosted prerequisites hoàn tất trước khi bật async trên Railway.
- [ ] Internal rollout metrics/SLO và rollback rehearsal đạt; không coi đây là public GA.

### Chrome Web Store/production GA done

- [ ] Phase 10 Store ID/publisher ownership, privacy/listing/submission review và signed release controls đạt.
- [ ] Production canary, security/privacy observation và rollback/revoke evidence đạt trước general availability.
- [ ] Canonical docs phản ánh đúng implementation/release state hiện tại.

## Tài liệu nền

- [Product and Architecture](PRODUCT_ARCHITECTURE.md)
- [Current Status](CURRENT_STATUS.md)
- [Controlled Progress Streaming Implementation Plan](STREAMING_PROGRESS_IMPLEMENTATION_PLAN.md)
- [Deployment](DEPLOYMENT.md)
- [Testing](TESTING.md)

Manifest V3, Chrome 116+, Side Panel và local CSP assumptions đã được verify cho Phase 1 scaffold. Trước mỗi phase liên
quan vẫn phải verify lại tài liệu chính thức: `contextMenus`/storage ở Phase 2, `chrome.identity` ở Phase 3/9,
service-worker lifecycle/origin/CSP ở Phase 4–9 và Chrome Web Store User Data/Limited Use policy ở Phase 10.

Nguồn platform chính thức:

- [Chrome Side Panel API](https://developer.chrome.com/docs/extensions/reference/api/sidePanel)
- [Chrome contextMenus API](https://developer.chrome.com/docs/extensions/reference/api/contextMenus)
- [Chrome Identity API](https://developer.chrome.com/docs/extensions/reference/api/identity)
- [Chrome manifest key](https://developer.chrome.com/docs/extensions/reference/manifest/key)
- [Extension service-worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)
- [The activeTab permission](https://developer.chrome.com/docs/extensions/develop/concepts/activeTab)
- [Chrome Extension storage](https://developer.chrome.com/docs/extensions/reference/api/storage)
- [Chrome Extension security guidance](https://developer.chrome.com/docs/extensions/develop/security-privacy/stay-secure)
- [Chrome Web Store User Data policy](https://developer.chrome.com/docs/webstore/user_data)
