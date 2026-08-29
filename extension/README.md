# TrustGuard Chrome Extension

Phase 3 provides a local-only Manifest V3 capture and OIDC boundary, Phase 4 hardens the backend browser-origin boundary,
Phase 5 adds consent-gated `/api/v4` submission, and Phase 6 adds ticketed WebSocket progress with cursor-polling fallback.
The extension captures only user-selected text/links and uses
Authorization Code + PKCE through `chrome.identity`; auth transactions and tokens stay in trusted `storage.session`.
The Side Panel receives only minimal auth/analysis state. Bearer-authenticated API requests stay in the background; the
extension has no content script or arbitrary host access. WebSocket tickets are short-lived/single-use; event text,
evidence and risk hints never become presentation state, and the final analysis endpoint remains authoritative.

## Run locally

Prerequisites: Chrome 116+ and Node.js 22.22.2+.

```powershell
cd extension
npm ci
npm run build
```

Then open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**, and select the absolute
`extension/dist` directory. Pin **TrustGuard AI (Local)** and click its toolbar icon. The Side Panel must show
`Kết nối nội bộ: sẵn sàng`.

Smoke the capture flow:

1. Select text in a normal page and in an iframe, then choose **Analyze selected text with TrustGuard**.
2. Right-click a link and choose **Analyze link with TrustGuard**.
3. Confirm the Side Panel shows only the selected value and that **Hủy và xóa nội dung** clears it.
4. Capture two different values quickly and confirm the latest value wins.
5. Inspect the service worker and Side Panel consoles; capture itself must not cause a network request.

## Configure local OIDC

First load the unconfigured build and copy the exact callback from the extension service-worker console:

```javascript
chrome.identity.getRedirectURL("oidc")
```

Create a separate OIDC **public client** and register that exact callback. Do not create or copy a client secret. Then
copy `.env.example` to ignored `.env.local`, replace issuer/client/audience/endpoints with the local provider values,
run `npm run build`, and reload `extension/dist`. The configured manifest receives only the exact token/revocation
origin in `host_permissions` and `connect-src`; cross-origin, wildcard and non-local HTTP endpoints fail the build.

Use **Đăng nhập** and **Đăng xuất** in the Side Panel to smoke `launchWebAuthFlow`, token exchange and revocation. Reloading
the unpacked extension intentionally clears auth; a normal service-worker restart preserves an in-flight transaction in
`storage.session`.

## Configure the local backend origin

Copy the current unpacked extension ID from `chrome://extensions`, then set its exact origin only in the repository's
ignored backend `.env`:

```dotenv
CHROME_EXTENSION_ORIGINS=chrome-extension://<current-unpacked-extension-id>
```

Restart the backend after changing it. Do not use a wildcard, commit the unpacked ID, or reuse it as the Railway/Store
identity. Phase 4 rejects a missing or different WebSocket `Origin` before consuming the single-use ticket; API auth,
owner scope and ticket validation still apply.

In the extension's ignored `.env.local`, configure the exact local backend origin alongside the OIDC public-client
settings:

```dotenv
VITE_TRUSTGUARD_API_URL=http://localhost:8000
```

Only localhost may use HTTP. The value cannot contain a wildcard, credentials, path, query or fragment. Build and reload
the extension after changing it; the generated manifest should contain only `http://localhost:8000/*` plus any exact
OIDC origin you configured. Its `connect-src` also contains the derived exact `ws://localhost:8000` stream origin.

Smoke Phase 5–6 after the backend and local OIDC client are running:

1. Sign in, capture text/link and inspect the exact preview.
2. Choose request-scoped external/official lookup consent and submit.
3. Confirm a 200 inline result or 202 async acknowledgement appears with only an analysis ID/status.
4. Confirm the pending raw capture disappears after acceptance and the same owner can see the case on TrustGuard web.
5. Test 401/offline/rate-limit behavior; an ambiguous inline timeout must not be automatically resubmitted.
6. For async mode, confirm the panel shows allow-listed progress, reconnects with a new ticket, and falls back to polling
   when WebSocket is unavailable.
7. Close/reopen the panel and restart the service worker; confirm replay resumes from the saved cursor without regressing.
8. Confirm terminal progress triggers an authoritative final fetch. Progress text must never be treated as a verdict.

After changing source files, rerun `npm run build` and click **Reload** on the extension card. Do not load the source
directory: Chrome must load `extension/dist`.

## Verification

```powershell
npm run check
```

The build declares only `sidePanel`, `contextMenus`, `storage` and `identity`. Without `.env.local` it uses
`connect-src 'none'` and has no host permissions. With valid configuration it permits only the exact API/OIDC origins.
It has no content scripts and emits no source maps. Bundle checks reject embedded client-secret markers, remote code,
EventSource and XMLHttpRequest, require WebSocket construction only in the Side Panel, and reject it in the background
worker. The package checks fail if those boundaries drift.

The committed v4 subset lives in `contracts/openapi-v4.json`. When backend contracts intentionally change, regenerate
the snapshot and TypeScript types from the repository root environment:

```powershell
cd extension
npm run contracts:generate
```

The backend contract test rejects unreviewed snapshot drift.
