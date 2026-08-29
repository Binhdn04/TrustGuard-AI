# TrustGuard Chrome Extension

Phase 3 provides a local-only Manifest V3 capture and OIDC boundary. It captures only user-selected text/links and uses
Authorization Code + PKCE through `chrome.identity`; auth transactions and tokens stay in trusted `storage.session`.
The Side Panel receives only a minimal auth status. The extension does not call TrustGuard APIs yet, inject a content
script or request arbitrary host access.

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

After changing source files, rerun `npm run build` and click **Reload** on the extension card. Do not load the source
directory: Chrome must load `extension/dist`.

## Verification

```powershell
npm run check
```

The build declares only `sidePanel`, `contextMenus`, `storage` and `identity`. Without `.env.local` it uses
`connect-src 'none'` and has no host permissions. With valid OIDC config it permits only the exact issuer/token origin.
It has no content scripts and emits no source maps. Bundle checks reject embedded client-secret markers, remote code,
WebSocket, EventSource and XMLHttpRequest. The package checks fail if those boundaries drift.

The committed v4 subset lives in `contracts/openapi-v4.json`. When backend contracts intentionally change, regenerate
the snapshot and TypeScript types from the repository root environment:

```powershell
cd extension
npm run contracts:generate
```

The backend contract test rejects unreviewed snapshot drift.
