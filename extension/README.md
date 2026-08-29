# TrustGuard Chrome Extension

Phase 2 provides a local-only Manifest V3 capture boundary. It registers exactly two context-menu actions for selected
text and explicit links, keeps one 10-minute pending capture in trusted `storage.session`, and renders a text-only Side
Panel preview. It does not authenticate, call TrustGuard APIs, inject a content script or request host access.

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

Smoke the Phase 2 flow before starting auth integration:

1. Select text in a normal page and in an iframe, then choose **Analyze selected text with TrustGuard**.
2. Right-click a link and choose **Analyze link with TrustGuard**.
3. Confirm the Side Panel shows only the selected value and that **Hủy và xóa nội dung** clears it.
4. Capture two different values quickly and confirm the latest value wins.
5. Inspect the service worker and Side Panel consoles; neither should report an error or network request.

After changing source files, rerun `npm run build` and click **Reload** on the extension card. Do not load the source
directory: Chrome must load `extension/dist`.

## Verification

```powershell
npm run check
```

The build deliberately declares only `sidePanel`, `contextMenus` and `storage`, uses `connect-src 'none'`, has no host
permissions/content scripts, and emits no source maps. Phase 2 bundle checks also reject fetch, WebSocket, EventSource
and XMLHttpRequest code. The package checks fail if those local-only boundaries drift.

The committed v4 subset lives in `contracts/openapi-v4.json`. When backend contracts intentionally change, regenerate
the snapshot and TypeScript types from the repository root environment:

```powershell
cd extension
npm run contracts:generate
```

The backend contract test rejects unreviewed snapshot drift.
