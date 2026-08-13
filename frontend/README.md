# TrustGuard AI Frontend

Next.js investigation workspace cho Security Triage. Product path dùng `/api/v4`; reviewed-action execution
tiếp tục dùng `/api/v3` có nhãn trong compatibility window. General fact-check metrics và source discovery v3
chỉ xuất hiện tại `/admin/compatibility`.

## Chạy local

```bash
npm install
copy .env.example .env.local
npm run dev
```

Kết nối backend thật:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_USE_MOCK_API=false
```

Nếu backend local bật demo auth:

```env
NEXT_PUBLIC_DEMO_USER_TOKEN=dev-user-token
NEXT_PUBLIC_DEMO_ADMIN_TOKEN=dev-admin-token
```

Hai token trên phải khớp `DEMO_USER_TOKEN`/`DEMO_ADMIN_TOKEN` của backend. Hosted production không dùng demo
token và dùng Authorization Code + PKCE:

```env
NEXT_PUBLIC_OIDC_ISSUER=https://your-tenant.auth0.com/
NEXT_PUBLIC_OIDC_CLIENT_ID=your-public-spa-client-id
NEXT_PUBLIC_OIDC_AUDIENCE=https://api.trustguard.example
NEXT_PUBLIC_OIDC_REDIRECT_URI=https://app.trustguard.example/auth/callback
NEXT_PUBLIC_OIDC_LOGOUT_URL=https://your-tenant.auth0.com/v2/logout?client_id=...&returnTo=...
```

Đăng ký redirect URI `/auth/callback`, logout URL và web origin tương ứng ở Identity Provider. Frontend tạo
`state`, `nonce`, PKCE verifier/challenge, đổi authorization code lấy token và giữ OIDC session theo browser tab.
Refresh-token rotation được dùng nếu provider cấp refresh token. Role đọc từ ID-token chỉ điều khiển presentation;
backend vẫn xác minh chữ ký access token và RBAC cho mọi API call. Các endpoint authorize/token và tên role claim
có thể override bằng các biến được liệt kê trong `.env.example`.

## Product surface

- Security Chat là entry point; sau intake chuyển thành workspace Conversation/Investigation/Action.
- OOS, need-more-info, multi-turn, WebSocket → polling fallback, report và appeal đều dùng contract v4.
- `/history` dùng server pagination/filter; `/cases/{id}` đọc owner-scoped detail và structured conversation resume.
- Admin gồm Observatory, Review Room, Trust lifecycle và Unified Audit.
- `/admin` redirect sang `/admin/review`; `/admin/platform` là alias của compatibility surface.
- UI chỉ dựng Signal Map, Timeline, Evidence và metrics từ field API có thật.

## Kiểm tra chất lượng

```bash
npm test
npm run lint
npm run typecheck
npm run check:cutover
npm run build
npm run build -- --webpack
npm run test:e2e
```

`npm run test:e2e` chạy Chromium trên standalone production server, tự copy `.next/static`/`public`, quản lý
server theo PID và dừng server sau test. Playwright cover mobile/keyboard user report-appeal-history-resume và
admin Review/Observatory/Trust/Audit, kèm WCAG structural checks và theme contrast assertion.

Trạng thái và boundary canonical nằm tại
[`docs/implementation-status.md`](../docs/implementation-status.md) và
[`docs/SECURITY_TRIAGE_IMPLEMENTATION_PLAN.md`](../docs/SECURITY_TRIAGE_IMPLEMENTATION_PLAN.md).
