# AI PROTECT Frontend

Next.js frontend cho luồng fact-check chính và kiểm tra URL bổ trợ. Runtime mặc định dùng contract `/api/v3`; mock adapter chỉ được bật rõ ràng cho phát triển component hoặc fixture offline.

## Chạy local

```bash
npm install
copy .env.example .env.local
npm run dev
```

Cấu hình kết nối backend thật:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_USE_MOCK_API=false
```

Trong môi trường local còn dùng demo auth của backend, có thể thêm:

```env
NEXT_PUBLIC_DEMO_USER_TOKEN=dev-user-token
NEXT_PUBLIC_DEMO_ADMIN_TOKEN=dev-admin-token
```

Hosted production không được cấu hình hai demo token trên. Thay vào đó, đặt `NEXT_PUBLIC_OIDC_LOGIN_URL` và lưu access token nhận được từ callback OIDC vào `ai_protect_access_token`; API client luôn ưu tiên token này.

## Runtime tại baseline hiện tại

- Tạo/đọc/list/report analysis qua REST v3.
- Xin WebSocket ticket và nối event stream; reconnect có cursor/dedupe, tự động fallback sang polling nếu stream chưa sẵn sàng.
- UI hỗ trợ consent disclosure, provisional warning, live plan, final result, limitations và report.
- History lấy từ REST, không dùng dữ liệu product hard-coded.
- Legacy case/blacklist admin vẫn đọc và quyết định qua REST v2 compatibility; appeal, reviewed
  action, campaign và operations metrics dùng REST v3.
- User report đi vào review queue v3; admin phải nhận review trước khi quyết định, và UI xử lý 409/double-submit bằng cách tải lại state.
- History cho phép theo dõi appeal; analysis workspace có screenshot consent/status và signed artifact view.
- Platform admin có review campaign và quản lý reviewed Source Registry Tier B qua REST v3.
- URL do người dùng gửi luôn được hiển thị dưới dạng text, không phải liên kết có thể bấm.

Backend hiện persist/emit `provisional_warning` và step transition ngay trong planning loop. Advanced
fact-check và campaign production path đã được wire vào worker; để dùng dữ liệu thật cần chạy profile
PostgreSQL/Redis và cấu hình provider keys với `LIVE_PROVIDERS_REQUIRED=true`. Hosted OIDC/browser E2E
và live-provider smoke vẫn thuộc release gate.

## Kiểm tra chất lượng

```bash
npm run lint
npm run typecheck
npm test
npm run build
npm run test:e2e
```

Playwright có fixture tại ranh giới HTTP để kiểm tra hai flow: user login → provisional → final → history và critical case → admin approval → blacklist. Khi chạy integration với backend thật, giữ `NEXT_PUBLIC_USE_MOCK_API=false` và không đăng ký fixture route.
