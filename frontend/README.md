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

## Runtime Wave 1

- Tạo/đọc/list/report analysis qua REST v3.
- Xin WebSocket ticket và nối event stream; reconnect có cursor/dedupe, tự động fallback sang polling nếu stream chưa sẵn sàng.
- Hiển thị consent disclosure, provisional warning, live plan, final result, limitations và report.
- History lấy từ REST, không dùng dữ liệu product hard-coded.
- Admin queue và blacklist lấy từ REST; quyết định dùng endpoint v2 tương thích trong thời gian admin-action v3 còn là `501`.
- URL do người dùng gửi luôn được hiển thị dưới dạng text, không phải liên kết có thể bấm.

## Kiểm tra chất lượng

```bash
npm run lint
npm run typecheck
npm test
npm run build
npm run test:e2e
```

Playwright có fixture tại ranh giới HTTP để kiểm tra hai flow: user login → provisional → final → history và critical case → admin approval → blacklist. Khi chạy integration với backend thật, giữ `NEXT_PUBLIC_USE_MOCK_API=false` và không đăng ký fixture route.
