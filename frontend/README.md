# AI PROTECT Frontend

Next.js frontend cho AI Security Triage Assistant: user gửi message/URL đáng ngờ, theo dõi
investigation và nhận cảnh báo phishing/scam/impersonation. Runtime mặc định dùng contract `/api/v3`;
mock adapter chỉ được bật rõ ràng cho phát triển component hoặc fixture offline. Product boundary
canonical nằm tại [`docs/scope.md`](../docs/scope.md); general fact-check không phải product flow.

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

## Runtime hiện tại

- Tạo/đọc/list/report analysis qua REST v3.
- Xin WebSocket ticket và nối event stream; reconnect có cursor/dedupe, tự động fallback sang polling nếu stream chưa sẵn sàng.
- UI hỗ trợ consent disclosure, provisional warning, live plan, final result, limitations và report.
- History lấy từ REST, không dùng dữ liệu product hard-coded.
- Legacy case/blacklist admin vẫn đọc và quyết định qua REST v2 compatibility; appeal, reviewed
  action, campaign và operations metrics dùng REST v3.
- User report đi vào review queue v3; admin phải nhận review trước khi quyết định, và UI xử lý 409/double-submit bằng cách tải lại state.
- History cho phép theo dõi appeal; analysis workspace có screenshot consent/status và signed artifact view.
- Platform admin có review scam campaign, whitelist/blacklist và audit qua REST v3.
- URL do người dùng gửi luôn được hiển thị dưới dạng text, không phải liên kết có thể bấm.

Frontend này chưa đạt scope mới: workspace/composer/summary/history vẫn dùng “Fact-Check AI”, claim
stance và general-news/medical examples; chưa có scope boundary state hoặc multi-turn chat. Các
component `FactCheck*`, `ClaimResultCard`, source-management UI và screenshot UI là legacy hoặc ngoài
scope. Xem [`docs/implementation-status.md`](../docs/implementation-status.md) trước khi mở rộng UI.

Backend hiện persist/emit `provisional_warning` và step transition ngay trong planning loop. Để dùng
security provider thật cần chạy profile PostgreSQL/Redis và cấu hình provider keys phù hợp. Không dùng
`LIVE_PROVIDERS_REQUIRED=true` như production profile mới cho đến khi Google Fact Check/Tavily đã được
gỡ khỏi danh sách key bắt buộc.

## Kiểm tra chất lượng

```bash
npm run lint
npm run typecheck
npm test
npm run build
npm run test:e2e
```

Playwright có fixture tại ranh giới HTTP để kiểm tra hai flow: user login → provisional → final → history và critical case → admin approval → blacklist. Khi chạy integration với backend thật, giữ `NEXT_PUBLIC_USE_MOCK_API=false` và không đăng ký fixture route.
