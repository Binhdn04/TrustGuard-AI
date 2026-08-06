# AI PROTECT Frontend

Next.js frontend cho luồng phân tích tin nhắn/URL của AI PROTECT. Phần này thuộc phạm vi Frontend/QA của Hiếu và tuân theo contract v1 trong `../docs/02-CONTRACT_AND_FIXTURES.md`.

## Chạy local

```bash
npm install
copy .env.example .env.local
npm run dev
```

Mở `http://localhost:3000`. Mặc định frontend gọi FastAPI tại `http://localhost:8000` và dùng demo bearer token theo role đăng nhập.

Để cấu hình kết nối FastAPI, đặt:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_USE_MOCK_API=false
```

Backend cần cung cấp:

- `POST /api/v1/analyses`
- `GET /api/v1/analyses/{analysis_id}`

## Kiểm tra chất lượng

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

## Quyết định triển khai

- UI bám workflow Analyze → Processing → Result, không bám endpoint `/chat` starter.
- URL trong evidence được render dưới dạng text thay vì link có thể bấm.
- Mock và HTTP client cùng triển khai `AnalysisApi`, giúp thay backend mà không sửa component.
- Polling được dùng cho vertical slice đầu; WebSocket sẽ bổ sung khi event API ổn định.
