# TrustGuard AI — Security Triage Assistant

TrustGuard AI giúp người dùng đánh giá tin nhắn và URL đáng ngờ trước khi chuyển tiền, đăng nhập, cung cấp OTP hoặc thực hiện hành động có rủi ro. Public runtime duy nhất là **Security Triage API v4** tại `/api/v4`; public API v2/v3 và vector-search compatibility đã được gỡ bỏ.

> Web đã deploy: <https://frontend-production-3dd5.up.railway.app/>
>
> Tài khoản admin để test: `TestTrustGuard@AI.com`  
> Mật khẩu: `TestTrustGuard@AI.com`
>
> Kết quả evaluation: [eval/results/security-langfuse-report.json](eval/results/security-langfuse-report.json). Ảnh chụp Langfuse nằm trong [eval/evidence](eval/evidence).

## Bắt đầu nhanh

Yêu cầu: Python 3.11+, [uv](https://docs.astral.sh/uv/) và Node.js 22+. Docker + Docker Compose chỉ cần cho full stack.

### Local inline

Chế độ này dùng SQLite và demo auth; không cần PostgreSQL, Redis hay API key bên ngoài.

```bash
cp .env.example .env
uv sync
uv run uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

Chạy frontend ở terminal khác:

```bash
cd frontend
cp .env.example .env.local
npm ci
npm run dev
```

Để đăng nhập bằng demo auth local, cấu hình hai demo token theo [hướng dẫn frontend](frontend/README.md).

- Frontend: <http://localhost:3000>
- Backend: <http://localhost:8000>
- API docs (local/development): <http://localhost:8000/docs>
- Readiness: <http://localhost:8000/health/ready>

### Full stack với Docker Compose

```bash
cp .env.example .env
cp frontend/.env.example frontend/.env.local
docker compose up --build -d
```

Services dùng các địa chỉ mặc định: frontend `http://localhost:3000`, backend `http://localhost:8000`, PostgreSQL và Redis chỉ internal. Dừng stack bằng `docker compose down`; không dùng `-v` nếu chưa có backup cho volumes.

## Tài liệu

| Nội dung | Tài liệu canonical |
|---|---|
| Phạm vi sản phẩm, API v4, runtime flow, safety invariants và persistence | [Product and Architecture](docs/PRODUCT_ARCHITECTURE.md) |
| Trạng thái implementation, phần pending và release gates | [Current Status](docs/CURRENT_STATUS.md) |
| Cấu hình môi trường, Railway, migrations, async/streaming rollout và rollback | [Deployment and Operations](docs/DEPLOYMENT.md) |
| Lệnh kiểm thử, evaluation và manual/hosted smoke | [Testing and Verification](docs/TESTING.md) |
| Sơ đồ topology và trust boundary | [Architecture diagram](ARCHITECTURE.md) |
| Đặc tả sản phẩm và thiết kế tóm tắt | [Specification and design](SPECIFICATION_AND_DESIGN.md) |
| Hướng dẫn kiểm thử root và evidence workspace gần nhất | [Root testing guide](TESTING.md) |

Các thay đổi runtime cần tuân thủ safety invariants và release gates trong tài liệu canonical ở trên.
