# TrustGuard AI — Kiểm thử và đảm bảo chất lượng

Tài liệu này phản ánh cấu hình test hiện tại trong `pyproject.toml`, `frontend/package.json`, test suites và scripts. Pytest mặc định chạy `tests/` và loại marker `integration`; coverage backend có ngưỡng `68%`.

## Bộ lệnh chuẩn

```bash
# Backend: local/unit/contract/API/evaluation tests (không gồm integration marker)
uv run ruff check .
uv run pytest -q
uv run pytest -q --cov --cov-report=term-missing --cov-report=xml:coverage.xml
uv run alembic heads

# PostgreSQL integration: dùng database disposable đã migrated
DATABASE_URL=postgresql://app:app@localhost:5432/p068_integration uv run alembic upgrade head
TEST_DATABASE_URL=postgresql://app:app@localhost:5432/p068_integration \
  uv run pytest tests/integration -o addopts= -m integration -q

# Frontend
cd frontend
npm test
npm run lint
npm run typecheck
npm run check:cutover
npm run build
npm run test:e2e
```

Nếu shell hiện tại không tìm thấy `uv` qua pyenv, chọn Python environment có `uv` hoặc dùng launcher hook `scripts/_pyrun.sh`; không đổi source/configuration chỉ để chạy test.

## Xác minh workspace lần này

Ngày 2026-09-01 (UTC), đã chạy:

- `uv run alembic heads`: đạt, một migration head `0023_account_lookup_consent`.
- `uv run ruff check .`: đạt, không có lint violation.
- `uv run pytest -q tests/unit/test_config.py tests/contract/test_openapi_v4.py`: đạt, `17 passed` trong `0.89s`.

Chưa ghi số lượng pass/coverage cho toàn suite: các số đó chỉ được cập nhật sau một lượt `pytest`/coverage hoàn tất trên revision cần phát hành. Không coi các kết quả trên là bằng chứng cho PostgreSQL thật, Redis, OIDC hosted, provider live, load hoặc backup/restore.

## Phạm vi automation

| Lớp | Vị trí | Mục tiêu |
|---|---|---|
| Unit | `tests/unit/` | scope, risk v7, consent, SSRF/tool policy, trust, memory, AI grounding/fallback, progress, auth và config. |
| API/contract | `tests/test_api/`, `tests/contract/` | OpenAPI v4, triage, conversation, reports/appeals, admin RBAC, blacklist, page capture và route compatibility. |
| Integration | `tests/integration/` | Parity `PostgresPlatformRepository` trên PostgreSQL. |
| Evaluation | `tests/eval/`, `scripts/evaluate_*.py` | Dataset-driven Security v4, AI, memory và official-link verification. |
| Frontend | `frontend/src/**/*.test.*`, Playwright | UI, a11y, cutover guard và production E2E. |

## Security regression checklist

- Out-of-scope/need-more-info không gọi investigation hay provider.
- Consent deny/undecided không mở external lookup; URL/redirect SSRF bị chặn.
- Provider no-hit/error/timeout không nâng verdict thành `SAFE`.
- Evidence, whitelist/blacklist and official verification precedence giữ policy deterministic; AI injection/failure không đổi risk/score.
- User read và conversation/event/replay phải owner-scoped; admin routes phải từ chối non-`security_admin`.
- Async kiểm tra idempotency, lease, outbox, replay cursor và WebSocket ticket; polling fallback vẫn dùng được khi realtime degrade.
- Report/appeal/admin action phải audit được; Copilot chỉ tạo gợi ý.
- Logs, persistence và artifact test không chứa raw private message, credential, OTP, token hoặc URL query nhạy cảm.

## Evaluation và smoke

```bash
uv run python scripts/evaluate_security_v4.py
uv run python scripts/evaluate_security_memory_v2.py
uv run python scripts/evaluate_security_ai.py
uv run python scripts/evaluate_official_link_verification.py
uv run python scripts/evaluate_security_langfuse.py validate
uv run python scripts/check_security_ai_rollout.py --target-stage off
```

Chạy smoke hosted sau deploy với hai danh tính OIDC riêng: user tạo/review flow, admin review flow, Redis/WebSocket outage với cursor polling fallback, provider consent/failure, rồi backup/restore rehearsal. Chỉ lưu evidence đã sanitize; không đưa token hoặc nội dung nhạy cảm vào CLI, log hay report.

Chi tiết manual scenarios và hosted-evidence validation: [docs/TESTING.md](docs/TESTING.md). Đặc tả kiến trúc: [ARCHITECTURE.md](ARCHITECTURE.md).
