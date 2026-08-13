# Evaluation Status

**Ngày kiểm tra:** 2026-08-13

## Automated checks

| Check | Result |
|---|---|
| Backend tests | 198 passed, 1 skipped |
| Frontend unit tests | 30 passed trong 6 test files |
| Frontend ESLint | Pass |
| Frontend TypeScript | Pass |

Commands:

```bash
PYENV_VERSION=myenv pytest -q
cd frontend
npm test
npm run lint
npm run typecheck
```

## Interpretation

Các kết quả trên xác nhận runtime/contract cũ đang ổn định. Chúng không chứng minh sản phẩm đã đạt
[scope mới](../../docs/scope.md). Test suite hiện vẫn tập trung vào URL safety và general fact-check;
chưa có acceptance coverage đầy đủ cho:

- security scope routing và zero provider calls cho request ngoài scope;
- multi-turn investigation và conversation ownership;
- recruitment/payment/OTP/fake-promotion threat taxonomy;
- whitelist precedence và brand/official-domain matching;
- bounded OfficialClaimVerifier và `NOT_FOUND != FALSE`;
- risk taxonomy mới và false-positive thresholds;
- wide-action proposal → review → execution end-to-end.

## Chưa được verify trong lần audit này

- Browser E2E.
- PostgreSQL/Redis integration với service thật.
- Live security-provider smoke.
- Hosted OIDC deployment.
- Load, backup/restore và production security test.
- Precision/recall/false-positive hoặc user satisfaction trên evaluation set scope mới.

Không dùng file này làm release evidence cho đến khi các gap trên có kết quả đo và artifact tái lập.
