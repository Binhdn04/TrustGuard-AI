# Contract and Fixtures — Current State and Required Migration

## 1. Contract đang chạy

`/api/v3` dùng `AnalysisCreateRequestV3`, kế thừa v2:

```json
{
  "message": "Nhận quà tại https://example.com/login",
  "consent_to_scan_urls": true,
  "consent_to_capture_screenshot": false
}
```

Không có `conversation_id`, scope decision hoặc official-verification consent riêng.

Response hiện dùng hai lớp classification:

```text
RiskLevel: low | medium | high | critical
Verdict: safe | suspicious | malicious | inconclusive
```

Nó còn chứa `claims`, `fact_check_basis`, `fact_check_confidence`, `ClaimStance` và
`CLAIM_RETRIEVER`; đây là contract cũ cần deprecate.

## 2. API đã implement

| API group | Trạng thái |
|---|---|
| `/api/v3/analyses` create/list/get | Implemented |
| analysis events với cursor | Implemented |
| ticketed analysis WebSocket | Implemented |
| reports và report review queue | Implemented |
| user/admin appeals | Implemented |
| admin actions list/get/decision | Implemented; thiếu product-flow proposal/executor |
| admin campaigns list/detail/decision | Implemented |
| admin metrics | Implemented |
| screenshot status/signed artifact | Implemented nhưng ngoài scope mới |
| admin sources/source discoveries | Implemented nhưng deprecated |
| `/api/v2` analysis/admin | Compatibility legacy |
| `/api/v2/chat` | Starter legacy |

## 3. Contract vNext cần có

### Request

```json
{
  "message": "HR yêu cầu tôi đóng 500.000 đồng phí hồ sơ",
  "conversation_id": "optional-owner-scoped-id",
  "consent": {
    "external_url_lookup": true,
    "official_source_lookup": true
  }
}
```

### Scope decision

```text
IN_SCOPE | NEED_MORE_INFO | OUT_OF_SCOPE_GENERAL_FACT_CHECK
```

Out-of-scope response phải terminal trước provider routing. `NEED_MORE_INFO` chứa một câu hỏi tập
trung và cho phép follow-up trong cùng conversation.

### Structured security context

```text
claimed_entity, scenario, requested_action, amount, urgency,
urls, credential_request, otp_request, payment_request,
impersonation_signals, potential_threat
```

### Official verification

```text
OFFICIAL_CONFIRMED | OFFICIAL_CONTRADICTED | NOT_FOUND | INSUFFICIENT_EVIDENCE
```

Chỉ allow purpose: official campaign, brand announcement, recruitment program, official domain và
official contact. Enforce một claim, hai query, năm official sources; `NOT_FOUND != FALSE`.

### Product risk

```text
SAFE | LOW_RISK | SUSPICIOUS | HIGH_RISK | MALICIOUS | INSUFFICIENT_EVIDENCE
```

Contract mới không expose `TRUE/FALSE/FAKE_NEWS` hoặc claim stance như product verdict.

## 4. Safety invariants cần giữ và bổ sung

Đã có:

- LLM không có quyền trực tiếp ghi score/risk/action.
- Provider failure/no-hit không tự tạo safe.
- External URL/domain call cần consent.
- Admin blacklist decision và evidence/audit được persist atomically.

Cần bổ sung:

- Out-of-scope không tạo tool/provider call.
- Whitelist chạy trước negative scoring và có provenance/version.
- Official `NOT_FOUND` chỉ tạo limitation.
- Domain mismatch/age đứng riêng không đủ cho malicious.
- Wide action không execute nếu chưa có approved decision.

## 5. Fixtures hiện tại

`tests/fixtures/analyses.jsonl` có 12 scenario frozen cho contract cũ. Các case URL safety, no-consent,
provider timeout, Unicode domain và SSRF vẫn hữu ích. Các case `suspicious_claim_001`,
`false_claim_001`, claim retriever và stance là legacy.

Fixture vNext bắt buộc:

| Fixture | Assertion chính |
|---|---|
| phishing credential | URL/brand/credential evidence, high risk |
| OTP impersonation | OTP + brand + urgency, high risk |
| financial transfer | payment/social engineering routing |
| recruitment fee | recruitment + payment + contact/domain evidence |
| fake promotion | promotion + unofficial domain + login |
| safe official | whitelist precedence, safe/low risk |
| domain mismatch only | không được malicious |
| provider no-hit/timeout | limitation, không được safe vì no-hit |
| official not found | không map false/malicious |
| general news/politics/medical/sports | out-of-scope, zero provider calls |
| missing context | need-more-info và focused question |
| multi-turn follow-up | đúng owner/conversation, không trộn case |
| no consent | chỉ local tools |
| wide action | không bypass approval/audit |

## 6. Compatibility strategy

1. Thêm vNext model/route hoặc version mới, không nhồi nullable field vào v2.
2. Chuyển frontend sang contract mới.
3. Giữ v2 read-only trong compatibility window nếu còn consumer.
4. Đo usage, sau đó xóa `/api/v2/chat`, v2 write routes và legacy model/tool enums.
5. Xóa fixture legacy sau khi scope-new evaluation suite thay thế tương đương URL/security coverage.
