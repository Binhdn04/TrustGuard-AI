# Contract and Fixtures — Security v4 Current State

Security product contract hiện tại là `v4` tại `/api/v4`. `/api/v2` và `/api/v3` là compatibility
contracts; không được dùng enum/field claim-centric của chúng để mở rộng Security v4.

## 1. Request và conversation contract

Single-turn request:

```json
{
  "message": "HR yêu cầu tôi đóng 500.000 đồng phí hồ sơ",
  "consent": {
    "external_url_lookup": true,
    "official_source_lookup": false
  }
}
```

Follow-up phải gửi đồng thời owner-scoped conversation ID và optimistic version:

```json
{
  "message": "Họ còn yêu cầu tôi gửi OTP",
  "conversation_id": "10000000-0000-4000-8000-000000000001",
  "conversation_version": 1,
  "consent": {
    "external_url_lookup": false,
    "official_source_lookup": false
  }
}
```

Thiếu một trong `conversation_id`/`conversation_version` bị reject. Stale version trả conflict; khác
owner trả forbidden; follow-up mô tả case/entity khác bị yêu cầu mở conversation mới.

## 2. Scope và structured security context

Scope decision:

```text
IN_SCOPE | NEED_MORE_INFO | OUT_OF_SCOPE_GENERAL_FACT_CHECK
```

- `OUT_OF_SCOPE_GENERAL_FACT_CHECK`: terminal `END`, có `boundary_message`, không resolve investigation.
- `NEED_MORE_INFO`: terminal `END`, có đúng một focused `follow_up_question`.
- `IN_SCOPE`: có `SecurityContextV4`; sau investigation/risk sẽ terminal với grounded result.

`SecurityContextV4` gồm:

```text
claimed_entity, scenario, requested_action, amount, urgency, urls,
credential_request, otp_request, payment_request,
personal_information_request, impersonation_signals, potential_threat
```

Scenario hiện có recruitment, promotion/prize, account verification, payment, refund và unknown.
Potential threat gồm phishing, brand impersonation, financial/recruitment/promotion scam,
credential theft và undetermined security threat.

## 3. Investigation, evidence và risk response

Response v4 giữ:

```text
scope decision + reasons
conversation ID/version
investigation status/plan
SecurityEvidenceV4[] + normalized tool errors
risk + score + confidence + threat type + policy version
recommended actions + grounded explanation + explanation evidence refs
limitations + lifecycle timestamps
```

Product risk taxonomy:

```text
SAFE | LOW_RISK | SUSPICIOUS | HIGH_RISK | MALICIOUS | INSUFFICIENT_EVIDENCE
```

Official verification taxonomy:

```text
OFFICIAL_CONFIRMED | OFFICIAL_CONTRADICTED | NOT_FOUND | INSUFFICIENT_EVIDENCE
```

Contract v4 không expose `TRUE/FALSE/FAKE_NEWS`, `ClaimStance`, claim retriever hoặc general
fact-check confidence như product verdict.

## 4. API v4 đã implement

| API group | Routes chính | Trạng thái |
|---|---|---|
| Capabilities | `GET /api/v4/capabilities` | Implemented, truthful `pre_cutover` profile |
| Analysis | `POST/GET /api/v4/analyses`, `GET /analyses/page`, `GET /analyses/{id}` | Implemented, owner-scoped + paginated/filterable |
| Conversation | `GET /api/v4/conversations`, `GET /conversations/{id}` | Implemented, owner-scoped page + versioned resume |
| Events/realtime | `GET /analyses/{id}/events`, `POST /ws-tickets`, WebSocket `/stream` | Implemented, cursor replay + single-use ticket |
| Feedback | user create/list under analyses; admin pages + terminal decision under `/api/v4/admin/reports|appeals`; privacy-minimized case read tại `GET /api/v4/admin/analyses/{analysis_id}` | Implemented, owner/RBAC + immutable audit; admin detail không trả raw conversation/owner |
| Brand registry | create/list/page/disable `/api/v4/admin/brands` | Implemented, admin-only |
| Whitelist | create/list/page/disable `/api/v4/admin/whitelist` | Implemented, admin-only |
| Security Memory | list/page/correct/audit `/api/v4/admin/security-memory` | Implemented, admin-only |
| Security campaign | list/page/detail/decision/audit `/api/v4/admin/security-campaigns` | Implemented, admin-only |
| Intelligence | `/api/v4/admin/intelligence/domains|threats` | Implemented, paginated/filterable |
| Unified v4 audit | `GET /api/v4/admin/audit` | Implemented cho trust/memory/campaign/feedback |

Security v4 tái sử dụng reviewed-action API v3:

- `GET /api/v3/admin/actions`, detail và audit;
- `POST /api/v3/admin/actions/{id}/decision`;
- action record có `security_analysis_id`, canonical target và immutable evidence snapshot;
- final status là `rejected`, `executed` hoặc `failed`; `approved` chỉ là execution attempt trung gian.

V3 report-review/appeal/metrics infrastructure vẫn tồn tại. V3 source discovery, general campaigns,
screenshot và v2 routes là legacy compatibility, không phải Security v4 product contract.

Các route page là additive và trả `{contract_version, items, total, limit, offset}`. Route list cũ vẫn trả
array để giữ compatibility cho frontend hiện tại. `SecurityReportRecordV4` và `SecurityAppealRecordV4`
chỉ có reviewer/outcome/decision fields ở terminal state; quyết định lần hai trả `409 CONFLICT`.

## 5. Security Memory và campaign contracts

`SecurityMemoryRecordV4` lưu structured intelligence, không lưu raw message:

```text
analysis_id, canonical_domains, url_fingerprints, redirect_targets,
claimed_brand, scenario, requested_action, security_patterns, lexical_features,
threat_type, risk, risk_policy_version, fingerprint_version,
first/last seen, report_count, admin_verdict, evidence_refs
```

Correction yêu cầu admin verdict khác `unreviewed` và reviewer note. Audit snapshot giữ previous/current
verdict, reviewer, note, evidence refs và policy/fingerprint version.

`SecurityCampaignRecordV4` luôn bắt đầu `pending_review`, có ít nhất ba unique analysis IDs, time window,
named aggregate signals, evidence refs và clustering version. Confirm/reject không tạo broad warning;
mọi decision append campaign audit.

## 6. Safety invariants đã enforce

- Out-of-scope không gọi investigation/provider/legacy analysis service.
- External URL lookup cần consent; local rules/trust lookup vẫn chạy an toàn.
- Whitelist có provenance/version và precedes negative scoring.
- `NOT_FOUND`, provider no-hit/error, domain age hoặc mismatch riêng lẻ không đủ tạo malicious.
- LLM không trực tiếp ghi score/risk/admin action.
- Wide action không execute khi chưa có approved decision, reviewer, note, evidence snapshot và target.
- Duplicate proposal/decision/execution không tạo side effect thứ hai.
- Memory/campaign không lưu raw conversation hoặc URL query token; Security campaign không dùng claim
  embeddings.

## 7. Test fixtures và evidence hiện có

Automated tests hiện tại cover:

- phishing/credential/OTP, financial, recruitment và promotion/prize context;
- out-of-scope và need-more-info terminal transitions;
- text, URL, consent/no-consent, DNS/redirect/RDAP/reputation errors và SSRF;
- whitelist precedence, brand match/mismatch, official confirmed/contradicted/not-found;
- deterministic risk thresholds, grounded evidence refs và persistence lifecycle;
- multi-turn owner/version/retention/conflicting-case behavior;
- HITL auth, rejection, idempotency, execution rollback và audit;
- repeated domain, shared redirect, same brand/different domain, scenario/action pattern, unrelated case,
  time window, memory correction, provenance/version và SQLite reopen.
- capabilities/OpenAPI freeze, owner-scoped pages, admin feedback RBAC/terminal conflict, unified audit và
  domain/threat intelligence explorer.
- frontend OOS/need-more-info/risk presentation, polling fallback, multi-turn/history resume, report/appeal,
  admin review, Observatory, Trust/Audit, RBAC và compatibility isolation bằng typed v4 fixtures.

Các fixture analysis, claim/stance, source-discovery và screenshot cũ đã được xóa cùng test contract của
deprecated product path. WP9 giữ versioned deterministic dataset/report cho threat, safe official,
false-positive, OOS, provider failure, multi-turn và wide-action, cùng contract reviewed-action v3 còn hoạt động.

## 8. Compatibility và cutover còn lại

1. Frontend product path đã dùng v4; `/admin` redirect sang Review Room và metrics/source discovery v3 chỉ còn
   trong compatibility surface. Reviewed-action execution v3 vẫn là ngoại lệ có nhãn đã công bố.
2. Drain job, freeze legacy writers/source discovery, rồi đo `legacy_read/legacy_write` trong compatibility window.
3. Kiểm chứng backup/export/restore rồi archive hoặc drop `fact_check_*`, source discovery, claim vectors
   và pgvector nếu không còn consumer.
4. Xóa deprecated provider config, v2 starter route, v3 product writers và frontend compatibility code.
5. Chỉ tuyên bố release sau hosted PostgreSQL/Redis/OIDC/provider smoke, restore/load và các gate WP9 còn lại.
