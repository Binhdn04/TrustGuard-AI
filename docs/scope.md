# Product Scope — AI Security Triage Assistant

## 1. Định nghĩa sản phẩm

**AI Security Triage Assistant** là trợ lý AI hội thoại giúp người dùng kiểm tra các **tin nhắn và đường link đáng ngờ** có dấu hiệu:

- Phishing
- Lừa đảo (scam)
- Giả mạo tổ chức/thương hiệu
- Đánh cắp thông tin đăng nhập
- Lừa chuyển tiền / OTP
- Lừa tuyển dụng
- Khuyến mãi / trúng thưởng giả

trước khi người dùng thực hiện hành động có rủi ro.

> **Sản phẩm không phải hệ thống fact-check tin tức tổng quát.**

Câu hỏi trung tâm mà hệ thống trả lời:

> **"Tin nhắn này có dấu hiệu lừa đảo, phishing hoặc giả mạo nhằm khiến người dùng thực hiện một hành động nguy hiểm hay không?"**

Thay vì:

> "Mọi thông tin trong tin nhắn này có đúng sự thật hay không?"

---

# 2. Đối tượng sử dụng

## 2.1. User

Người dùng nhận được nội dung đáng ngờ qua:

- Zalo
- Messenger
- SMS
- Email
- Telegram
- WhatsApp
- Các nền tảng chat khác

Người dùng **chủ động gửi hoặc forward nội dung nghi ngờ** cho AI Assistant.

Hệ thống không tự động đọc toàn bộ private chat của người dùng.

---

## 2.2. Security Admin

Security Admin chịu trách nhiệm:

- Review các case nghiêm trọng
- Quản lý whitelist
- Quản lý blacklist
- Review domain đáng ngờ
- Xử lý user report
- Xử lý appeal
- Phê duyệt block domain
- Phê duyệt cảnh báo diện rộng
- Theo dõi các scam campaign
- Kiểm tra audit log

---

# 3. Input được hỗ trợ

## 3.1. Text

Ví dụ:

> "Bạn được hoàn 5 triệu. Đăng nhập vào đường link bên dưới để nhận tiền."

---

## 3.2. URL

Ví dụ:

```text
https://example.com/...
```

---

## 3.3. Tin nhắn + URL

Ví dụ:

> "Ngân hàng yêu cầu xác minh tài khoản tại https://example.com"

---

## 3.4. Multi-turn Conversation

Ví dụ:

```text
User:
HR này yêu cầu tôi đóng 500k phí hồ sơ.
Có bình thường không?

AI:
Họ có gửi website, email hoặc thông tin liên hệ cho bạn không?

User:
Có, đây là link...

AI:
Tôi sẽ kiểm tra link và đối chiếu với thông tin của tổ chức này.
```

Agent duy trì context trong phạm vi investigation hiện tại.

---

# 4. Threat Scope

Sản phẩm tập trung vào 5 nhóm threat chính.

## 4.1. Phishing

Phát hiện các dấu hiệu:

- Phishing URL
- Fake login
- Credential harvesting
- OTP harvesting
- Account verification scam
- Malicious redirect
- Suspicious login page

---

## 4.2. Brand / Organization Impersonation

Phát hiện:

- Fake domain
- Typosquatting
- Lookalike domain
- Suspicious subdomain
- Unicode / homograph attack
- Giả mạo thương hiệu
- Giả mạo ngân hàng
- Giả mạo doanh nghiệp
- Giả mạo cơ quan/tổ chức

Ví dụ:

```text
vietcombank-login.xyz
shopee-refund.net
facebook-security.example
```

---

## 4.3. Financial Scam

Bao gồm:

- Yêu cầu chuyển tiền
- Advance-fee scam
- Refund scam
- Prize scam
- Payment request
- Yêu cầu OTP
- Yêu cầu thông tin ngân hàng
- Investment solicitation có dấu hiệu scam

Agent chỉ đánh giá **dấu hiệu scam/rủi ro bảo mật**, không đánh giá một khoản đầu tư có sinh lời hay không.

---

## 4.4. Recruitment Scam

Ví dụ:

> "Bạn đã trúng tuyển. Chuyển 500.000 VNĐ phí hồ sơ để xác nhận vị trí."

Agent phân tích:

```text
Recruitment context
        +
Organization impersonation
        +
Payment request
        +
Urgency
        +
Suspicious contact/domain
```

---

## 4.5. Fake Promotion / Prize

Ví dụ:

> "Tập đoàn X tặng voucher 5 triệu. Nhận quà tại đường link bên dưới."

Agent kiểm tra:

- Organization
- URL
- Domain
- Campaign
- Requested action
- Payment request
- Credential request
- Official announcement khi cần

---

# 5. Out of Scope

## 5.1. General Fact-check

Không xử lý các câu hỏi như:

```text
"Tây Ban Nha vô địch World Cup đúng không?"

"Việt Nam tăng trưởng GDP 8% đúng không?"

"CEO công ty X vừa từ chức phải không?"
```

Hệ thống trả về:

```text
OUT_OF_SCOPE_GENERAL_FACT_CHECK
```

---

## 5.2. Political Misinformation

Không xác minh các phát biểu, chính sách hoặc tuyên bố chính trị nói chung.

---

## 5.3. General News Verification

Không xây pipeline:

```text
Claim
  ↓
Search toàn Internet
  ↓
Crawl báo chí
  ↓
Cross-source verification
  ↓
TRUE / FALSE
```

---

## 5.4. Science / Medical Fact-checking

Không xác minh claim khoa học, y tế hoặc học thuật nói chung.

---

## 5.5. Deepfake Detection

Không xác định:

- Video deepfake
- Audio deepfake
- AI-generated video

---

## 5.6. Malware Sandbox

Không chạy executable hoặc attachment không tin cậy trong sandbox trong scope hiện tại.

---

# 6. Scope Gate

Mọi request phải đi qua `Security Scope Classifier`.

```text
User Message
      │
      ▼
Security Scope Classifier
      │
 ┌────┴──────────────┐
 │                   │
 ▼                   ▼
IN_SCOPE       NEED_MORE_INFO
 │                   │
 │                Ask User
 │
 ▼
Investigation

hoặc

OUT_OF_SCOPE
      │
      ▼
Explain Product Boundary
```

Các tín hiệu security có thể bao gồm:

```text
URL
Login
Password
OTP
Payment
Bank account
Promotion
Prize
Recruitment
Urgency
Threat
Personal information
Download
QR/payment
Brand impersonation
Organization impersonation
```

Agent không được tự mở rộng nhiệm vụ chỉ vì phát hiện một factual claim.

---

# 7. AI Capabilities

## 7.1. Conversational AI

User tương tác trực tiếp với chatbot bằng ngôn ngữ tự nhiên.

Ví dụ:

```text
User:
Mẹ tôi vừa gửi link này.
Có nên mở không?

User:
HR bên này yêu cầu tôi đóng tiền.
Có lừa đảo không?

User:
Tại sao bạn cho rằng domain này đáng ngờ?

User:
Tôi đã nhập số điện thoại rồi nhưng chưa nhập OTP.
Tôi nên làm gì?
```

---

## 7.2. Message Understanding

LLM phân tích nội dung tin nhắn thành structured information.

Ví dụ:

```json
{
  "claimed_entity": "Company X",
  "scenario": "recruitment",
  "requested_action": "payment",
  "amount": 500000,
  "urgency": true,
  "url": null,
  "potential_threat": "recruitment_scam"
}
```

---

## 7.3. Investigation Planning

Agent tự quyết định investigation plan dựa trên context.

### Có URL

```text
URL
 ↓
URL Reputation
 ↓
RDAP
 ↓
Redirect
 ↓
Brand Matching
 ↓
Threat Intelligence
```

### Không có URL

```text
Message
 ↓
Scenario Detection
 ↓
Organization Extraction
 ↓
Scam Pattern Analysis
 ↓
Official Source Verification
```

---

## 7.4. Tool Orchestration

Agent có thể sử dụng:

- Threat Intelligence
- URL Reputation
- RDAP
- DNS
- Redirect Analyzer
- URL Analyzer
- Brand Matcher
- Official Source Retriever
- Internal Blacklist
- Internal Whitelist

Agent lựa chọn tool dựa trên investigation plan thay vì luôn gọi toàn bộ tool.

---

## 7.5. Evidence Synthesis

AI tổng hợp evidence kỹ thuật thành giải thích dễ hiểu.

Ví dụ raw evidence:

```json
{
  "domain_age_days": 3,
  "redirect_count": 4,
  "threat_intel_hits": 7,
  "official_domain_similarity": 0.87
}
```

AI giải thích:

> Website này mới được đăng ký, không thuộc tên miền chính thức của tổ chức đang được nhắc đến và có nhiều tín hiệu bảo mật đáng ngờ. Đặc biệt, trang đang yêu cầu bạn đăng nhập để nhận quà. Bạn không nên nhập mật khẩu hoặc OTP.

---

## 7.6. Multi-turn Investigation

Agent duy trì context của case.

```text
User:
HR yêu cầu tôi chuyển tiền.

AI:
Bạn có link, email hoặc thông tin liên hệ của họ không?

User:
Có, đây là link...

AI:
Tôi đã kiểm tra link...
```

---

## 7.7. Uncertainty Handling

Agent không bắt buộc mọi case phải là `SAFE` hoặc `MALICIOUS`.

Có thể kết luận:

```text
SUSPICIOUS
INSUFFICIENT_EVIDENCE
```

Ví dụ:

> Tôi chưa có đủ bằng chứng để kết luận website này là phishing. Tuy nhiên, domain không thuộc website chính thức và tin nhắn đang yêu cầu OTP, vì vậy bạn không nên tiếp tục cho đến khi xác minh được nguồn gửi.

---

# 8. Official Claim Verification

Không xây `GeneralFactCheckAgent`.

Thành phần này được giới hạn thành:

```text
OfficialClaimVerifier
```

Nhiệm vụ:

> Xác minh một claim chỉ khi claim đó ảnh hưởng trực tiếp đến việc đánh giá scam/phishing/impersonation.

Ví dụ:

```text
"Vietcombank đang phát voucher 5 triệu."
```

Agent có thể kiểm tra nguồn chính thức của Vietcombank để xác định chương trình này có được công bố hay không.

Kết quả:

```text
OFFICIAL_CONFIRMED
OFFICIAL_CONTRADICTED
NOT_FOUND
INSUFFICIENT_EVIDENCE
```

Quy tắc bắt buộc:

```text
NOT_FOUND != FALSE
```

Không tìm thấy thông tin trên nguồn chính thức không đồng nghĩa thông tin chắc chắn là giả.

---

# 9. Fact-check Boundary

Fact verification chỉ được gọi khi:

```text
Claim
  │
  ▼
Does this claim directly affect
security/scam determination?
  │
 ┌┴──────────────┐
 │               │
NO              YES
 │               │
 ▼               ▼
Skip       Official Verification
```

Giới hạn:

```yaml
official_verification:
  max_claims_per_case: 1
  max_search_queries: 2
  max_sources: 5

  allowed_purposes:
    - verify_official_campaign
    - verify_brand_announcement
    - verify_recruitment_program
    - verify_official_domain
    - verify_official_contact

  forbidden:
    - general_news
    - politics
    - sports
    - science
    - medical
    - predictions
```

---

# 10. Risk Engine

LLM không tự quyết định toàn bộ risk score.

```text
Evidence
   │
   ▼
Deterministic Risk Engine
   │
   ▼
Risk + Confidence
   │
   ▼
LLM Explanation
```

Risk signals có thể bao gồm:

```text
Threat intelligence
Blacklist
Whitelist

Domain age
Domain reputation
Typosquatting
Homograph
Redirect

Credential request
OTP request
Payment request

Brand impersonation
Urgency
Social engineering

Official verification
```

---

# 11. Risk Classification

Output chuẩn:

```text
SAFE
LOW_RISK
SUSPICIOUS
HIGH_RISK
MALICIOUS
INSUFFICIENT_EVIDENCE
```

Không sử dụng:

```text
TRUE
FALSE
FAKE_NEWS
```

Ví dụ structured output:

```json
{
  "risk": "HIGH_RISK",
  "score": 87,
  "confidence": "HIGH",
  "threat_type": "BRAND_IMPERSONATION",
  "evidence": [
    "Domain does not match official domain",
    "Domain was recently registered",
    "Page requests credentials"
  ],
  "recommended_actions": [
    "Do not enter credentials",
    "Do not provide OTP",
    "Verify through the organization's official website"
  ]
}
```

---

# 12. False Positive Policy

False positive là requirement quan trọng của sản phẩm.

Không có evidence mạnh:

```text
SUSPICIOUS
```

thay vì:

```text
MALICIOUS
```

`MALICIOUS` cần evidence mạnh, ví dụ:

```text
Threat Intelligence confirmed
OR
Internal confirmed blacklist
OR
Security Admin confirmed
OR
Multiple independent high-confidence indicators
```

Domain khác official domain **không tự động đồng nghĩa phishing**.

Whitelist phải được ưu tiên để tránh cảnh báo nhầm.

---

# 13. Human-in-the-loop

## Agent được phép

```text
Analyze message
Analyze URL
Warn individual user
Recommend action
Create security report
Suggest blacklist
Suggest escalation
Cluster related reports
```

## Agent không được tự động

```text
Block domain globally
Issue organization-wide warning
Ban user
Declare organization compromised
```

Flow:

```text
Agent detects high-risk case
           │
           ▼
Recommend escalation
           │
           ▼
Security Admin
           │
      ┌────┴────┐
      ▼         ▼
   Approve    Reject
      │
      ▼
Blacklist / Global Warning
```

---

# 14. Memory

## 14.1. Case Memory

Memory phục vụ multi-turn investigation.

```text
User:
HR yêu cầu tôi chuyển tiền.

AI:
Bạn có URL không?

User:
Đây...

→ Agent hiểu URL thuộc investigation trước đó.
```

---

## 14.2. Security Memory

Lưu structured threat intelligence:

```text
domain
url_fingerprint
brand
threat_type
risk
first_seen
last_seen
report_count
admin_verdict
evidence
```

Không cần lưu toàn bộ private conversation nếu không cần thiết.

---

# 15. User-facing Product

Giao diện chính là **AI Chatbot**.

```text
┌──────────────────────────────────────────┐
│ AI Security Assistant                    │
├──────────────────────────────────────────┤
│                                          │
│ Gửi tin nhắn hoặc đường link mà          │
│ bạn cảm thấy đáng ngờ.                   │
│                                          │
│ User                                     │
│ "Tôi nhận được tin này..."               │
│                                          │
│ Assistant                                │
│ ⚠ HIGH RISK                             │
│                                          │
│ Tin nhắn có dấu hiệu giả mạo...          │
│                                          │
│ Evidence                                 │
│ ✓ Domain không chính thức                │
│ ✓ Domain mới đăng ký                     │
│ ✓ Yêu cầu đăng nhập                      │
│                                          │
│ [Technical Details]                      │
│ [Report]                                 │
│                                          │
│ ┌──────────────────────────────────────┐ │
│ │ Hỏi thêm hoặc gửi tin nhắn/link...  │ │
│ └──────────────────────────────────────┘ │
└──────────────────────────────────────────┘
```

---

# 16. Security Admin Product

Security Admin Dashboard bao gồm:

```text
Overview
Cases
Reports
Domains
Threats
Campaigns
Blacklist
Whitelist
Appeals
Audit Logs
```

Security Admin có **AI Security Copilot**.

Ví dụ:

```text
Admin:
Có campaign nào mới trong 24h?

AI:
Phát hiện một cụm gồm 27 report có nội dung tương tự,
liên quan đến 3 domain đang giả mạo chương trình
khuyến mãi của Brand X.
```

Admin có thể hỏi:

```text
"Tại sao domain X bị đánh giá HIGH_RISK?"

"Tóm tắt evidence của campaign này."

"Các domain nào đang liên quan?"

"Những case nào cần review trước?"
```

AI có quyền **recommend**, nhưng quyết định block/cảnh báo diện rộng thuộc Security Admin.

---

# 17. Product Architecture

```text
                         USER
                           │
                           ▼
                    AI Chat Interface
                           │
                           ▼
                    Security Agent
                           │
                 ┌─────────┴─────────┐
                 │    Scope Gate     │
                 └─────────┬─────────┘
                           │
                           ▼
                  Message Understanding
                           │
                           ▼
                    Investigation Plan
                           │
       ┌───────────────────┼────────────────────┐
       │                   │                    │
       ▼                   ▼                    ▼
 URL Intelligence     Scam Analysis      Brand Analysis
       │                   │                    │
 ┌─────┼─────┐             │                    │
 ▼     ▼     ▼             │                    │
RDAP   TI  Redirect        │                    │
       │                   │                    │
       └───────────┬───────┴────────────────────┘
                   │
                   ▼
          OfficialClaimVerifier
             (only if needed)
                   │
                   ▼
              Evidence Set
                   │
                   ▼
              Risk Engine
                   │
           ┌───────┴────────┐
           ▼                ▼
     AI Explanation    Escalation Engine
                            │
                            ▼
                      Security Admin
                            │
                            ▼
                       HITL Decision
```

---

# 18. Product Boundary

> **Sản phẩm không xác định một thông tin nói chung là thật hay giả. Sản phẩm đánh giá liệu một tin nhắn hoặc đường link do người dùng chủ động cung cấp có dấu hiệu phishing, scam hoặc giả mạo tổ chức/thương hiệu nhằm thúc đẩy người dùng thực hiện hành động có rủi ro hay không.**
>
> **Việc xác minh thông tin chỉ được thực hiện khi claim đó ảnh hưởng trực tiếp đến đánh giá rủi ro bảo mật và ưu tiên nguồn chính thức của tổ chức liên quan.**

---

# 19. Product Scope Summary

## IN SCOPE

- AI Security Chatbot
- Multi-turn investigation
- Message understanding
- URL analysis
- Phishing detection
- Scam detection
- Brand impersonation
- Recruitment scam
- Promotion/prize scam
- Credential/OTP theft detection
- Financial scam signals
- RDAP/DNS analysis
- Redirect analysis
- Threat Intelligence
- Blacklist / Whitelist
- Official-source verification
- Risk scoring
- Confidence estimation
- Explainable warning
- User report
- Security Admin
- HITL
- Security memory
- Case memory
- Campaign clustering
- Appeal
- Audit logging
- API cost/rate-limit monitoring

## OUT OF SCOPE

- General fact-check
- General fake-news detection
- Political misinformation verification
- General news verification
- Science fact-check
- Medical fact-check
- Sports fact-check
- Prediction verification
- Deepfake detection
- Audio/video verification
- General-purpose web search for truth
- Automatic global blocking without HITL
- Reading all private conversations
- Executing suspicious files in a malware sandbox
