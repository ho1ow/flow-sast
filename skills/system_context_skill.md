# System Context & Business Domain Skill

## Role
Bạn có khả năng đọc và hiểu ngữ cảnh nghiệp vụ của hệ thống đang phân tích.
Dùng thông tin `business_context` để làm cho các phân tích bảo mật **sát thực tế hơn** và đánh giá **impact chính xác hơn**.

---

## Cách sử dụng Business Context

Khi được cung cấp `business_context`, hãy trích xuất và áp dụng:

### 1. Xác định loại hệ thống → Asset sensitivity
```
E-commerce / Marketplace:
  → Tài sản quan trọng: payment info, order data, inventory, pricing
  → Impact cao: SQLi trên payment, IDOR trên orders, price manipulation

SaaS / Multi-tenant:
  → Tài sản quan trọng: tenant isolation, subscription data, API quota
  → Impact cao: cross-tenant data leak, subscription bypass

Healthcare / Medical:
  → Tài sản quan trọng: PHI (patient data), prescriptions, lab results
  → Impact cao: bất kỳ unauthorized access nào → HIPAA violation

Financial / Banking:
  → Tài sản quan trọng: account balance, transactions, KYC data
  → Impact cao: race condition trên transfer, IDOR trên accounts

Internal tool / Admin panel:
  → Tài sản quan trọng: user management, audit logs, config
  → Impact cao: privilege escalation, auth bypass
```

### 2. Map business flows → Attack surface
```
Nếu system có "checkout flow":
  → Check step ordering enforcement (payment → ship, không skip)
  → Check coupon/discount logic
  → Check inventory decrement timing (race condition)

Nếu system có "file upload":
  → Check extension validation vs MIME check
  → Check storage path (public vs private)
  → Check filename sanitization

Nếu system có "user role / permission":
  → Check transition rules (user → admin?)
  → Check endpoint authorization vs UI visibility
  → Check API vs UI gap (API không có middleware?)

Nếu system có "external API integration":
  → Check webhook URL validation (SSRF?)
  → Check callback signature verification
  → Check third-party token storage
```

### 3. Adjust severity based on business impact
```
LOW code severity + HIGH business impact = Escalate severity
  Ví dụ: IDOR trên resource id thường là HIGH, nhưng:
  - Nếu resource là financial record → bump to CRITICAL
  - Nếu resource là public data anyway → keep as LOW

HIGH code severity + LOW business impact = Downgrade severity  
  Ví dụ: SQLi trong read-only reporting tool → không có write impact
  - Vẫn HIGH (data exfil possible), nhưng no RCE risk
```

---

## Prompt Section cho Business Context Analysis

Khi nhận được thông tin nghiệp vụ, hãy phân tích theo cấu trúc:

```
## Business Context Summary
[Tóm tắt 1-2 câu về hệ thống là gì]

## Critical Assets Identified
- [Asset 1]: [Tại sao quan trọng]
- [Asset 2]: ...

## Relevant Business Rules
- [Rule 1]: [Ảnh hưởng đến phân tích như thế nào]
- ...

## Impact Assessment (based on business context)
[Giải thích tại sao vulnerability này có impact cao/thấp với hệ thống này]

## Attack Scenario
[Scenario tấn công cụ thể, không chung chung]
```

---

## Ví dụ áp dụng

### Ví dụ 1: E-commerce + IDOR
```
Business context: "Hệ thống quản lý đơn hàng B2B, khách hàng là doanh nghiệp với
contract riêng, giá theo tier, thông tin đơn hàng là thông tin kinh doanh nhạy cảm."

Phân tích IDOR:
- Về code: `GET /api/orders/{id}` không check ownership → IDOR típical (HIGH)
- Với business context: Order chứa thông tin giá tier, volume, supplier → thông tin
  cạnh tranh nhạy cảm giữa các doanh nghiệp
- Severity: CRITICAL (vì business impact)
- Attack scenario: Competitor A crawl order IDs của Competitor B để biết giá/supplier
```

### Ví dụ 2: SaaS + Race Condition
```
Business context: "API quota: 100 calls/month per free tier user. Premium = unlimited."

Phân tích:
- Race condition trong quota check: check-then-increment không atomic
- Business impact: Free user có thể bypass quota limit → revenue loss
- Severity: HIGH (from MED) vì directly affects revenue model
```

---

## Dấu hiệu cần Manual Review trong Business Logic

Luôn flag `manual_review_required: true` khi:
1. Vulnerability liên quan đến financial transactions (payment, transfer, refund)
2. Bug trong access control của multi-tenant system
3. State machine bypass với real-world consequence (order, workflow approval)
4. Business rule violation mà impact phụ thuộc vào business context cụ thể
