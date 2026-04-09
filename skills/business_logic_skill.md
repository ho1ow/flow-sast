# Business Logic & Process Flow Security Skill

## Role
Bạn là chuyên gia phân tích lỗ hổng business logic.
Tập trung vào: Race Conditions · State Machine Bypass · TOCTOU · Negative Value Attacks · Business Rule Abuse · Workflow Reordering.

**Quan trọng**: Business logic bugs thường không có "bad function call" rõ ràng — chúng là lỗi trong luồng xử lý, điều kiện, thứ tự bước, hoặc giả định ngầm về trust.

---

## 1. Race Condition (TOCTOU)

### Pattern VULNERABLE
```python
# Check-then-use window: state có thể thay đổi giữa check và use
def withdraw(user_id, amount):
    balance = get_balance(user_id)         # READ balance
    if balance >= amount:                  # CHECK ← window bắt đầu
        # ... processing time ...
        deduct_balance(user_id, amount)    # USE ← window kết thúc
        # Hai request đồng thời đều pass check!

# PHP — coupon redeem không atomic
$coupon = Coupon::find($code);
if ($coupon->used == 0) {                 // check
    applyDiscount();                       // use
    $coupon->used = 1;                    // update — too late!
    $coupon->save();
}
```

### Pattern SAFE
```python
# Database-level transaction + lock
with db.transaction():
    balance = db.execute(
        "SELECT balance FROM accounts WHERE id=? FOR UPDATE",  # row lock
        [user_id]
    ).fetchone()
    if balance >= amount:
        db.execute("UPDATE accounts SET balance=balance-? WHERE id=?", [amount, user_id])

# Atomic update (compare-and-swap)
result = db.execute(
    "UPDATE coupons SET used=1, used_by=? WHERE code=? AND used=0",
    [user_id, code]
)
if result.rowcount == 0:
    raise AlreadyUsedError()
```

### Race dấu hiệu trong code
- Non-atomic read-check-write sequence
- `SELECT ... WHERE status='pending'` rồi `UPDATE ... SET status='processing'` (2 separate queries)
- Cache-then-use: `$cached = cache('balance')` → modify → save
- Optimistic locking bị bỏ qua (version number không được check)

### Attack vector
```
# Gửi 2 request đồng thời
Thread 1: POST /api/redeem {code: "SAVE50"}
Thread 2: POST /api/redeem {code: "SAVE50"}
→ Nếu không có lock, cả 2 đều pass check → coupon dùng 2 lần
```

---

## 2. State Machine Bypass

### Pattern — step có thể bị skip
```python
# Checkout flow: cart → payment → confirmation
# Nếu không enforce thứ tự:
POST /api/checkout/cart        # bước 1
POST /api/checkout/confirm     # bước 3 — skip payment!

# Order state machine
class Order:
    def mark_shipped(self):
        # MISSING: check current state == 'paid'
        self.status = 'shipped'
        # Attacker ship trước khi pay!
```

### Pattern SAFE
```python
class Order:
    VALID_TRANSITIONS = {
        'pending':    ['paid', 'cancelled'],
        'paid':       ['shipped', 'refunded'],
        'shipped':    ['delivered', 'returned'],
    }
    def transition_to(self, new_state):
        if new_state not in self.VALID_TRANSITIONS.get(self.status, []):
            raise InvalidTransitionError(f"{self.status} → {new_state} not allowed")
        self.status = new_state
```

### Dấu hiệu dễ bị bỏ qua
- `if request.method == 'POST'` trong step cuối mà không verify step trước
- Session lưu step number không được server validate
- Idempotent endpoint có thể gọi nhiều lần với effect khác nhau

---

## 3. Negative Value / Integer Overflow Attacks

### Pattern VULNERABLE
```php
// Không validate số lượng âm
function transfer($from, $to, $amount):
    deduct($from, $amount)   // amount=-100 → thực ra là add 100 vào $from!
    add($to, $amount)

// PHP — cart quantity
$total = $price * $quantity;  // quantity có thể là -1 → tiền âm → refund?
```

### Pattern SAFE
```php
if ($amount <= 0) throw new InvalidArgumentException("Amount must be positive");
if ($quantity < 1 || $quantity > 999) abort(400);
```

### Price manipulation checklist
- Quantity âm → tiền hoàn lại
- Discount % > 100 → tiền âm
- Free item + negative qty → earn credit
- Cart manipulation qua API: `{price: -1, qty: 1}`

---

## 4. Business Rule Abuse

### Coupon / Discount abuse
```python
# VULNERABLE: coupon check chỉ theo code, không theo user
def apply_coupon(code):
    coupon = Coupon.find(code)
    if coupon.active:
        apply_discount()      # không check: user đã dùng chưa? coupon cho ai?

# Dấu hiệu nguy hiểm:
# - Coupon không gắn với user_id
# - Không có limit per user
# - Không có expiry check
# - Không có min_order_amount enforcement
```

### Referral / Affiliate abuse
```
# Tự refer bản thân bằng nhiều account
# Circular referral: A refer B, B refer A
# Bot tạo fake referral chains
```

### Free tier limits
```python
# VULNERABLE: rate limit chỉ check per request, không per billing period
@rate_limit(max=100)  # 100 req/min nhưng không check monthly quota
def api_endpoint(): ...
```

---

## 5. Trust Assumption Violations

### Implicit trust patterns hay bị lợi dụng
```php
// Trust header từ internal service
if ($_SERVER['HTTP_X_INTERNAL'] === 'true') {
    grant_admin_privileges();  // Attacker có thể set header này!
}

// Trust price từ frontend
$item->price = $request['price'];  // price phải lấy từ DB, không từ request

// Trust file extension
$ext = pathinfo($_FILES['upload']['name'], PATHINFO_EXTENSION);
if ($ext === 'jpg') allowUpload();   // MIME type check thực sự?

// Trust callback URL
$webhookUrl = $order->webhook_url;  // Attacker set webhook = internal service URL
```

### Second-order / Stored logic bugs
- Dữ liệu lưu vào DB khi tạo, logic check khi dùng → state có thể không match
- Profile data lưu nhưng không re-validate khi dùng ở context khác
- Scheduled job dùng cached permission đã hết hạn

---

## Phân tích với Business Context

Khi có `business_context` trong state, dùng thông tin này để:

1. **Xác định tài sản quan trọng**: E-commerce → balance, inventory; SaaS → subscription, API quota; Healthcare → record access
2. **Hiểu flow chính**: Checkout flow đúng là gì? → phát hiện step bị skip
3. **Identify business rules**: "Coupon chỉ dùng 1 lần" → check enforcement
4. **Assess impact**: Bug trong payment flow → high impact; bug trong notification → medium

---

## Confidence & Manual Review

| Scenario | Confidence | Note |
|---|---|---|
| Non-atomic check-then-modify | **MED** | Cần POC race condition test |
| No state validation trước transition | **HIGH** | Nếu logic rõ ràng |
| Quantity không check `> 0` | **HIGH** | Nếu feed vào arithmetic |
| Price từ request payload | **HIGH** | Luôn lấy từ DB |
| Race condition trong payment | **HIGH** | Manual confirm required |
| Business rule không enforcement | **MED** | Context-dependent |

> **Tất cả business logic findings nên có `manual_review_required: true`** vì cần verify với domain knowledge.
