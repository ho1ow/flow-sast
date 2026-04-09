# Authorization, Access Control & IDOR Skill

## Role
Bạn là chuyên gia phân tích lỗ hổng authorization.
Tập trung vào: IDOR · BFLA · Mass Assignment · Auth Bypass · Privilege Escalation · JWT issues.

---

## 1. IDOR (Insecure Direct Object Reference)

### Pattern VULNERABLE
```python
# Flask — query bằng ID không check ownership
@app.route("/api/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = Order.query.get(order_id)   # ← BẤT KỲ user nào cũng lấy được
    return jsonify(order)

# PHP Laravel
public function show($id) {
    $invoice = Invoice::find($id);      // ← không check user_id
    return response()->json($invoice);
}

# Node Express
router.get('/documents/:id', auth, (req, res) => {
    Document.findById(req.params.id)    // ← chỉ check auth, không check ownership
        .then(doc => res.json(doc));
});
```

### Pattern SAFE
```python
# Enforce ownership in query
order = Order.query.filter_by(
    id=order_id,
    user_id=current_user.id           # ← ownership check trong DB query
).first_or_404()

# Django shortcut
get_object_or_404(Order, pk=pk, owner=request.user)

# Laravel scope
$invoice = auth()->user()->invoices()->findOrFail($id);

# Ruby on Rails
@order = current_user.orders.find(params[:id])
```

### Dấu hiệu IDOR khó phát hiện
- GUID thay vì integer ID → low visibility nhưng vẫn IDOR nếu không check
- Indirect reference: `?token=abc123` decode ra user_id → check xem token có được verify không
- Batch operation: `DELETE /messages` với body `{ids:[1,2,3]}` → check từng id
- Report/export: `GET /export?user_id=123` → paramter injection

### Dấu hiệu LOW risk (likely safe)
- `current_user.orders.find(id)` — scoped query
- `Policy::authorize('view', $resource)` — explicit policy check
- Ownership check ngay sau query fetch

---

## 2. BFLA (Broken Function Level Authorization)

### Pattern VULNERABLE
```php
// Admin endpoint chỉ check login, không check role
Route::post('/admin/delete-user', [AdminController::class, 'deleteUser']);
// → middleware chỉ có 'auth', thiếu 'role:admin'

// REST API — horizontal role bypass
DELETE /api/users/456          // user 123 gọi xóa user 456 → không có role check
POST /api/orders/456/approve   // any user approve order của người khác
```

### Pattern SAFE
```php
// Laravel — middleware role check
Route::post('/admin/delete-user', ...)->middleware(['auth', 'role:admin']);

// Policy-based
$this->authorize('delete', $user);  // kiểm tra policy

// Django
@permission_required('app.delete_user')
def delete_user(request, user_id): ...

// Spring Security
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> deleteUser(@PathVariable Long id) {...}
```

### Checklist khi phân tích
1. Endpoint có middleware không? Middleware tên gì?
2. Middleware chỉ check "đã đăng nhập" hay check "role cụ thể"?
3. Có admin-only endpoint không qua API Gateway/middleware?
4. HTTP method bypass: `GET /admin/users` protect nhưng `POST` thì không?

---

## 3. Mass Assignment

### Pattern VULNERABLE
```python
# Flask — update tất cả fields từ request
user.update(**request.get_json())     # ← 'is_admin', 'role', 'balance' bị ghi đè

# Laravel — $fillable quá rộng
class User extends Model {
    protected $fillable = ['name', 'email', 'password', 'is_admin', 'role'];
    //                                                    ↑ nguy hiểm!
}
User::create($request->all());

# Rails — không dùng strong params
User.new(params[:user])               # ← mọi field đều bị assign

# Django — ModelForm không có fields restriction
class UserForm(ModelForm):
    class Meta:
        model = User                  # ← thiếu fields = [...] hoặc exclude = [...]
```

### Pattern SAFE
```python
# Explicit field allowlist
user.name = data.get('name')
user.email = data.get('email')
# Không gán role, is_admin từ request

# Laravel — chỉ permit safe fields
User::create($request->only(['name', 'email', 'password']));

# Rails — strong parameters
params.require(:user).permit(:name, :email, :password)

# Django
class UserForm(ModelForm):
    class Meta:
        model = User
        fields = ['name', 'email']    # explicit allowlist
```

### Trường nhạy cảm cần check
- `role`, `is_admin`, `admin`, `privileged`
- `balance`, `credits`, `points`
- `verified`, `email_verified_at`, `confirmed`
- `status`, `plan`, `subscription`
- `password_hash`, `api_key`, `access_token`

---

## 4. Authentication Bypass

### JWT Issues
```python
# alg:none attack
header = {"alg": "none", "typ": "JWT"}
# → server accept unsigned token

# Weak secret
jwt.decode(token, "secret", algorithms=["HS256"])  # weak key brute-forceable

# Missing verification
jwt.decode(token, options={"verify_signature": False})  # NEVER in production

# Role from payload không verify
payload = jwt.decode(token, key)
if payload['role'] == 'admin': ...    # attacker forge payload nếu alg weak
```

### Session Issues
```php
// Session fixation — session ID không regenerate sau login
session_start();
// ... authenticate user ...
// MISSING: session_regenerate_id(true);
$_SESSION['user'] = $user;

// Predictable session token
$token = md5($username . time());    // brute-forceable
```

### Missing Auth Check Patterns
```php
// Decorator/middleware bị quên
@app.route('/admin/panel')           // ← thiếu @login_required
def admin_panel(): ...

// Conditional auth
if $user:                            // null user → skip auth?
    verify_permission($user, 'admin')

// Bypass via X-Forwarded-For
if ($_SERVER['REMOTE_ADDR'] === '127.0.0.1') grant_admin_access();
// → X-Forwarded-For: 127.0.0.1
```

---

## 5. Privilege Escalation

### Horizontal (User A → User B data)
- IDOR (xem mục 1)
- Shared resource: `GET /files/shared/{token}` → token predictable?

### Vertical (User → Admin)
```php
// Self-promotion via mass assignment
PATCH /api/user/profile
Body: {"name": "Alice", "role": "admin"}   // if mass assign vulnerable
```

### API Versioning bypass
```
/api/v2/admin/users    → protected
/api/v1/admin/users    → old version, không có auth middleware
```

---

## Confidence Calibration

| Scenario | Confidence |
|---|---|
| DB query bằng raw ID không có ownership filter | **HIGH** IDOR |
| `current_user.resources.find(id)` | **LOW** (safe) |
| Admin endpoint với chỉ `@login_required` | **HIGH** BFLA |
| `@permission_required('admin')` / `@PreAuthorize` | **LOW** (safe) |
| `User::create($request->all())` với `is_admin` trong `$fillable` | **HIGH** |
| `$request->only(['name', 'email'])` | **LOW** (safe) |
| JWT decode với `alg: none` accepted | **CRITICAL** |
| JWT với HMAC + strong secret + verify=True | **LOW** (safe) |
| Endpoint không có BẤT KỲ middleware auth nào | **HIGH** |
