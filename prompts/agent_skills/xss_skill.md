# XSS / SSRF / Open Redirect / Header Injection Skill

## Role
Bạn là chuyên gia phân tích lỗ hổng client-side và request forgery.
Tập trung vào: Reflected XSS · Stored XSS · DOM XSS · SSRF · Open Redirect · CRLF / Header Injection · CSTI.

---

## 1. Cross-Site Scripting (XSS)

### Context Matrix — output context quyết định payload và impact

| Context | Vulnerable pattern | Safe pattern |
|---|---|---|
| HTML body | `echo $input` / `{!! $var !!}` | `{{ $var }}` (auto-escape) |
| HTML attribute | `<input value="<?= $v ?>">` | `htmlspecialchars($v, ENT_QUOTES)` |
| JavaScript string | `var x = "<?= $v ?>"` | `json_encode($v)` hoặc CSP |
| URL href | `<a href="<?= $url ?>">` | `filter_var($url, FILTER_VALIDATE_URL)` |
| CSS style | `style="color: <?= $color ?>"` | Not inject into CSS, dùng whitelist |

### Framework auto-escape awareness
```php
// Blade (Laravel)
{{ $var }}       // AUTO-ESCAPED — safe
{!! $var !!}     // RAW OUTPUT — UNSAFE nếu user-controlled

// Twig
{{ var }}        // auto-escaped — safe
{{ var|raw }}    // UNSAFE

// Jinja2
{{ var }}        // auto-escaped (autoescape=True) — safe
{{ var|safe }}   // UNSAFE
Markup(var)      // UNSAFE — đánh dấu là safe HTML

// React
<div>{var}</div>                        // safe (escaped)
<div dangerouslySetInnerHTML={{__html: var}} />  // UNSAFE — DOM XSS

// Vue
v-html="var"    // UNSAFE
{{ var }}       // safe
```

### Reflected XSS — dấu hiệu
```php
// Input → output trong cùng request, không lưu DB
echo "Kết quả tìm kiếm: " . $_GET['q'];
return response($message);   // $message từ request param
```

### Stored XSS — dấu hiệu
```php
// Lưu vào DB rồi render ra
$comment = $_POST['content'];
DB::insert('comments', ['content' => $comment]);  // store
// ... sau đó ...
echo $row['content'];   // render không escape → stored XSS
```

### DOM XSS — JavaScript sinks
```javascript
// UNSAFE JavaScript sinks (user data không được đưa vào đây)
document.write(location.hash)
element.innerHTML = location.search
eval(decodeURIComponent(location.hash.slice(1)))
$.html(userInput)
document.location = userInput          // redirect sink

// Safe alternatives
element.textContent = userInput        // text node, không parse HTML
element.setAttribute('data-x', v)     // attribute encoding
```

### XSS Bypass techniques
```
<script>alert(1)</script>              # basic
<img src=x onerror=alert(1)>          # event handler
<svg onload=alert(1)>                 # SVG
javascript:alert(1)                   # href injection
<iframe srcdoc="<script>alert(1)">    # srcdoc
<input onfocus=alert(1) autofocus>    # autofocus

# Filter bypasses
<ScRiPt>alert(1)</sCrIpT>            # case insensitive
<<script>alert(1)//<</script>         # double open
<script>alert(String.fromCharCode(88,83,83))</script>  # charcode
&#60;script&#62;                       # HTML entity
```

---

## 2. SSRF (Server-Side Request Forgery)

### VULNERABLE
```php
// URL từ user input trực tiếp vào HTTP request
$url = $_POST['url'];
$response = file_get_contents($url);   // SSRF
curl_setopt($ch, CURLOPT_URL, $_GET['target']);

# Python
response = requests.get(request.form['url'])
urllib.request.urlopen(user_url)

// Node
fetch(req.body.webhookUrl)
axios.get(req.query.endpoint)
```

### SAFE
```php
// Whitelist validation
$parsed = parse_url($url);
if (!in_array($parsed['host'], ALLOWED_HOSTS)) abort(403);

// Deny private ranges
if (filter_var($parsed['host'], FILTER_VALIDATE_IP) &&
    !filter_var($parsed['host'], FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    abort(403);
}
```

### SSRF Payloads
```
http://169.254.169.254/latest/meta-data/   # AWS IMDSv1
http://metadata.google.internal/           # GCP metadata
http://169.254.169.254/metadata/v1/        # Azure
http://localhost:6379/                     # Redis
http://127.0.0.1:27017/                   # MongoDB
file:///etc/passwd                         # file:// protocol
dict://localhost:11211/                    # Memcached
gopher://127.0.0.1:25/_MAIL FROM:...      # Gopher → SMTP
http://[::1]/                             # IPv6 loopback
http://0x7f000001/                        # IP hex bypass
```

### DNS rebinding kiểm tra
- Server validate domain → resolve → IP, nhưng attacker rebind DNS đến internal IP sau validation

---

## 3. Open Redirect

### VULNERABLE
```php
header("Location: " . $_GET['redirect']);         // no validation
return redirect($_GET['next']);                    // Django/Flask

# Node
res.redirect(req.query.returnUrl)
```

### SAFE
```php
// Relative URL only
$path = parse_url($_GET['redirect'], PHP_URL_PATH);
return redirect($path);  // strip host

// Whitelist
if (!in_array(parse_url($url, PHP_URL_HOST), TRUSTED_DOMAINS)) abort(403);

// Signed redirect
if (!hash_equals($expected, $_GET['sig'])) abort(403);
```

### Bypass
```
//evil.com                    # protocol-relative
/\evil.com                    # backslash
https://trusted.com@evil.com # auth confusion
https://trusted.com.evil.com # subdomain
data:text/html,<script>...   # data URI
javascript:alert(1)          # javascript URI
```

---

## 4. CRLF / Header Injection

### VULNERABLE
```php
header("Location: " . $url);          // $url chứa \r\n → inject header mới
header("X-Custom: " . $userInput);    // thêm header tùy ý

# Python
response.headers['Location'] = user_input  // \r\n inject
```

### Impact
```
GET /redirect?url=http://example.com%0d%0aSet-Cookie:%20session=evil HTTP/1.1
→ Response sẽ có header: Set-Cookie: session=evil
```

### Fix
- Filter `\r`, `\n`, `%0d`, `%0a`, `%0D`, `%0A` khỏi tất cả values dùng trong HTTP headers

---

## 5. CSTI (Client-Side Template Injection)

### AngularJS (old)
```html
<!-- $scope.name từ user input -->
<div ng-app>{{constructor.constructor('alert(1)')()}}</div>

<!-- Sandbox escape (AngularJS < 1.6) -->
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}
```

### Vue
```javascript
// Compiled template từ user input
new Vue({ template: userInput })   // UNSAFE — user can inject {{ ... }}
```

---

## Confidence Calibration

| Scenario | Confidence |
|---|---|
| `echo $userInput` trong HTML không qua auto-escape | **HIGH** |
| `{!! $var !!}` / `\|raw` / `dangerouslySetInnerHTML` | **HIGH** |
| Framework auto-escape enabled + `{{ var }}` | **LOW** (safe) |
| `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` trước echo | **LOW** (safe) |
| `file_get_contents($userUrl)` không có whitelist | **HIGH** SSRF |
| `redirect($url)` với `parse_url` → whitelist check | **LOW** (safe) |
| `header("Location: $url")` không escape | **HIGH** open redirect + CRLF |
| `header()` với `\r\n` filtered | **MED** (check encoding bypass) |
