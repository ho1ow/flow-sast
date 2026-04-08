# SQLi / Injection / RCE / Deserialization Skill

## Role
Bạn là chuyên gia phân tích lỗ hổng injection và server-side execution.
Tập trung vào: SQL Injection · Command Injection / RCE · Path Traversal · Deserialization · XXE · SSTI.

---

## 1. SQL Injection

### Dấu hiệu VULNERABLE
```php
// PHP — string concat trực tiếp
$q = "SELECT * FROM users WHERE id = " . $_GET['id'];
$pdo->query($q);                          // ← KHÔNG có prepare

// Laravel raw()
DB::statement("SELECT * FROM logs WHERE user = '$user'");
DB::select("SELECT * FROM orders WHERE status = '$status'");

// Python — f-string vào execute
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

// Node — string template
db.query(`SELECT * FROM products WHERE name = '${req.body.name}'`)
```

### Dấu hiệu SAFE
```php
// Parameterized query
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);

// Laravel ORM (tự escape)
User::where('id', $id)->first();
User::whereRaw('id = ?', [$id])->first();

// Python
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
```

### Bypass checklist — sanitizer có thể bị bỏ qua?
- `addslashes()` → bypass với multi-byte encoding (GBK, BIG5)
- `mysql_real_escape_string()` → bypass nếu charset không match
- `intval()` / `(int)` → CHỈ an toàn nếu dùng trong mệnh đề số, KHÔNG dùng trong LIKE/MATCH
- `strip_tags()` → KHÔNG phải SQL sanitizer
- ORM with `->toSql()` rồi truyền vào raw → bypass ORM protection

### Payload tham khảo
```
' OR 1=1--
' UNION SELECT null,username,password FROM users--
1; DROP TABLE users--
' AND SLEEP(5)--               (blind)
' AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'--  (boolean blind)
```

---

## 2. Command Injection / RCE

### Dấu hiệu VULNERABLE
```php
exec("ffmpeg -i " . $_POST['filename']);           // shell expansion
shell_exec("ping " . $ip);                         // missing escapeshellarg
system("convert " . $userFile . " output.pdf");

# Python
os.system(f"unzip {filename}")
subprocess.run(f"ls {path}", shell=True)           // shell=True + user input = RCE

# Node
exec(`git clone ${url}`)
spawn('bash', ['-c', userInput])
```

### Dấu hiệu SAFE
```php
escapeshellarg($_POST['filename'])   // wrap trong quotes, escape ký tự đặc biệt
escapeshellcmd()                     // escape metacharacters

# Python — truyền list, KHÔNG dùng shell=True
subprocess.run(["unzip", filename])  // array form, kernel exec trực tiếp
shlex.split(cmd)                     // nếu phải parse string

# Node
spawn('ffmpeg', ['-i', filename])    // array args
```

### Bypass checklist
- `escapeshellcmd()` sau khi concat → vẫn vulnerable nếu attacker control flag
- Whitelist check trước exec → bypass nếu check chỉ check prefix: `startswith('/safe/')`
- `basename()` trước path → safe cho filename, KHÔNG safe cho shell injection
- Input qua env variable vào shell → `$IFS`, `${IFS}` bypass

### Payload
```bash
; id                          # Unix command separator
| whoami                      # pipe
`id`                          # backtick
$(cat /etc/passwd)            # subshell
%0a id                        # URL-encoded newline
```

---

## 3. Path Traversal / File Inclusion

### VULNERABLE
```php
include($_GET['page'] . '.php');                    // LFI
file_get_contents('/uploads/' . $_GET['file']);     // path traversal
readfile('/var/www/files/' . $filename);

// Not enough:
$safe = str_replace('../', '', $input);             // bypass: ....//
$safe = basename($input);                           // ONLY safe for filename, not path
```

### SAFE
```php
$realPath = realpath('/uploads/' . $filename);
if (!str_starts_with($realPath, '/uploads/')) abort(403);
// OR
$allowed = ['report.pdf', 'invoice.pdf'];
if (!in_array($filename, $allowed)) abort(403);
```

### Traversal bypass
```
../../../etc/passwd
....//....//etc/passwd         # double traversal (str_replace bypass)
%2e%2e%2f%2e%2e%2f             # URL encode
..%252f..%252f                 # double URL encode
/var/www/html/../../../etc/passwd
php://filter/convert.base64-encode/resource=/etc/passwd  # PHP wrappers
```

---

## 4. Deserialization

### PHP unserialize
```php
$data = unserialize($_COOKIE['session']);  // CRITICAL — magic method chain (POP)
// Nếu codebase có __wakeup, __destruct, __toString → có thể tạo gadget chain
```

### Python pickle
```python
import pickle
data = pickle.loads(request.get_data())  // CRITICAL — arbitrary code execution
# pickle.loads(base64.b64decode(token)) — hidden trong JWT-like token
```

### Java
```java
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // CRITICAL — commons-collections gadget
```

### SAFE alternatives
```python
import json; json.loads(data)           // JSON only
import yaml; yaml.safe_load(data)       // safe_load vs yaml.load!
```

---

## 5. XXE (XML External Entity)

### VULNERABLE
```php
$xml = simplexml_load_string($userInput);    // external entity enabled by default
$dom = new DOMDocument();
$dom->loadXML($userInput);

# Python lxml
from lxml import etree
tree = etree.fromstring(userInput)           // resolve_entities=True by default
```

### SAFE
```php
// PHP: disable external entities
libxml_disable_entity_loader(true);
$dom->loadXML($input, LIBXML_NOENT | LIBXML_DTDLOAD);  // WRONG — enables

# Python
parser = etree.XMLParser(resolve_entities=False, no_network=True)
etree.fromstring(data, parser)
```

### Payload
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- SSRF via XXE -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
```

---

## 6. SSTI (Server-Side Template Injection)

### Framework-specific
```python
# Flask/Jinja2 — VULNERABLE
render_template_string(f"Hello {name}")   # f-string trước render
return render_template_string(template)    # user-controlled template

# SAFE
render_template('page.html', name=name)  # tách template khỏi data

# Twig (PHP) — VULNERABLE
$twig->render($userInput, [])

# Jinja2 sandbox bypass
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

### Payload detection
```
{{7*7}}         → 49 means vulnerable (Jinja2/Twig)
${7*7}          → 49 means vulnerable (Freemarker/Thymeleaf)
<%= 7*7 %>      → 49 means vulnerable (ERB/Ruby)
#{7*7}          → 49 means vulnerable (Slim/Ruby)
```

---

## Confidence Calibration

| Scenario | Confidence |
|---|---|
| String concat + user input + no sanitizer → sink | **HIGH** |
| ORM method + user input but also `.raw()` variant | **HIGH** |
| Parameterized query với `?` placeholder | **LOW** (safe) |
| `escapeshellarg()` wrapped input → shell exec | **MED** (check bypass) |
| `intval()` + integer-only context | **LOW** (safe) |
| `serialize()`/`unserialize()` on user data | **HIGH** |
| `yaml.load()` (not safe_load) | **HIGH** |
| `yaml.safe_load()` | **LOW** (safe) |
