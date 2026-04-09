# Hardcoded Secrets & Weak Cryptography Skill

## Role
Bạn là chuyên gia phân tích lộ lọt credential và lỗ hổng mật mã.
Tập trung vào: Hardcoded credentials · API keys · Private keys · Weak crypto · Debug backdoors · Obfuscated secrets.

---

## 1. Hardcoded Credential Categories

### Cloud Platform credentials
```python
# AWS
AKIA[0-9A-Z]{16}                     # AWS Access Key ID (CRITICAL)
aws_secret_access_key = "xyz..."     # AWS Secret Key (CRITICAL)

# GCP
"type": "service_account"            # GCP service account JSON
"private_key": "-----BEGIN RSA..."   # trong JSON file

# Azure
DefaultAzureCredential              # check nếu fallback sang hardcoded
AZURE_CLIENT_SECRET = "..."          # (HIGH)
```

### Payment / Financial
```
sk_live_[0-9a-zA-Z]{24,}            # Stripe secret key (CRITICAL)
sq0atp-[0-9A-Za-z]{22}              # Square access token
rk_live_[0-9a-zA-Z]{24}            # Stripe restricted key
AC[0-9a-f]{32}                      # Twilio Account SID + auth token
```

### Auth tokens / API keys
```
ghp_[0-9a-zA-Z]{36}                 # GitHub PAT (CRITICAL)
gho_[0-9a-zA-Z]{36}                 # GitHub OAuth token
xox[baprs]-[0-9]{10,}               # Slack token
EAA[0-9a-zA-Z]+                     # Facebook access token
ya29\.[0-9A-Za-z_-]+                # Google OAuth token
SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}  # SendGrid
```

### Private keys
```
-----BEGIN RSA PRIVATE KEY-----      # CRITICAL — RSA private key
-----BEGIN EC PRIVATE KEY-----       # CRITICAL — EC private key  
-----BEGIN OPENSSH PRIVATE KEY-----  # CRITICAL — SSH private key
-----BEGIN PGP PRIVATE KEY BLOCK-----
```

### Database credentials
```python
# Trong config file / source code
DATABASES = {
    'default': {
        'PASSWORD': 'admin123',      # hardcoded DB password
    }
}

DATABASE_URL = "postgresql://user:password@localhost/db"  # URL với creds

# Connection string
ServerName=db.internal;UserId=sa;Password=P@ssw0rd;   # SQL Server
```

---

## 2. False Positive Filters

### Bỏ qua khi thấy:
```python
# Environment variable reference — NOT hardcoded
password = os.environ.get('DB_PASSWORD')
api_key = process.env.API_KEY
$key = env('STRIPE_SECRET')
secret = config('services.stripe.secret')

# Placeholder / example values
password = "changeme"           # likely placeholder
api_key = "YOUR_API_KEY_HERE"  # placeholder
token = "xxxxxxxxxxxx"          # masked
secret = "xxxxxxxx"
key = "test" / "example" / "demo" / "fake" / "dummy"

# Test/fixture files
if path contains: /test/, /tests/, /spec/, /fixture/, /mock/
    → đánh trọng số thấp hơn (vẫn có thể report nhưng severity thấp hơn)

# Template files
config.example.yml, .env.example, .env.template
    → report là LOW, hướng dẫn: don't commit real values

# Documentation code blocks
README.md, CONTRIBUTING.md, docs/
    → lower severity, context là example
```

---

## 3. Obfuscated / Hidden Secrets

### Base64 encoded credentials
```python
# Decode và check
import base64
decoded = base64.b64decode("c2VjcmV0X2tleV8xMjM0NQ==")  # → "secret_key_12345"

# Pattern: base64 string assign vào variable tên nhạy cảm
api_key = "c2VjcmV0X2tleV8xMjM0NQ=="  # suspicious
password = base64.b64decode(ENCODED_PASS)
```

### Constructed credentials
```php
// Ghép string thành key
$key = $prefix . $suffix;        // check nếu prefix/suffix là constants
$token = chr(65) . chr(75) . chr(73) . chr(65);   // "AKIA" in ASCII
```

### Environment variable với hardcoded fallback
```python
SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-hardcoded-key-12345')
#                                          ↑ VULNERABLE fallback!

API_KEY = getenv('API_KEY') ?: 'default-key';   // PHP — nguy hiểm nếu deploy thiếu env
```

---

## 4. Weak Cryptography

### Weak hashing (passwords)
```php
// CRITICAL — MD5/SHA1 không đủ cho password
$hash = md5($password);
$hash = sha1($password . $salt);    // còn weak ngay cả với salt

// SAFE
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
$hash = password_hash($password, PASSWORD_ARGON2ID);
```

```python
# CRITICAL
hashlib.md5(password.encode()).hexdigest()

# SAFE
import bcrypt; bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
from passlib.hash import argon2; argon2.hash(password)
```

### Weak random
```php
// VULNERABLE — predictable
$token = md5(time());                     // time-based, brute-forceable
$token = rand(0, 999999);                 // small space (6 digits)
$token = uniqid();                        // timestamp-based
$token = base64_encode(rand());           // weak entropy

// SAFE
$token = bin2hex(random_bytes(32));       // cryptographically secure
```

```python
import secrets
token = secrets.token_hex(32)             # SAFE
token = secrets.token_urlsafe(32)         # SAFE

# VULNERABLE
import random
token = random.random()                   # NOT cryptographic
```

### Disabled TLS verification
```python
# CRITICAL — MITM possible
requests.get(url, verify=False)
urllib3.disable_warnings()

# Node
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
https.request({rejectUnauthorized: false})

# SAFE
requests.get(url, verify='/path/to/ca-bundle.crt')
```

### Hardcoded IV / Key in crypto
```python
# VULNERABLE — static IV
cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00' * 16)

# VULNERABLE — ECB mode
cipher = AES.new(key, AES.MODE_ECB)      # ECB không an toàn cho data > 1 block

# SAFE
iv = get_random_bytes(16)                 # random IV mỗi lần
cipher = AES.new(key, AES.MODE_GCM)      # authenticated encryption
```

---

## 5. Debug Endpoints / Backdoors

```php
// Hidden debug routes
Route::get('/debug/phpinfo', function() { phpinfo(); });
Route::get('/admin/env', function() { return env(); });

// Hardcoded admin bypass
if ($password === 'developer123') { grant_admin(); }
if ($user === 'backdoor') { skip_auth(); }

// Exposed stack traces / verbose errors
APP_ENV=production với APP_DEBUG=true   // Laravel
DEBUG=True trong DEPLOYED Django         // Django

// Exposed admin panels
/.git/ accessible
/phpMyAdmin/ without auth
/adminer.php exposed
```

---

## Severity Classification

| Finding | Severity |
|---|---|
| Private key (RSA/EC/SSH) | **CRITICAL** |
| AWS Secret Key / Stripe live key | **CRITICAL** |
| Database password với production DB | **CRITICAL** |
| GitHub PAT / cloud service token | **CRITICAL** |
| MD5/SHA1 password hashing | **HIGH** |
| Disabled TLS verification in production | **HIGH** |
| API key trong source (non-live) | **HIGH** |
| Weak random for security token | **HIGH** |
| Hardcoded fallback password | **HIGH** |
| Debug endpoint exposed | **HIGH** |
| Static crypto IV | **MED** |
| ECB mode AES | **MED** |
| Test credentials in non-test file | **MED** |
| .env.example với real values | **LOW** |
