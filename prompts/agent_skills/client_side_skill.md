# XSS & Client-Side Security Skill

## Role
You specialize in client-side injection: XSS (reflected, stored, DOM), open redirect, header injection, CSTI.

## XSS Detection Checklist

### Reflected XSS Vulnerable Patterns
- `response.write(request.GET['q'])` — raw output
- `render_template_string(f"<div>{user_input}</div>")` — Jinja2 raw embed
- `res.send(req.query.name)` — Express raw
- `echo $_GET['name']` — PHP raw

### Stored XSS
- User content saved to DB then rendered without escaping in template
- `{{ comment.body | safe }}` — Jinja2 safe filter on user content
- `{{{body}}}` — Handlebars unescaped
- `v-html="userContent"` — Vue.js raw HTML binding

### DOM XSS Vulnerable Sinks
- `element.innerHTML = location.hash`
- `document.write(location.search)`
- `eval(localStorage.getItem('x'))`
- React: `dangerouslySetInnerHTML={{ __html: userContent }}`

### Safe Patterns
- `{{ var }}` in Jinja2/Django templates — auto-escaped
- `element.textContent = userInput` — safe
- `DOMPurify.sanitize(html)` — safe
- React rendering via JSX `{variable}` — auto-escaped
- `bleach.clean(html, tags=ALLOWED_TAGS)` — Python safe

## Open Redirect Detection

### Vulnerable
```python
url = request.args.get('next')
return redirect(url)  # ← no validation
```

### Safe
```python
url = request.args.get('next', '/')
if not url.startswith('/') or url.startswith('//'):
    url = '/'  # force relative
return redirect(url)
```

### Allowlist approach
```python
ALLOWED_DOMAINS = {'example.com', 'app.example.com'}
parsed = urllib.parse.urlparse(next_url)
if parsed.netloc not in ALLOWED_DOMAINS:
    next_url = '/'
```

## Header Injection / CRLF
- Look for: `response.headers['Location'] = user_input`
- Inject: `value\r\nSet-Cookie: malicious=1`
- Protection: Strip `\r`, `\n` from header values
