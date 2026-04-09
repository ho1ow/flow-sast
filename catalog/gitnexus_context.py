"""
catalog/gitnexus_context.py
──────────────────────────────────────
GitNexus query generation & context extraction
"""

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List

import yaml
try:
    import anthropic
except ImportError:
    anthropic = None

from shared.logger import audit_log

# ── Doc file patterns ─────────────────────────────────────────────────────────

README_NAMES = ["README.md", "README.rst", "README.txt", "README", "readme.md"]
DOC_DIRS = ["docs", "doc", "documentation", "wiki", ".github"]
OPENAPI_FILES = [
    "openapi.yaml", "openapi.yml", "openapi.json",
    "swagger.yaml", "swagger.yml", "swagger.json",
    "api.yaml", "api.yml",
]
MANIFEST_FILES = ["package.json", "composer.json", "pyproject.toml", "go.mod"]
ENV_EXAMPLES = [".env.example", ".env.sample", ".env.template"]

# ── System type classification ────────────────────────────────────────────────

SYSTEM_TYPE_SIGNALS: Dict[str, List[str]] = {
    "ecommerce":  ["cart", "checkout", "order", "payment", "product", "inventory",
                   "shipping", "coupon", "discount", "marketplace", "shop"],
    "saas":       ["subscription", "tenant", "workspace", "organization", "plan",
                   "billing", "quota", "api key", "multi-tenant"],
    "healthcare": ["patient", "medical", "health", "clinic", "prescription",
                   "diagnosis", "ehr", "emr", "hipaa"],
    "fintech":    ["bank", "finance", "loan", "credit", "account", "transfer",
                   "transaction", "balance", "wallet", "kyc", "ledger"],
    "social":     ["social", "feed", "post", "comment", "follow", "friend",
                   "message", "notification", "community"],
    "internal":   ["admin", "internal", "dashboard", "management", "hr",
                   "employee", "crm", "erp", "backoffice"],
    "api":        ["rest api", "graphql", "webhook", "sdk", "microservice"],
}

CRITICAL_ASSET_SIGNALS: Dict[str, List[str]] = {
    "Payment data (PCI-DSS)":       ["payment", "card", "stripe", "paypal", "billing"],
    "Personal data (PII/GDPR)":     ["personal data", "pii", "gdpr", "user data"],
    "Healthcare records (HIPAA)":   ["patient", "medical record", "health data", "phi"],
    "Financial records":            ["account balance", "transaction", "ledger"],
    "Authentication credentials":   ["password", "token", "session", "oauth", "jwt"],
    "Multi-tenant isolation":       ["tenant", "organization", "workspace"],
    "API access control":           ["api key", "rate limit", "quota"],
}

BUSINESS_FLOW_SIGNALS: Dict[str, List[str]] = {
    "User registration & onboarding": ["register", "signup", "onboarding", "verify email"],
    "Authentication & session":       ["login", "logout", "session", "2fa", "mfa"],
    "Checkout & payment":             ["checkout", "payment", "purchase", "cart"],
    "File upload & storage":          ["upload", "file", "attachment", "media"],
    "User management & roles":        ["role", "permission", "admin", "privilege"],
    "Data export & reporting":        ["export", "report", "download", "csv"],
    "Webhook & integration":          ["webhook", "callback", "integration"],
    "Subscription & billing":         ["subscribe", "plan", "billing", "invoice"],
}

# ── Main function ─────────────────────────────────────────────────────────────

def catalog_gitnexus_context(repo_path: str, endpoints: list, run_id: str = "local", gitnexus_cfg: dict = None, business_ctx: dict = None) -> dict:
    """Build business_context via gitnexus context + doc reading."""
    if gitnexus_cfg is None:
        gitnexus_cfg = {}
    if business_ctx is None:
        business_ctx = {}
        
    audit_dir = "reports/" + run_id
    os.makedirs(audit_dir, exist_ok=True)
    binary = gitnexus_cfg.get("binary", "gitnexus")
    timeout = gitnexus_cfg.get("timeout_seconds", 60)

    audit_log(audit_dir, run_id, "catalog_gitnexus_context:start", {"repo": repo_path})
    raw_parts: List[str] = []

    # Inject structured business context components directly into the prompt for Cypher generation
    if business_ctx:
        ctx_dump = json.dumps({
            "custom_sinks": business_ctx.get("custom_sinks", []),
            "sensitive_flows": business_ctx.get("sensitive_flows", []),
            "business_notes": business_ctx.get("business_notes", "")
        }, indent=2)
        raw_parts.append("=== USER PROVIDED CONTEXT ===\\n" + ctx_dump)

    # Step 1: gitnexus context --symbol <fn>
    entry_fns = [e.get("handler", "") for e in endpoints[:10] if e.get("handler")]
    if entry_fns and _gitnexus_available(binary):
        context_parts = _gitnexus_context_symbols(binary, repo_path, entry_fns, timeout)
        if context_parts:
            raw_parts.extend(context_parts)
            audit_log(audit_dir, run_id, "catalog_gitnexus_context:symbols", {
                "queried": len(entry_fns), "results": len(context_parts)
            })

    # Step 2: Doc reading
    repo = Path(repo_path)
    raw_parts += _read_readme(repo)
    raw_parts += _read_docs(repo)
    raw_parts += [_read_openapi(repo)]
    raw_parts += [_read_manifest(repo)]
    raw_parts += [_read_env_example(repo)]
    raw_parts += [_read_schema(repo)]

    raw_parts = [p for p in raw_parts if p and p.strip()]
    combined = "\n\n".join(raw_parts)
    business_context = _analyze(combined, raw_parts)

    audit_log(audit_dir, run_id, "catalog_gitnexus_context:done", {
        "system_type": business_context.get("system_type"),
        "assets":      len(business_context.get("critical_assets", [])),
        "flows":       len(business_context.get("business_flows", [])),
        "doc_chars":   len(combined),
    })

    return {"business_context": business_context}


def generate_catalog_queries(business_context: dict) -> list[str]:
    """Claude generates Cypher queries to discover custom wrapper sinks and non-HTTP sources based on business context."""
    if not anthropic:
        return []
        
    client = anthropic.Anthropic()
    prompt = f"Given the business context:\\n{json.dumps(business_context, indent=2)}\\n"
    prompt += "Generate Cypher queries for GitNexus to discover custom wrapper sinks and non-HTTP sources. Return ONLY a JSON array of string queries."
    
    try:
        response = client.messages.create(
            model="claude-3-5-sonnet-latest",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        content = response.content[0].text
        # Extract JSON array
        start = content.find('[')
        end = content.rfind(']')
        if start != -1 and end != -1:
            queries = json.loads(content[start:end+1])
            return queries
    except Exception as e:
        print(f"Anthropic generation error: {e}")
        
    return []


# ── Internal functions remain unchanged ─────────────────────────────────────
def _gitnexus_context_symbols(binary: str, repo_path: str, symbols: List[str], timeout: int) -> List[str]:
    results = []
    for symbol in symbols:
        if not symbol:
            continue
        try:
            proc = subprocess.run(
                [binary, "context", "--symbol", symbol, "--repo", repo_path, "--format", "json"],
                capture_output=True, text=True, timeout=timeout,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                data = _try_json(proc.stdout)
                if data:
                    results.append(
                        f"=== Symbol: {symbol} ===\\n"
                        + json.dumps(data, indent=2)[:800]
                    )
        except Exception:
            break
    return results

def _gitnexus_available(binary: str) -> bool:
    try:
        r = subprocess.run([binary, "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except OSError:
        return False

def _try_json(raw: str):
    try:
        return json.loads(raw)
    except Exception:
        return None

def _read_readme(repo: Path) -> List[str]:
    for name in README_NAMES:
        f = repo / name
        if f.exists():
            return [f"=== {name} ===\\n" + _read(f, 6000)]
    return []

def _read_docs(repo: Path) -> List[str]:
    parts = []
    for d in DOC_DIRS:
        doc_dir = repo / d
        if not doc_dir.is_dir():
            continue
        for f in sorted(doc_dir.rglob("*"))[:8]:
            if f.suffix in {".md", ".rst", ".txt"} and f.is_file():
                rel = str(f.relative_to(repo))
                parts.append(f"=== {rel} ===\\n" + _read(f, 1500))
        break
    return parts

def _read_openapi(repo: Path) -> str:
    for name in OPENAPI_FILES:
        f = repo / name
        if not f.exists():
            continue
        try:
            if f.suffix == ".json":
                data = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
            else:
                data = yaml.safe_load(f.read_text(encoding="utf-8", errors="ignore"))
            info = data.get("info", {})
            paths = list(data.get("paths", {}).keys())[:20]
            tags = list({
                t if isinstance(t, str) else t.get("name", "")
                for path_item in data.get("paths", {}).values()
                for method in path_item.values()
                if isinstance(method, dict)
                for t in method.get("tags", [])
            })
            return (
                f"=== OpenAPI: {name} ===\\n"
                f"Title: {info.get('title', '')}\\n"
                f"Description: {str(info.get('description', ''))[:300]}\\n"
                f"Version: {info.get('version', '')}\\n"
                f"Endpoints ({len(paths)}): {', '.join(paths[:15])}\\n"
                f"Tags: {', '.join(str(t) for t in tags[:10])}"
            )
        except Exception:
            return "=== OpenAPI ===\\n" + _read(f, 1200)
    return ""

def _read_manifest(repo: Path) -> str:
    for name in MANIFEST_FILES:
        f = repo / name
        if not f.exists():
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            if name == "package.json":
                d = json.loads(content)
                return (
                    f"=== {name} ===\\n"
                    f"Name: {d.get('name','')}\\n"
                    f"Description: {d.get('description','')}\\n"
                    f"Keywords: {', '.join(d.get('keywords',[]))}"
                )
            elif name == "composer.json":
                d = json.loads(content)
                return f"=== {name} ===\\nName: {d.get('name','')}\\nDescription: {d.get('description','')}"
            elif name == "pyproject.toml":
                n = re.search(r'name\\s*=\\s*["\']([^"\']+)', content)
                desc = re.search(r'description\\s*=\\s*["\']([^"\']+)', content)
                return (
                    f"=== pyproject.toml ===\\n"
                    f"Name: {n.group(1) if n else ''}\\n"
                    f"Description: {desc.group(1) if desc else ''}"
                )
            elif name == "go.mod":
                first = content.splitlines()[0] if content else ""
                return f"=== go.mod ===\\n{first}"
        except Exception:
            pass
    return ""

def _read_env_example(repo: Path) -> str:
    for name in ENV_EXAMPLES:
        f = repo / name
        if f.exists():
            content = _read(f, 2000)
            keys = [
                line.split("=")[0].strip()
                for line in content.splitlines()
                if "=" in line and not line.strip().startswith("#")
            ]
            return "=== .env.example keys ===\\n" + ", ".join(keys[:40])
    return ""

def _read_schema(repo: Path) -> str:
    tables: List[str] = []
    for f in list(repo.rglob("*.sql"))[:5]:
        if any(x in str(f) for x in ["test", "fixture"]):
            continue
        m = re.findall(r"CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?[`\"]?(\w+)[`\"]?",
                       _read(f, 5000), re.IGNORECASE)
        tables.extend(m)
    schema_rb = repo / "db" / "schema.rb"
    if schema_rb.exists():
        m = re.findall(r'create_table\\s+"(\w+)"', _read(schema_rb, 5000))
        tables.extend(m)
    unique = list(dict.fromkeys(tables))[:30]
    return ("=== DB Tables ===\\n" + ", ".join(unique)) if unique else ""

def _read(f: Path, max_chars: int) -> str:
    try:
        return f.read_text(encoding="utf-8", errors="ignore")[:max_chars]
    except OSError:
        return ""

def _analyze(text: str, raw_parts: List[str]) -> dict:
    tl = text.lower()
    scores = {k: sum(1 for s in signals if s in tl)
              for k, signals in SYSTEM_TYPE_SIGNALS.items()}
    system_type = max(scores, key=scores.get) if any(scores.values()) else "unknown"

    critical_assets = [a for a, sigs in CRITICAL_ASSET_SIGNALS.items()
                       if any(s in tl for s in sigs)]
    business_flows  = [f for f, sigs in BUSINESS_FLOW_SIGNALS.items()
                       if any(s in tl for s in sigs)]
    description = _first_paragraph(raw_parts[0] if raw_parts else "")
    tech_hints  = _tech_hints(text)

    return {
        "system_type":     system_type,
        "description":     description,
        "critical_assets": critical_assets,
        "business_flows":  business_flows,
        "tech_stack_hints": tech_hints[:15],
        "raw_excerpts":    [p[:400] for p in raw_parts[:4]],
        "total_doc_chars": len(text),
    }

def _first_paragraph(text: str) -> str:
    paragraphs, buf = [], []
    for line in text.splitlines():
        if line.strip().startswith("#"):
            if buf:
                paragraphs.append(" ".join(buf)); buf = []
            continue
        if line.strip():
            buf.append(line.strip())
        else:
            if buf:
                paragraphs.append(" ".join(buf)); buf = []
    if buf:
        paragraphs.append(" ".join(buf))
    return next((p[:400] for p in paragraphs if len(p) > 30), "")

def _tech_hints(text: str) -> List[str]:
    patterns = [
        (r'\bDjango\b', "Python/Django"), (r'\bFlask\b', "Python/Flask"),
        (r'\bFastAPI\b', "Python/FastAPI"), (r'\bLaravel\b', "PHP/Laravel"),
        (r'\bSymfony\b', "PHP/Symfony"), (r'\bExpress\b', "Node.js/Express"),
        (r'\bNestJS\b', "Node.js/NestJS"), (r'\bSpring Boot\b', "Java/Spring Boot"),
        (r'\bRails\b', "Ruby/Rails"), (r'\bGin\b', "Go/Gin"),
        (r'\bPostgreSQL\b', "PostgreSQL"), (r'\bMySQL\b', "MySQL"),
        (r'\bMongoDB\b', "MongoDB"), (r'\bRedis\b', "Redis"),
        (r'\bStripe\b', "Payment/Stripe"), (r'\bJWT\b', "JWT auth"),
        (r'\bOAuth\b', "OAuth"), (r'\bGraphQL\b', "GraphQL"),
        (r'\bKafka\b|\bRabbitMQ\b', "Message queue"),
        (r'\bS3\b|\bAWS\b', "AWS/S3"),
    ]
    hints = []
    for pat, label in patterns:
        if re.search(pat, text, re.IGNORECASE):
            hints.append(label)
    return list(dict.fromkeys(hints))
