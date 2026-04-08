"""
phases/1_catalog/context_runner.py
────────────────────────────────────
LangGraph node: catalog_context

Đọc và tổng hợp mô tả nghiệp vụ hệ thống từ:
  - README.md, README.rst, README.txt
  - docs/, documentation/, wiki/
  - CHANGELOG, CHANGELOG.md
  - OpenAPI/Swagger specs (openapi.yaml, swagger.json)
  - Docstrings từ models/ và controllers/
  - DB schema (schema.sql, migration files)
  - .env.example (reveals system services)
  - package.json / composer.json / pyproject.toml (app name + description)

Output: state["business_context"] — dict với:
  - system_type: "ecommerce" | "saas" | "healthcare" | "fintech" | "internal" | "api" | "unknown"
  - description: str — mô tả ngắn của hệ thống
  - key_features: List[str] — tính năng chính
  - critical_assets: List[str] — tài sản quan trọng cần bảo vệ
  - business_flows: List[str] — các flow nghiệp vụ chính
  - tech_stack_hints: List[str] — clue về tech stack từ docs
  - raw_excerpts: List[str] — đoạn text thô quan trọng (cho Claude analyze)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from core.reliability import audit_log, checkpoint_load, checkpoint_save, safe_node
from core.state import PentestState


# ── File patterns to scan ────────────────────────────────────────────────────

README_PATTERNS = [
    "README.md", "README.rst", "README.txt", "README",
    "readme.md", "Readme.md",
]

DOC_DIRS = ["docs", "doc", "documentation", "wiki", "pages", ".github"]
DOC_EXTENSIONS = {".md", ".rst", ".txt", ".adoc"}

OPENAPI_FILES = [
    "openapi.yaml", "openapi.yml", "openapi.json",
    "swagger.yaml", "swagger.yml", "swagger.json",
    "api.yaml", "api.yml", "api-docs.json",
]

SCHEMA_FILES = [
    "schema.sql", "schema.rb", "db/schema.rb",
    "database.sql", "init.sql", "structure.sql",
]

PROJECT_MANIFEST = [
    "package.json", "composer.json", "pyproject.toml",
    "Cargo.toml", "go.mod", "build.gradle", "pom.xml",
    "setup.py", "setup.cfg",
]

ENV_EXAMPLE = [".env.example", ".env.sample", ".env.template", "env.example"]


# ── System type patterns ─────────────────────────────────────────────────────

SYSTEM_TYPE_SIGNALS = {
    "ecommerce": [
        "cart", "checkout", "order", "payment", "product", "inventory",
        "shipping", "coupon", "discount", "marketplace", "shop", "store",
        "purchase", "invoice", "customer", "catalog",
    ],
    "saas": [
        "subscription", "tenant", "workspace", "organization", "plan",
        "billing", "quota", "api key", "dashboard", "analytics", "report",
        "multi-tenant", "white-label",
    ],
    "healthcare": [
        "patient", "medical", "health", "clinic", "hospital", "prescription",
        "diagnosis", "ehr", "emr", "lab", "appointment", "physician", "hipaa",
    ],
    "fintech": [
        "bank", "finance", "loan", "credit", "debit", "account", "transfer",
        "transaction", "balance", "wallet", "investment", "trading", "kyc",
        "aml", "payment gateway", "ledger",
    ],
    "social": [
        "social", "feed", "post", "comment", "like", "follow", "friend",
        "message", "notification", "profile", "community",
    ],
    "internal": [
        "admin", "internal tool", "dashboard", "management", "hr",
        "employee", "crm", "erp", "backoffice", "back office",
    ],
    "api": [
        "api", "rest api", "graphql", "webhook", "sdk", "integration",
        "microservice", "service mesh",
    ],
}

CRITICAL_ASSET_SIGNALS = {
    "Payment data (PCI-DSS)": ["payment", "card", "credit card", "stripe", "paypal", "billing"],
    "Personal data (PII/GDPR)": ["personal data", "pii", "gdpr", "user data", "profile"],
    "Healthcare records (HIPAA)": ["patient", "medical record", "health data", "phi", "hipaa"],
    "Financial records": ["account balance", "transaction", "ledger", "bank"],
    "Authentication credentials": ["password", "token", "session", "oauth", "jwt"],
    "Multi-tenant isolation": ["tenant", "organization", "workspace", "isolation"],
    "API access control": ["api key", "rate limit", "quota", "permission"],
}

BUSINESS_FLOW_SIGNALS = {
    "User registration & onboarding": ["register", "signup", "sign up", "onboarding", "verify email"],
    "Authentication & session": ["login", "logout", "session", "token refresh", "2fa", "mfa"],
    "Checkout & payment": ["checkout", "payment", "purchase", "order", "cart"],
    "File upload & storage": ["upload", "file", "attachment", "media", "image"],
    "User management & roles": ["role", "permission", "admin", "moderator", "privilege"],
    "Data export & reporting": ["export", "report", "download", "csv", "pdf"],
    "Webhook & integration": ["webhook", "callback", "integration", "third-party"],
    "Subscription & billing": ["subscribe", "plan", "billing", "invoice", "renewal"],
    "Content moderation": ["moderate", "review", "approve", "reject", "flag"],
    "Search & filtering": ["search", "filter", "query", "elasticsearch"],
}


@safe_node("catalog_context")
def catalog_context(state: PentestState) -> dict:
    """LangGraph node — extract business context from project documentation."""
    cfg = state["config"]
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")
    repo_path = state["repo_path"]
    checkpoint_dir = state["checkpoint_dir"]

    cached = checkpoint_load(checkpoint_dir, run_id, "catalog_context")
    if cached:
        return cached

    audit_log(audit_dir, run_id, "catalog_context:start", {"repo": repo_path})

    repo = Path(repo_path)
    raw_text_parts: List[str] = []

    # ── 1. README files ────────────────────────────────────────────────────────
    for name in README_PATTERNS:
        f = repo / name
        if f.exists():
            content = _read_file(f, max_chars=8000)
            if content:
                raw_text_parts.append(f"=== {name} ===\n{content}")
            break  # first README is enough

    # ── 2. Docs directory ──────────────────────────────────────────────────────
    for doc_dir in DOC_DIRS:
        d = repo / doc_dir
        if d.is_dir():
            for f in sorted(d.rglob("*"))[:10]:  # max 10 doc files
                if f.suffix in DOC_EXTENSIONS and f.is_file():
                    content = _read_file(f, max_chars=2000)
                    if content:
                        rel = str(f.relative_to(repo))
                        raw_text_parts.append(f"=== {rel} ===\n{content}")

    # ── 3. OpenAPI / Swagger specs ─────────────────────────────────────────────
    openapi_info = _extract_openapi_info(repo)
    if openapi_info:
        raw_text_parts.append(f"=== OpenAPI Spec ===\n{openapi_info}")

    # ── 4. Project manifest (name + description) ──────────────────────────────
    manifest_info = _extract_manifest_info(repo)
    if manifest_info:
        raw_text_parts.append(f"=== Project Manifest ===\n{manifest_info}")

    # ── 5. .env.example (service hints) ──────────────────────────────────────
    env_info = _extract_env_example(repo)
    if env_info:
        raw_text_parts.append(f"=== Service Hints (.env.example) ===\n{env_info}")

    # ── 6. DB schema snippets ─────────────────────────────────────────────────
    schema_info = _extract_schema_info(repo)
    if schema_info:
        raw_text_parts.append(f"=== DB Schema (key tables) ===\n{schema_info}")

    # ── 7. Model docstrings ───────────────────────────────────────────────────
    model_docs = _extract_model_docstrings(repo)
    if model_docs:
        raw_text_parts.append(f"=== Model Docstrings ===\n{model_docs}")

    # ── Analyze collected text ────────────────────────────────────────────────
    combined_text = "\n\n".join(raw_text_parts)
    context = _analyze_context(combined_text, raw_text_parts)

    audit_log(audit_dir, run_id, "catalog_context:done", {
        "system_type": context["system_type"],
        "features": len(context["key_features"]),
        "flows": len(context["business_flows"]),
        "assets": len(context["critical_assets"]),
        "text_sources": len(raw_text_parts),
    })

    result = {"business_context": context}
    checkpoint_save(checkpoint_dir, run_id, "catalog_context", result)
    return result


# ── Context analyzers ─────────────────────────────────────────────────────────

def _analyze_context(text: str, raw_parts: List[str]) -> dict:
    text_lower = text.lower()

    # System type scoring
    scores: Dict[str, int] = {}
    for sys_type, signals in SYSTEM_TYPE_SIGNALS.items():
        scores[sys_type] = sum(1 for s in signals if s in text_lower)
    system_type = max(scores, key=scores.get) if any(scores.values()) else "unknown"

    # Critical assets
    critical_assets = [
        asset for asset, signals in CRITICAL_ASSET_SIGNALS.items()
        if any(s in text_lower for s in signals)
    ]

    # Business flows
    business_flows = [
        flow for flow, signals in BUSINESS_FLOW_SIGNALS.items()
        if any(s in text_lower for s in signals)
    ]

    # Key features — extract bullet points from README
    key_features = _extract_features(text)

    # Short description from first paragraph of README
    description = _extract_description(raw_parts[0] if raw_parts else "")

    # Tech stack hints from env example / manifest
    tech_hints = _extract_tech_hints(text)

    return {
        "system_type": system_type,
        "description": description,
        "key_features": key_features[:10],
        "critical_assets": critical_assets,
        "business_flows": business_flows,
        "tech_stack_hints": tech_hints[:15],
        "raw_excerpts": [p[:500] for p in raw_parts[:5]],  # clip for Claude
        "total_doc_chars": len(text),
    }


def _extract_features(text: str) -> List[str]:
    """Extract bullet points or feature list from text."""
    features = []
    for line in text.splitlines():
        line = line.strip()
        # Markdown bullets
        if line.startswith(("- ", "* ", "• ", "+ ")):
            feat = line[2:].strip()
            if 10 < len(feat) < 120 and not feat.startswith("#"):
                features.append(feat)
        # Numbered list
        elif re.match(r'^\d+\.\s+', line):
            feat = re.sub(r'^\d+\.\s+', '', line).strip()
            if 10 < len(feat) < 120:
                features.append(feat)
    return features[:15]


def _extract_description(readme_text: str) -> str:
    """Extract first non-empty paragraph after title."""
    lines = readme_text.splitlines()
    paragraphs = []
    current = []

    for line in lines:
        if line.strip().startswith("#"):
            if current:
                paragraphs.append(" ".join(current))
                current = []
            continue
        if line.strip():
            current.append(line.strip())
        else:
            if current:
                paragraphs.append(" ".join(current))
                current = []

    if current:
        paragraphs.append(" ".join(current))

    # Return first substantial paragraph
    for p in paragraphs:
        if len(p) > 30:
            return p[:500]
    return ""


def _extract_tech_hints(text: str) -> List[str]:
    hints = []
    patterns = [
        (r'\bDjango\b', "Python/Django"),
        (r'\bFlask\b', "Python/Flask"),
        (r'\bFastAPI\b', "Python/FastAPI"),
        (r'\bLaravel\b', "PHP/Laravel"),
        (r'\bSymfony\b', "PHP/Symfony"),
        (r'\bExpress\b', "Node.js/Express"),
        (r'\bNestJS\b', "Node.js/NestJS"),
        (r'\bNext\.js\b', "Node.js/Next.js"),
        (r'\bSpring Boot\b', "Java/Spring Boot"),
        (r'\bRails\b', "Ruby/Rails"),
        (r'\bGin\b', "Go/Gin"),
        (r'\bPostgreSQL\b|\bpsql\b', "PostgreSQL"),
        (r'\bMySQL\b|\bMariaDB\b', "MySQL"),
        (r'\bMongoDB\b|\bmongoose\b', "MongoDB"),
        (r'\bRedis\b', "Redis"),
        (r'\bElasticsearch\b', "Elasticsearch"),
        (r'\bS3\b|\bAWS\b', "AWS/S3"),
        (r'\bStripe\b', "Payment/Stripe"),
        (r'\bTwilio\b', "SMS/Twilio"),
        (r'\bSendGrid\b|\bMailgun\b', "Email service"),
        (r'\bJWT\b|\bjson.?web.?token\b', "JWT auth"),
        (r'\bOAuth\b', "OAuth"),
        (r'\bGraphQL\b', "GraphQL"),
        (r'\bRabbitMQ\b|\bKafka\b|\bSQS\b', "Message queue"),
        (r'\bDocke\b|\bkubernetes\b|\bk8s\b', "Containerized"),
    ]
    for pattern, label in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            hints.append(label)
    return list(dict.fromkeys(hints))  # dedup preserve order


# ── File extractors ───────────────────────────────────────────────────────────

def _extract_openapi_info(repo: Path) -> str:
    for name in OPENAPI_FILES:
        f = repo / name
        if not f.exists():
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            if f.suffix == ".json":
                data = json.loads(content)
            else:
                data = yaml.safe_load(content)

            info = data.get("info", {})
            paths = list(data.get("paths", {}).keys())[:20]
            tags = list({
                t.get("name", "")
                for p in data.get("paths", {}).values()
                for method in p.values()
                if isinstance(method, dict)
                for t in method.get("tags", [{}])
                if isinstance(t, dict)
            })

            return (
                f"Title: {info.get('title', '')}\n"
                f"Description: {info.get('description', '')[:500]}\n"
                f"Version: {info.get('version', '')}\n"
                f"API Endpoints ({len(paths)}): {', '.join(paths[:15])}\n"
                f"Tags: {', '.join(tags[:10])}"
            )
        except Exception:
            # Fallback: return raw text snippet
            return _read_file(f, max_chars=1500)

    return ""


def _extract_manifest_info(repo: Path) -> str:
    parts = []
    for name in PROJECT_MANIFEST:
        f = repo / name
        if not f.exists():
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            if name == "package.json":
                data = json.loads(content)
                parts.append(
                    f"Name: {data.get('name', '')}\n"
                    f"Description: {data.get('description', '')}\n"
                    f"Keywords: {', '.join(data.get('keywords', []))}"
                )
            elif name == "composer.json":
                data = json.loads(content)
                parts.append(
                    f"Name: {data.get('name', '')}\n"
                    f"Description: {data.get('description', '')}"
                )
            elif name == "pyproject.toml":
                # Simple regex parse
                m = re.search(r'description\s*=\s*["\']([^"\']+)', content)
                n = re.search(r'name\s*=\s*["\']([^"\']+)', content)
                if n:
                    parts.append(f"Name: {n.group(1)}")
                if m:
                    parts.append(f"Description: {m.group(1)}")
        except Exception:
            pass
        if parts:
            break  # first manifest is enough

    return "\n".join(parts)


def _extract_env_example(repo: Path) -> str:
    for name in ENV_EXAMPLE:
        f = repo / name
        if f.exists():
            content = _read_file(f, max_chars=2000)
            # Extract just key names (not values)
            keys = [
                line.split("=")[0].strip()
                for line in content.splitlines()
                if "=" in line and not line.strip().startswith("#")
            ]
            return "Service/Config keys: " + ", ".join(keys[:40])
    return ""


def _extract_schema_info(repo: Path) -> str:
    # Look for migration files listing table names
    table_names: List[str] = []

    for f in repo.rglob("*.sql"):
        if any(skip in str(f) for skip in ["test", "fixture"]):
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            tables = re.findall(
                r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"]?(\w+)[`"]?',
                content, re.IGNORECASE
            )
            table_names.extend(tables)
            if len(table_names) > 30:
                break
        except OSError:
            pass

    # Also check schema.rb (Rails)
    schema_rb = repo / "db" / "schema.rb"
    if schema_rb.exists():
        try:
            content = schema_rb.read_text(encoding="utf-8", errors="ignore")
            tables = re.findall(r'create_table\s+"(\w+)"', content)
            table_names.extend(tables)
        except OSError:
            pass

    unique_tables = list(dict.fromkeys(table_names))[:30]
    return "Tables: " + ", ".join(unique_tables) if unique_tables else ""


def _extract_model_docstrings(repo: Path) -> str:
    model_docs: List[str] = []

    model_dirs = ["models", "app/models", "src/models", "domain", "entities"]
    for model_dir in model_dirs:
        d = repo / model_dir
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*"))[:10]:
            if f.suffix not in {".py", ".rb", ".php", ".java", ".go"}:
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                # Python docstring
                m = re.search(r'class\s+\w+[^:]*:\s*"""([^"]+)"""', content, re.DOTALL)
                if m:
                    model_docs.append(f"{f.stem}: {m.group(1).strip()[:200]}")
                # PHPDoc
                m = re.search(r'/\*\*\s*(.*?)\s*\*/', content, re.DOTALL)
                if m:
                    model_docs.append(f"{f.stem}: {m.group(1)[:200]}")
            except OSError:
                pass

    return "\n".join(model_docs[:10])


def _read_file(f: Path, max_chars: int = 5000) -> str:
    try:
        return f.read_text(encoding="utf-8", errors="ignore")[:max_chars]
    except OSError:
        return ""
