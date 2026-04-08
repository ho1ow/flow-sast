"""
phases/4_analyze/hardcode_agent.py
────────────────────────────────────
ANALYZE agent: Hardcoded Secrets & Credentials

Scans the ENTIRE repository (not just taint paths) for:
  - API keys / tokens (AWS, GCP, Stripe, Twilio, etc.)
  - Hardcoded passwords / database connection strings
  - Private keys (RSA/EC/PEM)
  - JWT secrets
  - OAuth client secrets
  - Internal URLs / IPs with credentials embedded

This agent is unique: it runs an independent grep scan of the repo,
not just the current path. Invoked once per pipeline run.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path
from typing import List, Tuple

from core.reliability import audit_log, safe_node
from core.state import PentestState
from phases._shared.finding_builder import load_skill


SKILL_FILE = Path(__file__).parents[2] / "prompts" / "agent_skills" / "hardcode_skill.md"

SKIP_DIRS = {".git", "node_modules", "__pycache__", "vendor", "dist", "build",
             ".tox", "venv", ".env", "test", "tests", "spec", "fixtures"}
SKIP_EXTS = {".pyc", ".pyo", ".class", ".jar", ".so", ".dll", ".exe", ".png",
             ".jpg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".pdf"}

# (pattern, vuln_type, severity, cwe)
SECRET_PATTERNS: List[Tuple[re.Pattern, str, str, str]] = [
    # AWS
    (re.compile(r'AKIA[0-9A-Z]{16}'), "aws_access_key", "CRITICAL", "CWE-798"),
    (re.compile(r'(?i)(aws.{0,20}secret.{0,20}["\'])[0-9a-zA-Z/+]{40}'), "aws_secret_key", "CRITICAL", "CWE-798"),
    # GCP
    (re.compile(r'"type"\s*:\s*"service_account"'), "gcp_service_account", "CRITICAL", "CWE-798"),
    # Private keys
    (re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'), "private_key", "CRITICAL", "CWE-321"),
    # JWT secrets
    (re.compile(r'(?i)(jwt.{0,10}secret|secret.{0,10}key)\s*[=:]\s*["\'][^"\']{8,}["\']'), "jwt_secret", "HIGH", "CWE-321"),
    # Generic passwords/secrets
    (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']'), "hardcoded_password", "HIGH", "CWE-259"),
    (re.compile(r'(?i)(secret|api_?key|api_?secret|auth_?token)\s*[=:]\s*["\'][^"\']{8,}["\']'), "hardcoded_secret", "HIGH", "CWE-798"),
    # Database URLs
    (re.compile(r'(?i)(postgres|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@'), "db_connection_string", "HIGH", "CWE-312"),
    # Stripe / payment
    (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), "stripe_live_key", "CRITICAL", "CWE-798"),
    (re.compile(r'pk_live_[0-9a-zA-Z]{24,}'), "stripe_publish_key", "HIGH", "CWE-798"),
    # GitHub tokens
    (re.compile(r'ghp_[0-9a-zA-Z]{36}'), "github_token", "CRITICAL", "CWE-798"),
    (re.compile(r'github_pat_[0-9a-zA-Z_]{82}'), "github_pat", "CRITICAL", "CWE-798"),
    # Slack
    (re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}'), "slack_token", "HIGH", "CWE-798"),
    # Generic high-entropy strings assigned to key-like variables
    (re.compile(r'(?i)(token|secret|credential)\s*=\s*["\'][A-Za-z0-9+/]{32,}={0,2}["\']'), "high_entropy_secret", "MEDIUM", "CWE-798"),
]

# False-positive filters: skip if these appear in the same line
FP_PATTERNS = re.compile(
    r'(example|placeholder|changeme|your.key|insert.your|xxx+|'
    r'test|replace|todo|env\[|os\.environ|os\.getenv|config\.|'
    r'process\.env|dotenv|vault|secrets\.)',
    re.IGNORECASE,
)

# CWE → OWASP mapping
CWE_OWASP = {
    "CWE-798": "A07:2021 – Identification and Authentication Failures",
    "CWE-321": "A02:2021 – Cryptographic Failures",
    "CWE-259": "A07:2021 – Identification and Authentication Failures",
    "CWE-312": "A02:2021 – Cryptographic Failures",
}


@safe_node("hardcode_agent")
def hardcode_agent(state: PentestState) -> dict:
    """Scan entire repo for hardcoded secrets and credentials."""
    cfg = state["config"]
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")
    repo_path = state["repo_path"]

    audit_log(audit_dir, run_id, "hardcode_agent:start", {"repo": repo_path})

    findings: List[dict] = []
    seen: set[str] = set()

    repo = Path(repo_path)
    for src_file in _iter_files(repo):
        try:
            content = src_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        lines = content.splitlines()
        rel_path = str(src_file.relative_to(repo))

        for lineno, line in enumerate(lines, start=1):
            # Skip likely false positives
            if FP_PATTERNS.search(line):
                continue

            for pattern, vuln_type, severity, cwe in SECRET_PATTERNS:
                m = pattern.search(line)
                if m:
                    uid = hashlib.md5(f"{rel_path}:{lineno}:{vuln_type}".encode()).hexdigest()[:12]
                    if uid in seen:
                        continue
                    seen.add(uid)

                    findings.append({
                        "id": uid,
                        "vuln_type": vuln_type,
                        "title": f"Hardcoded {vuln_type.replace('_', ' ').title()}",
                        "severity": severity,
                        "confidence": "HIGH",
                        "phase": "hardcode",
                        "file": rel_path,
                        "line_start": lineno,
                        "line_end": lineno,
                        "code_snippet": _redact(line.strip()),
                        "cwe": cwe,
                        "owasp": CWE_OWASP.get(cwe, "A02:2021 – Cryptographic Failures"),
                        "sarif_rule_id": f"hardcode/{vuln_type}",
                        "attack_vector": f"Attacker reads source code or build artifact and finds {vuln_type}",
                        "reasoning": f"Hardcoded credential found: pattern '{pattern.pattern[:60]}' matched at line {lineno}",
                        "sanitizers_found": [],
                        "confirmed_pocs": [],
                    })

    audit_log(audit_dir, run_id, "hardcode_agent:done", {"secrets_found": len(findings)})
    return {"findings": findings}


def _iter_files(repo: Path):
    for f in repo.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix in SKIP_EXTS:
            continue
        if any(p in f.parts for p in SKIP_DIRS):
            continue
        yield f


def _redact(line: str) -> str:
    """Replace the secret value portion with [REDACTED] for safe logging."""
    return re.sub(r'(["\'])([^"\']{8,})(["\'])', r'\1[REDACTED]\3', line)
