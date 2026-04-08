"""
phases/1_catalog/secrets_runner.py
────────────────────────────────────
LangGraph node: catalog_secrets

Chạy Gitleaks để detect hardcoded secrets/credentials.
Kết quả đi THẲNG vào findings[] — không cần qua Phase 2 (confidence: HIGH).

Fallback: regex scan nội bộ nếu Gitleaks binary không có.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import List

from core.reliability import audit_log, checkpoint_load, checkpoint_save, safe_node
from core.state import PentestState


# ── Gitleaks output → finding mapper ─────────────────────────────────────────

CWE_MAP = {
    "generic-api-key":        ("CWE-798", "A07:2021 – Identification and Authentication Failures"),
    "aws-access-token":       ("CWE-798", "A07:2021 – Identification and Authentication Failures"),
    "aws-secret-access-key":  ("CWE-798", "A07:2021 – Identification and Authentication Failures"),
    "github-pat":             ("CWE-798", "A07:2021 – Identification and Authentication Failures"),
    "github-fine-grained":    ("CWE-798", "A07:2021 – Identification and Authentication Failures"),
    "private-key":            ("CWE-321", "A02:2021 – Cryptographic Failures"),
    "jwt":                    ("CWE-321", "A02:2021 – Cryptographic Failures"),
    "stripe-access-token":    ("CWE-798", "A07:2021 – Identification and Authentication Failures"),
    "stripe-publishable-key": ("CWE-798", "A07:2021 – Identification and Authentication Failures"),
    "slack-access-token":     ("CWE-798", "A07:2021 – Identification and Authentication Failures"),
    "sendgrid-api-token":     ("CWE-798", "A07:2021 – Identification and Authentication Failures"),
    "twilio-api-key":         ("CWE-798", "A07:2021 – Identification and Authentication Failures"),
    "generic-credential":     ("CWE-259", "A07:2021 – Identification and Authentication Failures"),
    "password-in-url":        ("CWE-312", "A02:2021 – Cryptographic Failures"),
}

SEVERITY_MAP = {
    "CRITICAL": ["private-key", "aws-secret-access-key", "stripe-access-token", "github-pat"],
    "HIGH":     ["aws-access-token", "generic-api-key", "jwt", "github-fine-grained",
                 "sendgrid-api-token", "twilio-api-key", "generic-credential"],
}


@safe_node("catalog_secrets")
def catalog_secrets(state: PentestState) -> dict:
    """LangGraph node — run Gitleaks and output findings directly."""
    cfg = state["config"]
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")
    repo_path = state["repo_path"]
    checkpoint_dir = state["checkpoint_dir"]

    # Resume check
    cached = checkpoint_load(checkpoint_dir, run_id, "catalog_secrets")
    if cached:
        audit_log(audit_dir, run_id, "catalog_secrets:resumed", {"findings": len(cached.get("findings", []))})
        return cached

    audit_log(audit_dir, run_id, "catalog_secrets:start", {"repo": repo_path})

    findings: List[dict] = []

    # Try Gitleaks first
    gitleaks_findings = _run_gitleaks(repo_path, cfg, run_id, audit_dir)
    if gitleaks_findings is not None:
        findings.extend(_map_gitleaks_findings(gitleaks_findings))
        audit_log(audit_dir, run_id, "catalog_secrets:gitleaks", {"count": len(gitleaks_findings)})
    else:
        # Fallback: enhanced regex scan
        regex_findings = _regex_fallback(repo_path)
        findings.extend(regex_findings)
        audit_log(audit_dir, run_id, "catalog_secrets:regex_fallback", {"count": len(regex_findings)})

    result = {"findings": findings}
    checkpoint_save(checkpoint_dir, run_id, "catalog_secrets", result)

    audit_log(audit_dir, run_id, "catalog_secrets:done", {
        "total_secrets": len(findings),
        "critical": len([f for f in findings if f.get("severity") == "CRITICAL"]),
        "high": len([f for f in findings if f.get("severity") == "HIGH"]),
    })

    return result


# ── Gitleaks execution ────────────────────────────────────────────────────────

def _run_gitleaks(repo_path: str, cfg: dict, run_id: str, audit_dir: str):
    """Run gitleaks, return raw findings list or None if unavailable."""
    gitleaks_cfg = cfg.get("gitleaks", {})
    binary = gitleaks_cfg.get("binary", "gitleaks")
    timeout = gitleaks_cfg.get("timeout_seconds", 120)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
        report_path = tmp.name

    try:
        result = subprocess.run(
            [
                binary, "detect",
                "--source", repo_path,
                "--report-format", "json",
                "--report-path", report_path,
                "--no-git",
                "--exit-code", "0",   # don't fail if secrets found
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode not in (0, 1):  # 1 = secrets found (expected)
            audit_log(audit_dir, run_id, "catalog_secrets:gitleaks_error",
                      {"stderr": result.stderr[:300]})
            return None

        raw = Path(report_path).read_text(encoding="utf-8", errors="ignore")
        if not raw.strip():
            return []

        return json.loads(raw)

    except FileNotFoundError:
        audit_log(audit_dir, run_id, "catalog_secrets:gitleaks_not_found", {})
        return None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        audit_log(audit_dir, run_id, "catalog_secrets:gitleaks_exc", {"error": str(exc)})
        return None
    finally:
        Path(report_path).unlink(missing_ok=True)


def _map_gitleaks_findings(raw_findings: list) -> List[dict]:
    """Convert Gitleaks JSON output to normalized finding dicts."""
    findings = []
    for r in raw_findings:
        rule_id = r.get("RuleID", "generic-api-key")
        cwe, owasp = CWE_MAP.get(rule_id, ("CWE-798", "A07:2021"))
        severity = _get_severity(rule_id)

        # Redact actual secret value
        secret_display = _redact(r.get("Secret", ""))

        finding_id = hashlib.md5(
            f"{r.get('File','')}:{r.get('StartLine',0)}:{rule_id}".encode()
        ).hexdigest()[:12]

        findings.append({
            "id": finding_id,
            "category": "hardcode",
            "vuln_type": "hardcoded_secret",
            "title": f"Hardcoded Secret: {rule_id.replace('-', ' ').title()}",
            "severity": severity,
            "confidence": "HIGH",
            "needs_dynamic": False,
            "file": r.get("File", ""),
            "line_start": r.get("StartLine", 0),
            "line_end": r.get("EndLine", r.get("StartLine", 0)),
            "code_snippet": _redact(r.get("Match", "")),
            "secret_display": secret_display,
            "rule_id": rule_id,
            "cwe": cwe,
            "owasp": owasp,
            "sarif_rule_id": f"gitleaks/{rule_id}",
            "attack_vector": f"Source code exposure reveals {rule_id}",
            "remediation": "Move credential to environment variable or secrets manager (Vault, AWS Secrets Manager)",
            "detected_by": ["gitleaks"],
            "manual_review": False,
            "path": {},
        })

    return findings


def _get_severity(rule_id: str) -> str:
    for sev, rules in SEVERITY_MAP.items():
        if rule_id in rules:
            return sev
    return "HIGH"  # default


def _redact(text: str) -> str:
    return re.sub(r'(["\']?)([A-Za-z0-9+/\-_]{8,})(["\']?)',
                  lambda m: f"{m.group(1)}[REDACTED]{m.group(3)}", text, count=1)


# ── Regex fallback ─────────────────────────────────────────────────────────────

REGEX_PATTERNS = [
    (re.compile(r'AKIA[0-9A-Z]{16}'), "aws-access-token", "CRITICAL"),
    (re.compile(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'), "private-key", "CRITICAL"),
    (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), "stripe-access-token", "CRITICAL"),
    (re.compile(r'ghp_[0-9a-zA-Z]{36}'), "github-pat", "CRITICAL"),
    (re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}'), "slack-access-token", "HIGH"),
    (re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']'), "generic-credential", "HIGH"),
    (re.compile(r'(?i)(?:api_?key|auth_?token|secret_?key)\s*[=:]\s*["\'][^"\']{8,}["\']'), "generic-api-key", "HIGH"),
    (re.compile(r'(?i)(?:postgres|mysql|mongodb)://[^:]+:[^@]+@'), "password-in-url", "HIGH"),
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", "vendor", "dist", "build", "test", "tests"}
SKIP_EXTS = {".pyc", ".pyo", ".class", ".png", ".jpg", ".gif", ".svg", ".woff", ".pdf", ".lock"}
FP_FILTER = re.compile(r'(?i)(example|placeholder|changeme|your.key|xxx|test|fake|env\[|os\.environ|os\.getenv|config\.|process\.env)', )


def _regex_fallback(repo_path: str) -> List[dict]:
    findings = []
    seen: set[str] = set()
    repo = Path(repo_path)

    for f in repo.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix in SKIP_EXTS:
            continue
        if any(d in f.parts for d in SKIP_DIRS):
            continue

        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        rel = str(f.relative_to(repo))
        for lineno, line in enumerate(lines, 1):
            if FP_FILTER.search(line):
                continue
            for pattern, rule_id, severity in REGEX_PATTERNS:
                if pattern.search(line):
                    uid = hashlib.md5(f"{rel}:{lineno}:{rule_id}".encode()).hexdigest()[:12]
                    if uid in seen:
                        continue
                    seen.add(uid)
                    cwe, owasp = CWE_MAP.get(rule_id, ("CWE-798", "A07:2021"))
                    findings.append({
                        "id": uid,
                        "category": "hardcode",
                        "vuln_type": "hardcoded_secret",
                        "title": f"Potential Secret: {rule_id.replace('-', ' ').title()}",
                        "severity": severity,
                        "confidence": "MED",  # regex = MED (gitleaks = HIGH)
                        "needs_dynamic": False,
                        "file": rel,
                        "line_start": lineno,
                        "line_end": lineno,
                        "code_snippet": _redact(line.strip()),
                        "cwe": cwe,
                        "owasp": owasp,
                        "sarif_rule_id": f"regex/{rule_id}",
                        "attack_vector": f"Source code exposure reveals {rule_id}",
                        "remediation": "Move to environment variable or secrets manager",
                        "detected_by": ["regex_fallback"],
                        "manual_review": False,
                        "path": {},
                    })
    return findings
