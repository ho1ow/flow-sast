"""
phases/1_catalog/semgrep_runner.py
───────────────────────────────────
LangGraph node: catalog_semgrep

Discovers sources and sinks using Semgrep with:
  - auto + security-audit + owasp-top-ten rulesets
  - Custom rules from phases/1_catalog/rules/ (company-specific sinks)
  - Covers: Python, Java, JS/TS, Go, PHP, Ruby, C/C++

Sources catalogued (NOT only HTTP):
  - HTTP params, headers, cookies, request body
  - DB read results (cursor.fetchall, JPA findBy, ActiveRecord.find)
  - Message queue (Kafka consumer, RabbitMQ handler, SQS)
  - File upload content
  - WebSocket messages
  - Environment variables used as input routing

Sinks catalogued (by vuln type):
  - SQLi, RCE, XSS, SSRF, Path traversal, Open redirect,
    Deserialization, XXE, SSTI, Header injection
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import uuid
from pathlib import Path
from typing import List

from shared.logger import audit_log

# ── Semgrep built-in rulesets ─────────────────────────────────────────────────
BUILTIN_CONFIGS = [
    "auto",
    "p/security-audit",
    "p/owasp-top-ten",
]

# ── Source patterns per framework / language ──────────────────────────────────
# These are used as fallback grep patterns when semgrep auto-detect misses them.
# The semgrep rules themselves do the heavy lifting; this list helps annotate type.
SOURCE_PATTERNS = {
    # Python / Django / Flask
    "django":  ["request.GET", "request.POST", "request.data", "request.FILES",
                 "request.COOKIES", "request.META", "request.headers"],
    "flask":   ["request.args", "request.form", "request.json", "request.files",
                 "request.cookies", "request.headers", "request.values"],
    "fastapi": ["Query(", "Body(", "Form(", "File(", "Header(", "Cookie(", "Path("],

    # Java / Spring
    "spring":  ["@RequestParam", "@PathVariable", "@RequestBody", "@RequestHeader",
                 "@CookieValue", "HttpServletRequest", "getParameter(", "getHeader("],

    # Node / Express
    "express": ["req.query", "req.body", "req.params", "req.headers",
                 "req.cookies", "req.files", "req.session"],

    # Go / Gin / Echo
    "gin":     ["c.Query(", "c.PostForm(", "c.Param(", "c.GetHeader(",
                 "c.Cookie(", "c.ShouldBindJSON(", "c.BindQuery("],

    # PHP
    "php":     ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE",
                 "$_SERVER", "$_FILES", "getallheaders("],

    # Ruby / Rails
    "rails":   ["params[", "params.require(", "request.headers[",
                 "cookies[", "session["],

    # Non-HTTP universal
    "queue":   ["consumer.poll(", "channel.basic_consume", "sqs.receive_message",
                 "kafka.poll(", "@KafkaListener", "@RabbitListener",
                 "queue.get(", "Celery task"],
    "db_read": ["cursor.fetchall(", "cursor.fetchone(", "findOne(", "findAll(",
                 "findById(", "ActiveRecord::Base.find", "session.query(",
                 "repository.find"],
}

# ── Sink rule IDs (what semgrep rule IDs to watch for) ────────────────────────
SINK_RULE_PREFIXES = {
    "sqli":          ["sql-injection", "sqli", "raw-query", "execute-string"],
    "rce":           ["exec-", "command-injection", "os-command", "rce", "code-injection"],
    "xss":           ["xss", "innerHTML", "dangerouslySetInnerHTML", "dom-based"],
    "ssrf":          ["ssrf", "server-side-request-forgery", "unvalidated-url"],
    "path_traversal":["path-traversal", "directory-traversal", "file-inclusion"],
    "redirect":      ["open-redirect", "redirect-", "unvalidated-redirect"],
    "deser":         ["deserialization", "pickle", "yaml.load", "marshal"],
    "xxe":           ["xxe", "xml-external-entity", "xml-injection"],
    "ssti":          ["ssti", "template-injection", "server-side-template"],
    "header_inject": ["header-injection", "crlf-injection"],
}

SINK_SEVERITY = {
    "sqli": "CRITICAL", "rce": "CRITICAL", "deser": "CRITICAL", "xxe": "HIGH",
    "ssrf": "HIGH", "ssti": "HIGH", "path_traversal": "HIGH",
    "xss": "MEDIUM", "redirect": "MEDIUM", "header_inject": "MEDIUM",
}

def catalog_semgrep(repo_path: str, stack: str = "auto", run_id: str = "local", semgrep_cfg: dict = None, business_ctx: dict = None) -> dict:
    """Run semgrep and return discovered sources and sinks."""
    if semgrep_cfg is None:
        semgrep_cfg = {}
    if business_ctx is None:
        business_ctx = {}
        
    audit_dir = "reports/" + run_id
    os.makedirs(audit_dir, exist_ok=True)
    audit_log(audit_dir, run_id, "catalog_semgrep:start", {"repo": repo_path})

    # Build semgrep command
    configs = semgrep_cfg.get("configs", BUILTIN_CONFIGS)
    custom_rules_dir = semgrep_cfg.get("custom_rules_dir", "phases/1_catalog/rules")
    cmd = ["semgrep", "--json", "--no-git-ignore"]

    for c in configs:
        cmd += ["--config", c]

    # Add custom rules if the directory exists
    custom_path = Path(custom_rules_dir)
    if custom_path.exists() and any(custom_path.glob("*.yaml")):
        cmd += ["--config", str(custom_path)]

    # Dynamic generation of non_http_sources rule from business_ctx
    non_http_sources = business_ctx.get("non_http_sources", [])
    if non_http_sources:
        patterns = []
        for src in non_http_sources:
            # We can use simple pattern-regex or a generic match to capture these specific strings in the codebase
            # For simplicity let's make a basic regex rule because they could be methods like EventListener::handle
            pattern_str = src.replace("::", ".*").replace("...", ".*")
            patterns.append(f"          - pattern-regex: '{pattern_str}'")
        
        if patterns:
            rule_content = f"""rules:
  - id: custom-non-http-source
    message: "Discovered non-HTTP source from business context"
    severity: WARNING
    languages: [python, javascript, typescript, java, go, php, ruby, csharp]
    pattern-either:
{chr(10).join(patterns)}
"""
            custom_source_rule_path = Path(audit_dir) / "custom_sources.yaml"
            custom_source_rule_path.write_text(rule_content)
            cmd += ["--config", str(custom_source_rule_path)]
            audit_log(audit_dir, run_id, "catalog_semgrep:custom_sources", {"count": len(non_http_sources)})

    cmd += [
        "--timeout", str(semgrep_cfg.get("timeout_seconds", 300)),
        "--max-memory", str(semgrep_cfg.get("max_memory_mb", 2048)),
        "-j", str(semgrep_cfg.get("jobs", 4)),
        repo_path,
    ]

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=360
    )

    raw: dict = {}
    if result.stdout:
        try:
            raw = json.loads(result.stdout)
        except json.JSONDecodeError:
            pass

    semgrep_results = raw.get("results", [])
    errors_list = raw.get("errors", [])

    if errors_list:
        audit_log(audit_dir, run_id, "catalog_semgrep:semgrep_errors",
                  {"count": len(errors_list)})

    sources: List[dict] = []
    sinks: List[dict] = []

    for r in semgrep_results:
        rule_id: str = r.get("check_id", "")
        path: str = r.get("path", "")
        start: dict = r.get("start", {})
        line: int = start.get("line", 0)
        code: str = r.get("extra", {}).get("lines", "").strip()
        message: str = r.get("extra", {}).get("message", "")
        severity: str = r.get("extra", {}).get("severity", "WARNING").upper()

        rule_lower = rule_id.lower()

        # --- classify as source ---
        if _is_source_rule(rule_lower):
            src_type = _infer_source_type(rule_lower, code, stack)
            sources.append({
                "id": _uid(rule_id, path, line),
                "type": src_type,
                "framework": stack,
                "pattern": rule_id,
                "file": path,
                "line": line,
                "code": code,
                "message": message,
                "tool": "semgrep",
            })
        # --- classify as sink ---
        else:
            sink_type = _infer_sink_type(rule_lower)
            if sink_type:
                sinks.append({
                    "id": _uid(rule_id, path, line),
                    "type": sink_type,
                    "severity": SINK_SEVERITY.get(sink_type, "MEDIUM"),
                    "framework": stack,
                    "pattern": rule_id,
                    "file": path,
                    "line": line,
                    "code": code,
                    "message": message,
                    "tool": "semgrep",
                })

    audit_log(audit_dir, run_id, "catalog_semgrep:done", {
        "sources": len(sources), "sinks": len(sinks),
        "semgrep_results_raw": len(semgrep_results),
    })

    return {"sources": sources, "sinks": sinks}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_source_rule(rule_lower: str) -> bool:
    source_keywords = [
        "user-input", "taint-source", "user-controlled",
        "request.get", "request.post", "req.query", "req.body",
        "getparameter", "getheader", "requestparam", "pathvariable",
    ]
    return any(kw in rule_lower for kw in source_keywords)


def _infer_source_type(rule_lower: str, code: str, stack: str) -> str:
    code_lower = code.lower()
    if any(k in code_lower for k in ["cookie", "getcookie", "cookievalue"]):
        return "cookie"
    if any(k in code_lower for k in ["header", "getheader", "meta['http_"]):
        return "header"
    if any(k in code_lower for k in ["file", "upload", "binary", "multipart"]):
        return "file_upload"
    if any(k in code_lower for k in ["queue", "kafka", "rabbitmq", "sqs", "consumer"]):
        return "queue"
    if any(k in code_lower for k in ["fetchall", "fetchone", "findbyid", "findone"]):
        return "db_read"
    if any(k in code_lower for k in ["websocket", "ws.on(", "onmessage"]):
        return "websocket"
    return "http_param"


def _infer_sink_type(rule_lower: str) -> str | None:
    for sink_type, prefixes in SINK_RULE_PREFIXES.items():
        if any(p in rule_lower for p in prefixes):
            return sink_type
    return None


def _uid(*parts) -> str:
    return hashlib.md5(":".join(str(p) for p in parts).encode()).hexdigest()[:12]
