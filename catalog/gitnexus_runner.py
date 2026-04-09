"""
phases/1_catalog/gitnexus_runner.py
─────────────────────────────────────
LangGraph node: catalog_gitnexus

Dùng GitNexus CLI với Cypher queries để:
  Step 1 — Custom wrapper sink discovery
  Step 2 — Endpoint + auth context mapping
  Step 3 — Process flow discovery (4 topic queries)
  Step 4 — Auto-generate custom Semgrep rules từ wrapper sinks

CLI interface:
  gitnexus query --cypher "<CYPHER>" --repo /path/to/repo [--format json]
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from shared.logger import audit_log


# ── Known sink names for Step 1 wrapper discovery ────────────────────────────

KNOWN_SINKS_CYPHER = [
    # OS exec
    "exec", "system", "shell_exec", "passthru", "popen", "proc_open",
    "os.system", "subprocess.run", "subprocess.Popen", "child_process.exec",
    "child_process.execSync", "child_process.spawn",
    # DB
    "mysqli_query", "PDO::exec", "DB::statement", "DB::unprepared",
    "cursor.execute", "engine.execute", "db.query", "sequelize.query", "knex.raw",
    # File
    "file_put_contents", "fwrite", "move_uploaded_file", "unlink",
    "fs.writeFile", "fs.writeFileSync", "createWriteStream",
    # Template / HTML
    "render_template_string", "Markup", "innerHTML", "dangerouslySetInnerHTML",
    # URL / SSRF
    "curl_exec", "file_get_contents", "requests.get", "urllib.request.urlopen",
    "fetch", "axios.get", "axios.post",
    # Deserialize
    "unserialize", "pickle.loads", "yaml.load", "jsonpickle.decode",
    # Eval / code injection
    "eval", "include", "require",
]

# Topics for process flow discovery
PROCESS_FLOW_TOPICS = [
    "authentication authorization login logout",
    "file upload processing storage",
    "payment checkout order transaction",
    "admin privilege role permission",
]

# Auth middleware name hints
AUTH_MIDDLEWARE_HINTS = ["auth", "middleware", "guard", "jwt", "oauth", "permission", "role", "acl"]


def catalog_gitnexus(repo_path: str, run_id: str = "local", stack: str = "auto", gitnexus_cfg: dict = None) -> dict:
    """GitNexus Cypher-based catalog."""
    if gitnexus_cfg is None:
        gitnexus_cfg = {}
        
    audit_dir = "reports/" + run_id
    import os
    os.makedirs(audit_dir, exist_ok=True)

    binary = gitnexus_cfg.get("binary", "gitnexus")
    timeout = gitnexus_cfg.get("timeout_seconds", 120)

    # Check binary availability
    if not _gitnexus_available(binary):
        audit_log(audit_dir, run_id, "catalog_gitnexus:unavailable", {})
        return {"custom_sinks": [], "endpoints": [], "process_flows": []}

    audit_log(audit_dir, run_id, "catalog_gitnexus:start", {"repo": repo_path})

    # ── Step 1: Custom wrapper sink discovery ─────────────────────────────────
    custom_sinks = _discover_custom_sinks(binary, repo_path, timeout, run_id, audit_dir)

    # ── Step 2: Endpoint + auth context mapping ───────────────────────────────
    endpoints = _discover_endpoints(binary, repo_path, timeout, run_id, audit_dir)

    # ── Step 3: Process flow discovery ───────────────────────────────────────
    process_flows = _discover_process_flows(binary, repo_path, timeout, run_id, audit_dir)

    # ── Step 4: Auto-generate custom Semgrep rules ────────────────────────────
    _write_custom_sink_rules(custom_sinks, stack, repo_path, audit_dir, run_id)

    result = {
        "custom_sinks": custom_sinks,
        "endpoints": endpoints,
        "process_flows": process_flows,
    }

    audit_log(audit_dir, run_id, "catalog_gitnexus:done", {
        "custom_sinks": len(custom_sinks),
        "endpoints": len(endpoints),
        "process_flows": len(process_flows),
    })

    return result


# ── Step 1: Custom wrapper sinks ──────────────────────────────────────────────

STEP1_QUERY = """
MATCH (wrapper:Symbol)-[:CALLS]->(known_sink:Symbol)
WHERE known_sink.name IN [{sink_list}]
AND wrapper.filePath CONTAINS 'src/'
AND NOT wrapper.name IN [{sink_list}]
RETURN DISTINCT
    wrapper.name     AS custom_sink_name,
    wrapper.filePath AS file,
    wrapper.line     AS line,
    known_sink.name  AS wraps_sink,
    COUNT(*) AS call_count
ORDER BY call_count DESC
LIMIT 50
"""


def _discover_custom_sinks(
    binary: str, repo_path: str, timeout: int, run_id: str, audit_dir: str
) -> List[dict]:
    sink_list = ", ".join(f'"{s}"' for s in KNOWN_SINKS_CYPHER)
    query = STEP1_QUERY.replace("{sink_list}", sink_list)
    rows = _run_cypher(binary, repo_path, query, timeout)

    sinks = []
    for row in rows:
        sink_id = hashlib.md5(
            f"{row.get('file', '')}:{row.get('custom_sink_name', '')}".encode()
        ).hexdigest()[:10]
        sinks.append({
            "id": sink_id,
            "name": row.get("custom_sink_name", ""),
            "wraps": row.get("wraps_sink", ""),
            "file": row.get("file", ""),
            "line": row.get("line", 0),
            "call_count": row.get("call_count", 1),
            "type": "custom_wrapper",
            "tool": "gitnexus",
        })

    return sinks


# ── Step 2: Endpoint + auth context ──────────────────────────────────────────

STEP2_QUERY = """
MATCH (handler:Symbol)
WHERE handler.filePath CONTAINS 'controller'
   OR handler.filePath CONTAINS 'route'
   OR handler.filePath CONTAINS 'handler'
   OR handler.filePath CONTAINS 'action'
OPTIONAL MATCH (middleware:Symbol)-[:CALLS]->(handler)
WHERE middleware.name CONTAINS 'auth'
   OR middleware.name CONTAINS 'middleware'
   OR middleware.name CONTAINS 'guard'
   OR middleware.name CONTAINS 'jwt'
   OR middleware.name CONTAINS 'permission'
RETURN
    handler.name           AS handler_fn,
    handler.filePath       AS file,
    handler.line           AS line,
    collect(DISTINCT middleware.name) AS auth_middleware
ORDER BY handler.filePath
LIMIT 200
"""


def _discover_endpoints(
    binary: str, repo_path: str, timeout: int, run_id: str, audit_dir: str
) -> List[dict]:
    rows = _run_cypher(binary, repo_path, STEP2_QUERY, timeout)

    endpoints = []
    for row in rows:
        middleware = [m for m in row.get("auth_middleware", []) if m]
        has_auth = len(middleware) > 0
        ep_id = hashlib.md5(
            f"{row.get('file', '')}:{row.get('handler_fn', '')}".encode()
        ).hexdigest()[:10]
        endpoints.append({
            "id": ep_id,
            "handler": row.get("handler_fn", ""),
            "file": row.get("file", ""),
            "line": row.get("line", 0),
            "auth_middleware": middleware,
            "auth_required": has_auth,
            "ownership_check": False,  # Will be enriched by analyze_authz
            "tool": "gitnexus",
        })

    return endpoints


# ── Step 3: Process flows ─────────────────────────────────────────────────────

def _discover_process_flows(
    binary: str, repo_path: str, timeout: int, run_id: str, audit_dir: str
) -> List[dict]:
    """Run semantic topic queries to discover business process flows."""
    flows = []

    for topic in PROCESS_FLOW_TOPICS:
        # Use gitnexus search/query for semantic flow discovery
        query = f"""
MATCH (fn:Symbol)-[:CALLS*1..4]->(related:Symbol)
WHERE (
    '{topic.split()[0]}' IN [w IN split(fn.name, '_') | toLower(w)]
    OR toLower(related.name) CONTAINS '{topic.split()[0]}'
)
RETURN DISTINCT
    fn.name AS process_fn,
    fn.filePath AS file,
    fn.line AS line,
    collect(DISTINCT related.name)[..8] AS related_calls
ORDER BY fn.filePath
LIMIT 30
"""
        rows = _run_cypher(binary, repo_path, query, timeout)
        if rows:
            flow_name = topic.split()[0].title() + "Flow"
            flows.append({
                "name": flow_name,
                "topic": topic,
                "functions": [
                    {
                        "name": r.get("process_fn", ""),
                        "file": r.get("file", ""),
                        "line": r.get("line", 0),
                        "calls": r.get("related_calls", []),
                    }
                    for r in rows
                ],
            })

    return flows


# ── Step 4: Custom Semgrep rules from discovered sinks ────────────────────────

TAINT_SOURCES_BY_STACK = {
    "php": [
        {"pattern": "$_GET"},
        {"pattern": "$_POST"},
        {"pattern": "$_FILES"},
        {"pattern": "$_COOKIE"},
        {"pattern": "$_REQUEST"},
        {"pattern": "$_SERVER['HTTP_']"},
    ],
    "python": [
        {"pattern": "request.args.get(...)"},
        {"pattern": "request.form.get(...)"},
        {"pattern": "request.json"},
        {"pattern": "request.data"},
        {"pattern": "request.files"},
    ],
    "node": [
        {"pattern": "req.body"},
        {"pattern": "req.query"},
        {"pattern": "req.params"},
        {"pattern": "req.headers"},
    ],
    "java": [
        {"pattern": "request.getParameter(...)"},
        {"pattern": "request.getHeader(...)"},
        {"pattern": "@RequestParam ..."},
        {"pattern": "@RequestBody ..."},
    ],
}


def _write_custom_sink_rules(
    custom_sinks: List[dict],
    stack: str,
    repo_path: str,
    audit_dir: str,
    run_id: str,
) -> None:
    """Write auto-generated Semgrep taint rules to rules/custom_sinks.yaml."""
    if not custom_sinks:
        return

    # Normalize stack key
    stack_key = stack.split("_")[-1] if "_" in stack else stack
    if stack_key not in TAINT_SOURCES_BY_STACK:
        stack_key = "php"  # safe default

    sources = TAINT_SOURCES_BY_STACK[stack_key]
    rules = []

    for sink in custom_sinks:
        sink_name = sink.get("name", "")
        if not sink_name or len(sink_name) < 3:
            continue
        wraps = sink.get("wraps", "")

        rule = {
            "id": f"custom-wrapper-sink-{sink_name.lower().replace('_', '-')}",
            "message": f"Custom wrapper sink '{sink_name}' wraps dangerous function '{wraps}'. User-controlled data reaches this sink.",
            "severity": "ERROR",
            "languages": [_map_stack_to_lang(stack)],
            "mode": "taint",
            "pattern-sources": sources,
            "pattern-sinks": [{"pattern": f"{sink_name}(...)"}],
            "metadata": {
                "category": "security",
                "source": "gitnexus-auto-generated",
                "wraps_sink": wraps,
            },
        }
        rules.append(rule)

    if not rules:
        return

    rules_dir = Path(repo_path).parent / "pentest_rules"
    rules_dir.mkdir(exist_ok=True)
    rules_file = rules_dir / "custom_sinks.yaml"
    rules_file.write_text(
        yaml.dump({"rules": rules}, default_flow_style=False, allow_unicode=True),
        encoding="utf-8",
    )

    audit_log(audit_dir, run_id, "catalog_gitnexus:custom_rules_written", {
        "file": str(rules_file), "count": len(rules)
    })


def _map_stack_to_lang(stack: str) -> str:
    mapping = {
        "php": "php", "laravel": "php", "symfony": "php",
        "python": "python", "django": "python", "flask": "python", "fastapi": "python",
        "node": "javascript", "express": "javascript", "nestjs": "typescript",
        "java": "java", "spring": "java",
        "go": "go", "gin": "go",
        "ruby": "ruby", "rails": "ruby",
    }
    return mapping.get(stack.lower(), "python")


# ── GitNexus CLI runner ───────────────────────────────────────────────────────

def _run_cypher(binary: str, repo_path: str, query: str, timeout: int) -> List[dict]:
    """Execute a Cypher query via GitNexus CLI and return result rows."""
    try:
        result = subprocess.run(
            [binary, "query", "--cypher", query, "--repo", repo_path, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return []

        raw = result.stdout.strip()
        if not raw:
            return []

        # GitNexus may return NDJSON (one object per line) or a JSON array
        parsed = _parse_json_output(raw)
        return parsed if isinstance(parsed, list) else []

    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []


def _parse_json_output(raw: str) -> list:
    """Parse JSON array or NDJSON output from GitNexus."""
    # Try plain JSON array first
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    # Try NDJSON
    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _gitnexus_available(binary: str) -> bool:
    try:
        result = subprocess.run(
            [binary, "--version"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError):
        return False
