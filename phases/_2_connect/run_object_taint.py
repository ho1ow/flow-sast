"""
phases/2_connect/run_object_taint.py
──────────────────────────────────────
LangGraph node: path_object

Chạy GitNexus Cypher object taint query để tìm:
  constructor(tainted_param) → $this->prop → method() → sink()

CLI: gitnexus query --cypher "..." --repo /path/to/repo --format json
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import List

from core.reliability import audit_log, checkpoint_load, checkpoint_save, safe_node
from core.state import PentestState


OBJECT_TAINT_QUERY = """
MATCH (controller:Symbol)-[:CALLS]->(constructor:Symbol)
WHERE constructor.name IN ['__construct', '__init', 'constructor', 'create', 'make']
AND (
    controller.filePath CONTAINS 'controller'
    OR controller.filePath CONTAINS 'handler'
    OR controller.filePath CONTAINS 'route'
    OR controller.filePath CONTAINS 'action'
)
MATCH (class:Symbol)-[:DEFINES]->(constructor)
MATCH (class)-[:DEFINES]->(method:Symbol)-[:CALLS]->(sink:Symbol)
WHERE sink.name IN [
    'move_uploaded_file', 'file_put_contents', 'fwrite', 'unlink',
    'exec', 'system', 'shell_exec', 'passthru', 'popen',
    'mysqli_query', 'PDO::exec', 'executeQuery', 'DB::statement',
    'eval', 'include', 'require', 'include_once', 'require_once',
    'curl_exec', 'file_get_contents', 'requests.get',
    'render_template_string', 'Markup', 'innerHTML',
    'cursor.execute', 'engine.execute', 'db.raw', 'knex.raw',
    'subprocess.run', 'subprocess.Popen', 'os.system'
]
AND method.name <> '__construct'
AND method.name <> '__init'
AND method.name <> 'constructor'
RETURN
    class.name          AS class_name,
    class.filePath      AS class_file,
    class.line          AS class_line,
    constructor.name    AS constructor_fn,
    method.name         AS sink_method,
    sink.name           AS sink_fn,
    sink.filePath       AS sink_file,
    sink.line           AS sink_line,
    controller.name     AS called_from,
    controller.filePath AS caller_file
ORDER BY class.filePath
LIMIT 50
"""

SINK_TYPE_MAP = {
    "move_uploaded_file": ("FILE_SINK", "path_traversal"),
    "file_put_contents":  ("FILE_SINK", "path_traversal"),
    "fwrite":             ("FILE_SINK", "path_traversal"),
    "exec":               ("EXEC_SINK", "rce"),
    "system":             ("EXEC_SINK", "rce"),
    "shell_exec":         ("EXEC_SINK", "rce"),
    "passthru":           ("EXEC_SINK", "rce"),
    "mysqli_query":       ("DB_SINK",   "sqli"),
    "PDO::exec":          ("DB_SINK",   "sqli"),
    "executeQuery":       ("DB_SINK",   "sqli"),
    "DB::statement":      ("DB_SINK",   "sqli"),
    "eval":               ("EXEC_SINK", "rce"),
    "curl_exec":          ("URL_SINK",  "ssrf"),
    "requests.get":       ("URL_SINK",  "ssrf"),
    "render_template_string": ("HTML_SINK", "ssti"),
    "Markup":             ("HTML_SINK", "xss"),
    "innerHTML":          ("HTML_SINK", "xss"),
    "cursor.execute":     ("DB_SINK",   "sqli"),
    "subprocess.run":     ("EXEC_SINK", "rce"),
    "subprocess.Popen":   ("EXEC_SINK", "rce"),
    "os.system":          ("EXEC_SINK", "rce"),
}


@safe_node("path_object")
def path_object(state: PentestState) -> dict:
    """LangGraph node — GitNexus Cypher object taint discovery."""
    cfg = state["config"]
    gitnexus_cfg = cfg.get("gitnexus", {})
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")
    repo_path = state["repo_path"]
    checkpoint_dir = state["checkpoint_dir"]

    cached = checkpoint_load(checkpoint_dir, run_id, "path_object")
    if cached:
        return cached

    binary = gitnexus_cfg.get("binary", "gitnexus")
    timeout = gitnexus_cfg.get("timeout_seconds", 120)

    # Add custom sinks to the query
    custom_sinks = state.get("custom_sinks", [])
    custom_sink_names = [s.get("name", "") for s in custom_sinks if s.get("name")]

    query = _enrich_query_with_custom(OBJECT_TAINT_QUERY, custom_sink_names)

    audit_log(audit_dir, run_id, "path_object:start", {
        "custom_sinks_added": len(custom_sink_names)
    })

    rows = _run_cypher(binary, repo_path, query, timeout)
    paths = [_normalize_object_path(row) for row in rows]

    result = {"object_paths": paths}
    checkpoint_save(checkpoint_dir, run_id, "path_object", result)

    audit_log(audit_dir, run_id, "path_object:done", {"total": len(paths)})
    return result


def _enrich_query_with_custom(query: str, custom_sink_names: List[str]) -> str:
    """Insert custom sink names into the WHERE clause."""
    if not custom_sink_names:
        return query
    extra = ", ".join(f'"{s}"' for s in custom_sink_names[:20])
    # Append to the existing sink.name IN [...] list
    return query.replace(
        "'subprocess.run', 'subprocess.Popen', 'os.system'",
        f"'subprocess.run', 'subprocess.Popen', 'os.system', {extra}",
    )


def _normalize_object_path(row: dict) -> dict:
    sink_fn = row.get("sink_fn", "")
    sink_cat, sink_type = SINK_TYPE_MAP.get(sink_fn, ("CUSTOM", "custom"))
    class_file = row.get("class_file", "")
    sink_line = int(row.get("sink_line", 0))
    caller_file = row.get("caller_file", class_file)

    path_id = hashlib.md5(
        f"obj:{class_file}:{row.get('class_name', '')}:{row.get('sink_method', '')}:{sink_fn}".encode()
    ).hexdigest()[:12]

    return {
        "id": path_id,
        "query_type": "object",
        "class_name": row.get("class_name", ""),
        "class_file": class_file,
        "constructor_fn": row.get("constructor_fn", "__construct"),
        "sink_method": row.get("sink_method", ""),
        "called_from": row.get("called_from", ""),
        "entry_file": caller_file,
        "source": {
            "type": "http_param",
            "file": caller_file,
            "line": int(row.get("class_line", 0)),
            "code": f"{row.get('class_name', '')}::{row.get('constructor_fn', '__construct')}",
        },
        "sink": {
            "type": sink_type,
            "category": sink_cat,
            "name": sink_fn,
            "file": row.get("sink_file", class_file),
            "line": sink_line,
            "code": f"{row.get('sink_method', '')} → {sink_fn}",
        },
        "call_chain": [row.get("called_from", ""), row.get("constructor_fn", ""),
                       row.get("class_name", ""), row.get("sink_method", ""), sink_fn],
        "intermediate": [
            {"method": row.get("class_name", ""), "file": class_file},
            {"method": row.get("sink_method", ""), "file": class_file},
        ],
        "hops": 3,
        "path_length": 3,
        "sink_cat": sink_cat,
        "score": 0.0,
        "triage_detail": {},
        "path_decision": None,
    }


def _run_cypher(binary: str, repo_path: str, query: str, timeout: int) -> List[dict]:
    try:
        result = subprocess.run(
            [binary, "query", "--cypher", query, "--repo", repo_path, "--format", "json"],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            return []
        raw = result.stdout.strip()
        if not raw:
            return []
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []
