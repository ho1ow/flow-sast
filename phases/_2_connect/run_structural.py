"""
phases/2_connect/run_structural.py
────────────────────────────────────
LangGraph node: path_structural

Chạy 5 GitNexus Cypher queries (DB/EXEC/FILE/HTML/URL sink categories)
và cũng include custom_sinks từ catalog trong query.

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


# ── GitNexus Cypher queries per sink category ─────────────────────────────────
# Mỗi query là template — {sink_list} và {exclude_list} được fill tại runtime

STRUCTURAL_QUERIES = {
    "DB_SINK": {
        "sinks": [
            "mysqli_query", "PDO::exec", "executeQuery", "DB::statement",
            "DB::unprepared", "cursor.execute", "engine.execute", "db.query",
            "sequelize.query", "knex.raw", "db.raw",
        ],
        "excludes": [
            "bindParam", "bindValue", "prepare", "prepared", "escape",
            "mysqli_real_escape_string", "pg_escape_string", "quote",
            "sanitize_sql", "sanitize_sql_array",
        ],
    },
    "EXEC_SINK": {
        "sinks": [
            "exec", "system", "shell_exec", "passthru", "popen", "proc_open",
            "os.system", "subprocess.run", "subprocess.Popen",
            "child_process.exec", "child_process.execSync", "child_process.spawn",
            "eval",
        ],
        "excludes": [
            "escapeshellarg", "escapeshellcmd", "shlex.quote", "shlex.split",
            "sanitize", "validate", "filter",
        ],
    },
    "FILE_SINK": {
        "sinks": [
            "file_put_contents", "fwrite", "move_uploaded_file", "unlink", "rename",
            "fs.writeFile", "fs.writeFileSync", "createWriteStream",
            "open", "write", "shutil.copy", "shutil.move",
        ],
        "excludes": [
            "basename", "realpath", "pathinfo", "os.path.abspath",
            "os.path.normpath", "path.resolve", "path.normalize",
            "sanitize", "validate",
        ],
    },
    "HTML_SINK": {
        "sinks": [
            "echo", "print", "render_template_string", "Markup", "innerHTML",
            "dangerouslySetInnerHTML", "document.write", "res.send",
        ],
        "excludes": [
            "htmlspecialchars", "htmlentities", "strip_tags", "DOMPurify",
            "escape", "bleach.clean", "markupsafe.escape",
        ],
    },
    "URL_SINK": {
        "sinks": [
            "curl_exec", "file_get_contents", "requests.get", "requests.post",
            "urllib.request.urlopen", "fetch", "axios.get", "axios.post",
            "redirect", "header",
        ],
        "excludes": [],
    },
    "DESERIALIZE_SINK": {
        "sinks": [
            "unserialize", "pickle.loads", "yaml.load", "jsonpickle.decode",
        ],
        "excludes": ["yaml.safe_load", "yaml.safe_dump"],
    },
}


def _build_query(sink_cat: str, sinks: List[str], excludes: List[str], extra_sinks: List[str]) -> str:
    all_sinks = list(set(sinks + extra_sinks))
    sink_list = ", ".join(f'"{s}"' for s in all_sinks)
    exclude_clause = ""
    if excludes:
        ex_list = ", ".join(f'"{e}"' for e in excludes)
        exclude_clause = f"AND NONE(node IN nodes(path) WHERE node.name IN [{ex_list}])"

    return f"""
MATCH path = (entry:Symbol)-[:CALLS*1..6]->(sink:Symbol)
WHERE sink.name IN [{sink_list}]
AND (
    entry.filePath CONTAINS 'controller'
    OR entry.filePath CONTAINS 'route'
    OR entry.filePath CONTAINS 'handler'
    OR entry.filePath CONTAINS 'action'
    OR entry.filePath CONTAINS 'api'
)
{exclude_clause}
RETURN
    entry.name           AS entry_fn,
    entry.filePath       AS entry_file,
    entry.line           AS entry_line,
    [n IN nodes(path) | n.name]  AS call_chain,
    sink.name            AS sink_fn,
    sink.filePath        AS sink_file,
    sink.line            AS sink_line,
    length(path)         AS hops,
    '{sink_cat}'         AS sink_cat
ORDER BY hops ASC
LIMIT 100
"""


@safe_node("path_structural")
def path_structural(state: PentestState) -> dict:
    """LangGraph node — GitNexus Cypher structural path discovery."""
    cfg = state["config"]
    gitnexus_cfg = cfg.get("gitnexus", {})
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")
    repo_path = state["repo_path"]
    checkpoint_dir = state["checkpoint_dir"]

    cached = checkpoint_load(checkpoint_dir, run_id, "path_structural")
    if cached:
        return cached

    binary = gitnexus_cfg.get("binary", "gitnexus")
    timeout = gitnexus_cfg.get("timeout_seconds", 120)

    # Pull custom sinks from catalog to add to queries
    custom_sinks = state.get("custom_sinks", [])
    custom_sink_names = [s.get("name", "") for s in custom_sinks if s.get("name")]

    audit_log(audit_dir, run_id, "path_structural:start", {
        "categories": list(STRUCTURAL_QUERIES.keys()),
        "custom_sinks": len(custom_sink_names),
    })

    all_paths: List[dict] = []

    for sink_cat, cat_cfg in STRUCTURAL_QUERIES.items():
        query = _build_query(
            sink_cat=sink_cat,
            sinks=cat_cfg["sinks"],
            excludes=cat_cfg["excludes"],
            extra_sinks=custom_sink_names,
        )

        rows = _run_cypher(binary, repo_path, query, timeout)
        paths = [_normalize_path(row, "structural") for row in rows]
        all_paths.extend(paths)

        audit_log(audit_dir, run_id, f"path_structural:{sink_cat}", {"count": len(paths)})

    result = {"structural_paths": all_paths}
    checkpoint_save(checkpoint_dir, run_id, "path_structural", result)

    audit_log(audit_dir, run_id, "path_structural:done", {"total": len(all_paths)})
    return result


def _normalize_path(row: dict, query_type: str) -> dict:
    """Normalize GitNexus row into a standard path dict."""
    source_file = row.get("entry_file", "")
    source_line = int(row.get("entry_line", 0))
    sink_file = row.get("sink_file", source_file)
    sink_line = int(row.get("sink_line", 0))
    sink_cat = row.get("sink_cat", "CUSTOM")
    call_chain = row.get("call_chain", [])

    # Generate stable ID
    path_id = hashlib.md5(
        f"{source_file}:{source_line}:{row.get('sink_fn', '')}:{sink_line}".encode()
    ).hexdigest()[:12]

    return {
        "id": path_id,
        "query_type": query_type,
        "entry_fn": row.get("entry_fn", ""),
        "entry_file": source_file,
        "source": {
            "type": "http_param",
            "file": source_file,
            "line": source_line,
            "code": row.get("entry_fn", ""),
        },
        "sink": {
            "type": _sink_cat_to_type(sink_cat),
            "category": sink_cat,
            "name": row.get("sink_fn", ""),
            "file": sink_file,
            "line": sink_line,
            "code": row.get("sink_fn", ""),
        },
        "call_chain": call_chain,
        "intermediate": [{"method": n} for n in call_chain[1:-1]],
        "hops": int(row.get("hops", len(call_chain))),
        "path_length": int(row.get("hops", len(call_chain))),
        "sink_cat": sink_cat,
        "score": 0.0,
        "triage_detail": {},
        "path_decision": None,  # filled by joern_pre_filter
    }


def _sink_cat_to_type(cat: str) -> str:
    mapping = {
        "DB_SINK": "sqli",
        "EXEC_SINK": "rce",
        "FILE_SINK": "path_traversal",
        "HTML_SINK": "xss",
        "URL_SINK": "ssrf",
        "DESERIALIZE_SINK": "deser",
    }
    return mapping.get(cat, "custom")


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
