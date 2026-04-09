"""
connect/gitnexus_connect.py
──────────────────────────────
GitNexus Connect Phase

1. Generates Cypher queries dynamically via Claude to trace custom catalog sources to sinks.
2. Runs standard Structural DB/EXEC/FILE/HTML/URL queries.
3. Runs Object Taint queries.
4. Uses classifier.py for sink types.
"""

import hashlib
import json
import subprocess
import os
from typing import List

try:
    import anthropic
except ImportError:
    anthropic = None

from shared.logger import audit_log
from connect.classifier import classify_sink

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

def connect_gitnexus(repo_path: str, catalog_output: dict, run_id: str = "local", gitnexus_cfg: dict = None, business_ctx: dict = None) -> dict:
    """Run GitNexus Cypher structural, object, and LLM-generated path discovery."""
    if gitnexus_cfg is None:
        gitnexus_cfg = {}
    if business_ctx is None:
        business_ctx = {}
        
    audit_dir = "reports/" + run_id
    os.makedirs(audit_dir, exist_ok=True)
    binary = gitnexus_cfg.get("binary", "gitnexus")
    timeout = gitnexus_cfg.get("timeout_seconds", 120)

    # Pull custom sinks from catalog
    custom_sinks = catalog_output.get("custom_sinks", [])
    custom_sink_names = [s.get("name", "") for s in custom_sinks if s.get("name")]
    
    # Extract sources and sinks for LLM
    sources = catalog_output.get("sources", [])
    sinks = catalog_output.get("sinks", [])

    audit_log(audit_dir, run_id, "connect_gitnexus:start", {
        "custom_sinks": len(custom_sink_names),
        "sources": len(sources),
        "sinks": len(sinks),
    })

    all_paths: List[dict] = []

    # 1. Structural queries
    for sink_cat, cat_cfg in STRUCTURAL_QUERIES.items():
        query = _build_structural_query(
            sink_cat=sink_cat,
            sinks=cat_cfg["sinks"],
            excludes=cat_cfg["excludes"],
            extra_sinks=custom_sink_names,
        )
        rows = _run_cypher(binary, repo_path, query, timeout)
        paths = [_normalize_path(row, "structural", business_ctx) for row in rows]
        all_paths.extend(paths)

    # 2. Object taint query
    obj_query = _enrich_obj_query_with_custom(OBJECT_TAINT_QUERY, custom_sink_names)
    rows = _run_cypher(binary, repo_path, obj_query, timeout)
    obj_paths = [_normalize_object_path(row, business_ctx) for row in rows]
    all_paths.extend(obj_paths)

    # 3. LLM generated queries for custom sink tracing
    custom_queries = _generate_custom_trace_queries(sources, custom_sinks)
    for i, query in enumerate(custom_queries):
        rows = _run_cypher(binary, repo_path, query, timeout)
        # Assuming the query returns similar structure to structural query
        paths = [_normalize_path(row, "claude-custom", business_ctx) for row in rows]
        all_paths.extend(paths)

    audit_log(audit_dir, run_id, "connect_gitnexus:done", {"total_paths": len(all_paths)})
    return {"candidate_paths": all_paths}


def _generate_custom_trace_queries(sources: list, custom_sinks: list) -> list:
    """Uses Claude to generate Cypher queries to connect custom sources and sinks."""
    if not anthropic or not sources or not custom_sinks:
        return []

    client = anthropic.Anthropic()
    
    # Just take top a few to prevent overwhelming the prompt
    source_names = list(set([s.get("code") or s.get("pattern", "") for s in sources[:50]]))
    sink_names = list(set([s.get("name", "") for s in custom_sinks[:20]]))
    
    prompt = (
        "Generate GitNexus Cypher queries to find data flow paths from the following sources to the following custom sinks.\n"
        f"Sources (samples): {', '.join(source_names)}\n"
        f"Custom Mapped Sinks: {', '.join(sink_names)}\n\n"
        "The GitNexus schema represents AST as a graph: (entry:Symbol)-[:CALLS*1..6]->(sink:Symbol)\n"
        "Return ONLY a JSON array of raw string Cypher queries to find these paths. Ensure the RETURN clause exactly provides:\n"
        "entry.name AS entry_fn, entry.filePath AS entry_file, entry.line AS entry_line, [n IN nodes(path) | n.name] AS call_chain, "
        "sink.name AS sink_fn, sink.filePath AS sink_file, sink.line AS sink_line, length(path) AS hops, 'CUSTOM_SINK' AS sink_cat\n"
    )

    try:
        response = client.messages.create(
            model="claude-3-5-haiku-latest",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        content = response.content[0].text
        start = content.find('[')
        end = content.rfind(']')
        if start != -1 and end != -1:
            return json.loads(content[start:end+1])
    except Exception as e:
        pass
    return []


def _build_structural_query(sink_cat: str, sinks: List[str], excludes: List[str], extra_sinks: List[str]) -> str:
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

def _enrich_obj_query_with_custom(query: str, custom_sink_names: List[str]) -> str:
    if not custom_sink_names:
        return query
    extra = ", ".join(f'"{s}"' for s in custom_sink_names[:20])
    return query.replace(
        "'subprocess.run', 'subprocess.Popen', 'os.system'",
        f"'subprocess.run', 'subprocess.Popen', 'os.system', {extra}",
    )

def _normalize_path(row: dict, query_type: str, business_ctx: dict) -> dict:
    source_file = row.get("entry_file", "")
    source_line = int(row.get("entry_line", 0) or 0)
    sink_file = row.get("sink_file", source_file)
    sink_line = int(row.get("sink_line", 0) or 0)
    sink_cat = row.get("sink_cat", "CUSTOM_SINK")
    call_chain = row.get("call_chain", [])

    path_id = hashlib.md5(
        f"{source_file}:{source_line}:{row.get('sink_fn', '')}:{sink_line}".encode()
    ).hexdigest()[:12]

    sink_fn = row.get("sink_fn", "")
    
    # Use classifier to determine vulnerability type robustly
    cls = classify_sink(sink_fn, is_custom=(query_type=="claude-custom"), custom_known_sinks=business_ctx.get("custom_sinks"))
    
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
            "type": cls["vuln_type"],
            "category": sink_cat,
            "name": sink_fn,
            "file": sink_file,
            "line": sink_line,
            "code": row.get("sink_fn", ""),
            "sink_type": "custom" if query_type=="claude-custom" else "known"
        },
        "vuln_type_source": cls["source"],
        "call_chain": call_chain,
        "intermediate": [{"method": n} for n in call_chain[1:-1]] if len(call_chain) > 2 else [],
        "hops": int(row.get("hops", len(call_chain))),
        "path_length": int(row.get("hops", len(call_chain))),
        "sink_cat": sink_cat,
        "score": 0.0,
        "triage_detail": {},
        "path_decision": None,
    }


def _normalize_object_path(row: dict, business_ctx: dict) -> dict:
    sink_fn = row.get("sink_fn", "")
    class_file = row.get("class_file", "")
    sink_line = int(row.get("sink_line", 0) or 0)
    caller_file = row.get("caller_file", class_file)

    path_id = hashlib.md5(
        f"obj:{class_file}:{row.get('class_name', '')}:{row.get('sink_method', '')}:{sink_fn}".encode()
    ).hexdigest()[:12]

    cls = classify_sink(sink_fn, is_custom=False, custom_known_sinks=business_ctx.get("custom_sinks"))
    
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
            "line": int(row.get("class_line", 0) or 0),
            "code": f"{row.get('class_name', '')}::{row.get('constructor_fn', '__construct')}",
        },
        "sink": {
            "type": cls["vuln_type"],
            "category": "OBJECT_SINK",
            "name": sink_fn,
            "file": row.get("sink_file", class_file),
            "line": sink_line,
            "code": f"{row.get('sink_method', '')} → {sink_fn}",
            "sink_type": "known"
        },
        "vuln_type_source": cls["source"],
        "call_chain": [row.get("called_from", ""), row.get("constructor_fn", ""),
                       row.get("class_name", ""), row.get("sink_method", ""), sink_fn],
        "intermediate": [
            {"method": row.get("class_name", ""), "file": class_file},
            {"method": row.get("sink_method", ""), "file": class_file},
        ],
        "hops": 3,
        "path_length": 3,
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
