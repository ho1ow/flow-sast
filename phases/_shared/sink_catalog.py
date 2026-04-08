"""
phases/_shared/sink_catalog.py
────────────────────────────────
Single source of truth cho tất cả KNOWN_SINKS và SANITIZERS.
Import ở đây để tránh hardcode và desync giữa:
  - phases/1_catalog/gitnexus_runner.py   (Cypher queries)
  - phases/1_catalog/semgrep_runner.py    (taint sink patterns)
  - phases/2_connect/run_structural.py    (path query sink lists)
  - phases/2_connect/run_object_taint.py  (object taint sink lists)
  - phases/2_connect/gitnexus_fp_filter.py (FP filter)
"""

from __future__ import annotations

from typing import Dict, List, Set


# ── Sink categories ───────────────────────────────────────────────────────────

DB_SINKS: List[str] = [
    # PHP
    "mysqli_query", "mysqli_real_query", "mysql_query",
    "pg_query", "pg_execute", "pg_send_query",
    "PDO::exec", "PDO::query", "PDOStatement::execute",
    # Laravel / ORM
    "DB::statement", "DB::unprepared", "DB::select", "DB::insert", "DB::update",
    "whereRaw", "orderByRaw", "groupByRaw", "havingRaw", "selectRaw",
    # Python
    "cursor.execute", "cursor.executemany",
    "engine.execute", "engine.text",
    "session.execute",
    # Django
    "RawSQL", "extra", "raw",
    # Node / JS
    "db.query", "pool.query", "connection.query",
    "sequelize.query", "knex.raw",
    # Java
    "createNativeQuery", "createQuery", "executeQuery", "executeUpdate",
    "prepareStatement",
]

EXEC_SINKS: List[str] = [
    # PHP
    "exec", "system", "shell_exec", "passthru", "popen", "proc_open",
    "pcntl_exec",
    "eval", "assert", "preg_replace",  # /e modifier
    "include", "require", "include_once", "require_once",
    # Python
    "os.system", "os.popen", "os.execv", "os.execve", "os.spawnl",
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_output", "subprocess.check_call",
    "commands.getoutput", "commands.getstatusoutput",
    "eval", "exec", "compile",
    # Node / JS
    "child_process.exec", "child_process.execSync",
    "child_process.spawn", "child_process.spawnSync",
    "child_process.execFile", "child_process.execFileSync",
    "eval",
    # Go
    "exec.Command", "os/exec.Command",
    # Ruby
    "system", "exec", "spawn", "IO.popen", "Open3.popen3", "backtick",
]

FILE_SINKS: List[str] = [
    # PHP
    "file_put_contents", "fwrite", "fputs", "fputcsv",
    "move_uploaded_file", "copy", "rename", "unlink",
    "file_get_contents", "readfile", "fread",
    "include", "require",   # also exec sink
    # Python
    "open", "write", "writelines",
    "shutil.copy", "shutil.copy2", "shutil.move", "shutil.copyfile",
    "os.rename", "os.remove", "os.unlink",
    "pathlib.Path.write_text", "pathlib.Path.write_bytes",
    # Node / JS
    "fs.writeFile", "fs.writeFileSync", "fs.appendFile", "fs.appendFileSync",
    "fs.rename", "fs.unlink", "fs.unlinkSync",
    "createWriteStream",
    # Java
    "FileWriter", "FileOutputStream", "Files.write", "Files.copy",
]

HTML_SINKS: List[str] = [
    # PHP
    "echo", "print", "printf", "vprintf", "print_r", "var_dump",
    "Markup",
    # Python / Jinja2
    "render_template_string", "Markup", "mark_safe",
    # Templates (as call patterns)
    "raw", "safe",
    # JS DOM
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "insertAdjacentHTML",
    "dangerouslySetInnerHTML",
    # Node
    "res.send", "res.write", "res.json",
]

URL_SINKS: List[str] = [
    # PHP
    "curl_exec", "curl_setopt", "file_get_contents", "fopen",
    "header",  # redirect + CRLF
    "fsockopen",
    # Python
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.request", "requests.Session.get",
    "urllib.request.urlopen", "urllib.request.urlretrieve",
    "httpx.get", "httpx.post",
    "aiohttp.ClientSession.get",
    # Node
    "fetch", "axios.get", "axios.post", "axios.request",
    "http.get", "https.get", "request.get",
    # Go
    "http.Get", "http.Post", "http.Do",
]

DESERIALIZE_SINKS: List[str] = [
    # PHP
    "unserialize",
    # Python
    "pickle.loads", "pickle.load",
    "yaml.load",   # NOT yaml.safe_load
    "marshal.loads",
    "jsonpickle.decode",
    "dill.loads",
    # Java
    "ObjectInputStream.readObject",
    "XMLDecoder.readObject",
    "XStream.fromXML",
    # Node
    "node-serialize",
    "serialize-javascript",
]

XML_SINKS: List[str] = [
    # PHP
    "simplexml_load_string", "simplexml_load_file",
    "DOMDocument.loadXML", "DOMDocument.load",
    "XMLReader.open", "XMLReader.xml",
    # Python
    "etree.fromstring", "etree.parse",
    "lxml.etree.fromstring",
    "xml.etree.ElementTree.fromstring",
    "xml.etree.ElementTree.parse",
    # Java
    "SAXParser.parse", "DocumentBuilder.parse",
]

LOG_SINKS: List[str] = [
    "logger.info", "logger.debug", "logger.warning", "logger.error",
    "logging.info", "logging.debug", "logging.warning", "logging.error",
    "console.log", "console.error", "console.warn",
    "print",   # Python stdout → often log context
    "Log.d", "Log.e", "Log.i",  # Android
]

TEMPLATE_SINKS: List[str] = [
    "render_template_string",   # Flask Jinja2 — SSTI
    "Markup",
    "env.from_string",
    "Template.render",
    "Environment.from_string",
    "Twig.createTemplate",   # PHP Twig
]

# ── Combined dict by category ─────────────────────────────────────────────────

SINKS_BY_CATEGORY: Dict[str, List[str]] = {
    "DB_SINK":          DB_SINKS,
    "EXEC_SINK":        EXEC_SINKS,
    "FILE_SINK":        FILE_SINKS,
    "HTML_SINK":        HTML_SINKS,
    "URL_SINK":         URL_SINKS,
    "DESERIALIZE_SINK": DESERIALIZE_SINKS,
    "XML_SINK":         XML_SINKS,
    "LOG_SINK":         LOG_SINKS,
    "TEMPLATE_SINK":    TEMPLATE_SINKS,
}

# Flat set for quick membership check
ALL_SINKS: Set[str] = {s for sinks in SINKS_BY_CATEGORY.values() for s in sinks}


# ── Sanitizers per sink category ──────────────────────────────────────────────
# Functions that make a sink safe — used by triage, joern_filter, FP detection

SANITIZERS_BY_CATEGORY: Dict[str, List[str]] = {
    "DB_SINK": [
        "prepare", "bindParam", "bindValue", "bindColumn",
        "escape", "real_escape_string", "mysqli_real_escape_string",
        "pg_escape_string", "pg_escape_literal", "pg_escape_identifier",
        "quote", "sanitize_sql", "sanitize_sql_array", "sanitize_sql_like",
    ],
    "EXEC_SINK": [
        "escapeshellarg", "escapeshellcmd",
        "shlex.quote", "shlex.split",   # only safe if split+list form
    ],
    "FILE_SINK": [
        "basename", "realpath", "pathinfo",
        "os.path.abspath", "os.path.normpath", "os.path.basename",
        "path.resolve", "path.normalize", "path.basename",
    ],
    "HTML_SINK": [
        "htmlspecialchars", "htmlentities", "strip_tags",
        "DOMPurify.sanitize", "bleach.clean", "markupsafe.escape",
        "h(", "escape(", "encode(",
    ],
    "URL_SINK": [
        "filter_var", "filter_input",  # with FILTER_VALIDATE_URL
        "parse_url",   # partial — must check host against allowlist
    ],
    "DESERIALIZE_SINK": [
        "yaml.safe_load", "yaml.safe_dump",
        "json.loads", "json.load",
    ],
    "XML_SINK": [
        "XMLParser(resolve_entities=False)",
        "libxml_disable_entity_loader",
        "FEATURE_EXTERNAL_GENERAL_ENTITIES",
    ],
    "TEMPLATE_SINK": [
        "escape(",
        "autoescape=True",
    ],
}

# ── Sink severity weights (for triage scoring) ────────────────────────────────

SINK_SEVERITY_SCORE: Dict[str, int] = {
    "EXEC_SINK":        5,
    "DESERIALIZE_SINK": 4,
    "DB_SINK":          4,
    "FILE_SINK":        4,
    "TEMPLATE_SINK":    3,
    "HTML_SINK":        3,
    "URL_SINK":         3,
    "XML_SINK":         3,
    "LOG_SINK":         1,
    "CUSTOM":           2,
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_category(sink_name: str) -> str:
    """Return sink category for a given function name."""
    for cat, sinks in SINKS_BY_CATEGORY.items():
        if sink_name in sinks:
            return cat
    return "CUSTOM"


def get_severity_score(sink_name: str) -> int:
    """Return numeric severity score for triage."""
    return SINK_SEVERITY_SCORE.get(get_category(sink_name), 2)


def is_sanitizer(fn_name: str, sink_cat: str) -> bool:
    """Check if a function name is a known sanitizer for the given sink category."""
    sanitizers = SANITIZERS_BY_CATEGORY.get(sink_cat, [])
    return any(fn_name.lower().startswith(s.lower()) for s in sanitizers)


def cypher_sink_list(category: str) -> str:
    """Return a Cypher-compatible quoted comma-separated sink list."""
    sinks = SINKS_BY_CATEGORY.get(category, [])
    return ", ".join(f'"{s}"' for s in sinks)


def cypher_all_sinks() -> str:
    """Return ALL sinks as Cypher list (for object taint query)."""
    return ", ".join(f'"{s}"' for s in sorted(ALL_SINKS))
