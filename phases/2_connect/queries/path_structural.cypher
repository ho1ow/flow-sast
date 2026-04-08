// GitNexus Cypher — Structural Path Queries
// Finds source-to-sink data flow paths for 3 sink categories:
// DB_SINK, EXEC_SINK, FILE_SINK
//
// Sử dụng: gitnexus query --cypher "<query>" --repo /path/to/repo --format json
//
// Output mỗi row:
//   { entry_fn, entry_file, call_chain[], sink_fn, sink_cat, hops }

// ─── DB_SINK ─────────────────────────────────────────────────────────────────
// Mục đích: Tìm đường từ controller/route → SQL execution functions
// Loại trừ: Các hàm parameterized query (bindParam, prepare, v.v.)

MATCH path = (entry:Symbol)-[:CALLS*1..6]->(sink:Symbol)
WHERE sink.name IN [
    'mysqli_query', 'PDO::exec', 'executeQuery', 'DB::statement',
    'DB::unprepared', 'cursor.execute', 'engine.execute', 'db.query',
    'sequelize.query', 'knex.raw', 'db.raw'
]
AND (
    entry.filePath CONTAINS 'controller'
    OR entry.filePath CONTAINS 'route'
    OR entry.filePath CONTAINS 'handler'
    OR entry.filePath CONTAINS 'action'
    OR entry.filePath CONTAINS 'api'
)
AND NONE(node IN nodes(path) WHERE node.name IN [
    'bindParam', 'bindValue', 'prepare', 'prepared', 'escape',
    'mysqli_real_escape_string', 'pg_escape_string', 'quote',
    'sanitize_sql', 'sanitize_sql_array'
])
RETURN
    entry.name           AS entry_fn,
    entry.filePath       AS entry_file,
    entry.line           AS entry_line,
    [n IN nodes(path) | n.name] AS call_chain,
    sink.name            AS sink_fn,
    sink.filePath        AS sink_file,
    sink.line            AS sink_line,
    length(path)         AS hops,
    'DB_SINK'            AS sink_cat
ORDER BY hops ASC
LIMIT 100

// ─── EXEC_SINK ───────────────────────────────────────────────────────────────
// Mục đích: Tìm đường từ controller → shell execution functions
// Loại trừ: Các hàm escape shell args

MATCH path = (entry:Symbol)-[:CALLS*1..5]->(sink:Symbol)
WHERE sink.name IN [
    'exec', 'system', 'shell_exec', 'passthru', 'popen', 'proc_open',
    'os.system', 'subprocess.run', 'subprocess.Popen',
    'child_process.exec', 'child_process.execSync', 'child_process.spawn',
    'eval'
]
AND (
    entry.filePath CONTAINS 'controller'
    OR entry.filePath CONTAINS 'route'
    OR entry.filePath CONTAINS 'handler'
)
AND NONE(node IN nodes(path) WHERE node.name IN [
    'escapeshellarg', 'escapeshellcmd', 'shlex.quote', 'shlex.split',
    'sanitize', 'validate', 'filter'
])
RETURN
    entry.name           AS entry_fn,
    entry.filePath       AS entry_file,
    entry.line           AS entry_line,
    [n IN nodes(path) | n.name] AS call_chain,
    sink.name            AS sink_fn,
    sink.filePath        AS sink_file,
    sink.line            AS sink_line,
    length(path)         AS hops,
    'EXEC_SINK'          AS sink_cat
ORDER BY hops ASC
LIMIT 100

// ─── FILE_SINK ───────────────────────────────────────────────────────────────
// Mục đích: Tìm đường từ controller → file write functions
// Loại trừ: basename/realpath/pathinfo (path sanitizers)

MATCH path = (entry:Symbol)-[:CALLS*1..5]->(sink:Symbol)
WHERE sink.name IN [
    'file_put_contents', 'fwrite', 'move_uploaded_file', 'unlink', 'rename',
    'fs.writeFile', 'fs.writeFileSync', 'createWriteStream',
    'open', 'write', 'shutil.copy', 'shutil.move'
]
AND (
    entry.filePath CONTAINS 'controller'
    OR entry.filePath CONTAINS 'route'
    OR entry.filePath CONTAINS 'handler'
    OR entry.filePath CONTAINS 'upload'
)
AND NONE(node IN nodes(path) WHERE node.name IN [
    'basename', 'realpath', 'pathinfo', 'os.path.abspath',
    'os.path.normpath', 'path.resolve', 'path.normalize',
    'sanitize', 'validate'
])
RETURN
    entry.name           AS entry_fn,
    entry.filePath       AS entry_file,
    entry.line           AS entry_line,
    [n IN nodes(path) | n.name] AS call_chain,
    sink.name            AS sink_fn,
    sink.filePath        AS sink_file,
    sink.line            AS sink_line,
    length(path)         AS hops,
    'FILE_SINK'          AS sink_cat
ORDER BY hops ASC
LIMIT 100

// ─── HTML_SINK ───────────────────────────────────────────────────────────────
MATCH path = (entry:Symbol)-[:CALLS*1..5]->(sink:Symbol)
WHERE sink.name IN [
    'echo', 'print', 'render_template_string', 'Markup', 'innerHTML',
    'dangerouslySetInnerHTML', 'document.write', 'res.send'
]
AND (
    entry.filePath CONTAINS 'controller'
    OR entry.filePath CONTAINS 'route'
    OR entry.filePath CONTAINS 'view'
)
AND NONE(node IN nodes(path) WHERE node.name IN [
    'htmlspecialchars', 'htmlentities', 'strip_tags', 'DOMPurify',
    'escape', 'h(', 'bleach.clean', 'markupsafe.escape'
])
RETURN
    entry.name           AS entry_fn,
    entry.filePath       AS entry_file,
    entry.line           AS entry_line,
    [n IN nodes(path) | n.name] AS call_chain,
    sink.name            AS sink_fn,
    sink.filePath        AS sink_file,
    sink.line            AS sink_line,
    length(path)         AS hops,
    'HTML_SINK'          AS sink_cat
ORDER BY hops ASC
LIMIT 100

// ─── URL_SINK ────────────────────────────────────────────────────────────────
MATCH path = (entry:Symbol)-[:CALLS*1..5]->(sink:Symbol)
WHERE sink.name IN [
    'curl_exec', 'file_get_contents', 'requests.get', 'requests.post',
    'urllib.request.urlopen', 'fetch', 'axios.get', 'axios.post',
    'redirect', 'header'
]
AND (
    entry.filePath CONTAINS 'controller'
    OR entry.filePath CONTAINS 'route'
    OR entry.filePath CONTAINS 'handler'
)
RETURN
    entry.name           AS entry_fn,
    entry.filePath       AS entry_file,
    entry.line           AS entry_line,
    [n IN nodes(path) | n.name] AS call_chain,
    sink.name            AS sink_fn,
    sink.filePath        AS sink_file,
    sink.line            AS sink_line,
    length(path)         AS hops,
    'URL_SINK'           AS sink_cat
ORDER BY hops ASC
LIMIT 100
