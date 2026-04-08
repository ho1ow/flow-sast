// GitNexus Cypher — Object Taint Query
// Tìm taint qua constructor → property → sink (không có direct call edge)
//
// Pattern: controller gọi constructor với tainted param →
//          constructor lưu vào $this->prop →
//          method của cùng class gọi sink với prop đó
//
// Sử dụng: gitnexus query --cypher "<query>" --repo /path/to/repo --format json

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
