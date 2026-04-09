"""
connect/classifier.py
───────────────────────
Gán vuln_type cho các finding.

1. Known sinks → lookup table (deterministic, không cần LLM)
2. Custom sinks (gitnexus-discovered) → Claude classify
"""

import json
from typing import Dict

try:
    import anthropic
except ImportError:
    anthropic = None

# ── Lookup table for known sinks ──────────────────────────────────────────────

KNOWN_SINK_MAPPING: Dict[str, str] = {
    # SQLi
    "DB::statement": "sqli", "DB::select": "sqli", "mysqli_query": "sqli",
    "PDO::query": "sqli", "cursor.execute": "sqli", "engine.execute": "sqli",
    "db.query": "sqli", "sequelize.query": "sqli", "knex.raw": "sqli",
    "db.raw": "sqli",
    
    # RCE
    "exec": "rce", "system": "rce", "shell_exec": "rce", "passthru": "rce",
    "proc_open": "rce", "os.system": "rce", "subprocess.run": "rce",
    "subprocess.Popen": "rce", "child_process.exec": "rce",
    "child_process.execSync": "rce", "child_process.spawn": "rce",

    # LFI / Path Traversal
    "include": "lfi", "require": "lfi", "file_get_contents": "lfi",
    "file_put_contents": "path_traversal", "fwrite": "path_traversal",
    "move_uploaded_file": "path_traversal", "unlink": "path_traversal",
    "fs.writeFile": "path_traversal", "fs.writeFileSync": "path_traversal",
    "createWriteStream": "path_traversal", "open": "path_traversal",

    # XXE
    "simplexml_load_string": "xxe", "DOMDocument::loadXML": "xxe",

    # Deserialize
    "unserialize": "deserialize", "yaml_parse": "deserialize",
    "pickle.loads": "deserialize", "yaml.load": "deserialize",
    "jsonpickle.decode": "deserialize",

    # SSTI
    "render": "ssti", "Twig::render": "ssti", "eval": "ssti",
    "render_template_string": "ssti", "Markup": "ssti",

    # XSS
    "echo": "xss", "print": "xss", "innerHTML": "xss", "document.write": "xss",
    "dangerouslySetInnerHTML": "xss", "res.send": "xss",

    # SSRF
    "curl_exec": "ssrf", "requests.get": "ssrf", "requests.post": "ssrf",
    "urllib.request.urlopen": "ssrf", "fetch": "ssrf", "axios.get": "ssrf",
    "axios.post": "ssrf",

    # Redirect / Header
    "redirect": "redirect", "Redirect::to": "redirect", "header()": "crlf",
    "Response::header": "crlf", "header": "crlf",

    # Authz / Logic
    "Model::find": "idor", "$request->all": "mass_assign",
}


def classify_sink(sink_name: str, sink_code: str = "", is_custom: bool = False, custom_known_sinks: list = None) -> dict:
    """
    Returns: {"vuln_type": str, "source": "lookup|claude|unknown"}
    """
    if custom_known_sinks is None:
        custom_known_sinks = []

    # 0. Check custom known sinks from business context first
    for ks in custom_known_sinks:
        if ks.get("name") and ks["name"].lower() in sink_name.lower():
            if ks.get("confidence", "").upper() == "HIGH" and ks.get("vuln_type"):
                return {"vuln_type": ks["vuln_type"], "source": "business_context"}

    # 1. Lookup table next
    for known_sink, v_type in KNOWN_SINK_MAPPING.items():
        if known_sink.lower() in sink_name.lower():
            return {"vuln_type": v_type, "source": "lookup"}

    # 2. If it's a structural default (DB_SINK, HTML_SINK etc from gitnexus connect)
    # The caller in `gitnexus_connect/triage` might have already assigned a hint via sink_cat.
    
    # 3. Custom sinks (Claude classify)
    if is_custom and anthropic:
        try:
            client = anthropic.Anthropic()
            prompt = f"Given the following custom sink function name:\n{sink_name}\n"
            if sink_code:
                prompt += f"And its implementation/context:\n{sink_code}\n"
                
            prompt += (
                "Classify this sink into one of the following vulnerability types:\n"
                "sqli, rce, lfi, path_traversal, xxe, deserialize, ssti, xss, ssrf, redirect, crlf, idor, mass_assign, secrets, weak_crypto.\n"
                "Return ONLY a JSON object with 'vuln_type' (string) and 'confidence' (HIGH/MED/LOW). If you cannot determine, return 'unknown' for vuln_type."
            )
            
            response = client.messages.create(
                model="claude-3-5-haiku-latest",
                max_tokens=100,
                messages=[{"role": "user", "content": prompt}]
            )
            content = response.content[0].text
            start = content.find('{')
            end = content.rfind('}')
            if start != -1 and end != -1:
                res = json.loads(content[start:end+1])
                return {"vuln_type": res.get("vuln_type", "unknown"), "source": "claude"}
        except Exception as e:
            pass
            
    return {"vuln_type": "unknown", "source": "unknown"}
