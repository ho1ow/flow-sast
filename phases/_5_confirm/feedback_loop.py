"""
phases/5_confirm/feedback_loop.py
────────────────────────────────────
LangGraph node: feedback_expand

Sau confirmed_pocs, dùng GitNexus Cypher để tìm sibling vulnerabilities
dùng cùng sink pattern.

GitNexus Cypher query:
  MATCH (fn:Symbol)-[:CALLS]->(sink:Symbol {name: '{confirmed_sink}'})
  WHERE fn.name <> '{confirmed_entry}'
  RETURN fn.name, fn.filePath, fn.line
  ORDER BY fn.filePath

Cap: tối đa 20 new candidates từ feedback per confirmed finding.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from typing import List

from core.reliability import audit_log, safe_node
from core.state import PentestState


FEEDBACK_QUERY_TEMPLATE = """
MATCH (fn:Symbol)-[:CALLS]->(sink:Symbol)
WHERE sink.name = '{confirmed_sink}'
AND fn.name <> '{confirmed_entry}'
AND NOT fn.filePath CONTAINS '/test/'
AND NOT fn.filePath CONTAINS '/spec/'
AND NOT fn.filePath CONTAINS '/migration/'
RETURN DISTINCT
    fn.name AS similar_fn,
    fn.filePath AS file,
    fn.line AS line,
    sink.name AS sink_fn
ORDER BY fn.filePath
LIMIT 20
"""


@safe_node("feedback_expand")
def feedback_expand(state: PentestState) -> dict:
    """LangGraph node — GitNexus re-query for sibling vulnerabilities."""
    cfg = state["config"]
    gitnexus_cfg = cfg.get("gitnexus", {})
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")
    repo_path = state["repo_path"]

    binary = gitnexus_cfg.get("binary", "gitnexus")
    timeout = gitnexus_cfg.get("timeout_seconds", 120)

    confirmed_pocs: List[dict] = state.get("confirmed_pocs", [])
    findings: List[dict] = state.get("findings", [])

    # Use both confirmed PoCs and HIGH-confidence findings
    high_findings = [
        f for f in findings
        if f.get("confidence") == "HIGH" and f.get("severity") in ("CRITICAL", "HIGH")
    ]
    poc_finding_ids = {p.get("finding_id") for p in confirmed_pocs}

    targets = list({
        (f.get("path", {}).get("sink", {}).get("name", "") or f.get("sink_fn", ""),
         f.get("path", {}).get("entry_fn", "") or f.get("handler", ""))
        for f in high_findings
        if f.get("path", {}).get("sink", {}).get("name") or f.get("sink_fn")
    })

    audit_log(audit_dir, run_id, "feedback_expand:start", {
        "confirmed_pocs": len(confirmed_pocs),
        "high_findings": len(high_findings),
        "unique_sinks": len(targets),
    })

    if not targets:
        return {}

    existing_path_ids = {p.get("id") for p in state.get("prioritized", [])}
    new_paths: List[dict] = []

    for confirmed_sink, confirmed_entry in targets[:10]:  # cap 10 unique sinks
        if not confirmed_sink:
            continue

        query = FEEDBACK_QUERY_TEMPLATE.format(
            confirmed_sink=confirmed_sink,
            confirmed_entry=confirmed_entry or "___none___",
        )

        rows = _run_cypher(binary, repo_path, query, timeout)

        for row in rows:
            sink_fn = row.get("sink_fn", confirmed_sink)
            path_id = hashlib.md5(
                f"feedback:{row.get('file','')}:{row.get('line',0)}:{sink_fn}".encode()
            ).hexdigest()[:12]

            if path_id in existing_path_ids:
                continue
            existing_path_ids.add(path_id)

            new_paths.append({
                "id": path_id,
                "query_type": "feedback",
                "entry_fn": row.get("similar_fn", ""),
                "entry_file": row.get("file", ""),
                "source": {
                    "type": "http_param",
                    "file": row.get("file", ""),
                    "line": int(row.get("line", 0)),
                    "code": row.get("similar_fn", ""),
                },
                "sink": {
                    "type": "custom",
                    "name": sink_fn,
                    "file": row.get("file", ""),
                    "line": int(row.get("line", 0)),
                    "code": sink_fn,
                },
                "call_chain": [row.get("similar_fn", ""), sink_fn],
                "intermediate": [],
                "hops": 1,
                "path_length": 1,
                "sink_cat": "CUSTOM",
                "score": 6.5,  # Automatically above threshold
                "triage_detail": {"feedback": True, "original_sink": confirmed_sink},
                "path_decision": "full_verify",  # Always full verify for feedback paths
            })

            if len(new_paths) >= 20:  # Global cap
                break
        if len(new_paths) >= 20:
            break

    audit_log(audit_dir, run_id, "feedback_expand:done", {"new_paths": len(new_paths)})

    if not new_paths:
        return {}

    return {"prioritized": new_paths}  # Annotated → merges with existing


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
