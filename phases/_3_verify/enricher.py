"""
phases/3_verify/enricher.py
─────────────────────────────
LangGraph node: verify_enrich

For the current path being processed (state["current_path"]):
  1. Read source + sink files, extract ±N lines of context
  2. Read intermediate call sites (from path nodes)
  3. Extract import statements
  4. Build enriched_context dict for Claude

Also advances current_path_idx: pops the next unprocessed path
from prioritized[] into current_path.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from core.reliability import audit_log, safe_node
from core.state import PentestState


@safe_node("verify_enrich")
def verify_enrich(state: PentestState) -> dict:
    """LangGraph node — enrich the current path with file context."""
    cfg = state["config"]
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")
    context_lines = pipeline_cfg.get("code_context_lines", 50)

    prioritized: List[dict] = state.get("prioritized", [])
    idx: int = state.get("current_path_idx", 0)

    # Advance to next unprocessed path
    if idx >= len(prioritized):
        # No more paths to process
        return {"current_path": None, "current_enriched": None}

    path = prioritized[idx]
    repo_path = state["repo_path"]

    audit_log(audit_dir, run_id, "verify_enrich:start", {
        "idx": idx, "path_id": path.get("id"), "score": path.get("score"),
    })

    source_info = path.get("source", {})
    sink_info = path.get("sink", {})

    # Read source context
    source_snippet = _read_context(
        repo_path, source_info.get("file", ""), source_info.get("line", 0), context_lines
    )
    # Read sink context (may be different file)
    sink_snippet = _read_context(
        repo_path, sink_info.get("file", ""), sink_info.get("line", 0), context_lines
    )

    # Read intermediate nodes
    intermediate_fn_snippets: List[dict] = []
    for node in path.get("intermediate", []):
        snip = _read_context(
            repo_path, node.get("file", ""), node.get("line", 0), 30
        )
        if snip:
            intermediate_fn_snippets.append({
                "method": node.get("method", ""),
                "file": node.get("file", ""),
                "line": node.get("line", 0),
                "code": snip,
            })

    # Extract imports from both files
    imports = _extract_imports(repo_path, source_info.get("file", ""))
    if sink_info.get("file") != source_info.get("file"):
        imports += _extract_imports(repo_path, sink_info.get("file", ""))

    enriched = {
        "path_id": path.get("id"),
        "path_summary": _summarise_path(path),
        "source": {
            **source_info,
            "snippet": source_snippet,
        },
        "sink": {
            **sink_info,
            "snippet": sink_snippet,
        },
        "intermediate_fns": intermediate_fn_snippets,
        "imports": list(set(imports))[:30],  # cap at 30 import lines
        "score": path.get("score"),
        "triage_detail": path.get("triage_detail", {}),
    }

    audit_log(audit_dir, run_id, "verify_enrich:done", {"path_id": path.get("id")})

    return {
        "current_path": path,
        "current_enriched": enriched,
        "verify_retry_count": 0,  # reset on new path
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read_context(repo_path: str, rel_file: str, center_line: int, half_window: int) -> str:
    """Read ±half_window lines around center_line from rel_file."""
    if not rel_file or center_line <= 0:
        return ""
    p = Path(repo_path) / rel_file
    if not p.exists():
        # Try absolute path
        p = Path(rel_file)
    if not p.exists():
        return ""
    try:
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""

    start = max(0, center_line - half_window - 1)
    end = min(len(lines), center_line + half_window)

    numbered = []
    for i, line in enumerate(lines[start:end], start=start + 1):
        marker = ">>>" if i == center_line else "   "
        numbered.append(f"{i:4d} {marker} {line}")
    return "\n".join(numbered)


def _extract_imports(repo_path: str, rel_file: str) -> List[str]:
    """Extract import/require/include lines from the top of a file."""
    if not rel_file:
        return []
    p = Path(repo_path) / rel_file
    if not p.exists():
        p = Path(rel_file)
    if not p.exists():
        return []
    try:
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    imports = []
    import_re = re.compile(
        r'^(import |from |require\(|include\(|using |#include)'
    )
    for line in lines[:50]:  # imports are almost always at the top
        if import_re.match(line.strip()):
            imports.append(line.strip())
    return imports


def _summarise_path(path: dict) -> str:
    source = path.get("source", {})
    sink = path.get("sink", {})
    return (
        f"Source: {source.get('type', '?')} in {source.get('file', '?')}:{source.get('line', '?')} "
        f"→ Sink: {sink.get('type', '?')} in {sink.get('file', '?')}:{sink.get('line', '?')} "
        f"[score={path.get('score', 0)}, hops={path.get('path_length', 1)}]"
    )
