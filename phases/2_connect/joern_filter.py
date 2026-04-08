"""
phases/2_connect/joern_filter.py
──────────────────────────────────
LangGraph node: joern_pre_filter

Sau triage_score, node này dùng Joern REST API để xác nhận taint flow
với CFG-awareness. Quyết định PathDecision cho từng path:

  PathDecision:
    CONFIRMED_HIGH        → skip Claude hoàn toàn (clear taint + no sanitizer)
    CLAUDE_SANITIZER_ONLY → gửi Claude với ~800 token prompt (sanitizer check)
    CLAUDE_FULL_VERIFY    → gửi Claude full prompt ~2500 tokens (GitNexus only)
    CLAUDE_OBJECT_TRACE   → gửi Claude object trace ~3000 tokens
    SKIP_NO_FLOW          → discard (Joern xác nhận không có data flow)
    SKIP_FALSE_POSITIVE   → discard (FP pattern detected)
    MANUAL_REVIEW         → queue for human (dynamic dispatch, second-order)

Output:
  - `joern_confirmed`: paths CONFIRMED_HIGH (đã có taint, no sanitizer)
  - `prioritized`: update với path_decision field cho mỗi path
  - `retry_queue`: MANUAL_REVIEW paths

Token optimization: CONFIRMED_HIGH và SKIP paths không gọi Claude.
Expected reduction: ~70-94% token cost vs sending everything to Claude.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Dict, List, Optional

from core.reliability import audit_log, safe_node
from core.state import PentestState
from phases._2_connect.joern_client import JoernClient


class PathDecision(Enum):
    CONFIRMED_HIGH        = "confirmed"
    CLAUDE_SANITIZER_ONLY = "sanitizer"
    CLAUDE_FULL_VERIFY    = "full_verify"
    CLAUDE_OBJECT_TRACE   = "object_trace"
    SKIP_NO_FLOW          = "skip_no_flow"
    SKIP_FALSE_POSITIVE   = "skip_fp"
    MANUAL_REVIEW         = "manual"


# Known sanitizer function names to check for
SANITIZER_NAMES = {
    # SQL
    "bindParam", "bindValue", "prepare", "prepared", "escape", "quote",
    "mysqli_real_escape_string", "pg_escape_string", "PDO::quote",
    "parameterize", "sanitize_sql", "sanitize_sql_array",
    # OS
    "escapeshellarg", "escapeshellcmd", "shlex.quote", "shlex.split",
    # HTML/XSS
    "htmlspecialchars", "htmlentities", "strip_tags", "DOMPurify",
    "escape", "h(", "bleach.clean", "markupsafe.escape",
    "template.HTML",  # Go
    # Path
    "basename", "realpath", "pathinfo", "os.path.abspath", "os.path.normpath",
    "path.resolve", "path.normalize",
    # Deserialize
    "json_decode", "json.loads",  # safe deserialization alternatives
}

# False positive patterns — trustworthy sources that shouldn't be flagged
FP_PATTERNS = [
    "auth()->id()",         # $userId = auth()->id() — internal, not user input
    "Auth::id()",           # Laravel auth facade
    "request->user->id",    # object property from auth
    "session->get(",        # internal session value
    "config(",              # config() helper
    "env(",                 # env() helper
]

# Patterns indicating manual review needed (dynamic dispatch, second-order)
MANUAL_PATTERNS = [
    r"\$\w+->",             # $obj->$var() — dynamic method dispatch
    r"call_user_func",      # dynamic function call
    r"\$$\w+\(",            # variable function: $fn()
    r"__call",              # magic method
]

# File path patterns to skip (test/migration files)
SKIP_FILE_PATTERNS = [
    "/test/", "/tests/", "/spec/", "/fixture/", "/fixtures/",
    "/migration/", "/migrations/", "/seeder/", "/seeders/",
    "Test.php", "Spec.php", "_test.go", "_test.py", ".test.js",
]


@safe_node("joern_pre_filter")
def joern_pre_filter(state: PentestState) -> dict:
    """LangGraph node — Joern CFG-aware taint confirm + PathDecision routing."""
    cfg = state["config"]
    joern_cfg = cfg.get("joern", {})
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")

    prioritized: List[dict] = state.get("prioritized", [])
    if not prioritized:
        return {}

    # Check if Joern is available
    joern_available = _check_joern_available(joern_cfg)
    if not joern_available:
        audit_log(audit_dir, run_id, "joern_pre_filter:skip_unavailable", {})
        # Fallback: assign FULL_VERIFY to all, detect FPs statically
        return _fallback_no_joern(prioritized, audit_dir, run_id)

    audit_log(audit_dir, run_id, "joern_pre_filter:start", {
        "paths_in": len(prioritized),
    })

    client = JoernClient(
        base_url=joern_cfg.get("base_url", "http://localhost:8080"),
        timeout=joern_cfg.get("timeout_seconds", 300),
    )

    # Build or get CPG
    repo_path = state["repo_path"]
    cpg_id = _get_or_build_cpg(client, repo_path, joern_cfg, audit_dir, run_id)
    if not cpg_id:
        audit_log(audit_dir, run_id, "joern_pre_filter:cpg_failed", {})
        return _fallback_no_joern(prioritized, audit_dir, run_id)

    confirmed_high: List[dict] = []
    updated_prioritized: List[dict] = []
    retry_queue: List[dict] = []

    decision_summary: Dict[str, int] = {d.value: 0 for d in PathDecision}

    for path in prioritized:
        decision, sanitizer_found, conditions = _decide_path(client, cpg_id, path)
        path = {**path, "path_decision": decision.value, "joern_sanitizer": sanitizer_found}
        decision_summary[decision.value] = decision_summary.get(decision.value, 0) + 1

        if decision == PathDecision.CONFIRMED_HIGH:
            confirmed_high.append(path)
            updated_prioritized.append(path)

        elif decision in (PathDecision.CLAUDE_SANITIZER_ONLY,
                          PathDecision.CLAUDE_FULL_VERIFY,
                          PathDecision.CLAUDE_OBJECT_TRACE):
            updated_prioritized.append(path)

        elif decision == PathDecision.MANUAL_REVIEW:
            retry_queue.append(path)

        elif decision in (PathDecision.SKIP_NO_FLOW, PathDecision.SKIP_FALSE_POSITIVE):
            audit_log(audit_dir, run_id, "joern_pre_filter:skip", {
                "id": path.get("id"), "reason": decision.value
            })

    audit_log(audit_dir, run_id, "joern_pre_filter:done", {
        "total": len(prioritized),
        **decision_summary,
        "token_saved_paths": decision_summary["confirmed"] + decision_summary["skip_no_flow"] + decision_summary["skip_fp"],
    })

    return {
        "joern_confirmed": confirmed_high,
        "prioritized": updated_prioritized,   # Annotated → extends
        "retry_queue": retry_queue,
    }


# ── Decision logic ────────────────────────────────────────────────────────────

def _decide_path(
    client: JoernClient,
    cpg_id: str,
    path: dict,
) -> tuple[PathDecision, List[str], List[str]]:
    """
    Run Joern taint query and return (decision, sanitizers_found, conditions).
    """
    source = path.get("source", {})
    sink = path.get("sink", {})
    query_type = path.get("query_type", "structural")

    # Static FP check first (no Joern call needed)
    if _is_fp_path(path):
        return PathDecision.SKIP_FALSE_POSITIVE, [], []

    # Object taint paths → always CLAUDE_OBJECT_TRACE (too complex for Joern taint)
    if query_type == "object":
        return PathDecision.CLAUDE_OBJECT_TRACE, [], []

    source_pattern = _make_joern_pattern(source)
    sink_pattern = _make_joern_pattern(sink)

    if not source_pattern or not sink_pattern:
        return PathDecision.CLAUDE_FULL_VERIFY, [], []

    # Build and run Joern taint query
    scala_query = _build_taint_query(source_pattern, sink_pattern)
    try:
        result = client.run_query(cpg_id, scala_query, timeout=30)
    except Exception:
        # Joern query failed → fall back to full Claude verify
        return PathDecision.CLAUDE_FULL_VERIFY, [], []

    has_flow = result.get("has_flow", False)
    sanitizers = result.get("sanitizers", [])
    conditions = result.get("conditions", [])

    if not has_flow:
        # Check if this is a known manual-review pattern
        if _needs_manual_review(path):
            return PathDecision.MANUAL_REVIEW, sanitizers, conditions
        return PathDecision.SKIP_NO_FLOW, sanitizers, conditions

    # Has flow
    if not sanitizers:
        return PathDecision.CONFIRMED_HIGH, sanitizers, conditions
    else:
        return PathDecision.CLAUDE_SANITIZER_ONLY, sanitizers, conditions


def _is_fp_path(path: dict) -> bool:
    entry_file = path.get("entry_file", path.get("file", ""))
    source_code = path.get("source", {}).get("code", "")

    # Test/migration files
    for pattern in SKIP_FILE_PATTERNS:
        if pattern in entry_file:
            return True

    # Trusted source patterns
    for fp in FP_PATTERNS:
        if fp in source_code:
            return True

    return False


def _needs_manual_review(path: dict) -> bool:
    import re
    call_chain = " ".join(str(n) for n in path.get("call_chain", []))
    for pattern in MANUAL_PATTERNS:
        if re.search(pattern, call_chain):
            return True
    return False


def _make_joern_pattern(node: dict) -> Optional[str]:
    """Extract a Joern-compatible regex pattern from a source/sink node."""
    code = node.get("code", node.get("name", ""))
    if not code:
        return None
    # Escape special regex chars, then make it a contains-pattern
    import re
    escaped = re.escape(code.split("(")[0].strip())
    return escaped


def _build_taint_query(source_pattern: str, sink_pattern: str) -> str:
    """Build Joern Scala taint query for a source→sink pair."""
    sanitizer_list = '", "'.join(SANITIZER_NAMES)
    return f"""
val sanitizerNames = Set("{sanitizer_list}")
val src  = cpg.call.name("{source_pattern}").argument
val sink = cpg.call.name("{sink_pattern}").argument
val flows = sink.reachableByFlows(src).l

Map(
  "has_flow"   -> flows.nonEmpty,
  "flow_count" -> flows.size,
  "sanitizers" -> flows.flatMap(f => f.elements.map(_.code)
                    .filter(c => sanitizerNames.exists(s => c.contains(s)))).distinct.l,
  "conditions" -> flows.flatMap(f => f.elements.filter(_.isControlStructure).map(_.code).l).distinct.l
).toJson
"""


# ── Fallback when Joern unavailable ────────────────────────────────────────────

def _fallback_no_joern(prioritized: List[dict], audit_dir: str, run_id: str) -> dict:
    """Static-only fallback: assign decisions without Joern."""
    updated: List[dict] = []
    for path in prioritized:
        if _is_fp_path(path):
            decision = PathDecision.SKIP_FALSE_POSITIVE
        elif path.get("query_type") == "object":
            decision = PathDecision.CLAUDE_OBJECT_TRACE
        elif _needs_manual_review(path):
            decision = PathDecision.MANUAL_REVIEW
        else:
            decision = PathDecision.CLAUDE_FULL_VERIFY
        updated.append({**path, "path_decision": decision.value, "joern_sanitizer": []})

    audit_log(audit_dir, run_id, "joern_pre_filter:fallback_static", {"paths": len(updated)})
    return {"prioritized": updated}


def _check_joern_available(joern_cfg: dict) -> bool:
    """Quick health check — Joern REST server reachable?"""
    if joern_cfg.get("skip"):
        return False
    import httpx
    try:
        r = httpx.get(f"{joern_cfg.get('base_url', 'http://localhost:8080')}/health", timeout=3)
        return r.status_code < 500
    except Exception:
        return False


def _get_or_build_cpg(
    client: JoernClient,
    repo_path: str,
    joern_cfg: dict,
    audit_dir: str,
    run_id: str,
) -> Optional[str]:
    """Build CPG or return existing one."""
    try:
        cpg_id, _result = client.build_and_query(
            repo_path,
            query="cpg.metaData.l",
            build_timeout=joern_cfg.get("cpg_build_timeout", 600),
            audit_dir=audit_dir,
            run_id=run_id,
        )
        return cpg_id
    except Exception as exc:
        audit_log(audit_dir, run_id, "joern_pre_filter:cpg_error", {"error": str(exc)})
        return None
