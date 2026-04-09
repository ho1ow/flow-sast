"""
phases/2_connect/gitnexus_fp_filter.py
──────────────────────────────────────
LangGraph node: gitnexus_fp_filter

GitNexus-based False Positive filter — chạy SAU triage_score,
TRƯỚC joern_pre_filter để loại bỏ rõ ràng FP trước khi tốn Joern CPU.

Joern filter (joern_filter.py):  xác nhận taint path bằng CPG / CFG analysis
GitNexus FP filter (file này):    loại trừ FP theo patterns không cần CPG:
  - Test / fixture / migration files
  - Trusted (server-controlled) sources
  - Read-only sinks (log only)
  - Sink in dead code / utility classes
  - Mismatch: sink type vs entry point type

Mỗi path qua filter sẽ có thêm field:
  "fp_decision": "pass" | "skip" | "low_priority"
  "fp_reason":   str giải thích lý do

path với fp_decision == "skip" bị loại khỏi danh sách tiếp tục.
"""

from __future__ import annotations

from typing import List, Tuple

from shared.logger import audit_log
from shared.source_catalog import (
    TRUSTED_SOURCES,
    TEST_FILE_PATTERNS,
    READONLY_SINKS,
    is_trusted_source,
    is_test_file,
)
from shared.sink_catalog import (
    SINK_SEVERITY_SCORE,
    get_category,
)


# ── Dead code / utility path patterns ────────────────────────────────────────
UTILITY_PATH_PATTERNS = [
    "/helper/", "/helpers/",
    "/util/", "/utils/",
    "/abstract/",
    "/base/",
    "/trait/",
    "/interface/",
    "/contract/",
]

# Sink categories that are clearly low-risk in specific entry contexts
LOW_RISK_COMBOS = {
    # Log sink in any entry → low priority (not skip)
    ("LOG_SINK",     "controller"): "low_priority",
    ("LOG_SINK",     "handler"):    "low_priority",
    ("LOG_SINK",     "route"):      "low_priority",
    # HTML sink in API-only routes → redirect risk is low
    ("HTML_SINK",    "api"):        "low_priority",
}

# Minimum score to survive FP filter (paths below this always skip)
FP_MIN_SCORE = 4


def gitnexus_fp_filter(prioritized: List[dict], run_id: str = "local", pipeline_cfg: dict = None) -> dict:
    """GitNexus pattern-based FP filter."""
    if pipeline_cfg is None:
        pipeline_cfg = {}
        
    audit_dir = "reports/" + run_id
    import os
    os.makedirs(audit_dir, exist_ok=True)

    paths = prioritized
    if not paths:
        return {}

    passed:       List[dict] = []
    skipped:      List[dict] = []
    low_priority: List[dict] = []

    for path in paths:
        decision, reason = _evaluate(path)
        path = {**path, "fp_decision": decision, "fp_reason": reason}

        if decision == "skip":
            skipped.append(path)
        elif decision == "low_priority":
            low_priority.append(path)
        else:
            passed.append(path)

    # Reorder: passed first, then low_priority (already triaged)
    filtered = passed + low_priority

    audit_log(audit_dir, run_id, "gitnexus_fp_filter:done", {
        "input":        len(paths),
        "passed":       len(passed),
        "low_priority": len(low_priority),
        "skipped":      len(skipped),
        "skip_reasons": _count_reasons(skipped),
    })

    return {"prioritized": filtered}


def _evaluate(path: dict) -> Tuple[str, str]:
    """Return (decision, reason) for a single path."""

    entry_file   = path.get("entry_file", path.get("source", {}).get("file", ""))
    source_code  = path.get("source", {}).get("code", "")
    sink_name    = path.get("sink", {}).get("name", "")
    sink_cat     = path.get("sink_cat", get_category(sink_name))
    score        = path.get("score", 0)

    # ── Rule 1: Absolute score too low ───────────────────────────────────────
    if score < FP_MIN_SCORE:
        return "skip", f"score_too_low:{score}"

    # ── Rule 2: Test / fixture / migration file ───────────────────────────────
    if is_test_file(entry_file):
        return "skip", "test_or_migration_file"

    # Check sink file too
    sink_file = path.get("sink", {}).get("file", "")
    if sink_file and is_test_file(sink_file):
        return "skip", "sink_in_test_file"

    # ── Rule 3: Trusted (server-controlled) source ───────────────────────────
    if source_code and is_trusted_source(source_code):
        return "skip", f"trusted_source:{source_code[:60]}"

    # ── Rule 4: Read-only sink (log) ──────────────────────────────────────────
    if sink_name in READONLY_SINKS:
        return "low_priority", "readonly_log_sink"

    # ── Rule 5: Utility / helper class entry point ────────────────────────────
    if any(p in entry_file.lower() for p in UTILITY_PATH_PATTERNS):
        return "low_priority", "utility_class_entry"

    # ── Rule 6: Low-risk sink+entry combo ────────────────────────────────────
    entry_context = _classify_entry(entry_file)
    combo = (sink_cat, entry_context)
    if combo in LOW_RISK_COMBOS:
        return LOW_RISK_COMBOS[combo], f"low_risk_combo:{sink_cat}+{entry_context}"

    # ── Rule 7: Feedback path (auto-pass) ────────────────────────────────────
    if path.get("query_type") == "feedback":
        return "pass", "feedback_path"

    # ── Rule 8: Object taint path — always pass (harder to FP) ───────────────
    if path.get("query_type") == "object":
        return "pass", "object_taint_path"

    return "pass", "no_fp_pattern_matched"


def _classify_entry(entry_file: str) -> str:
    """Classify entry file type for combo rules."""
    fl = entry_file.lower()
    for token in ["controller", "route", "handler", "action", "api", "endpoint",
                  "view", "template", "middleware", "service"]:
        if token in fl:
            return token
    return "unknown"


def _count_reasons(paths: List[dict]) -> dict:
    from collections import Counter
    return dict(Counter(p.get("fp_reason", "")[:30] for p in paths).most_common(5))
