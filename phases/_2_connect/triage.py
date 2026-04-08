"""
phases/2_connect/triage.py
───────────────────────────
LangGraph node: triage_score

Merge structural_paths + object_paths và score từng path.
Chỉ thông qua paths có score >= 6 (theo spec).

Scoring:
  Sink severity:   EXEC_SINK=5, DB_SINK=4, FILE_SINK=4,
                   HTML_SINK=3, URL_SINK=3, DESER=3, LOG=1
  Path length:     hops <= 2 → +3, hops <= 4 → +1
  Entry point:     controller/route/api/handler → +2
  Source match:    entry_fn in catalog sources → +3
  Object taint:    query_type == "object" → +1 bonus

FP patterns → score penalty:
  test/migration file → -10 (effectively discard)
  trusted source pattern → -10

Output: prioritized[] sorted desc by score
"""

from __future__ import annotations

import hashlib
from typing import List

from core.reliability import audit_log, safe_node
from core.state import PentestState


# Per-spec severity weights
SINK_SEVERITY: dict[str, int] = {
    "EXEC_SINK":        5,
    "DB_SINK":          4,
    "FILE_SINK":        4,
    "DESERIALIZE_SINK": 3,
    "HTML_SINK":        3,
    "URL_SINK":         3,
    "XML_SINK":         3,
    "LOG_SINK":         1,
    "CUSTOM":           2,
}

# Sink type aliases
SINK_TYPE_TO_CAT: dict[str, str] = {
    "sqli":          "DB_SINK",
    "rce":           "EXEC_SINK",
    "path_traversal":"FILE_SINK",
    "xss":           "HTML_SINK",
    "ssrf":          "URL_SINK",
    "redirect":      "URL_SINK",
    "deser":         "DESERIALIZE_SINK",
    "xxe":           "XML_SINK",
    "ssti":          "HTML_SINK",
    "custom":        "CUSTOM",
}

# File path patterns for FP detection
TEST_FILE_PATTERNS = [
    "/test/", "/tests/", "/spec/", "/fixture/", "/fixtures/",
    "/migration/", "/migrations/", "/seeder/", "/seeders/",
    "Test.php", "Spec.php", "_test.go", "_test.py", ".test.js",
    ".spec.ts", ".spec.js",
]

# Trusted source code patterns (not user input)
TRUSTED_SOURCE_PATTERNS = [
    "auth()->id()",
    "Auth::id()",
    "request->user->id",
    "session()->get(",
    "config(",
    "env(",
    "Cache::get(",
    "Redis::get(",
]

# Entry point path hints → +2
ENTRY_POINT_HINTS = ["controller", "route", "handler", "action", "api", "endpoint"]

# Min score to pass to Joern + Claude verify
TRIAGE_THRESHOLD = 6


@safe_node("triage_score")
def triage_score(state: PentestState) -> dict:
    """LangGraph node — score + filter paths, output prioritized[]."""
    cfg = state["config"]
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")
    threshold = pipeline_cfg.get("triage_threshold", TRIAGE_THRESHOLD)

    structural = state.get("structural_paths", [])
    objects = state.get("object_paths", [])
    all_paths = structural + objects

    # Dedup by id
    seen: set[str] = set()
    unique_paths: List[dict] = []
    for p in all_paths:
        pid = p.get("id", "")
        if pid not in seen:
            seen.add(pid)
            unique_paths.append(p)

    sources = state.get("sources", [])
    source_locations = {s.get("location", s.get("file", "")) for s in sources}
    source_fn_names = {s.get("name", "") for s in sources if s.get("name")}

    scored_paths: List[dict] = []
    skipped = 0

    for path in unique_paths:
        score, detail = _score_path(path, source_locations, source_fn_names)
        if score < threshold:
            skipped += 1
            continue
        scored_paths.append({**path, "score": score, "triage_detail": detail})

    # Sort descending by score
    scored_paths.sort(key=lambda p: p.get("score", 0), reverse=True)

    # Cap to prevent overload (top 200)
    max_paths = pipeline_cfg.get("max_paths_per_run", 200)
    prioritized = scored_paths[:max_paths]

    audit_log(audit_dir, run_id, "triage_score:done", {
        "total_paths": len(unique_paths),
        "passed_triage": len(scored_paths),
        "capped_at": len(prioritized),
        "skipped_below_threshold": skipped,
        "threshold": threshold,
        "score_distribution": _score_distribution(scored_paths),
    })

    return {"prioritized": prioritized}


def _score_path(
    path: dict,
    source_locations: set,
    source_fn_names: set,
) -> tuple[int, dict]:
    score = 0
    detail: dict = {}

    # ── FP penalties ─────────────────────────────────────────────────────────
    entry_file = path.get("entry_file", path.get("file", ""))
    source_code = path.get("source", {}).get("code", "")

    for pattern in TEST_FILE_PATTERNS:
        if pattern.lower() in entry_file.lower():
            return -10, {"fp": f"test_file:{pattern}"}

    for trusted in TRUSTED_SOURCE_PATTERNS:
        if trusted in source_code:
            return -10, {"fp": f"trusted_source:{trusted}"}

    # ── Sink severity (primary score) ────────────────────────────────────────
    sink = path.get("sink", {})
    sink_cat = path.get("sink_cat") or SINK_TYPE_TO_CAT.get(sink.get("type", ""), "CUSTOM")
    sev = SINK_SEVERITY.get(sink_cat, 1)
    score += sev
    detail["sink_severity"] = sev

    # ── Path length bonus ─────────────────────────────────────────────────────
    hops = int(path.get("hops", path.get("path_length", 99)))
    if hops <= 2:
        score += 3
        detail["hops_bonus"] = 3
    elif hops <= 4:
        score += 1
        detail["hops_bonus"] = 1
    else:
        detail["hops_bonus"] = 0

    # ── Entry point is public API ─────────────────────────────────────────────
    entry_fn = path.get("entry_fn", path.get("source", {}).get("code", ""))
    if any(hint in entry_file.lower() for hint in ENTRY_POINT_HINTS):
        score += 2
        detail["entry_point_bonus"] = 2
    else:
        detail["entry_point_bonus"] = 0

    # ── Source match catalog ──────────────────────────────────────────────────
    if entry_fn in source_fn_names or entry_file in source_locations:
        score += 3
        detail["source_match_bonus"] = 3
    else:
        detail["source_match_bonus"] = 0

    # ── Object taint bonus ────────────────────────────────────────────────────
    if path.get("query_type") == "object":
        score += 1
        detail["object_bonus"] = 1

    return score, detail


def _score_distribution(paths: List[dict]) -> dict:
    dist = {">=10": 0, "8-9": 0, "6-7": 0}
    for p in paths:
        s = p.get("score", 0)
        if s >= 10:
            dist[">=10"] += 1
        elif s >= 8:
            dist["8-9"] += 1
        else:
            dist["6-7"] += 1
    return dist
