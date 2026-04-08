"""
core/state.py
─────────────
PentestState — Central TypedDict shared across all LangGraph nodes.

Design decisions:
- `Annotated[List[dict], operator.add]` on list fields allows parallel nodes
  to independently append results; LangGraph merges them automatically.
- Scalar fields (str, int, dict) use last-write-wins semantics.
- `current_path` / `current_enriched` / `current_verify_result` are
  transient working fields for the per-path verify → analyze loop.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, List, Optional
from typing_extensions import TypedDict


# ── Individual item schemas (loose dicts for flexibility) ────────────────────
# Source: a taint source found by semgrep / gitnexus / api_parser
# {
#   "id":       str (unique hash),
#   "type":     "http_param" | "cookie" | "header" | "db_read" | "queue" | "file_upload" | "websocket",
#   "framework": str,
#   "pattern":  str,  # the matched pattern / rule id
#   "file":     str,
#   "line":     int,
#   "code":     str,  # matched code snippet
#   "tool":     "semgrep" | "gitnexus" | "api_parser"
# }

# Sink: a dangerous sink
# {
#   "id":        str,
#   "type":      "sqli" | "rce" | "xss" | "ssrf" | "path_traversal" | "redirect" | "deser" | "xxe",
#   "severity":  "CRITICAL" | "HIGH" | "MEDIUM",
#   "framework": str,
#   "pattern":   str,
#   "file":      str,
#   "line":      int,
#   "code":      str,
#   "tool":      "semgrep" | "gitnexus" | "api_parser"
# }

# Endpoint: parsed API route
# {
#   "method":  "GET" | "POST" | ...,
#   "path":    "/api/users/{id}",
#   "params":  [{"name": str, "type": str, "location": "query"|"body"|"path"|"header"|"cookie"}],
#   "handler": str,  # function / class name
#   "file":    str,
#   "line":    int,
#   "framework": str
# }

# Path: a source-to-sink data flow path
# {
#   "id":             str,
#   "source":         dict,  # source node
#   "sink":           dict,  # sink node
#   "intermediate":   List[dict],  # intermediate call nodes
#   "method_name":    str,
#   "file":           str,
#   "path_length":    int,
#   "query_type":     "structural" | "object",
#   "score":          float,   # filled by triage
#   "triage_detail":  dict     # score breakdown
# }

# Finding: a confirmed vulnerability finding
# {
#   "id":              str,
#   "vuln_type":       str,
#   "title":           str,
#   "severity":        "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
#   "confidence":      "HIGH" | "MED" | "LOW",
#   "path":            dict,   # the triggering path
#   "reasoning":       str,    # Claude's reasoning
#   "attack_vector":   str,    # PoC hint
#   "sanitizers_found": List[str],
#   "phase":           str,    # which analyze agent found it
#   "file":            str,
#   "line_start":      int,
#   "line_end":        int,
#   "code_snippet":    str,
#   "cwe":             str,    # e.g. "CWE-89"
#   "owasp":           str,    # e.g. "A03:2021"
#   "sarif_rule_id":   str
# }


class PentestState(TypedDict):
    # ── Inputs ───────────────────────────────────────────────────────────────
    repo_path: str
    run_id: str
    stack: str          # "django" | "flask" | "spring" | "express" | "rails" | "go" | "php" | "auto"
    checkpoint_dir: str
    config: dict        # loaded from tools_config.json
    retry_count: int    # global pipeline retry counter
    audit_log_path: str # path to JSONL audit file

    # ── Catalog ──────────────────────────────────────────────────────────────
    sources:      Annotated[List[dict], operator.add]
    sinks:        Annotated[List[dict], operator.add]
    endpoints:    Annotated[List[dict], operator.add]
    custom_sinks: Annotated[List[dict], operator.add]
    process_flows: List[dict]   # GitNexus business process flows
    business_context: dict       # Extracted from README/docs/OpenAPI/schema
    catalog_checksum: str
    cx_seed: dict               # Checkmarx SARIF seed (optional, not in Claude ctx)

    # ── Connect ───────────────────────────────────────────────────────────────
    structural_paths: List[dict]
    object_paths:     List[dict]

    # ── Triage ───────────────────────────────────────────────────────────────
    prioritized: List[dict]       # paths with score >= threshold, sorted desc
    current_path_idx: int         # index into `prioritized` during verify loop

    # ── Joern filter ─────────────────────────────────────────────────────────
    joern_confirmed: Annotated[List[dict], operator.add]  # CONFIRMED_HIGH paths
    retry_queue:     List[dict]                           # MANUAL_REVIEW paths

    # ── Per-path transient (verify loop) ─────────────────────────────────────
    current_path:          Optional[dict]   # path being processed right now
    current_enriched:      Optional[dict]   # enriched context for current path
    current_verify_result: Optional[dict]   # Claude's verify output
    verify_retry_count:    int              # retries for current path

    # ── Verify outputs (accumulated) ─────────────────────────────────────────
    verified_high:    Annotated[List[dict], operator.add]
    verified_partial: Annotated[List[dict], operator.add]

    # ── Findings (accumulated) ────────────────────────────────────────────────
    findings:       Annotated[List[dict], operator.add]
    confirmed_pocs: Annotated[List[dict], operator.add]

    # ── Audit / errors ────────────────────────────────────────────────────────
    errors: Annotated[List[dict], operator.add]


def initial_state(
    repo_path: str,
    run_id: str,
    stack: str,
    checkpoint_dir: str,
    config: dict,
) -> PentestState:
    """Return a fully initialised PentestState for a fresh run."""
    pipeline_cfg = config.get("pipeline", {})
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")
    return PentestState(
        repo_path=repo_path,
        run_id=run_id,
        stack=stack,
        checkpoint_dir=checkpoint_dir,
        config=config,
        retry_count=0,
        audit_log_path=f"{audit_dir}/{run_id}.jsonl",
        # catalog
        sources=[],
        sinks=[],
        endpoints=[],
        custom_sinks=[],
        process_flows=[],
        business_context={},
        catalog_checksum="",
        # connect
        structural_paths=[],
        object_paths=[],
        # triage + loop
        prioritized=[],
        current_path_idx=0,
        current_path=None,
        current_enriched=None,
        current_verify_result=None,
        verify_retry_count=0,
        # joern
        joern_confirmed=[],
        retry_queue=[],
        # outputs
        verified_high=[],
        verified_partial=[],
        findings=[],
        confirmed_pocs=[],
        errors=[],
    )
