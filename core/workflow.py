"""
core/workflow.py
─────────────────
LangGraph StateGraph — Full pipeline per spec.

Flow:
  START
    │
    ├──► catalog_semgrep   ─┐
    ├──► catalog_gitnexus  ─┤ (parallel fan-out, 4 nodes)
    ├──► catalog_api       ─┤
    └──► catalog_secrets   ─┘ (Gitleaks → findings[] directly)
                             │
                      catalog_merge (barrier)
                             │
                 ┌───────────┴───────────┐
          path_structural          path_object
          (GitNexus Cypher 2a)   (GitNexus Cypher 2a')
                 └───────────┬───────────┘
                             │
                       triage_score  (score >= 6 filter)
                             │
                      joern_pre_filter  ← NEW: PathDecision routing
                             │
              CONFIRMED_HIGH ─► skip verify_claude
              FULL_VERIFY/SANITIZER/OBJECT_TRACE ─► verify_enrich
                                                          │
                                                   verify_claude
                                                          │
                                                  confidence_gate
                                                   │         │
                                               analyze    retry/next
                                                   │
                ┌──────────────────────────────────┐
                server/client/authz/biz_logic/hardcode (parallel, max_concurrency=3)
                └──────────────────────────────────┘
                             │
                      advance_after_analyze
                             │
                       (loop back or confirm_burp)
                             │
                       feedback_expand (GitNexus re-query)
                             │
                            END
"""

from __future__ import annotations

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from core.state import PentestState

# Ensure phase aliases are registered before importing sub-modules
import phases  # noqa: F401

# CATALOG imports
from phases._1_catalog.semgrep_runner  import catalog_semgrep
from phases._1_catalog.gitnexus_runner import catalog_gitnexus
from phases._1_catalog.api_parser      import catalog_api
from phases._1_catalog.secrets_runner  import catalog_secrets
from phases._1_catalog.gitnexus_context import catalog_gitnexus_context  # gitnexus context

# CONNECT imports
from phases._2_connect.run_structural  import path_structural
from phases._2_connect.run_object_taint import path_object
from phases._2_connect.triage          import triage_score
from phases._2_connect.gitnexus_fp_filter import gitnexus_fp_filter  # FP filter
from phases._2_connect.joern_filter    import joern_pre_filter

# VERIFY imports
from phases._3_verify.enricher         import verify_enrich
from phases._3_verify.claude_verifier  import verify_claude
from phases._3_verify.router import (
    confidence_gate,
    next_path,
    increment_retry,
    advance_after_analyze,
)

# ANALYZE imports
from phases._4_analyze.server_agent    import server_agent
from phases._4_analyze.client_agent    import client_agent
from phases._4_analyze.authz_agent     import authz_agent
from phases._4_analyze.biz_logic_agent import biz_logic_agent
from phases._4_analyze.hardcode_agent  import hardcode_agent

# CONFIRM imports
from phases._5_confirm.burp_mcp_client import confirm_burp
from phases._5_confirm.feedback_loop   import feedback_expand


# ─────────────────────────────────────────────────────────────────────────────
# Helper / barrier nodes
# ─────────────────────────────────────────────────────────────────────────────

def catalog_merge(state: PentestState) -> dict:
    """Barrier node: all 4 catalog nodes complete → proceed to connect."""
    return {}


def check_more_paths(state: PentestState) -> str:
    """Conditional edge after advance_after_analyze."""
    idx = state.get("current_path_idx", 0)
    prioritized = state.get("prioritized", [])
    return "verify_enrich" if idx < len(prioritized) else "confirm_burp"


def check_done_or_enrich(state: PentestState) -> str:
    """Conditional edge after next_path (LOW discard)."""
    idx = state.get("current_path_idx", 0)
    prioritized = state.get("prioritized", [])
    return "verify_enrich" if idx < len(prioritized) else "confirm_burp"


# ─────────────────────────────────────────────────────────────────────────────
# Build graph
# ─────────────────────────────────────────────────────────────────────────────

def build_graph(use_memory_saver: bool = True) -> StateGraph:
    """
    Construct and compile the pentest agent LangGraph.

    Args:
        use_memory_saver: If True, compile with MemorySaver for resume support.
    Returns:
        Compiled CompiledGraph.
    """
    builder = StateGraph(PentestState)

    # ── CATALOG phase — 4 parallel nodes ─────────────────────────────────────
    builder.add_node("catalog_semgrep",  catalog_semgrep)
    builder.add_node("catalog_gitnexus", catalog_gitnexus)
    builder.add_node("catalog_api",      catalog_api)
    builder.add_node("catalog_secrets",  catalog_secrets)
    builder.add_node("catalog_context",  catalog_gitnexus_context)   # gitnexus context
    builder.add_node("catalog_merge",    catalog_merge)

    builder.add_edge(START, "catalog_semgrep")
    builder.add_edge(START, "catalog_gitnexus")
    builder.add_edge(START, "catalog_api")
    builder.add_edge(START, "catalog_secrets")
    builder.add_edge(START, "catalog_context")             # parallel

    builder.add_edge("catalog_semgrep",  "catalog_merge")
    builder.add_edge("catalog_gitnexus", "catalog_merge")
    builder.add_edge("catalog_api",      "catalog_merge")
    builder.add_edge("catalog_secrets",  "catalog_merge")
    builder.add_edge("catalog_context",  "catalog_merge")

    # ── CONNECT phase ─────────────────────────────────────────────────────────
    builder.add_node("path_structural", path_structural)
    builder.add_node("path_object",     path_object)
    builder.add_node("triage_score",      triage_score)
    builder.add_node("gitnexus_fp_filter", gitnexus_fp_filter)  # NEW: pattern FP
    builder.add_node("joern_pre_filter",   joern_pre_filter)    # NEW: CFG taint

    builder.add_edge("catalog_merge",   "path_structural")
    builder.add_edge("catalog_merge",   "path_object")
    builder.add_edge("path_structural", "triage_score")
    builder.add_edge("path_object",     "triage_score")
    builder.add_edge("triage_score",    "gitnexus_fp_filter")  # Step 1: pattern FP
    builder.add_edge("gitnexus_fp_filter", "joern_pre_filter") # Step 2: CPG confirm

    # ── VERIFY phase — loop with conditional edge ─────────────────────────────
    builder.add_node("verify_enrich",   verify_enrich)
    builder.add_node("verify_claude",   verify_claude)
    builder.add_node("increment_retry", increment_retry)
    builder.add_node("next_path",       next_path)

    builder.add_edge("joern_pre_filter", "verify_enrich")

    builder.add_edge("verify_enrich", "verify_claude")

    builder.add_conditional_edges(
        "verify_claude",
        confidence_gate,
        {
            "analyze":   "server_agent",
            "retry":     "increment_retry",
            "next_path": "next_path",
            "confirm":   "confirm_burp",
        },
    )

    builder.add_edge("increment_retry", "verify_enrich")    # retry loop

    builder.add_conditional_edges(
        "next_path",
        check_done_or_enrich,
        {
            "verify_enrich": "verify_enrich",
            "confirm_burp":  "confirm_burp",
        },
    )

    # ── ANALYZE phase — parallel fan-out (max_concurrency set at invoke) ──────
    builder.add_node("server_agent",    server_agent)
    builder.add_node("client_agent",    client_agent)
    builder.add_node("authz_agent",     authz_agent)
    builder.add_node("biz_logic_agent", biz_logic_agent)
    builder.add_node("hardcode_agent",  hardcode_agent)
    builder.add_node("advance_after_analyze", advance_after_analyze)

    # Fan-out: server_agent is entry, all others run in parallel
    for agent in ["client_agent", "authz_agent", "biz_logic_agent", "hardcode_agent"]:
        builder.add_edge("server_agent", agent)

    # Fan-in: all converge at advance
    for agent in ["server_agent", "client_agent", "authz_agent", "biz_logic_agent", "hardcode_agent"]:
        builder.add_edge(agent, "advance_after_analyze")

    builder.add_conditional_edges(
        "advance_after_analyze",
        check_more_paths,
        {
            "verify_enrich": "verify_enrich",
            "confirm_burp":  "confirm_burp",
        },
    )

    # ── CONFIRM + FEEDBACK phase ───────────────────────────────────────────────
    builder.add_node("confirm_burp",    confirm_burp)
    builder.add_node("feedback_expand", feedback_expand)

    builder.add_edge("confirm_burp",    "feedback_expand")
    builder.add_edge("feedback_expand", END)

    # ── Compile ───────────────────────────────────────────────────────────────
    checkpointer = MemorySaver() if use_memory_saver else None
    return builder.compile(checkpointer=checkpointer)


# Module-level compiled graph
graph = build_graph()
