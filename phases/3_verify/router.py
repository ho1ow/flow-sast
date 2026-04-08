"""
phases/3_verify/router.py
──────────────────────────
LangGraph conditional edge function: confidence_gate

Routes after verify_claude based on confidence:

  HIGH → "analyze"              : send to analyze fan-out
  MED  → "retry" or "analyze"  : retry verify_enrich up to max_retries,
                                  then forward to analyze (with partial flag)
  LOW  → "next_path"           : discard, advance to next prioritized path

Also handles the "no more paths" case → "confirm".
"""

from __future__ import annotations

from typing import Literal

from core.reliability import audit_log
from core.state import PentestState


RouteKey = Literal["analyze", "retry", "next_path", "confirm"]


def confidence_gate(state: PentestState) -> RouteKey:
    """
    LangGraph conditional edge — returns the next node name.
    Called after verify_claude completes.
    """
    cfg = state.get("config", {})
    pipeline_cfg = cfg.get("pipeline", {})
    max_retries = pipeline_cfg.get("verify_max_retries", 2)
    run_id = state.get("run_id", "")
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")

    verify_result = state.get("current_verify_result") or {}
    confidence: str = verify_result.get("confidence", "LOW").upper()
    is_vulnerable: bool = verify_result.get("is_vulnerable", False)
    retry_count: int = state.get("verify_retry_count", 0)
    current_path = state.get("current_path")

    # No current path → we're done with all paths
    if current_path is None:
        audit_log(audit_dir, run_id, "confidence_gate:no_paths", {})
        return "confirm"

    if confidence == "HIGH" and is_vulnerable:
        audit_log(audit_dir, run_id, "confidence_gate:HIGH", {
            "path_id": current_path.get("id"), "retry": retry_count
        })
        return "analyze"

    if confidence == "MED":
        if retry_count < max_retries:
            audit_log(audit_dir, run_id, "confidence_gate:MED_retry", {
                "path_id": current_path.get("id"), "retry": retry_count
            })
            return "retry"
        else:
            # Exhausted retries — forward with partial flag
            audit_log(audit_dir, run_id, "confidence_gate:MED_forward", {
                "path_id": current_path.get("id")
            })
            return "analyze"

    # LOW or not vulnerable
    audit_log(audit_dir, run_id, "confidence_gate:LOW_discard", {
        "path_id": current_path.get("id"), "confidence": confidence
    })
    return "next_path"


def next_path(state: PentestState) -> dict:
    """
    LangGraph node — advance current_path_idx to the next path.
    Called when confidence is LOW (discard current path).
    """
    idx = state.get("current_path_idx", 0)
    prioritized = state.get("prioritized", [])
    new_idx = idx + 1

    if new_idx >= len(prioritized):
        # All paths processed
        return {"current_path_idx": new_idx, "current_path": None}

    return {"current_path_idx": new_idx}


def increment_retry(state: PentestState) -> dict:
    """
    LangGraph node — increment retry counter before re-running verify_enrich.
    Called when confidence is MED and retry_count < max_retries.
    """
    retry_count = state.get("verify_retry_count", 0)
    return {"verify_retry_count": retry_count + 1}


def advance_after_analyze(state: PentestState) -> dict:
    """
    LangGraph node — advance current_path_idx after a path has been analyzed.
    Called after the analyze fan-out completes.
    """
    idx = state.get("current_path_idx", 0)
    prioritized = state.get("prioritized", [])
    new_idx = idx + 1

    updates: dict = {"current_path_idx": new_idx}

    if new_idx >= len(prioritized):
        updates["current_path"] = None
    
    return updates
