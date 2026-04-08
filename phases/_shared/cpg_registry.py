"""
phases/_shared/cpg_registry.py
────────────────────────────────
Singleton registry that holds the Joern CPG ID for the current run.
Ensures CPG is built only once and shared between path_structural and path_object.
"""

from __future__ import annotations

from typing import Optional

from phases._2_connect.joern_client import JoernClient

# Module-level singleton — one client + one CPG per process
JOERN_CLIENT: Optional[JoernClient] = None
_CPG_ID: Optional[str] = None
_BUILT_FOR_RUN: Optional[str] = None


def get_or_build_cpg(state: dict) -> Optional[str]:
    """
    Return the cached CPG ID for this run_id, or build a new one.
    Returns None if Joern is unavailable (error isolated by safe_node above).
    """
    global JOERN_CLIENT, _CPG_ID, _BUILT_FOR_RUN

    cfg = state["config"]
    joern_cfg = cfg.get("joern", {})
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    repo_path = state["repo_path"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")

    if _BUILT_FOR_RUN == run_id and _CPG_ID is not None:
        return _CPG_ID

    # Init client if needed
    if JOERN_CLIENT is None:
        JOERN_CLIENT = JoernClient(
            base_url=joern_cfg.get("base_url", "http://localhost:8080"),
            timeout=joern_cfg.get("timeout_seconds", 300),
        )

    try:
        from core.reliability import audit_log
        cpg_id, _ = JOERN_CLIENT.build_and_query(
            repo_path,
            query="cpg.metaData.l",  # smoke-test query
            build_timeout=joern_cfg.get("cpg_build_timeout", 600),
            audit_dir=audit_dir,
            run_id=run_id,
        )
        _CPG_ID = cpg_id
        _BUILT_FOR_RUN = run_id
        return cpg_id
    except Exception as exc:
        from core.reliability import audit_log
        audit_log(audit_dir, run_id, "cpg_registry:error", {"error": str(exc)})
        return None


def close_cpg_if_done(run_id: str) -> None:
    """Call after all Joern queries for a run are complete."""
    global JOERN_CLIENT, _CPG_ID, _BUILT_FOR_RUN
    if JOERN_CLIENT and _CPG_ID:
        JOERN_CLIENT.delete_cpg(_CPG_ID)
    _CPG_ID = None
    _BUILT_FOR_RUN = None
