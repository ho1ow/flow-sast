"""
core/reliability.py
────────────────────
4-layer reliability system for the pentest pipeline:

1. State persistence  — shelve checkpoint after every node
2. Retry + backoff    — tenacity exponential backoff (2/4/8 s)
                        Distinguishes RateLimit vs generic APIError
3. Audit trail        — JSONL append-only log per run
4. Error isolation    — safe_node() decorator catches all node exceptions,
                        appends to state.errors[], pipeline continues
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import shelve
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import anthropic
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)
import logging

logger = logging.getLogger("pentest_agent.reliability")

# ─────────────────────────────────────────────────────────────────────────────
# 1. State Persistence (shelve checkpoint)
# ─────────────────────────────────────────────────────────────────────────────


def checkpoint_save(state: dict, checkpoint_dir: str, run_id: str, node_name: str) -> None:
    """Persist the pipeline state after a node completes."""
    path = Path(checkpoint_dir)
    path.mkdir(parents=True, exist_ok=True)
    db_path = str(path / run_id)
    try:
        with shelve.open(db_path, flag="c") as db:
            key = f"{run_id}::{node_name}"
            db[key] = state
            db["__latest__"] = {"node": node_name, "ts": _now_iso()}
    except Exception as exc:
        logger.warning("checkpoint_save failed: %s", exc)


def checkpoint_load(checkpoint_dir: str, run_id: str) -> Optional[dict]:
    """Load the most recent checkpoint for a run_id, or None if not found."""
    db_path = str(Path(checkpoint_dir) / run_id)
    try:
        with shelve.open(db_path, flag="r") as db:
            latest = db.get("__latest__")
            if latest is None:
                return None
            key = f"{run_id}::{latest['node']}"
            return dict(db.get(key, {})) or None
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 2. Retry + Backoff
# ─────────────────────────────────────────────────────────────────────────────


class _RateLimitError(Exception):
    """Wrapper so tenacity can distinguish rate-limit from other API errors."""


def _wrap_rate_limit(exc: Exception) -> Exception:
    """Convert anthropic.RateLimitError to _RateLimitError for routing."""
    if isinstance(exc, anthropic.RateLimitError):
        return _RateLimitError(str(exc))
    return exc


# Decorator factories — use these on functions that call Claude or external APIs

def retry_on_rate_limit(max_attempts: int = 5):
    """Exponential backoff specifically for rate-limit errors (2/4/8/16/32 s)."""
    return retry(
        retry=retry_if_exception_type(_RateLimitError),
        wait=wait_exponential(multiplier=2, min=2, max=32),
        stop=stop_after_attempt(max_attempts),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )


def retry_on_api_error(max_attempts: int = 3):
    """Exponential backoff for transient API / network errors."""
    return retry(
        retry=retry_if_exception_type((anthropic.APIError, ConnectionError, TimeoutError)),
        wait=wait_exponential(multiplier=2, min=2, max=8),
        stop=stop_after_attempt(max_attempts),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )


def with_retry(fn: Callable, max_attempts: int = 3, rate_limit_max: int = 5):
    """
    Functional wrapper — wraps fn with both rate-limit and API-error retry.
    Returns a new callable; useful when you can't use decorators directly.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        attempt = 0
        delays = [2, 4, 8, 16, 32]
        while True:
            try:
                return fn(*args, **kwargs)
            except anthropic.RateLimitError as exc:
                if attempt >= rate_limit_max:
                    raise
                delay = delays[min(attempt, len(delays) - 1)]
                logger.warning("RateLimit hit — sleeping %ds (attempt %d)", delay, attempt + 1)
                time.sleep(delay)
                attempt += 1
            except (anthropic.APIError, ConnectionError, TimeoutError) as exc:
                if attempt >= max_attempts:
                    raise
                delay = delays[min(attempt, len(delays) - 1)]
                logger.warning("APIError %s — retrying in %ds", exc, delay)
                time.sleep(delay)
                attempt += 1
    return wrapper


# ─────────────────────────────────────────────────────────────────────────────
# 3. Audit Trail (JSONL)
# ─────────────────────────────────────────────────────────────────────────────


def _audit_file(audit_dir: str, run_id: str) -> Path:
    p = Path(audit_dir)
    p.mkdir(parents=True, exist_ok=True)
    return p / f"{run_id}.jsonl"


def audit_log(
    audit_dir: str,
    run_id: str,
    event: str,
    data: dict,
    prompt_text: Optional[str] = None,
) -> None:
    """Append a structured event to the run's JSONL audit trail."""
    entry: dict[str, Any] = {
        "ts": _now_iso(),
        "run_id": run_id,
        "event": event,
        "data": data,
    }
    if prompt_text is not None:
        entry["prompt_hash"] = hashlib.sha256(prompt_text.encode()).hexdigest()[:16]

    log_path = _audit_file(audit_dir, run_id)
    try:
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except Exception as exc:
        logger.warning("audit_log write failed: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Error Isolation — safe_node decorator
# ─────────────────────────────────────────────────────────────────────────────


def safe_node(node_name: str):
    """
    Decorator for LangGraph node functions.

    If the node raises any exception:
    - Logs the traceback
    - Appends an error entry to state["errors"]
    - Returns the state unchanged so the pipeline continues

    Usage:
        @safe_node("catalog_semgrep")
        def catalog_semgrep(state: PentestState) -> PentestState:
            ...
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(state: dict) -> dict:
            try:
                return fn(state)
            except Exception as exc:
                tb = traceback.format_exc()
                logger.error("[%s] node error: %s\n%s", node_name, exc, tb)
                error_entry = {
                    "node": node_name,
                    "error": str(exc),
                    "traceback": tb,
                    "ts": _now_iso(),
                }
                # Append to errors list (works with operator.add reducer)
                return {"errors": [error_entry]}
        return wrapper
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def load_config(config_path: str = "tools_config.json") -> dict:
    """Load tools_config.json from disk. Falls back to .env file if present."""
    p = Path(config_path)
    if not p.exists():
        # try fallback
        p = Path("tools_config.json.env")
    if not p.exists():
        raise FileNotFoundError(
            "tools_config.json not found. "
            "Copy tools_config.json.env to tools_config.json and fill in values."
        )
    with p.open(encoding="utf-8") as f:
        return json.load(f)
