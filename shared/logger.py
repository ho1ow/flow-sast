"""
shared/logger.py
─────────────────
Standalone audit logging and retry utilities for the CLI tool.
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

try:
    import anthropic
except ImportError:
    anthropic = None

logger = logging.getLogger("flow_sast.logger")


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _audit_file(audit_dir: str, run_id: str) -> Path:
    p = Path(audit_dir)
    p.mkdir(parents=True, exist_ok=True)
    return p / f"audit_{run_id}.jsonl"


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


def with_retry(fn: Callable, max_attempts: int = 3, rate_limit_max: int = 5):
    """
    Functional wrapper — wraps fn with both rate-limit and API-error retry.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not anthropic:
            return fn(*args, **kwargs)
            
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
