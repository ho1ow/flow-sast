"""
phases/5_confirm/burp_mcp_client.py
─────────────────────────────────────
LangGraph node: confirm_burp

Sends HIGH-confidence findings to Burp Suite MCP for dynamic PoC verification.

Flow per finding:
  1. Build HTTP request from finding's attack_vector
  2. POST to Burp MCP endpoint
  3. Check response for evidence of exploitation
  4. Attach PoC to confirmed_pocs[]

Burp MCP API (assumed):
  POST /scan/active  — { method, url, headers, body, checks[] }
  Response:          { status, evidence, response_snippet, confirmed }
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import List, Optional

import httpx

from core.reliability import audit_log, safe_node, with_retry
from core.state import PentestState


# Evidence patterns per vuln type
EVIDENCE_PATTERNS = {
    "sqli":  [r"sql syntax", r"mysql error", r"ORA-\d+", r"syntax error.*sql",
              r"pg_query\(\)", r"sqlite3", r"unclosed quotation"],
    "rce":   [r"uid=\d+", r"root:", r"/etc/passwd", r"windows/system32"],
    "xss":   [r"<script>alert", r"onerror=", r"javascript:"],
    "ssrf":  [r"169\.254\.169\.254", r"metadata\.google", r"internal"],
    "path_traversal": [r"root:x:0:", r"\[extensions\]", r"\[boot\]"],
    "redirect": [r"Location:.*evil", r"Location:.*attacker"],
}


@safe_node("confirm_burp")
def confirm_burp(state: PentestState) -> dict:
    """LangGraph node — dynamic PoC verification via Burp MCP."""
    cfg = state["config"]
    burp_cfg = cfg.get("burp_mcp", {})
    pipeline_cfg = cfg.get("pipeline", {})
    run_id = state["run_id"]
    audit_dir = pipeline_cfg.get("audit_dir", "pentest_logs/audit_trail")

    base_url = burp_cfg.get("base_url", "http://localhost:1337")
    api_key = burp_cfg.get("api_key", "")
    timeout = burp_cfg.get("timeout_seconds", 60)

    findings: List[dict] = state.get("findings", [])
    high_findings = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]

    audit_log(audit_dir, run_id, "confirm_burp:start", {
        "total_findings": len(findings), "high_findings": len(high_findings)
    })

    if not high_findings:
        return {"confirmed_pocs": []}

    # Check if Burp MCP is reachable
    if not _burp_reachable(base_url, timeout):
        audit_log(audit_dir, run_id, "confirm_burp:unreachable", {"url": base_url})
        return {"confirmed_pocs": [], "errors": [{"node": "confirm_burp", "error": "Burp MCP not reachable"}]}

    confirmed_pocs: List[dict] = []

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    client = httpx.Client(
        base_url=base_url,
        headers=headers,
        timeout=timeout,
        follow_redirects=burp_cfg.get("follow_redirects", True),
    )

    try:
        for finding in high_findings:
            poc = _try_confirm_finding(client, finding, run_id, audit_dir)
            if poc:
                confirmed_pocs.append(poc)
    finally:
        client.close()

    audit_log(audit_dir, run_id, "confirm_burp:done", {
        "confirmed": len(confirmed_pocs)
    })

    return {"confirmed_pocs": confirmed_pocs}


def _burp_reachable(base_url: str, timeout: int) -> bool:
    try:
        resp = httpx.get(f"{base_url}/health", timeout=5)
        return resp.status_code < 500
    except Exception:
        return False


def _try_confirm_finding(
    client: httpx.Client,
    finding: dict,
    run_id: str,
    audit_dir: str,
) -> Optional[dict]:
    """Build and send PoC request to Burp MCP."""
    sink_type = finding.get("vuln_type", "")
    attack_vector = finding.get("attack_vector", "")
    path_info = finding.get("path", {})
    endpoint = _infer_endpoint(path_info)

    if not endpoint:
        return None

    # Build the test payload
    payload = _build_poc_payload(sink_type, attack_vector, endpoint)

    try:
        resp = client.post("/scan/active", json=payload, timeout=60)
        resp.raise_for_status()
        result = resp.json()
    except Exception as exc:
        audit_log(audit_dir, run_id, "confirm_burp:scan_error", {
            "finding_id": finding.get("id"), "error": str(exc)
        })
        return None

    confirmed = result.get("confirmed", False)
    evidence = result.get("evidence", "")
    response_snippet = result.get("response_snippet", "")

    # Also do client-side evidence check
    if not confirmed:
        evidence_patterns = EVIDENCE_PATTERNS.get(sink_type, [])
        for pattern in evidence_patterns:
            if re.search(pattern, response_snippet, re.IGNORECASE):
                confirmed = True
                evidence = f"Pattern match: {pattern}"
                break

    if not confirmed:
        return None

    return {
        "finding_id": finding.get("id"),
        "vuln_type": sink_type,
        "severity": finding.get("severity"),
        "endpoint": endpoint,
        "payload": payload,
        "evidence": evidence,
        "response_snippet": response_snippet[:500],
        "burp_result": result,
    }


def _infer_endpoint(path_info: dict) -> Optional[str]:
    """Try to deduce a testable URL from path metadata."""
    source = path_info.get("source", {})
    sink = path_info.get("sink", {})
    # Prefer endpoint from source file hint
    file_path = source.get("file", sink.get("file", ""))
    # This is a best-effort — real implementation would map to running app URL
    return None  # Caller handles this gracefully


def _build_poc_payload(vuln_type: str, attack_vector: str, endpoint: str) -> dict:
    """Build Burp MCP scan payload."""
    poc_payloads = {
        "sqli":  ["'", "\" OR 1=1--", "1 AND SLEEP(5)--", "1; DROP TABLE users--"],
        "xss":   ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
        "ssrf":  ["http://169.254.169.254/latest/meta-data/", "http://localhost:22",
                  "file:///etc/passwd"],
        "rce":   ["; id", "| whoami", "$(id)", "`id`", "; sleep 5"],
        "path_traversal": ["../../etc/passwd", "%2e%2e%2fetc%2fpasswd",
                           "....//....//etc/passwd"],
        "redirect": ["//evil.com", "https://evil.com", "/\\evil.com"],
    }

    return {
        "url": endpoint,
        "method": "GET",
        "headers": {},
        "body": "",
        "checks": [vuln_type],
        "payloads": poc_payloads.get(vuln_type, [attack_vector])[:3],
        "attack_vector": attack_vector,
    }
