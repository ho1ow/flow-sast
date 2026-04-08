"""
phases/1_catalog/checkmarx_loader.py
──────────────────────────────────────
SARIF loader cho Checkmarx output.

Mục đích: dùng Checkmarx output làm SEED, không phải ground truth.
  - CATALOG: extract known sources/sinks/locations từ CX findings
  - CONNECT: dùng cx_seed để boost triage score (+2 per match)

KHÔNG đưa vào Claude context — Claude phải đưa ra independent judgment.
Claude chỉ thấy code, không thấy CX labels/severity.

Tại sao hữu ích:
  - Nhanh hơn cho known patterns (CX đã scan)
  - flow-sast tập trung vào những gì CX miss:
    business logic, object taint, custom wrapper sinks
  - Không bias Claude analysis (CX không xuất hiện trong prompt)

State key: cx_seed = {
    "locations":      {(file, line): vuln_type}   # CX đã flag
    "custom_sinks":   {fn_name: vuln_type}         # sinks CX dùng mà catalog chưa có
    "custom_sources": {param: "user_input"}        # sources CX dùng
    "cx_rules":       {rule_id: description}       # CX rule metadata
    "stats":          {total, by_severity, by_type}
}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.reliability import audit_log


# ── SARIF severity → internal mapping ────────────────────────────────────────
SARIF_LEVEL_MAP = {
    "error":   "CRITICAL",
    "warning": "HIGH",
    "note":    "MED",
    "none":    "LOW",
}

# Checkmarx rule ID prefix → vuln_type hint
CX_RULE_HINTS: Dict[str, str] = {
    "SQL_Injection":        "sqli",
    "Reflected_XSS":       "xss",
    "Stored_XSS":          "xss",
    "DOM_XSS":             "xss",
    "Command_Injection":   "rce",
    "Code_Injection":      "rce",
    "Path_Traversal":      "path_traversal",
    "SSRF":                "ssrf",
    "XXE":                 "xxe",
    "Deserialization":     "deser",
    "SSTI":                "ssti",
    "IDOR":                "idor",
    "Missing_Authorization": "authz",
    "Hardcoded_Password":  "hardcode",
    "Hardcoded_Secret":    "hardcode",
    "Weak_Cryptography":   "crypto",
    "Open_Redirect":       "redirect",
    "LDAP_Injection":      "sqli",
    "Header_Injection":    "crlf",
}


def load_checkmarx_sarif(
    sarif_path: str,
    run_id: str,
    audit_dir: str = "pentest_logs/audit_trail",
) -> dict:
    """
    Parse Checkmarx SARIF output → cx_seed dict.

    Returns:
        {"cx_seed": {...}}  → merged into PentestState
    """
    path = Path(sarif_path)
    if not path.exists():
        raise FileNotFoundError(f"Checkmarx SARIF not found: {sarif_path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid SARIF JSON: {e}") from e

    locations: Dict[Tuple[str, int], str] = {}   # (file, line) → vuln_type
    custom_sinks: Dict[str, str] = {}             # fn_name → vuln_type
    custom_sources: Dict[str, str] = {}           # param_name → "user_input"
    cx_rules: Dict[str, str] = {}                 # rule_id → description

    stats = {"total": 0, "by_severity": {}, "by_type": {}}

    for run in data.get("runs", []):
        # Extract rule metadata
        tool_rules = (run.get("tool", {})
                         .get("driver", {})
                         .get("rules", []))
        for rule in tool_rules:
            rid = rule.get("id", "")
            desc = (rule.get("shortDescription", {}).get("text", "")
                    or rule.get("fullDescription", {}).get("text", ""))
            cx_rules[rid] = desc

        # Parse results
        for result in run.get("results", []):
            rule_id  = result.get("ruleId", "")
            level    = result.get("level", "warning")
            sev      = SARIF_LEVEL_MAP.get(level, "MED")
            vuln_type = _infer_vuln_type(rule_id)

            stats["total"] += 1
            stats["by_severity"][sev]       = stats["by_severity"].get(sev, 0) + 1
            stats["by_type"][vuln_type]     = stats["by_type"].get(vuln_type, 0) + 1

            # Extract all locations in this finding
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                uri  = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                line = region.get("startLine", 0)
                if uri and line:
                    # Normalize path (remove %SRCROOT% prefix etc)
                    uri = _normalize_uri(uri)
                    locations[(uri, line)] = vuln_type

            # Extract code flow sinks/sources (dataflow path steps)
            for flow in result.get("codeFlows", []):
                thread_flows = flow.get("threadFlows", [])
                for thread in thread_flows:
                    steps = thread.get("locations", [])
                    # First step → source; Last step → sink
                    if steps:
                        _extract_source_from_step(steps[0],  custom_sources)
                        _extract_sink_from_step(steps[-1],   custom_sinks, vuln_type)

    cx_seed = {
        "locations":      {f"{f}:{ln}": vt for (f, ln), vt in locations.items()},
        "location_set":   {(f, ln) for (f, ln) in locations.keys()},
        "custom_sinks":   custom_sinks,
        "custom_sources": custom_sources,
        "cx_rules":       cx_rules,
        "sarif_path":     str(path.resolve()),
        "stats":          stats,
    }

    audit_log(audit_dir, run_id, "checkmarx_loader:done", {
        "sarif":    sarif_path,
        "total":    stats["total"],
        "locations": len(locations),
        "custom_sinks": len(custom_sinks),
    })

    return {"cx_seed": cx_seed}


def get_triage_boost(cx_seed: dict, source_file: str, source_line: int,
                     sink_file: str, sink_line: int) -> Tuple[int, str]:
    """
    Kiểm tra xem path có match với CX findings không.
    Returns: (boost_score, reason)

    Called from triage.py — KHÔNG inject vào Claude context.
    """
    if not cx_seed:
        return 0, ""

    location_set = cx_seed.get("location_set", set())
    boost = 0
    reasons = []

    # Source location match
    if (source_file, source_line) in location_set:
        boost += 2
        reasons.append("cx_source_match")

    # Sink location match
    if (sink_file, sink_line) in location_set:
        boost += 2
        reasons.append("cx_sink_match")

    # Both match in same CX finding → high confidence path
    src_key = f"{source_file}:{source_line}"
    snk_key = f"{sink_file}:{sink_line}"
    locations = cx_seed.get("locations", {})
    if src_key in locations and snk_key in locations:
        if locations[src_key] == locations[snk_key]:
            boost += 1  # same vuln type on both ends
            reasons.append("cx_same_vuln_type")

    return boost, "+".join(reasons) if reasons else ""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _infer_vuln_type(rule_id: str) -> str:
    for pattern, vuln_type in CX_RULE_HINTS.items():
        if pattern.lower() in rule_id.lower():
            return vuln_type
    return "unknown"


def _normalize_uri(uri: str) -> str:
    """Remove SARIF base URI markers and normalize path separators."""
    uri = uri.replace("%SRCROOT%/", "").replace("%SRCROOT%\\", "")
    uri = uri.lstrip("/")
    return uri


def _extract_source_from_step(step: dict, custom_sources: dict) -> None:
    """Extract user-controlled source parameter from first flow step."""
    loc = step.get("location", {})
    snippet = (loc.get("physicalLocation", {})
                  .get("region", {})
                  .get("snippet", {})
                  .get("text", ""))
    logical = loc.get("logicalLocations", [{}])[0].get("fullyQualifiedName", "")
    if snippet and len(snippet) < 80 and any(
        kw in snippet.lower() for kw in
        ["$_get", "$_post", "$_request", "request.", "input(", "params["]
    ):
        custom_sources[snippet.strip()[:60]] = "user_input"
    if logical:
        custom_sources[logical.split(".")[-1]] = "user_input"


def _extract_sink_from_step(step: dict, custom_sinks: dict, vuln_type: str) -> None:
    """Extract sink function name from last flow step."""
    loc = step.get("location", {})
    logical = loc.get("logicalLocations", [{}])[0].get("fullyQualifiedName", "")
    snippet = (loc.get("physicalLocation", {})
                  .get("region", {})
                  .get("snippet", {})
                  .get("text", ""))
    fn_name = logical.split(".")[-1] if logical else ""
    if fn_name and fn_name not in {"", "main", "run", "execute"}:
        custom_sinks[fn_name] = vuln_type
    # Try extract function name from snippet
    if snippet and "(" in snippet:
        candidate = snippet.split("(")[0].strip().split()[-1] if snippet.strip() else ""
        if candidate and len(candidate) < 50 and candidate.isidentifier():
            custom_sinks[candidate] = vuln_type


def print_cx_summary(cx_seed: dict) -> None:
    """Print Checkmarx seed summary to stdout (called from main.py)."""
    stats = cx_seed.get("stats", {})
    print(f"\n  \033[36m▶ Checkmarx seed loaded:\033[0m")
    print(f"    Total findings : {stats.get('total', 0)}")
    print(f"    Locations      : {len(cx_seed.get('locations', {}))}")
    print(f"    Custom sinks   : {len(cx_seed.get('custom_sinks', {}))}")
    by_sev = stats.get("by_severity", {})
    if by_sev:
        print(f"    By severity    : " + " | ".join(
            f"{k}:{v}" for k, v in sorted(by_sev.items())))
    by_type = stats.get("by_type", {})
    if by_type:
        top = sorted(by_type.items(), key=lambda x: -x[1])[:5]
        print(f"    Top types      : " + " | ".join(f"{k}:{v}" for k, v in top))
    print(f"  \033[2m  Note: CX seed used for prioritization only — NOT in Claude context\033[0m\n")
