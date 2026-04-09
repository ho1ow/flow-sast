#!/usr/bin/env python3
"""
scan.py
────────
Standalone CLI entry point for the flow-sast tool.
Orchestrates Phase 1 (Catalog), Phase 2 (Connect), and Triage into a linear pipeline.
Outputs findings.md and findings.json for Claude Code downstream agent analysis.
"""

import argparse
import json
import os
import time
from pathlib import Path

# -- Catalog Phase imports --
from catalog.semgrep_runner import catalog_semgrep
from catalog.api_parser import catalog_api
from catalog.secrets_runner import catalog_secrets
from catalog.gitnexus_context import catalog_gitnexus_context, generate_catalog_queries
from catalog.gitnexus_runner import catalog_gitnexus
from catalog.context_parser import parse_business_context

# -- Connect Phase & Triage imports --
from connect.gitnexus_connect import connect_gitnexus
from connect.triage import triage_score
from connect.gitnexus_fp_filter import gitnexus_fp_filter
from connect.joern_filter import joern_pre_filter
from catalog.checkmarx_loader import load_checkmarx_sarif

def main():
    parser = argparse.ArgumentParser(description="flow-sast Standalone Scanner")
    parser.add_argument("--repo", required=True, help="Path to the repository to scan")
    parser.add_argument("--stack", default="auto", help="Project stack (e.g., auto, php, python, node)")
    parser.add_argument("--run-id", default="", help="Optional run ID (timestamp if empty)")
    parser.add_argument("--checkmarx-sarif", help="Path to external Checkmarx SARIF result file (used as triage seed)")
    parser.add_argument("--no-joern", action="store_true", help="Skip Joern CPG validation")
    parser.add_argument("--config", help="Path to configuration JSON file")
    parser.add_argument("--context", help="Path to business context Markdown/Text file")

    args = parser.parse_args()

    repo = os.path.abspath(args.repo)
    stack = args.stack
    run_id = args.run_id or str(int(time.time()))
    no_joern = args.no_joern

    out_dir = Path("reports") / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    business_ctx = {}
    if args.context and os.path.exists(args.context):
        print(f"[*] Parsing business context from {args.context}...")
        with open(args.context, "r", encoding="utf-8") as f:
            context_text = f.read()
            business_ctx = parse_business_context(context_text, run_id)
        with open(out_dir / "business_ctx.json", "w", encoding="utf-8") as f:
            json.dump(business_ctx, f, indent=2)
        print("[*] Successfully parsed and saved business context.")

    print(f"[*] Starting flow-sast scan via scan.py")
    print(f"[*] Repository : {repo}")
    print(f"[*] Stack      : {stack}")
    print(f"[*] Run ID     : {run_id}")
    print(f"[*] Output Dir : {out_dir}")

    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, "r") as f:
            config = json.load(f)

    # ── Phase 1: Catalog ──────────────────────────────────────────────────────
    print("\n[+] Phase 1: Cataloging")
    
    # 1. Semgrep Runner
    print("  -> Running Semgrep...")
    semgrep_res = catalog_semgrep(repo, stack, run_id, config.get("semgrep"), business_ctx)
    sources = semgrep_res.get("sources", [])
    sinks = semgrep_res.get("sinks", [])
    
    # 2. Secrets Runner
    print("  -> Running Gitleaks/Secrets scan...")
    secrets_res = catalog_secrets(repo, run_id, config.get("secrets"))
    findings = secrets_res.get("findings", [])
    
    # 3. API Parser
    print("  -> Parsing API endpoints...")
    api_res = catalog_api(repo, stack, sources, sinks, run_id, config.get("api"))
    endpoints = api_res.get("endpoints", [])
    
    # 4. Gitnexus Context + Runner
    print("  -> Extracting GitNexus context & running Cypher queries...")
    business_ctx_res = catalog_gitnexus_context(repo, endpoints, run_id, config.get("gitnexus"), business_ctx)
    business_context = business_ctx_res.get("business_context", {})
    
    gn_res = catalog_gitnexus(repo, run_id, stack, config.get("gitnexus"))
    custom_sinks = gn_res.get("custom_sinks", [])
    
    catalog_output = {
        "sources": sources,
        "sinks": sinks,
        "endpoints": endpoints,
        "custom_sinks": custom_sinks,
        "business_context": business_context
    }
    
    with open(out_dir / "catalog.json", "w") as f:
        json.dump(catalog_output, f, indent=2)

    # ── Phase 2: Connect ──────────────────────────────────────────────────────
    print("\n[+] Phase 2: Connect")
    
    # Checkmarx Seed loading
    cx_seed = None
    if args.checkmarx_sarif and os.path.exists(args.checkmarx_sarif):
        print(f"  -> Loading Checkmarx seed from {args.checkmarx_sarif}...")
        cx_res = load_checkmarx_sarif(args.checkmarx_sarif, run_id)
        cx_seed = cx_res.get("cx_seed")

    print("  -> Connecting structural and object paths via GitNexus...")
    connect_res = connect_gitnexus(repo, catalog_output, run_id, config.get("gitnexus"))
    candidate_paths = connect_res.get("candidate_paths", [])

    print("  -> Triaging paths...")
    triage_res = triage_score(candidate_paths, sources, run_id, config.get("pipeline"), cx_seed, business_ctx)
    prioritized = triage_res.get("prioritized", [])

    print("  -> Running Gitnexus False Positive filter...")
    fp_res = gitnexus_fp_filter(prioritized, run_id, config.get("pipeline"))
    fp_filtered_paths = fp_res.get("prioritized", [])

    joern_res = {}
    if not no_joern:
        print("  -> Running Joern CPG filter...")
        joern_res = joern_pre_filter(repo, fp_filtered_paths, run_id, config.get("joern"))
        final_prioritized = joern_res.get("prioritized", [])
        confirmed_findings = joern_res.get("joern_confirmed", [])
    else:
        print("  -> Skipping Joern CFG filter as requested.")
        final_prioritized = [{"path_decision": "full_verify", **p} for p in fp_filtered_paths]
        confirmed_findings = []

    # Map candidate paths to findings properly for Claude to analyze
    for path in final_prioritized:
        findings.append({
            "id": path["id"],
            "category": path["sink"]["category"],
            "vuln_type": path["sink"].get("type", "unknown"),
            "severity": "HIGH",
            "confidence": "MED",
            "needs_dynamic": False,
            "file": path["sink"]["file"],
            "line_start": path["sink"]["line"],
            "line_end": path["sink"]["line"],
            "code_snippet": path["sink"]["code"],
            "path": path,
            "joern_sanitizer": path.get("joern_sanitizer", []),
            "path_decision": path.get("path_decision", "skip"),
            "score": path.get("score", 0),
        })

    # Filter out skipped paths
    findings = [f for f in findings if f.get("path_decision") not in ("skip_no_flow", "skip_fp", "skip")]

    print("\n[+] Scan Complete")
    print(f"  -> Total findings identified for review/export: {len(findings)}")

    with open(out_dir / "findings.json", "w") as f:
        json.dump({"findings": findings}, f, indent=2)

    # Output Markdown Findings
    md_content = f"# Scan Findings Report - {run_id}\n\n"
    for finding in findings:
        md_content += f"## {finding['category']} - {finding['vuln_type']} ({finding['severity']})\n"
        md_content += f"- File: {finding['file']}:{finding['line_start']}\n"
        md_content += f"- Score: {finding.get('score', 'N/A')}\n"
        md_content += f"- Path Decision: {finding.get('path_decision', 'N/A')}\n"
        if finding.get('path'):
            call_chain = " -> ".join(finding['path'].get('call_chain', []))
            md_content += f"- Path: {call_chain}\n"
        md_content += "\n"

    with open(out_dir / "findings.md", "w") as f:
        f.write(md_content)

    print(f"[*] Results written to {out_dir}/findings.json and {out_dir}/findings.md")
    print("[*] Claude Code can now pick up these files and proceed to Verify phase using CLAUDE.md guidance.")


if __name__ == "__main__":
    main()
