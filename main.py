"""
main.py
────────
flow-sast — CLI entry point.

Usage:
  python main.py --repo /path/to/repo --stack django
  python main.py --repo /path/to/repo --stack auto --run-id myrun001 --resume
  python main.py --repo /path/to/repo --stack flask --dry-run
  python main.py --repo /path/to/repo --stack laravel --context business.md

Output:
  reports/<run_id>/findings.sarif    — SARIF findings file
  reports/<run_id>/findings.json     — Raw findings JSON
  pentest_logs/audit_trail/<run_id>.jsonl  — Audit trail
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from core.reliability import load_config, audit_log, checkpoint_load
from core.state import initial_state
from core.workflow import build_graph
from phases._1_catalog.checkmarx_loader import load_checkmarx_sarif, print_cx_summary

console = Console()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="flow-sast — automated whitebox SAST + AI verification pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--repo",    required=True,  help="Path to repository to analyze")
    parser.add_argument("--stack",   default="auto",
                        choices=["auto", "django", "flask", "fastapi", "spring", "express",
                                 "nestjs", "gin", "rails", "php", "laravel",
                                 "csharp", "dotnet", "aspnet"],
                        help="Technology stack (auto = detect from file extensions)")
    parser.add_argument("--context", default=None,
                        help="(Optional) Path to a .md/.txt file describing system business context "
                             "(e.g. what the app does, critical assets, business flows). "
                             "If provided, overrides auto-detection from README/docs.")
    parser.add_argument("--checkmarx-sarif", default=None, dest="checkmarx_sarif",
                        help="(Optional) Path to Checkmarx SARIF output file. "
                             "Used as seed for CATALOG sources/sinks and triage boost signal. "
                             "NOT injected into Claude context — preserves independent AI judgment.")
    parser.add_argument("--run-id",  default=None,   help="Custom run ID (default: auto-generated)")
    parser.add_argument("--config",  default="tools_config.json",
                        help="Path to tools_config.json (default: tools_config.json)")
    parser.add_argument("--resume",  action="store_true",
                        help="Resume from last checkpoint for this run-id")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate config + catalog only, skip verify/analyze")
    parser.add_argument("--no-joern", action="store_true",
                        help="Skip Joern CPG queries (catalog + analyze only)")
    parser.add_argument("--no-burp", action="store_true",
                        help="Skip Burp MCP dynamic verification")
    parser.add_argument("--output",  default=None,
                        help="Custom output directory (default: reports/<run_id>)")
    args = parser.parse_args()

    # ── Setup ─────────────────────────────────────────────────────────────────
    console.print(Panel.fit(
        "[bold cyan]flow-sast[/bold cyan]\n"
        "[dim]Automated SAST + Semantic Verification Pipeline[/dim]",
        border_style="cyan",
    ))

    repo_path = str(Path(args.repo).resolve())
    if not Path(repo_path).exists():
        console.print(f"[red]✗ Repository not found: {repo_path}[/red]")
        sys.exit(1)

    # Load config
    try:
        cfg = load_config(args.config)
    except FileNotFoundError as e:
        console.print(f"[red]✗ {e}[/red]")
        sys.exit(1)

    # Apply CLI overrides to config
    if args.no_burp:
        cfg.setdefault("burp_mcp", {})["skip"] = True
    if args.no_joern:
        cfg.setdefault("joern", {})["skip"] = True

    run_id = args.run_id or _generate_run_id(repo_path)
    checkpoint_dir = cfg.get("pipeline", {}).get("checkpoint_dir", "pentest_logs/checkpoints")
    audit_dir = cfg.get("pipeline", {}).get("audit_dir", "pentest_logs/audit_trail")
    output_dir = args.output or f"{cfg.get('pipeline', {}).get('output_dir', 'pentest_logs/output')}/{run_id}"

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    stack = args.stack
    if stack == "auto":
        stack = _detect_stack(repo_path)
        console.print(f"[dim]Auto-detected stack: [bold]{stack}[/bold][/dim]")

    console.print(f"[green]▶ Run ID:[/green] {run_id}")
    console.print(f"[green]▶ Repo:[/green] {repo_path}")
    console.print(f"[green]▶ Stack:[/green] {stack}")
    console.print(f"[green]▶ Output:[/green] {output_dir}")

    # Load user-provided business context (optional)
    user_context: dict = {}
    if args.context:
        ctx_path = Path(args.context)
        if ctx_path.exists():
            raw = ctx_path.read_text(encoding="utf-8", errors="ignore")
            user_context = {
                "system_type":     "user_provided",
                "description":     raw[:500],
                "raw_excerpts":    [raw[:2000]],
                "source":          str(ctx_path),
                "user_provided":   True,
            }
            console.print(f"[green]▶ Context:[/green] {ctx_path} ({len(raw)} chars)")
        else:
            console.print(f"[yellow]⚠ --context file not found: {ctx_path} — skipping[/yellow]")

    # ── Initial state ──────────────────────────────────────────────────────────
    state = initial_state(
        repo_path=repo_path,
        run_id=run_id,
        stack=stack,
        checkpoint_dir=checkpoint_dir,
        config=cfg,
    )
    if user_context:
        state["business_context"] = user_context  # override auto-detect

    # Resume from checkpoint?
    if args.resume:
        saved = checkpoint_load(checkpoint_dir, run_id)
        if saved:
            state = {**state, **saved}
            console.print(f"[yellow]↩ Resumed from checkpoint[/yellow]")
        else:
            console.print("[dim]No checkpoint found — starting fresh[/dim]")

    audit_log(audit_dir, run_id, "pipeline:start", {
        "repo": repo_path, "stack": stack, "dry_run": args.dry_run
    })

    # ── Build and run graph ────────────────────────────────────────────────────
    graph = build_graph(use_memory_saver=True)

    thread_config = {
        "configurable": {"thread_id": run_id},
        "max_concurrency": cfg.get("anthropic", {}).get("max_concurrency", 3),
    }

    start_time = time.time()
    final_state: dict = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Running pipeline...", total=None)

        try:
            for chunk in graph.stream(
                state,
                config=thread_config,
                stream_mode="updates",
            ):
                for node_name, node_output in chunk.items():
                    progress.update(task, description=f"[cyan]{node_name}[/cyan]")
                    final_state.update(node_output or {})

                    # Early exit for dry-run
                    if args.dry_run and node_name == "triage_score":
                        progress.stop()
                        _print_dry_run_summary(final_state)
                        return

        except KeyboardInterrupt:
            console.print("\n[yellow]⚠ Interrupted — partial results saved[/yellow]")

    elapsed = time.time() - start_time

    # ── Output ────────────────────────────────────────────────────────────────
    findings = final_state.get("findings", []) + state.get("findings", [])
    confirmed_pocs = final_state.get("confirmed_pocs", []) + state.get("confirmed_pocs", [])
    errors = final_state.get("errors", []) + state.get("errors", [])

    # Deduplicate findings
    seen: set[str] = set()
    unique_findings = []
    for f in findings:
        if f.get("id") not in seen:
            seen.add(f.get("id", ""))
            unique_findings.append(f)

    # Write SARIF
    sarif_path = Path(output_dir) / "findings.sarif"
    sarif = _to_sarif(unique_findings, repo_path, run_id)
    sarif_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")

    # Write raw JSON
    raw_path = Path(output_dir) / "findings.json"
    raw_path.write_text(
        json.dumps({
            "run_id": run_id,
            "repo": repo_path,
            "stack": stack,
            "elapsed_seconds": round(elapsed, 1),
            "findings": unique_findings,
            "confirmed_pocs": confirmed_pocs,
            "errors": errors,
            "stats": {
                "total_findings": len(unique_findings),
                "confirmed_pocs": len(confirmed_pocs),
                "errors": len(errors),
                "severity_breakdown": _severity_breakdown(unique_findings),
            },
        }, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    audit_log(audit_dir, run_id, "pipeline:done", {
        "elapsed": round(elapsed, 1),
        "findings": len(unique_findings),
        "confirmed": len(confirmed_pocs),
        "errors": len(errors),
    })

    _print_summary(unique_findings, confirmed_pocs, errors, elapsed, output_dir)


# ── Output formatters ──────────────────────────────────────────────────────────

def _print_summary(findings, pocs, errors, elapsed, output_dir) -> None:
    console.print()

    table = Table(title="📊 Findings Summary", show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    breakdown = _severity_breakdown(findings)
    colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green", "INFO": "dim"}
    for sev, count in breakdown.items():
        if count > 0:
            table.add_row(f"[{colors.get(sev, 'white')}]{sev}[/]", str(count))

    console.print(table)
    console.print(f"  [dim]Confirmed PoCs:[/dim] {len(pocs)}")
    console.print(f"  [dim]Pipeline errors:[/dim] {len(errors)}")
    console.print(f"  [dim]Elapsed:[/dim] {elapsed:.1f}s")
    console.print()
    console.print(f"[green]✓ Output:[/green] {output_dir}/findings.sarif")
    console.print(f"[green]✓ Raw JSON:[/green] {output_dir}/findings.json")


def _print_dry_run_summary(state: dict) -> None:
    console.print("\n[yellow]── DRY RUN SUMMARY ──[/yellow]")
    console.print(f"  Sources found:   {len(state.get('sources', []))}")
    console.print(f"  Sinks found:     {len(state.get('sinks', []))}")
    console.print(f"  Endpoints found: {len(state.get('endpoints', []))}")
    console.print(f"  Paths found:     {len(state.get('structural_paths', [])) + len(state.get('object_paths', []))}")
    console.print(f"  Prioritized:     {len(state.get('prioritized', []))}")


def _severity_breakdown(findings: list) -> dict:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts = {s: 0 for s in order}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _to_sarif(findings: list, repo_path: str, run_id: str) -> dict:
    """Convert findings to SARIF 2.1.0 format."""
    rules = {}
    results = []

    for f in findings:
        rule_id = f.get("sarif_rule_id", f"pentest/{f.get('vuln_type', 'unknown')}")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.get("vuln_type", "unknown"),
                "shortDescription": {"text": f.get("title", rule_id)},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{f.get('cwe', 'CWE-20').replace('CWE-', '')}.html",
                "properties": {
                    "cwe": f.get("cwe", ""),
                    "owasp": f.get("owasp", ""),
                    "tags": ["security", f.get("phase", "")],
                },
            }

        severity_map = {
            "CRITICAL": "error", "HIGH": "error",
            "MEDIUM": "warning", "LOW": "note", "INFO": "none",
        }
        level = severity_map.get(f.get("severity", "MEDIUM"), "warning")

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f.get("reasoning", f.get("title", ""))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.get("file", ""),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": f.get("line_start", 1),
                        "endLine": f.get("line_end", f.get("line_start", 1)),
                    },
                }
            }],
            "properties": {
                "confidence": f.get("confidence", "MED"),
                "attack_vector": f.get("attack_vector", ""),
                "fix": f.get("fix_example", ""),
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "flow-sast",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/ho1ow/flow-sast",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "originalUriBaseIds": {"%SRCROOT%": {"uri": f"file:///{repo_path}/"}},
            "properties": {"run_id": run_id},
        }],
    }


def _generate_run_id(repo_path: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    repo_hash = hashlib.md5(repo_path.encode()).hexdigest()[:6]
    return f"run_{ts}_{repo_hash}"


def _detect_stack(repo_path: str) -> str:
    """Heuristic stack detection from file extensions and config files."""
    repo = Path(repo_path)

    indicators = {
        "django":  ["manage.py", "settings.py", "wsgi.py", "django.conf"],
        "flask":   ["app.py", "application.py", "flask_app.py"],
        "fastapi": ["main.py"],  # weak — combined with import check
        "spring":  ["pom.xml", "build.gradle", "application.properties", "application.yml"],
        "express": ["package.json"],
        "nestjs":  ["nest-cli.json", "package.json"],
        "gin":     ["go.mod", "go.sum"],
        "rails":   ["Gemfile", "config/routes.rb", "Rakefile"],
        "laravel": ["artisan", "composer.json"],
    }

    file_set = {f.name for f in repo.rglob("*") if f.is_file()}
    ext_counts: dict[str, int] = {}
    for f in repo.rglob("*"):
        if f.is_file():
            ext_counts[f.suffix] = ext_counts.get(f.suffix, 0) + 1

    for stack, files in indicators.items():
        if any(fname in file_set for fname in files):
            return stack

    # Fallback by majority extension
    if ext_counts.get(".py", 0) > 0: return "flask"
    if ext_counts.get(".java", 0) > 0: return "spring"
    if ext_counts.get(".js", 0) > ext_counts.get(".ts", 0): return "express"
    if ext_counts.get(".ts", 0) > 0: return "nestjs"
    if ext_counts.get(".go", 0) > 0: return "gin"
    if ext_counts.get(".rb", 0) > 0: return "rails"
    if ext_counts.get(".php", 0) > 0: return "laravel"

    return "auto"


if __name__ == "__main__":
    main()
