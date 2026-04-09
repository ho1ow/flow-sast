"""
phases/1_catalog/api_parser.py
────────────────────────────────
LangGraph node: catalog_api

Multi-framework AST/regex-based API parameter extractor.
Produces a unified endpoint[] list with full param metadata.

Frameworks supported:
  Python:  FastAPI, Flask, Django, Starlette
  Java:    Spring MVC / Spring Boot
  JS/TS:   Express, Fastify, NestJS
  Go:      Gin, Echo, Chi, net/http
  PHP:     Laravel, Slim
  Ruby:    Rails

For each endpoint extracts:
  method, path, params[{name, type, location}], handler, file, line

Also computes catalog_checksum from all collected catalog data.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from shared.logger import audit_log


# ── Language → file extensions ───────────────────────────────────────────────
LANG_EXTS: Dict[str, List[str]] = {
    "python": [".py"],
    "java":   [".java"],
    "js":     [".js", ".cjs", ".mjs"],
    "ts":     [".ts"],
    "go":     [".go"],
    "php":    [".php"],
    "ruby":   [".rb"],
}

ALL_EXTS = [e for exts in LANG_EXTS.values() for e in exts]

# ── Regex patterns ────────────────────────────────────────────────────────────

# Python decorator-based routes (Flask/FastAPI/Starlette)
PY_DECORATOR_RE = re.compile(
    r'@(?:\w+\.)*(?:get|post|put|delete|patch|options|head|route)\s*'
    r'\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
PY_MULTI_METHOD_RE = re.compile(
    r'methods\s*=\s*\[([^\]]+)\]',
    re.IGNORECASE,
)

# FastAPI Depends / Query / Body / Form parameters
PY_PARAM_RE = re.compile(
    r'(\w+)\s*:\s*(?:Optional\[)?(\w+)(?:\])?\s*=\s*(Query|Body|Form|File|Header|Cookie|Path)\(',
    re.IGNORECASE,
)

# Spring annotations
SPRING_MAPPING_RE = re.compile(
    r'@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\('
    r'(?:value\s*=\s*)?["\']([^"\']+)["\']',
    re.IGNORECASE,
)
SPRING_PARAM_RE = re.compile(
    r'@(RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody)'
    r'(?:\([^)]*\))?\s+(?:\w+\s+)?(\w+)',
    re.IGNORECASE,
)

# Express / Fastify / NestJS
JS_ROUTE_RE = re.compile(
    r'(?:app|router|fastify)\.(get|post|put|delete|patch|options|use)\s*'
    r'\(\s*["\`]([^"\`]+)["\`]',
    re.IGNORECASE,
)
JS_PARAM_ACCESS = re.compile(
    r'req\.(query|body|params|headers|cookies)\.(\w+)',
)

# NestJS decorators
NESTJS_RE = re.compile(
    r'@(Get|Post|Put|Delete|Patch)\s*\(\s*["\']([^"\']*)["\']',
)
NESTJS_PARAM_RE = re.compile(
    r'@(Query|Body|Param|Headers|Cookies)\(\s*["\']?(\w*)["\']?\)',
)

# Gin / Echo / Chi (Go)
GO_ROUTE_RE = re.compile(
    r'(?:r|e|g|router)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS)\s*'
    r'\(\s*"([^"]+)"',
    re.IGNORECASE,
)
GO_QUERY_RE = re.compile(r'c\.(?:Query|PostForm|DefaultQuery)\s*\(\s*"(\w+)"')
GO_PARAM_RE = re.compile(r'c\.Param\s*\(\s*"(\w+)"')

# Laravel (PHP)
PHP_ROUTE_RE = re.compile(
    r'Route::(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
PHP_INPUT_RE = re.compile(r'\$request->(\w+)\s*\(|Input::get\s*\(\s*["\'](\w+)["\']')

# Rails routes.rb
RAILS_ROUTE_RE = re.compile(
    r'(get|post|put|delete|patch|resources?)\s+["\']([^"\']+)["\']',
    re.IGNORECASE,
)

PATH_PARAM_RE = re.compile(r'\{(\w+)\}|:(\w+)|<(?:[\w]+:)?(\w+)>')


def catalog_api(repo_path: str, stack: str = "auto", sources: list = None, sinks: list = None, run_id: str = "local", api_cfg: dict = None) -> dict:
    """Parse API routes and params across all frameworks."""
    if api_cfg is None:
        api_cfg = {}
        
    audit_dir = "reports/" + run_id
    import os
    os.makedirs(audit_dir, exist_ok=True)

    audit_log(audit_dir, run_id, "catalog_api:start", {"repo": repo_path, "stack": stack})

    repo = Path(repo_path)
    endpoints: List[dict] = []

    for src_file in _iter_source_files(repo, stack):
        try:
            content = src_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel_path = str(src_file.relative_to(repo))
        ext = src_file.suffix.lower()

        if ext == ".py":
            endpoints.extend(_parse_python(content, rel_path, stack))
        elif ext == ".java":
            endpoints.extend(_parse_java(content, rel_path))
        elif ext in (".js", ".ts", ".cjs", ".mjs"):
            endpoints.extend(_parse_js_ts(content, rel_path, ext))
        elif ext == ".go":
            endpoints.extend(_parse_go(content, rel_path))
        elif ext == ".php":
            endpoints.extend(_parse_php(content, rel_path))
        elif ext == ".rb":
            endpoints.extend(_parse_ruby(content, rel_path))

    # Deduplicate
    seen: set[str] = set()
    unique_endpoints: List[dict] = []
    for ep in endpoints:
        if ep["id"] not in seen:
            seen.add(ep["id"])
            unique_endpoints.append(ep)

    # Compute catalog checksum — hash of all catalog data combined
    # (sources + sinks come from other nodes; we get them from the merged state after)
    catalog_checksum = _compute_checksum(unique_endpoints, sources or [], sinks or [])

    audit_log(audit_dir, run_id, "catalog_api:done", {
        "endpoints": len(unique_endpoints),
    })

    return {"endpoints": unique_endpoints, "catalog_checksum": catalog_checksum}


# ── Per-language parsers ──────────────────────────────────────────────────────

def _parse_python(content: str, file_path: str, stack: str) -> List[dict]:
    endpoints: List[dict] = []
    lines = content.splitlines()

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Decorator-based route
        m = PY_DECORATOR_RE.search(stripped)
        if m:
            path = m.group(1)
            method_m = PY_MULTI_METHOD_RE.search(stripped)
            if method_m:
                methods = [x.strip().strip('"\'') for x in method_m.group(1).split(",")]
            else:
                method_word = re.search(r'\.(get|post|put|delete|patch|options|head|route)\s*\(',
                                        stripped, re.IGNORECASE)
                methods = [method_word.group(1).upper() if method_word else "GET"]
                if "route" in (methods[0] or "").lower():
                    methods = ["GET"]

            handler = _resolve_next_function(lines, lineno)
            path_params = _extract_path_params(path)

            # Look ahead for FastAPI typed params
            fn_params = _parse_fastapi_params(lines, lineno)

            all_params = path_params + fn_params

            for method in methods:
                endpoints.append(_make_endpoint(
                    method.upper(), path, all_params, handler, file_path, lineno, stack
                ))

    return endpoints


def _resolve_next_function(lines: List[str], decorator_line: int, lookahead: int = 5) -> str:
    """Find the function name defined after a decorator."""
    for i in range(decorator_line, min(decorator_line + lookahead, len(lines))):
        m = re.search(r'(?:async\s+)?def\s+(\w+)\s*\(', lines[i])
        if m:
            return m.group(1)
    return ""


def _parse_fastapi_params(lines: List[str], decorator_line: int) -> List[dict]:
    """Extract FastAPI Query/Body/Form/Header/Cookie params from function signature."""
    params = []
    # Read the function signature (may span multiple lines)
    fn_text = ""
    in_fn = False
    for i in range(decorator_line, min(decorator_line + 20, len(lines))):
        ln = lines[i]
        if "def " in ln:
            in_fn = True
        if in_fn:
            fn_text += " " + ln
            if ":" in ln and not ln.strip().endswith(","):
                break

    for m in PY_PARAM_RE.finditer(fn_text):
        name, ptype, location = m.group(1), m.group(2), m.group(3).lower()
        params.append({"name": name, "type": ptype, "location": location})

    return params


def _parse_java(content: str, file_path: str) -> List[dict]:
    endpoints = []
    lines = content.splitlines()

    for lineno, line in enumerate(lines, start=1):
        m = SPRING_MAPPING_RE.search(line)
        if m:
            method = m.group(1).upper()
            path = m.group(2)
            if method == "REQUEST":
                method = "GET"  # default when not specified

            # Scan next 30 lines for @RequestParam etc
            params = _extract_path_params(path)
            for j in range(lineno, min(lineno + 30, len(lines))):
                pm = SPRING_PARAM_RE.search(lines[j])
                if pm:
                    annotation, name = pm.group(1), pm.group(2)
                    loc_map = {
                        "requestparam": "query", "pathvariable": "path",
                        "requestheader": "header", "cookievalue": "cookie",
                        "requestbody": "body",
                    }
                    location = loc_map.get(annotation.lower(), "query")
                    params.append({"name": name, "type": "string", "location": location})
                # Stop at next method definition
                if re.search(r'(public|private|protected)\s+\w+\s+\w+\s*\(', lines[j]) and j > lineno:
                    break

            handler_m = re.search(r'(public|private|protected)\s+\w+\s+(\w+)\s*\(', content[content.find(m.group(0)):])
            handler = handler_m.group(2) if handler_m else ""
            endpoints.append(_make_endpoint(method, path, params, handler, file_path, lineno, "spring"))

    return endpoints


def _parse_js_ts(content: str, file_path: str, ext: str) -> List[dict]:
    endpoints = []
    lines = content.splitlines()

    for lineno, line in enumerate(lines, start=1):
        # NestJS
        for m in NESTJS_RE.finditer(line):
            method, path = m.group(1).upper(), m.group(2)
            params = _extract_path_params(path)
            endpoints.append(_make_endpoint(method, path or "/", params, "", file_path, lineno, "nestjs"))

        # Express / Fastify
        m = JS_ROUTE_RE.search(line)
        if m:
            method, path = m.group(1).upper(), m.group(2)
            if method == "USE":
                method = "ALL"
            path_params = _extract_path_params(path)
            # Scan handler body for req.query.xxx etc
            query_params = _extract_js_req_params(lines, lineno)
            endpoints.append(_make_endpoint(
                method, path, path_params + query_params, "", file_path, lineno, "express"
            ))

    return endpoints


def _extract_js_req_params(lines: List[str], start: int, window: int = 40) -> List[dict]:
    params = []
    seen = set()
    for i in range(start, min(start + window, len(lines))):
        for m in JS_PARAM_ACCESS.finditer(lines[i]):
            location, name = m.group(1), m.group(2)
            key = (name, location)
            if key not in seen:
                seen.add(key)
                loc_map = {"query": "query", "body": "body", "params": "path",
                           "headers": "header", "cookies": "cookie"}
                params.append({"name": name, "type": "string", "location": loc_map.get(location, "query")})
    return params


def _parse_go(content: str, file_path: str) -> List[dict]:
    endpoints = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        m = GO_ROUTE_RE.search(line)
        if m:
            method, path = m.group(1).upper(), m.group(2)
            params = _extract_path_params(path)
            # Scan function body
            for j in range(lineno, min(lineno + 40, len(lines))):
                for qm in GO_QUERY_RE.finditer(lines[j]):
                    params.append({"name": qm.group(1), "type": "string", "location": "query"})
                for pm in GO_PARAM_RE.finditer(lines[j]):
                    params.append({"name": pm.group(1), "type": "string", "location": "path"})
            endpoints.append(_make_endpoint(method, path, params, "", file_path, lineno, "gin"))
    return endpoints


def _parse_php(content: str, file_path: str) -> List[dict]:
    endpoints = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        m = PHP_ROUTE_RE.search(line)
        if m:
            method, path = m.group(1).upper(), m.group(2)
            params = _extract_path_params(path)
            endpoints.append(_make_endpoint(method, path, params, "", file_path, lineno, "laravel"))
    return endpoints


def _parse_ruby(content: str, file_path: str) -> List[dict]:
    endpoints = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        m = RAILS_ROUTE_RE.search(line)
        if m:
            verb, path = m.group(1).lower(), m.group(2)
            if verb == "resources" or verb == "resource":
                # Expand RESTful resources
                for action_method in [("GET", f"/{path}"), ("POST", f"/{path}"),
                                       ("GET", f"/{path}/{{id}}"), ("PUT", f"/{path}/{{id}}"),
                                       ("DELETE", f"/{path}/{{id}}")]:
                    params = _extract_path_params(action_method[1])
                    endpoints.append(_make_endpoint(action_method[0], action_method[1], params, "", file_path, lineno, "rails"))
            else:
                method = verb.upper()
                params = _extract_path_params(path)
                endpoints.append(_make_endpoint(method, path, params, "", file_path, lineno, "rails"))
    return endpoints


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_path_params(path: str) -> List[dict]:
    params = []
    for m in PATH_PARAM_RE.finditer(path):
        name = next((g for g in m.groups() if g), None)
        if name:
            params.append({"name": name, "type": "string", "location": "path"})
    return params


def _make_endpoint(
    method: str, path: str, params: List[dict],
    handler: str, file_path: str, line: int, framework: str
) -> dict:
    uid = hashlib.md5(f"{method}:{path}:{file_path}:{line}".encode()).hexdigest()[:12]
    return {
        "id": uid,
        "method": method,
        "path": path,
        "params": params,
        "handler": handler,
        "file": file_path,
        "line": line,
        "framework": framework,
    }


def _iter_source_files(repo: Path, stack: str):
    """Yield source files relevant to the detected/specified stack."""
    for f in repo.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() not in ALL_EXTS:
            continue
        # Skip non-source directories
        if any(p in f.parts for p in [
            ".git", "node_modules", "__pycache__", "vendor",
            "dist", "build", ".tox", "venv", ".env", "migrations",
        ]):
            continue
        yield f


def _compute_checksum(endpoints: List[dict], sources: List[dict], sinks: List[dict]) -> str:
    data = sorted(
        [e["id"] for e in endpoints] +
        [s["id"] for s in sources] +
        [s["id"] for s in sinks]
    )
    return hashlib.sha256(json.dumps(data).encode()).hexdigest()
