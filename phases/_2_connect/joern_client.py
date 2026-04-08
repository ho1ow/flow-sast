"""
phases/2_connect/joern_client.py
──────────────────────────────────
HTTP client cho Joern REST server (Docker, port 8080).

API endpoints used:
  POST /api/cpg/create        — upload repo, trigger CPG build
  GET  /api/cpg/{id}/status   — poll until READY
  POST /api/query             — run Joern query language (Joern DSL)
  DELETE /api/cpg/{id}        — cleanup after run

Joern query language reference:
  Joern uses its own Scala-embedded DSL (not openCypher).
  Queries in .scala files are sent as-is to the /api/query endpoint.
"""

from __future__ import annotations

import time
from typing import Any, Optional

import httpx

from core.reliability import audit_log


class JoernError(Exception):
    pass


class JoernTimeoutError(JoernError):
    pass


class JoernClient:
    def __init__(self, base_url: str = "http://localhost:8080", timeout: int = 300):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._http = httpx.Client(
            base_url=self.base_url,
            timeout=httpx.Timeout(connect=10.0, read=timeout, write=60.0, pool=10.0),
        )

    # ── CPG lifecycle ─────────────────────────────────────────────────────────

    def create_cpg(self, repo_path: str) -> str:
        """
        Submit a repo for CPG creation.
        Returns cpg_id (Joern project name / workspace ID).
        """
        resp = self._http.post(
            "/api/cpg/create",
            json={"inputPath": repo_path},
        )
        resp.raise_for_status()
        data = resp.json()
        cpg_id = data.get("cpgId") or data.get("projectName") or data.get("id")
        if not cpg_id:
            raise JoernError(f"CPG create returned no ID: {data}")
        return str(cpg_id)

    def wait_cpg_ready(
        self,
        cpg_id: str,
        build_timeout: int = 600,
        poll_interval: int = 5,
    ) -> None:
        """Poll until CPG status is READY or timeout."""
        deadline = time.time() + build_timeout
        while time.time() < deadline:
            status = self._cpg_status(cpg_id)
            if status in ("DONE", "READY", "ready", "done"):
                return
            if status in ("FAILED", "ERROR", "failed", "error"):
                raise JoernError(f"CPG build failed for {cpg_id}: status={status}")
            time.sleep(poll_interval)
        raise JoernTimeoutError(f"CPG build timed out after {build_timeout}s for {cpg_id}")

    def _cpg_status(self, cpg_id: str) -> str:
        try:
            resp = self._http.get(f"/api/cpg/{cpg_id}/status")
            resp.raise_for_status()
            data = resp.json()
            return str(data.get("status", "unknown")).upper()
        except httpx.HTTPError:
            return "unknown"

    def delete_cpg(self, cpg_id: str) -> None:
        """Clean up CPG after analysis."""
        try:
            self._http.delete(f"/api/cpg/{cpg_id}")
        except httpx.HTTPError:
            pass

    # ── Query execution ───────────────────────────────────────────────────────

    def run_query(
        self,
        cpg_id: str,
        query: str,
        params: Optional[dict] = None,
    ) -> list[dict]:
        """
        Execute a Joern query against the CPG.
        Substitutes {key} placeholders in the query string with params values.

        Returns a list of result dicts.
        """
        if params:
            query = _substitute_params(query, params)

        payload: dict[str, Any] = {
            "query": query,
            "cpgId": cpg_id,
        }

        resp = self._http.post(
            "/api/query",
            json=payload,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()

        # Joern REST may return {"success": bool, "result": [...]} or just [...]
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            result = data.get("result") or data.get("results") or data.get("data") or []
            return result if isinstance(result, list) else [result]
        return []

    def build_and_query(
        self,
        repo_path: str,
        query: str,
        params: Optional[dict] = None,
        build_timeout: int = 600,
        audit_dir: str = "pentest_logs/audit_trail",
        run_id: str = "unknown",
    ) -> tuple[str, list[dict]]:
        """
        High-level helper: create CPG + wait + run query.
        Returns (cpg_id, results).
        Caller is responsible for calling delete_cpg() when done.
        """
        audit_log(audit_dir, run_id, "joern:create_cpg", {"repo": repo_path})
        cpg_id = self.create_cpg(repo_path)
        audit_log(audit_dir, run_id, "joern:wait_cpg", {"cpg_id": cpg_id})
        self.wait_cpg_ready(cpg_id, build_timeout=build_timeout)
        audit_log(audit_dir, run_id, "joern:cpg_ready", {"cpg_id": cpg_id})
        results = self.run_query(cpg_id, query, params)
        audit_log(audit_dir, run_id, "joern:query_done", {
            "cpg_id": cpg_id, "results": len(results)
        })
        return cpg_id, results

    def close(self) -> None:
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _substitute_params(query: str, params: dict) -> str:
    """Replace {key} placeholders in query with escaped string values."""
    for key, value in params.items():
        safe_val = str(value).replace('"', '\\"').replace("'", "\\'")
        query = query.replace(f"{{{key}}}", safe_val)
    return query
