"""
Test runner — takes a route, determines what tests to run, builds task list,
executes via the harness, and collects results.

Test categories (in priority order):
  1. AQL injection (syntax break, FILTER bypass)
  2. Graph traversal abuse (depth, direction, cross-tenant)
  3. Python injection (eval/exec/pickle/Jinja2)
  4. SSTI (template injection)
  5. CMD injection (on relevant routes)
  6. OOB (blind detection)
  7. Path ID fuzzing (malformed/injected IDs)
  8. IDOR (cross-org/workspace access)
  9. Input size variants (empty, oversized)
"""

import asyncio
import json
import sys
import os
import re
from urllib.parse import urlparse, quote

from .harness import Harness, TestResult, resolve_url, _p
from . import aql_payloads

# Add backend to path so we can import injectors
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_BACKEND_DIR = os.path.join(_PROJECT_ROOT, "backend")
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)


# ── ID regex (same as deep_crawl) ────────────────────────────────────────
_ID_RE = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    r'|[0-9A-Z]{26}'
    r'|[0-9a-f]{24}'
    r'|[0-9a-f]{8,16}'
    r'|\d+',
    re.IGNORECASE,
)

# ── Fuzz payloads for path {id} segments ─────────────────────────────────
PATH_FUZZ_PAYLOADS = [
    # AQL injection in path
    "' OR true //",
    "' FOR doc IN Users RETURN doc //",
    "' FOR v IN 1..10 ANY @start GRAPH 'default' RETURN v //",
    # Traversal
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    # Null / edge cases
    "",
    " ",
    "null",
    "undefined",
    "0",
    "-1",
    "9999999999",
    # Oversized
    "A" * 5000,
    # Special chars
    "*",
    "%00",
    "\x00",
    "{{7*7}}",
    "${7*7}",
    # ULID-shaped but fake
    "01ZZZZZZZZZZZZZZZZZZZZZZZZ",
    "00000000000000000000000000",
    # Document reference style
    "Users/admin",
    "_users/root",
    "../Users/admin",
]

# ── Input size variants ──────────────────────────────────────────────────
SIZE_PAYLOADS = {
    "empty": "",
    "whitespace": "   ",
    "single_char": "x",
    "medium": "A" * 500,
    "large": "A" * 10000,
    "very_large": "A" * 100000,
    "null_bytes": "\x00" * 100,
    "unicode_stress": "\u202e\u200b\u00ff" * 500,
    "deeply_nested_json": None,  # generated dynamically
}


def _make_nested_json(depth: int = 50) -> str:
    """Create a deeply nested JSON object."""
    obj = {"value": "leaf"}
    for i in range(depth):
        obj = {"nested": obj}
    return json.dumps(obj)


class RouteRunner:
    """Runs all applicable tests against a single route."""

    def __init__(
        self,
        harness: Harness,
        discovered_ids: dict,
        all_workspace_ids: list[str] | None = None,
        all_org_ids: list[str] | None = None,
    ):
        self.harness = harness
        self.discovered_ids = discovered_ids  # resource_type -> list[str]
        self.all_workspace_ids = all_workspace_ids or []
        self.all_org_ids = all_org_ids or []

    async def test_route(
        self,
        route: dict,
        test_types: list[str] | None = None,
        on_result=None,
    ) -> list[TestResult]:
        """Test a route with all applicable test categories.

        route: {"url": "https://...", "method": "GET", "sources": [...]}
        test_types: optional filter, e.g. ["aql", "graph", "fuzz"]
                    None = run all applicable
        """
        url_template = route["url"]
        method = route["method"]

        # Resolve {id} placeholders with real IDs
        id_map = {}
        for rtype, ids in self.discovered_ids.items():
            if isinstance(ids, list) and ids:
                id_map[rtype] = ids[0]
            elif isinstance(ids, str):
                id_map[rtype] = ids
        resolved_url = resolve_url(url_template, id_map)

        _p(f"\nTesting: {method} {url_template}")
        _p(f"Resolved: {method} {resolved_url}")

        # ── Get baseline ──────────────────────────────────────────────
        _p("  Getting baseline response...")
        baseline = await self.harness.request(method, resolved_url)
        _p(f"  Baseline: {baseline['status_code']} "
           f"({len(baseline['body'])} chars, {baseline['response_time_ms']:.0f}ms)")

        if baseline.get("error"):
            _p(f"  Baseline error: {baseline['error']}", error=True)

        # ── Determine which tests to run ──────────────────────────────
        has_path_ids = "{id}" in url_template
        is_write = method in ("POST", "PUT", "PATCH", "DELETE")
        is_get = method == "GET"

        all_types = self._pick_test_types(url_template, method)
        if test_types:
            all_types = [t for t in all_types if t in test_types]

        _p(f"  Test types: {', '.join(all_types)}")

        # ── Build and run tasks ───────────────────────────────────────
        all_results: list[TestResult] = []
        total_tasks = 0

        for test_type in all_types:
            tasks = self._build_tasks(
                test_type, url_template, resolved_url, method, baseline, id_map
            )
            if not tasks:
                continue

            total_tasks += len(tasks)
            _p(f"  Running {test_type}: {len(tasks)} payloads...")

            results = await self.harness.run_batch(tasks, on_result=on_result)
            all_results.extend(results)

            # Summary for this test type
            vulns = [r for r in results if r.is_vulnerable]
            errors = [r for r in results if r.error]
            if vulns:
                _p(f"    {len(vulns)} potential findings!")
                for v in vulns:
                    _p(f"      [{v.confidence}] {v.details[:120]}")
            if errors:
                _p(f"    {len(errors)} request errors")

        _p(f"\n  Done: {total_tasks} tests, "
           f"{len([r for r in all_results if r.is_vulnerable])} findings")

        return all_results

    def _pick_test_types(self, url_template: str, method: str) -> list[str]:
        """Decide which test categories are relevant for this route."""
        types = []
        path = urlparse(url_template).path.lower()

        # AQL + Graph always (ArangoDB backend)
        types.append("aql")
        types.append("graph")

        # Path ID fuzzing if route has {id} params
        if "{id}" in url_template:
            types.append("fuzz")
            types.append("idor")

        # Python injection on write endpoints (eval/exec risk)
        if method in ("POST", "PUT", "PATCH"):
            types.append("python")

        # SSTI on routes that accept text content
        if method in ("POST", "PUT", "PATCH"):
            types.append("ssti")

        # CMD injection on specific routes (upload, export, reprocess)
        if any(k in path for k in ("upload", "export", "reprocess", "transcribe", "blob")):
            types.append("cmd")

        # OOB on POST routes with opaque responses
        if method == "POST":
            types.append("oob")

        # Input size testing on all routes
        types.append("size")

        return types

    def _build_tasks(
        self,
        test_type: str,
        url_template: str,
        resolved_url: str,
        method: str,
        baseline: dict,
        id_map: dict,
    ) -> list[dict]:
        """Build a list of task dicts for the harness to execute."""
        tasks = []

        if test_type == "aql":
            tasks = self._build_aql_tasks(url_template, resolved_url, method, baseline, id_map)
        elif test_type == "graph":
            tasks = self._build_graph_tasks(url_template, resolved_url, method, baseline, id_map)
        elif test_type == "fuzz":
            tasks = self._build_fuzz_tasks(url_template, resolved_url, method, baseline, id_map)
        elif test_type == "idor":
            tasks = self._build_idor_tasks(url_template, resolved_url, method, baseline, id_map)
        elif test_type == "size":
            tasks = self._build_size_tasks(url_template, resolved_url, method, baseline, id_map)
        elif test_type in ("python", "ssti", "cmd", "oob"):
            tasks = self._build_injector_tasks(
                test_type, url_template, resolved_url, method, baseline, id_map
            )

        return tasks

    # ── AQL injection tasks ───────────────────────────────────────────

    def _build_aql_tasks(self, url_template, resolved_url, method, baseline, id_map):
        context = {"url": resolved_url, "method": method}
        payloads = aql_payloads.generate_payloads(context)
        tasks = []

        # Inject into path segments that are IDs
        path_targets = self._get_id_segments(resolved_url)
        for segment, seg_idx in path_targets:
            for payload in payloads:
                injected_url = self._replace_segment(resolved_url, seg_idx, payload)
                tasks.append({
                    "method": method,
                    "url": injected_url,
                    "route_url": url_template,
                    "test_type": "aql",
                    "payload": payload,
                    "injection_point": "path",
                    "target_key": f"path_segment_{seg_idx}",
                    "baseline": baseline,
                    "analyze_fn": aql_payloads.analyze_response,
                })

        # For POST/PUT/PATCH, also inject into query param "q" as a common search param
        if method == "GET":
            for payload in payloads[:15]:  # subset for query params
                tasks.append({
                    "method": method,
                    "url": resolved_url,
                    "params": {"q": payload},
                    "route_url": url_template,
                    "test_type": "aql",
                    "payload": payload,
                    "injection_point": "query",
                    "target_key": "q",
                    "baseline": baseline,
                    "analyze_fn": aql_payloads.analyze_response,
                })

        return tasks

    # ── Graph traversal tasks ─────────────────────────────────────────

    def _build_graph_tasks(self, url_template, resolved_url, method, baseline, id_map):
        context = {
            "url": resolved_url,
            "method": method,
            "org_id": id_map.get("organisation", ""),
            "workspace_id": id_map.get("workspace", ""),
        }
        payloads = aql_payloads.generate_graph_payloads(context)
        tasks = []

        path_targets = self._get_id_segments(resolved_url)
        for segment, seg_idx in path_targets:
            for payload in payloads:
                injected_url = self._replace_segment(resolved_url, seg_idx, payload)
                tasks.append({
                    "method": method,
                    "url": injected_url,
                    "route_url": url_template,
                    "test_type": "graph",
                    "payload": payload,
                    "injection_point": "path",
                    "target_key": f"path_segment_{seg_idx}",
                    "baseline": baseline,
                    "analyze_fn": aql_payloads.analyze_response,
                })

        return tasks

    # ── Path ID fuzz tasks ────────────────────────────────────────────

    def _build_fuzz_tasks(self, url_template, resolved_url, method, baseline, id_map):
        tasks = []
        path_targets = self._get_id_segments(resolved_url)

        for segment, seg_idx in path_targets:
            for payload in PATH_FUZZ_PAYLOADS:
                injected_url = self._replace_segment(resolved_url, seg_idx, payload)
                tasks.append({
                    "method": method,
                    "url": injected_url,
                    "route_url": url_template,
                    "test_type": "fuzz",
                    "payload": payload,
                    "injection_point": "path",
                    "target_key": f"path_segment_{seg_idx}",
                    "baseline": baseline,
                    "analyze_fn": aql_payloads.analyze_response,
                })

        return tasks

    # ── IDOR tasks ────────────────────────────────────────────────────

    def _build_idor_tasks(self, url_template, resolved_url, method, baseline, id_map):
        """Try accessing resources using IDs from different contexts."""
        tasks = []
        path_targets = self._get_id_segments(resolved_url)

        # For each ID segment, try IDs from other resource types
        for segment, seg_idx in path_targets:
            # Try all discovered IDs (cross-resource IDOR)
            for rtype, ids in self.discovered_ids.items():
                id_list = ids if isinstance(ids, list) else [ids]
                for alt_id in id_list[:3]:  # limit per type
                    if alt_id == segment:
                        continue  # skip the one already in use
                    injected_url = self._replace_segment(resolved_url, seg_idx, alt_id)
                    tasks.append({
                        "method": method,
                        "url": injected_url,
                        "route_url": url_template,
                        "test_type": "idor",
                        "payload": alt_id,
                        "injection_point": "path",
                        "target_key": f"idor_{rtype}_in_seg_{seg_idx}",
                        "baseline": baseline,
                        "analyze_fn": self._analyze_idor,
                    })

        return tasks

    # ── Input size tasks ──────────────────────────────────────────────

    def _build_size_tasks(self, url_template, resolved_url, method, baseline, id_map):
        tasks = []

        if method in ("POST", "PUT", "PATCH"):
            # Test body sizes
            for name, payload in SIZE_PAYLOADS.items():
                if payload is None:
                    payload = _make_nested_json()
                body = json.dumps({"data": payload}) if name != "deeply_nested_json" else payload
                tasks.append({
                    "method": method,
                    "url": resolved_url,
                    "body": body,
                    "headers": {"Content-Type": "application/json"},
                    "route_url": url_template,
                    "test_type": "size",
                    "payload": f"size:{name}",
                    "injection_point": "body",
                    "target_key": "full_body",
                    "baseline": baseline,
                    "analyze_fn": self._analyze_size,
                })
        else:
            # For GET, test with oversized query params
            for name in ("medium", "large", "very_large"):
                payload = SIZE_PAYLOADS[name]
                tasks.append({
                    "method": method,
                    "url": resolved_url,
                    "params": {"q": payload},
                    "route_url": url_template,
                    "test_type": "size",
                    "payload": f"size:{name}",
                    "injection_point": "query",
                    "target_key": "q",
                    "baseline": baseline,
                    "analyze_fn": self._analyze_size,
                })

        return tasks

    # ── Backend injector tasks (python, ssti, cmd, oob) ───────────────

    def _build_injector_tasks(self, test_type, url_template, resolved_url, method, baseline, id_map):
        """Build tasks using the project's built-in injectors."""
        tasks = []

        try:
            if test_type == "python":
                from injectors.python_injector import PythonInjector
                injector = PythonInjector()
            elif test_type == "ssti":
                from injectors.ssti_injector import SSTIInjector
                injector = SSTIInjector()
            elif test_type == "cmd":
                from injectors.cmd_injector import CMDInjector
                injector = CMDInjector()
            else:
                return tasks
        except ImportError as e:
            _p(f"  Could not import {test_type} injector: {e}", error=True)
            return tasks

        context = {"url": resolved_url, "method": method, "params": {}}
        payloads = injector.generate_payloads(context)

        # Inject into path ID segments
        path_targets = self._get_id_segments(resolved_url)
        for segment, seg_idx in path_targets:
            for payload in payloads[:20]:  # cap per-segment
                injected_url = self._replace_segment(resolved_url, seg_idx, payload)
                tasks.append({
                    "method": method,
                    "url": injected_url,
                    "route_url": url_template,
                    "test_type": test_type,
                    "payload": payload,
                    "injection_point": "path",
                    "target_key": f"path_segment_{seg_idx}",
                    "baseline": baseline,
                    "analyze_fn": lambda b, r, p, inj=injector: _wrap_injector_analyze(inj, b, r, p),
                })

        return tasks

    # ── Analysis helpers ──────────────────────────────────────────────

    @staticmethod
    def _analyze_idor(baseline: dict, test_response: dict, payload: str) -> dict:
        """Check if IDOR succeeded — got valid data with a foreign ID."""
        status = test_response.get("status_code", 0)
        body = test_response.get("body", "")
        base_status = baseline.get("status_code", 0)

        evidence = []

        # If we got 200 with substantial body using a foreign ID
        if status == 200 and len(body) > 50:
            # Check if it's actual data (not an error message)
            try:
                data = json.loads(body)
                if isinstance(data, dict) and not data.get("error"):
                    evidence.append(
                        f"Got 200 with {len(body)} chars using foreign ID: {payload[:40]}"
                    )
            except (json.JSONDecodeError, TypeError):
                pass

        # Auth downgrade: baseline required auth but foreign ID didn't
        if base_status in (401, 403) and status == 200:
            evidence.append(f"Auth bypass: {base_status} -> {status}")

        if evidence:
            return {
                "is_vulnerable": True,
                "confidence": "medium",
                "details": "; ".join(evidence),
                "evidence": evidence,
            }
        return {"is_vulnerable": False, "confidence": "low", "details": "", "evidence": []}

    @staticmethod
    def _analyze_size(baseline: dict, test_response: dict, payload: str) -> dict:
        """Check for crashes, timeouts, or info leaks from size testing."""
        status = test_response.get("status_code", 0)
        body = test_response.get("body", "")
        elapsed = test_response.get("response_time_ms", 0)
        base_elapsed = baseline.get("response_time_ms", 0)

        evidence = []

        if status == 500:
            evidence.append(f"Server error 500 with {payload}")

        # Resource exhaustion: server took way longer than baseline
        if base_elapsed > 0 and elapsed > base_elapsed * 5 and elapsed > 2000:
            evidence.append(
                f"Resource exhaustion (DoS): {elapsed:.0f}ms vs baseline {base_elapsed:.0f}ms "
                f"({elapsed / base_elapsed:.0f}x slower)"
            )

        # Connection killed — server choked on the input
        if status == 0 and test_response.get("error"):
            evidence.append(f"Server connection failed: {test_response['error'][:150]}")

        # Check for stack traces / debug info
        for pattern in ("Traceback", "stack trace", "debug", "internal server error"):
            if pattern.lower() in body.lower():
                evidence.append(f"Debug info in response: '{pattern}'")
                break

        if not evidence:
            return {"is_vulnerable": False, "confidence": "low", "details": "", "evidence": []}

        # Resource exhaustion with big multiplier = high confidence DoS
        has_dos = any("exhaustion" in e.lower() or "connection failed" in e.lower() for e in evidence)
        confidence = "high" if has_dos and elapsed > base_elapsed * 10 else "medium" if has_dos else "low"

        return {
            "is_vulnerable": True,
            "confidence": confidence,
            "details": "; ".join(evidence),
            "evidence": evidence,
        }

    # ── URL manipulation helpers ──────────────────────────────────────

    def _get_id_segments(self, url: str) -> list[tuple[str, int]]:
        """Find path segments that look like IDs. Returns [(segment, index), ...]."""
        parsed = urlparse(url)
        segments = parsed.path.split("/")
        targets = []
        for i, seg in enumerate(segments):
            if seg and _ID_RE.fullmatch(seg):
                targets.append((seg, i))
        return targets

    @staticmethod
    def _replace_segment(url: str, seg_idx: int, payload: str) -> str:
        """Replace a specific path segment by index with a payload."""
        parsed = urlparse(url)
        segments = parsed.path.split("/")
        if 0 <= seg_idx < len(segments):
            # URL-encode the payload for path safety, but keep some chars
            # unencoded so AQL payloads are readable in the URL
            segments[seg_idx] = quote(payload, safe="")
        new_path = "/".join(segments)
        return f"{parsed.scheme}://{parsed.netloc}{new_path}"


def _wrap_injector_analyze(injector, baseline: dict, test_response: dict, payload: str) -> dict:
    """Wrap a BaseInjector's analyze_response into a plain dict return."""
    try:
        report = injector.analyze_response(baseline, test_response, payload)
        return {
            "is_vulnerable": report.is_vulnerable,
            "confidence": report.confidence,
            "details": report.details,
            "evidence": report.evidence if hasattr(report, "evidence") else [],
        }
    except Exception as e:
        return {"is_vulnerable": False, "confidence": "low", "details": str(e), "evidence": []}
