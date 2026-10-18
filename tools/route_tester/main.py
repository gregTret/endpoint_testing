#!/usr/bin/env python3
"""
route_tester — Standalone tool for testing discovered API routes one at a time.

Loads a deep-crawl JSON, authenticates via the local backend, and runs
injection tests (AQL, graph traversal, Python, SSTI, CMD, OOB, fuzzing,
IDOR, input size) against each route with concurrency and backoff.

Usage:
    python tools/route_tester/main.py
    python tools/route_tester/main.py --crawl notes/scripts/deep_crawl_bcd07806.json
    python tools/route_tester/main.py --route 21
    python tools/route_tester/main.py --route 21 --types aql,graph
    python tools/route_tester/main.py --concurrency 10 --timeout 20
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Resolve project root for imports
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR = os.path.dirname(_SCRIPT_DIR)
_PROJECT_ROOT = os.path.dirname(_TOOLS_DIR)

# Allow running as `python tools/route_tester/main.py`
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

from route_tester.harness import Harness, _p
from route_tester.runner import RouteRunner

# ── Defaults ──────────────────────────────────────────────────────────────
DEFAULT_BACKEND = "http://127.0.0.1:8000"
DEFAULT_CONCURRENCY = 5
DEFAULT_TIMEOUT = 15.0

# The "Currently Here" marker — routes before this index are skipped by default
RESUME_FROM_COMMENT = "Currently Here"


def load_crawl(path: str) -> dict:
    """Load a deep-crawl JSON file (tolerates JS-style // comments)."""
    import re
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    # Strip single-line // comments that aren't inside strings
    cleaned = re.sub(r'^\s*//.*$', '', raw, flags=re.MULTILINE)
    return json.loads(cleaned)


def find_resume_index(routes: list[dict]) -> int:
    """Find the route index marked with 'Currently Here' comment (if any)."""
    # The comment was in the JSON source but won't survive json.load.
    # Use the known URL: organisations/{id}/data-points/{id} GET
    for i, r in enumerate(routes):
        if (r["method"] == "GET"
                and "organisations" in r["url"]
                and r["url"].endswith("/data-points/{id}")):
            return i
    return 0


def filter_api_routes(routes: list[dict]) -> list[dict]:
    """Keep only api.etain.app routes (skip frontend etain.app/ pages)."""
    return [r for r in routes if "api." in r["url"]]


async def pick_workspace(backend_url: str) -> str:
    """Interactive workspace picker (same as deep_crawl)."""
    import httpx
    async with httpx.AsyncClient(base_url=backend_url, timeout=10) as c:
        r = await c.get("/api/workspaces")
        r.raise_for_status()
        workspaces = r.json()

    if not workspaces:
        _p("No workspaces found. Create one in the app first.", error=True)
        sys.exit(1)

    print("\n  Available workspaces:\n")
    for i, ws in enumerate(workspaces, 1):
        name = ws.get("name", "unnamed")
        ws_id = ws.get("id", "?")
        print(f"    {i}) {name}  ({ws_id})")

    print()
    while True:
        try:
            choice = input("  Select workspace [1]: ").strip()
            idx = int(choice) - 1 if choice else 0
            if 0 <= idx < len(workspaces):
                selected = workspaces[idx]
                _p(f"Selected: {selected['name']} ({selected['id']})")
                return selected["id"]
        except (ValueError, EOFError):
            pass
        print(f"    Enter a number between 1 and {len(workspaces)}")


async def pick_crawl_file() -> str:
    """Find and pick a deep-crawl JSON file."""
    notes_dir = os.path.join(_PROJECT_ROOT, "notes", "scripts")
    candidates = []
    if os.path.isdir(notes_dir):
        for f in sorted(os.listdir(notes_dir)):
            if f.startswith("deep_crawl") and f.endswith(".json"):
                candidates.append(os.path.join(notes_dir, f))

    # Also check project root
    for f in sorted(os.listdir(_PROJECT_ROOT)):
        if f.startswith("deep_crawl") and f.endswith(".json"):
            candidates.append(os.path.join(_PROJECT_ROOT, f))

    if not candidates:
        _p("No deep_crawl JSON files found.", error=True)
        sys.exit(1)

    if len(candidates) == 1:
        _p(f"Using crawl file: {candidates[0]}")
        return candidates[0]

    print("\n  Available crawl files:\n")
    for i, path in enumerate(candidates, 1):
        print(f"    {i}) {os.path.basename(path)}")
    print()
    while True:
        try:
            choice = input("  Select crawl file [1]: ").strip()
            idx = int(choice) - 1 if choice else 0
            if 0 <= idx < len(candidates):
                return candidates[idx]
        except (ValueError, EOFError):
            pass


def display_routes(routes: list[dict], start_idx: int = 0):
    """Print the route list with indices."""
    print(f"\n  Routes ({len(routes)} total, starting from #{start_idx + 1}):\n")
    for i, r in enumerate(routes):
        global_idx = start_idx + i + 1
        method_pad = r["method"].ljust(7)
        src = ",".join(r.get("sources", []))
        print(f"    {global_idx:3d}) {method_pad} {r['url']}  [{src}]")
    print()


def pick_route(routes: list[dict], start_idx: int = 0) -> int:
    """Interactive route picker. Returns index into routes list."""
    while True:
        try:
            choice = input(f"  Select route [{start_idx + 1}] (or 'list', 'q'): ").strip()
            if choice.lower() == "q":
                sys.exit(0)
            if choice.lower() == "list":
                display_routes(routes, start_idx)
                continue
            if choice == "":
                return 0
            idx = int(choice) - start_idx - 1
            if 0 <= idx < len(routes):
                return idx
            print(f"    Enter a number between {start_idx + 1} and {start_idx + len(routes)}")
        except (ValueError, EOFError):
            print(f"    Enter a number, 'list', or 'q'")


def save_report(results: list, route: dict, output_dir: str):
    """Save test results as JSON."""
    os.makedirs(output_dir, exist_ok=True)
    # Sanitize URL for filename
    from urllib.parse import urlparse
    path = urlparse(route["url"]).path.replace("/", "_").replace("{id}", "ID")
    method = route["method"]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{method}_{path}_{ts}.json"
    filepath = os.path.join(output_dir, filename)

    vulns = [r for r in results if r.is_vulnerable]

    if not vulns:
        _p(f"No findings — skipping report for {method} {route['url']}")
        return None

    report = {
        "route": route,
        "tested_at": datetime.now(timezone.utc).isoformat(),
        "total_tests": len(results),
        "findings": [
            {
                "test_type": r.test_type,
                "confidence": r.confidence,
                "payload": r.payload,
                "injection_point": r.injection_point,
                "target_key": r.target_key,
                "status_code": r.status_code,
                "response_time_ms": r.response_time_ms,
                "details": r.details,
                "evidence": r.evidence,
                "response_body": r.response_body[:500],
            }
            for r in vulns
        ],
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    _p(f"Report saved: {filepath}")
    return filepath


def print_summary(results: list):
    """Print a findings summary to stdout."""
    vulns = [r for r in results if r.is_vulnerable]
    if not vulns:
        _p("No findings for this route.")
        return

    print(f"\n  === FINDINGS ({len(vulns)}) ===\n")
    for r in sorted(vulns, key=lambda x: {"high": 0, "medium": 1, "low": 2}[x.confidence]):
        print(f"    [{r.confidence.upper():6s}] {r.test_type:8s} | {r.injection_point:6s} "
              f"| {r.target_key}")
        print(f"             Payload: {r.payload[:80]}")
        print(f"             Status: {r.status_code} | {r.response_time_ms:.0f}ms")
        print(f"             {r.details[:120]}")
        print()


async def on_progress(result, idx, total):
    """Progress callback for batch execution."""
    pct = idx / total * 100 if total else 0
    marker = "!!" if result.is_vulnerable else "ok"
    sys.stdout.write(
        f"\r  [{idx}/{total}] {pct:5.1f}% [{marker}] {result.test_type:8s} "
        f"{result.status_code} {result.response_time_ms:7.0f}ms"
    )
    sys.stdout.flush()
    if idx == total:
        print()  # newline at end


async def main():
    ap = argparse.ArgumentParser(
        description="Test discovered API routes for vulnerabilities — one at a time."
    )
    ap.add_argument("--crawl", "-c", default=None,
                    help="Path to deep_crawl JSON (omit to pick interactively)")
    ap.add_argument("--workspace", "-w", default=None,
                    help="Workspace ID (omit to pick interactively)")
    ap.add_argument("--backend", "-b", default=DEFAULT_BACKEND,
                    help=f"Backend URL (default: {DEFAULT_BACKEND})")
    ap.add_argument("--route", "-r", type=int, default=None,
                    help="Route number to test (1-indexed, from full list)")
    ap.add_argument("--types", "-t", default=None,
                    help="Comma-separated test types: aql,graph,fuzz,idor,size,python,ssti,cmd,oob")
    ap.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                    help=f"Max concurrent requests (default: {DEFAULT_CONCURRENCY})")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    ap.add_argument("--output", "-o", default=None,
                    help="Output directory for reports (default: notes/route_tests/)")
    ap.add_argument("--all-from", type=int, default=None,
                    help="Run all routes starting from this number (non-interactive)")
    ap.add_argument("--api-only", action="store_true", default=True,
                    help="Skip frontend routes (default: True)")
    args = ap.parse_args()

    # ── Load crawl data ───────────────────────────────────────────────
    crawl_path = args.crawl or await pick_crawl_file()
    crawl = load_crawl(crawl_path)
    all_routes = crawl.get("routes", [])
    discovered_ids = crawl.get("discovered_ids", {})
    workspace_id_from_crawl = crawl.get("workspace_id", "")

    _p(f"Loaded {len(all_routes)} routes from {os.path.basename(crawl_path)}")

    # Filter to API routes if requested
    if args.api_only:
        api_routes = filter_api_routes(all_routes)
        _p(f"Filtered to {len(api_routes)} API routes (--api-only)")
    else:
        api_routes = all_routes

    # Find resume point
    resume_idx = find_resume_index(api_routes)
    remaining_routes = api_routes[resume_idx:]
    _p(f"Starting from route #{resume_idx + 1}: "
       f"{remaining_routes[0]['method']} {remaining_routes[0]['url']}")

    # ── Auth ──────────────────────────────────────────────────────────
    ws_id = args.workspace or workspace_id_from_crawl
    if not ws_id:
        ws_id = await pick_workspace(args.backend)

    harness = Harness(
        backend_url=args.backend,
        concurrency=args.concurrency,
        timeout=args.timeout,
    )

    # Determine API base URL from crawl's target domains
    target_domains = crawl.get("target_domains", [])
    api_domain = next((d for d in target_domains if d.startswith("api.")), None)
    api_base = f"https://{api_domain}" if api_domain else "https://api.etain.app"

    success = await harness.login(ws_id, api_base)
    if not success:
        _p("Auth failed — continuing without auth (only unauthenticated routes will work)", error=True)

    # ── Build runner ──────────────────────────────────────────────────
    # Collect all workspace/org IDs for IDOR testing
    all_ws_ids = discovered_ids.get("workspace", [])
    all_org_ids = discovered_ids.get("organisation", [])

    runner = RouteRunner(
        harness=harness,
        discovered_ids=discovered_ids,
        all_workspace_ids=all_ws_ids if isinstance(all_ws_ids, list) else [all_ws_ids],
        all_org_ids=all_org_ids if isinstance(all_org_ids, list) else [all_org_ids],
    )

    # ── Output dir ────────────────────────────────────────────────────
    output_dir = args.output or os.path.join(_PROJECT_ROOT, "notes", "route_tests")

    # ── Test types filter ─────────────────────────────────────────────
    test_types = args.types.split(",") if args.types else None

    # ── Run ───────────────────────────────────────────────────────────
    if args.all_from is not None:
        # Non-interactive: run all routes from a given index
        start = max(0, args.all_from - resume_idx - 1)
        for i, route in enumerate(remaining_routes[start:], start=start):
            global_idx = resume_idx + i + 1
            _p(f"\n{'='*60}")
            _p(f"Route {global_idx}/{len(api_routes)}: {route['method']} {route['url']}")
            _p(f"{'='*60}")

            results = await runner.test_route(route, test_types=test_types, on_result=on_progress)
            print_summary(results)
            save_report(results, route, output_dir)

    elif args.route is not None:
        # Single route by number
        # Route number is 1-indexed from the full api_routes list
        idx = args.route - 1
        if 0 <= idx < len(api_routes):
            route = api_routes[idx]
            results = await runner.test_route(route, test_types=test_types, on_result=on_progress)
            print_summary(results)
            save_report(results, route, output_dir)
        else:
            _p(f"Route {args.route} out of range (1-{len(api_routes)})", error=True)
    else:
        # Interactive mode: pick routes one at a time
        display_routes(remaining_routes[:20], resume_idx)
        if len(remaining_routes) > 20:
            _p(f"  ... and {len(remaining_routes) - 20} more (type 'list' to see all)")

        while True:
            idx = pick_route(remaining_routes, resume_idx)
            route = remaining_routes[idx]

            results = await runner.test_route(route, test_types=test_types, on_result=on_progress)
            print_summary(results)
            save_report(results, route, output_dir)

            print()
            cont = input("  Continue to next route? [Y/n/q]: ").strip().lower()
            if cont in ("q", "quit", "exit"):
                break
            if cont in ("n", "no"):
                continue  # back to picker
            # Default: advance to next
            if idx + 1 < len(remaining_routes):
                remaining_routes = remaining_routes[idx + 1:]
                resume_idx += idx + 1
            else:
                _p("All routes tested!")
                break


if __name__ == "__main__":
    asyncio.run(main())
