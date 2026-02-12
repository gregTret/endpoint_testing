"""
AI Analysis — spawns Claude Code CLI as a subprocess to analyse captured traffic.
No API key needed; Claude Code handles its own auth locally.
"""
import asyncio
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from storage.db import (
    get_request_logs,
    get_scan_results_by_workspace,
    save_ai_analysis,
    get_ai_analysis_results,
    delete_ai_analysis_results,
    delete_ai_analysis_by_id,
)

log = logging.getLogger(__name__)
router = APIRouter()

# ── In-memory status for the currently running analysis ──────────
_ai_status: dict = {
    "running": False,
    "error": None,
    "phase": "",       # "collecting" | "analyzing" | "done"
    "endpoint_count": 0,
}

# Import active workspace accessor from the main routes module
def _get_workspace():
    from api.routes import get_active_workspace
    return get_active_workspace()


# ── Helpers ──────────────────────────────────────────────────────

_BINARY_PREFIXES = ("image/", "font/", "video/", "audio/", "application/octet-stream", "application/wasm")


_SECURITY_HEADERS = {
    "authorization", "cookie", "set-cookie", "x-csrf-token",
    "content-type", "x-forwarded-for", "x-api-key", "www-authenticate",
    "access-control-allow-origin", "strict-transport-security",
    "x-frame-options", "x-content-type-options", "content-security-policy",
    "x-xss-protection", "location", "server",
}


def _slim_headers(raw) -> dict:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}
    if not isinstance(raw, dict):
        return {}
    return {k: v for k, v in raw.items() if k.lower() in _SECURITY_HEADERS}


def _prepare_traffic_payload(logs: list, host_filter: str = "") -> list[dict]:
    """Deduplicate logs by method+path. Lean output — no response bodies,
    request bodies only for mutating methods, security headers only."""
    seen = set()
    endpoints = []

    for entry in logs:
        if host_filter:
            if host_filter not in (entry.get("host") or ""):
                continue

        method = entry.get("method", "GET")
        path = entry.get("path", "") or entry.get("url", "")
        key = f"{method} {path}"
        if key in seen:
            continue
        seen.add(key)

        ct = (entry.get("content_type") or "").lower()
        if any(ct.startswith(p) for p in _BINARY_PREFIXES):
            continue

        ep = {
            "method": method,
            "path": path,
            "host": entry.get("host", ""),
            "status_code": entry.get("status_code", 0),
            "req_headers": _slim_headers(entry.get("request_headers", {})),
            "resp_headers": _slim_headers(entry.get("response_headers", {})),
        }
        # Only include request body for mutating methods
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            body = (entry.get("request_body") or "")[:300]
            if body:
                ep["request_body"] = body

        endpoints.append(ep)

    return endpoints


def _prepare_scan_payload(scan_rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Returns (confirmed_vulns, coverage_summary).

    confirmed_vulns: full detail for is_vulnerable=True results.
    coverage_summary: deduplicated non-vuln combos with payload counts only.
    """
    confirmed = []
    notvuln_seen: dict[str, int] = {}
    coverage: list[dict] = []

    for row in scan_rows:
        if row.get("is_vulnerable"):
            confirmed.append({
                "url": row.get("target_url", ""),
                "type": row.get("injector_type", ""),
                "payload": row.get("payload", ""),
                "where": row.get("injection_point", ""),
                "param": row.get("original_param", ""),
                "status": row.get("response_code", 0),
                "response_snippet": (row.get("response_body") or "")[:500],
                "time_ms": row.get("response_time_ms", 0),
                "confidence": row.get("confidence", "low"),
                "details": row.get("details", ""),
            })
        else:
            combo = f"{row.get('injector_type', '')}|{row.get('target_url', '')}"
            notvuln_seen[combo] = notvuln_seen.get(combo, 0) + 1
            if notvuln_seen[combo] == 1:
                coverage.append({
                    "url": row.get("target_url", ""),
                    "type": row.get("injector_type", ""),
                    "where": row.get("injection_point", ""),
                    "param": row.get("original_param", ""),
                    "payloads_tested": 1,
                })

    for entry in coverage:
        combo = f"{entry['type']}|{entry['url']}"
        entry["payloads_tested"] = notvuln_seen.get(combo, 1)

    return confirmed, coverage


def _build_full_prompt(endpoints: list[dict],
                       confirmed_vulns: list[dict] | None = None,
                       scan_coverage: list[dict] | None = None) -> str:
    """Build the complete prompt.  Keeps data compact:
    - Common response headers extracted once (not per-endpoint)
    - Per-endpoint only has unique/notable headers
    - Confirmed vulns in full, non-vulns as coverage summary
    """
    confirmed_vulns = confirmed_vulns or []
    scan_coverage = scan_coverage or []

    # ── Extract common headers so they aren't repeated per-endpoint ──
    # Collect all resp_headers, find ones that appear in >50% of endpoints
    if endpoints:
        header_counts: dict[str, dict[str, int]] = {}  # header -> {value -> count}
        for ep in endpoints:
            for k, v in (ep.get("resp_headers") or {}).items():
                header_counts.setdefault(k, {})
                vstr = str(v)
                header_counts[k][vstr] = header_counts[k].get(vstr, 0) + 1

        threshold = len(endpoints) * 0.5
        common_resp = {}
        for hdr, vals in header_counts.items():
            for val, cnt in vals.items():
                if cnt >= threshold:
                    common_resp[hdr] = val

        # Strip common headers from individual endpoints
        slim_endpoints = []
        for ep in endpoints:
            e = dict(ep)
            rh = e.pop("resp_headers", {})
            unique_rh = {k: v for k, v in rh.items()
                         if str(v) != common_resp.get(k)}
            if unique_rh:
                e["resp_headers"] = unique_rh
            slim_endpoints.append(e)
    else:
        common_resp = {}
        slim_endpoints = []

    traffic_json = json.dumps(slim_endpoints, indent=None, default=str)
    common_hdr_json = json.dumps(common_resp, indent=None, default=str)

    # ── Scan sections ──
    vuln_section = ""
    if confirmed_vulns:
        vuln_json = json.dumps(confirmed_vulns, indent=None, default=str)
        vuln_section = f"""

=== CONFIRMED VULNERABILITIES ({len(confirmed_vulns)}) ===
These are CONFIRMED by the scanner (error-based, time-based, or OOB callback).
{vuln_json}"""

    coverage_section = ""
    if scan_coverage:
        cov_json = json.dumps(scan_coverage, indent=None, default=str)
        coverage_section = f"""

=== SCAN COVERAGE (not vulnerable) ===
Injection types tested per endpoint (no vulns found for these):
{cov_json}"""

    total_scans = len(confirmed_vulns) + sum(c.get("payloads_tested", 1) for c in scan_coverage)

    return f"""Analyze this web application security data. Two sources:
1. {len(slim_endpoints)} HTTP endpoints (passive traffic capture)
2. {total_scans} injection payloads tested ({len(confirmed_vulns)} confirmed vulnerable)

Respond ONLY with JSON (no markdown, no backticks):
{{"summary":"...","findings":[{{"endpoint":"URL","method":"GET/POST","path":"/...","risk":"critical/high/medium/low/info","category":"Injection/Auth/...","title":"...","description":"...","evidence":"...","recommendation":"..."}}]}}

Sort by risk (critical first).

=== COMMON RESPONSE HEADERS (apply to most endpoints) ===
{common_hdr_json}

=== ENDPOINTS ===
{traffic_json}{vuln_section}{coverage_section}"""


_MODEL_MAP = {
    "opus": "opus",
    "sonnet": "sonnet",
    "haiku": "haiku",
}


def _find_claude_cli() -> str | None:
    """Locate the claude CLI binary, searching PATH and common install locations."""
    import shutil
    import sys
    import os

    # Try PATH first
    found = shutil.which("claude")
    if found:
        return found

    # Common install locations as fallbacks
    candidates = []
    home = os.path.expanduser("~")

    if sys.platform == "win32":
        # npm global installs, nvm, AppData
        candidates = [
            os.path.join(home, "AppData", "Roaming", "npm", "claude.cmd"),
            os.path.join(home, "AppData", "Local", "npm", "claude.cmd"),
            os.path.join(home, ".npm-global", "claude.cmd"),
        ]
        # nvm directories
        nvm_dir = os.environ.get("NVM_HOME") or os.environ.get("NVM_DIR") or ""
        if nvm_dir:
            candidates.append(os.path.join(nvm_dir, "nodejs", "claude.cmd"))
        # Common node paths
        for p in [r"C:\nvm4w\nodejs", r"C:\Program Files\nodejs"]:
            candidates.append(os.path.join(p, "claude.cmd"))
            candidates.append(os.path.join(p, "claude"))
        # nvm4w: scan version directories
        nvm4w_root = r"C:\nvm4w"
        if os.path.isdir(nvm4w_root):
            try:
                for entry in os.listdir(nvm4w_root):
                    d = os.path.join(nvm4w_root, entry)
                    if os.path.isdir(d):
                        candidates.append(os.path.join(d, "claude.cmd"))
                        candidates.append(os.path.join(d, "claude"))
            except OSError:
                pass
    else:
        # macOS / Linux
        candidates = [
            os.path.join(home, ".npm-global", "bin", "claude"),
            "/usr/local/bin/claude",
            "/opt/homebrew/bin/claude",
            os.path.join(home, ".local", "bin", "claude"),
            os.path.join(home, ".nvm", "current", "bin", "claude"),
        ]
        # nvm: check version directories (newest first)
        nvm_dir = os.path.join(home, ".nvm", "versions", "node")
        if os.path.isdir(nvm_dir):
            try:
                for ver in sorted(os.listdir(nvm_dir), reverse=True):
                    c = os.path.join(nvm_dir, ver, "bin", "claude")
                    if os.path.isfile(c):
                        candidates.insert(0, c)
                        break
            except OSError:
                pass
        # fnm (Fast Node Manager - common on macOS)
        fnm_dir = os.path.join(home, ".fnm", "node-versions")
        if os.path.isdir(fnm_dir):
            try:
                for ver in sorted(os.listdir(fnm_dir), reverse=True):
                    c = os.path.join(fnm_dir, ver, "installation", "bin", "claude")
                    if os.path.isfile(c):
                        candidates.insert(0, c)
                        break
            except OSError:
                pass
        # Volta
        volta_dir = os.path.join(home, ".volta", "bin")
        if os.path.isdir(volta_dir):
            candidates.append(os.path.join(volta_dir, "claude"))

    for c in candidates:
        if os.path.isfile(c):
            log.info("Found claude CLI at fallback path: %s", c)
            return c

    # Last resort on Windows: ask the shell via 'where'
    if sys.platform == "win32":
        try:
            import subprocess
            result = subprocess.run(
                ["where", "claude"], capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                path = result.stdout.strip().splitlines()[0]
                if os.path.isfile(path):
                    log.info("Found claude CLI via 'where': %s", path)
                    return path
        except Exception:
            pass
    else:
        try:
            import subprocess
            result = subprocess.run(
                ["which", "claude"], capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                path = result.stdout.strip()
                if os.path.isfile(path):
                    log.info("Found claude CLI via 'which': %s", path)
                    return path
        except Exception:
            pass

    return None


async def _run_claude(endpoints: list[dict], model: str,
                      confirmed_vulns: list[dict] | None = None,
                      scan_coverage: list[dict] | None = None) -> dict:
    """Spawn claude CLI, piping the full prompt via stdin.

    The prompt (instruction + compact data) is piped through stdin using
    ``-p`` with no argument — this is the approach that reliably works.
    Data is also saved to ai_traffic.json for transparency.
    """
    import sys
    import os
    from pathlib import Path

    model_arg = _MODEL_MAP.get(model, "opus")
    storage_dir = Path(__file__).resolve().parent.parent / "storage"
    storage_dir.mkdir(parents=True, exist_ok=True)
    debug_log_path = str(storage_dir / "ai_debug.log")

    def _debug(msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(debug_log_path, "a", encoding="utf-8") as f:
                f.write(f"[{ts}] {msg}\n")
        except OSError:
            pass

    try:
        claude_cmd = _find_claude_cli()
        if not claude_cmd:
            return {"error": "Claude CLI not found. Make sure 'claude' is installed and in your PATH."}

        _debug(f"Claude CLI: {claude_cmd}")

        # Save data for transparency / debugging
        data_path = storage_dir / "ai_traffic.json"
        with open(data_path, "w", encoding="utf-8") as f:
            json.dump({
                "endpoints": endpoints,
                "confirmed_vulns": confirmed_vulns or [],
                "scan_coverage": scan_coverage or [],
            }, f, indent=2, default=str)

        # Build compact prompt — piped via stdin (no cmd-line length limit)
        full_prompt = _build_full_prompt(endpoints, confirmed_vulns, scan_coverage)
        prompt_bytes = full_prompt.encode("utf-8")
        prompt_size_kb = len(prompt_bytes) / 1024
        _debug(f"Prompt size: {prompt_size_kb:.1f} KB, model: {model_arg}")

        # -p at end with no argument → reads prompt from stdin
        args = [
            claude_cmd,
            "--model", model_arg,
            "--output-format", "json",
            "-p",
        ]

        _debug(f"Args: {args}")

        if sys.platform == "win32" and claude_cmd.lower().endswith(".cmd"):
            proc = await asyncio.create_subprocess_exec(
                "cmd", "/c", *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        _debug("Subprocess started, piping prompt via stdin...")
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=prompt_bytes), timeout=600
            )
        except asyncio.TimeoutError:
            _debug("TIMEOUT after 10 minutes — killing process")
            proc.kill()
            await proc.wait()
            return {"error": "Claude analysis timed out after 10 minutes. Try a smaller dataset or faster model."}

        rc = proc.returncode
        raw_out = stdout.decode("utf-8", errors="replace").strip()
        raw_err = stderr.decode("utf-8", errors="replace").strip()

        _debug(f"Exit code: {rc}")
        _debug(f"Stdout length: {len(raw_out)} chars")
        _debug(f"Stderr (first 500): {raw_err[:500]}")
        _debug(f"Stdout (first 500): {raw_out[:500]}")

        if rc != 0:
            log.error("claude subprocess failed (rc=%d): %s", rc, raw_err[:500])
            return {"error": f"Claude process exited with code {rc}: {raw_err[:500]}"}

        if not raw_out:
            return {"error": "Claude returned empty output"}

        log.info("Claude raw output (first 500 chars): %s", raw_out[:500])
        return _parse_claude_output(raw_out)

    except FileNotFoundError:
        _debug("FileNotFoundError — claude CLI not on PATH")
        return {"error": "Claude CLI not found. Make sure 'claude' is installed and in your PATH."}
    except Exception as e:
        _debug(f"Exception: {e}")
        log.error("claude subprocess error: %s", e, exc_info=True)
        return {"error": str(e)}


def _strip_code_fences(text: str) -> str:
    """Remove markdown code fences (```json ... ``` or ``` ... ```) from text."""
    import re
    # Match ```json\n...\n``` or ```\n...\n```
    m = re.search(r'```(?:json)?\s*\n(.*?)\n\s*```', text, re.DOTALL)
    if m:
        return m.group(1).strip()
    return text


def _extract_json_object(text: str) -> dict | None:
    """Try to extract a JSON object from text, handling nested braces."""
    # Find the first { and try to parse from there
    start = text.find("{")
    if start < 0:
        return None

    # Try progressively larger substrings from the first {
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    continue
    return None


def _parse_claude_output(raw: str) -> dict:
    """Parse Claude CLI output, handling all known response formats.

    Formats handled:
    1. --output-format json: {"result": "...text...", "cost_usd": ...}
    2. Direct JSON: {"summary": "...", "findings": [...]}
    3. Text with code fences: ```json\n{...}\n```
    4. Text with embedded JSON object
    """
    # Step 1: Try parsing as the --output-format json wrapper
    try:
        outer = json.loads(raw)
        if isinstance(outer, dict):
            # Handle the wrapper format: {"result": "..."}
            if "result" in outer:
                inner_raw = str(outer["result"]).strip()
                log.info("Parsed outer wrapper, inner result (first 300 chars): %s", inner_raw[:300])

                # Inner might be direct JSON
                try:
                    parsed = json.loads(inner_raw)
                    if isinstance(parsed, dict) and ("findings" in parsed or "summary" in parsed):
                        return parsed
                except (json.JSONDecodeError, TypeError):
                    pass

                # Inner might have code fences
                stripped = _strip_code_fences(inner_raw)
                try:
                    parsed = json.loads(stripped)
                    if isinstance(parsed, dict):
                        return parsed
                except (json.JSONDecodeError, TypeError):
                    pass

                # Try extracting JSON object from inner text
                extracted = _extract_json_object(inner_raw)
                if extracted and ("findings" in extracted or "summary" in extracted):
                    return extracted

                # If inner has content but couldn't parse, return it as raw
                if inner_raw:
                    return {"raw_text": inner_raw, "error": "Could not parse AI response as JSON"}

            # Direct format: outer already has findings/summary
            if "findings" in outer or "summary" in outer:
                return outer
    except json.JSONDecodeError:
        pass

    # Step 2: Try stripping code fences from raw
    stripped = _strip_code_fences(raw)
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # Step 3: Try extracting any JSON object from raw
    extracted = _extract_json_object(raw)
    if extracted:
        return extracted

    return {"raw_text": raw[:2000], "error": "Could not parse Claude output as JSON"}




# ── Endpoints ────────────────────────────────────────────────────


@router.post("/ai/preview")
async def ai_preview(data: dict = None):
    """Preview: count endpoints that would be analyzed, without running Claude."""
    data = data or {}
    host_filter = (data.get("host_filter") or "").strip()
    workspace_id = _get_workspace()

    logs = await get_request_logs(session_id=workspace_id, limit=2000)
    endpoints = _prepare_traffic_payload(logs, host_filter)

    # Collect scan results
    raw_scans = await get_scan_results_by_workspace(workspace_id, limit=1000)
    confirmed_vulns, scan_coverage = _prepare_scan_payload(raw_scans)

    # Estimate prompt size by building the actual prompt
    prompt = _build_full_prompt(endpoints, confirmed_vulns, scan_coverage)
    size_kb = len(prompt.encode("utf-8")) / 1024

    # Get unique hosts for the host filter dropdown
    hosts = sorted({e.get("host", "") for e in logs if e.get("host")})

    return {
        "endpoint_count": len(endpoints),
        "total_logs": len(logs),
        "scan_result_count": len(raw_scans),
        "confirmed_vulns": len(confirmed_vulns),
        "estimated_size_kb": round(size_kb, 1),
        "hosts": hosts,
    }


@router.post("/ai/analyze")
async def ai_analyze(data: dict = None):
    """Start a background AI analysis."""
    global _ai_status
    data = data or {}

    if _ai_status["running"]:
        return JSONResponse(status_code=409, content={"error": "Analysis already in progress"})

    model = data.get("model", "opus")
    host_filter = (data.get("host_filter") or "").strip()
    workspace_id = _get_workspace()

    _ai_status = {
        "running": True,
        "error": None,
        "phase": "collecting",
        "endpoint_count": 0,
    }

    async def run_analysis():
        global _ai_status
        try:
            # Collect traffic
            logs = await get_request_logs(session_id=workspace_id, limit=2000)
            endpoints = _prepare_traffic_payload(logs, host_filter)
            _ai_status["endpoint_count"] = len(endpoints)

            # Collect injection scan results for this workspace
            raw_scans = await get_scan_results_by_workspace(workspace_id, limit=1000)
            confirmed_vulns, scan_coverage = _prepare_scan_payload(raw_scans)
            log.info("Collected %d scan results (%d confirmed vulnerable) for AI analysis",
                     len(raw_scans), len(confirmed_vulns))

            if not endpoints and not confirmed_vulns and not scan_coverage:
                _ai_status["running"] = False
                _ai_status["error"] = "No traffic or scan data found. Browse some sites or run scans first."
                _ai_status["phase"] = "done"
                return

            # Call Claude
            _ai_status["phase"] = "analyzing"
            result = await _run_claude(endpoints, model,
                                       confirmed_vulns=confirmed_vulns,
                                       scan_coverage=scan_coverage)

            if "error" in result and "findings" not in result:
                _ai_status["running"] = False
                _ai_status["error"] = result["error"]
                _ai_status["phase"] = "done"
                return

            # Extract findings
            findings = result.get("findings", [])
            summary = result.get("summary", "")
            raw_response = json.dumps(result, indent=2, default=str)

            # Save to DB
            await save_ai_analysis(
                workspace_id=workspace_id,
                model=model,
                host_filter=host_filter,
                endpoint_count=len(endpoints),
                findings=findings,
                summary=summary,
                raw_response=raw_response,
            )

            _ai_status["running"] = False
            _ai_status["phase"] = "done"
            log.info("AI analysis complete: %d findings from %d endpoints", len(findings), len(endpoints))

        except Exception as e:
            log.error("AI analysis failed: %s", e, exc_info=True)
            _ai_status["running"] = False
            _ai_status["error"] = str(e)
            _ai_status["phase"] = "done"

    asyncio.create_task(run_analysis())
    return {"status": "started", "model": model, "host_filter": host_filter}


@router.get("/ai/status")
async def ai_status():
    """Poll analysis progress."""
    return _ai_status


@router.get("/ai/results")
async def ai_results(limit: int = 20):
    """Fetch saved results for the active workspace."""
    workspace_id = _get_workspace()
    return await get_ai_analysis_results(workspace_id, limit)


@router.delete("/ai/results")
async def ai_clear_results():
    """Clear AI results for the active workspace."""
    workspace_id = _get_workspace()
    await delete_ai_analysis_results(workspace_id)
    return {"ok": True}


@router.delete("/ai/results/{result_id}")
async def ai_delete_result(result_id: int):
    """Delete a single AI analysis result by ID."""
    await delete_ai_analysis_by_id(result_id)
    return {"ok": True}
