"""
AI Analysis — spawns Claude Code CLI as a subprocess to analyse captured traffic.
No API key needed; Claude Code handles its own auth locally.
"""
import asyncio
import json
import logging
from datetime import datetime, timezone

import csv
import io

from fastapi import APIRouter
from fastapi.responses import JSONResponse, Response

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


def _safe_ascii(s: str) -> str:
    """Encode string to ASCII-safe form, replacing non-ASCII chars to avoid cp1252 crashes."""
    return s.encode("ascii", errors="replace").decode("ascii")

# ── In-memory status for the currently running analysis ──────────
_ai_status: dict = {
    "running": False,
    "error": None,
    "phase": "",       # "collecting" | "analyzing" | "done"
    "endpoint_count": 0,
}

# ── Auth context from a logged request (set via /ai/analyze-request) ──
_auth_context: dict | None = None  # { method, url, headers, body }


def set_auth_context(ctx: dict | None):
    """Store auth context (headers, cookies, tokens) from a logged request."""
    global _auth_context
    _auth_context = ctx


def get_auth_context() -> dict | None:
    """Return the current auth context, if any."""
    return _auth_context

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


def _prepare_traffic_payload(logs: list, host_filter: str = "",
                             auth_context: dict | None = None) -> list[dict]:
    """Deduplicate logs by method+path. Lean output — no response bodies,
    request bodies only for mutating methods, security headers only.

    If *auth_context* is provided, the authenticated request is prepended
    as the first endpoint (marked with ``"authenticated": true``) so the
    AI knows which tokens are valid.
    """
    seen = set()
    endpoints = []

    # Prepend the authenticated request so Claude sees the valid tokens first
    if auth_context:
        auth_ep = {
            "method": auth_context.get("method", "GET"),
            "path": auth_context.get("url", ""),
            "host": "",
            "authenticated": True,
            "req_headers": auth_context.get("headers", {}),
        }
        body = (auth_context.get("body") or "")[:500]
        if body:
            auth_ep["request_body"] = body
        # Try to extract host from url
        try:
            from urllib.parse import urlparse
            parsed = urlparse(auth_context.get("url", ""))
            auth_ep["host"] = parsed.netloc or ""
        except Exception:
            pass
        endpoints.append(auth_ep)

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


def _build_auth_section(auth_context: dict | None) -> str:
    """Build an optional auth context section for the prompt."""
    if not auth_context:
        return ""
    auth_json = json.dumps({
        "method": auth_context.get("method", "GET"),
        "url": auth_context.get("url", ""),
        "headers": auth_context.get("headers", {}),
        "body": (auth_context.get("body") or "")[:500],
    }, indent=None, default=str)
    return f"""

=== AUTHENTICATED REQUEST CONTEXT ===
The following request was captured from a logged-in session. Its headers contain valid authentication tokens (Bearer, Cookie, API key, etc.). Use these tokens to understand the application's auth mechanism and consider auth-related vulnerabilities (token reuse, privilege escalation, missing auth on other endpoints, etc.).
{auth_json}"""


def _build_full_prompt(endpoints: list[dict],
                       confirmed_vulns: list[dict] | None = None,
                       scan_coverage: list[dict] | None = None,
                       auth_context: dict | None = None) -> str:
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

    # ── Auth section ──
    auth_section = _build_auth_section(auth_context)

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
{auth_section}
=== ENDPOINTS ===
{traffic_json}{vuln_section}{coverage_section}"""


def _build_targeted_prompt(endpoints: list[dict],
                            confirmed_vulns: list[dict] | None = None,
                            scan_coverage: list[dict] | None = None,
                            auth_context: dict | None = None) -> str:
    """Build a prompt for Phase 4 of auto-scan: asks Claude to produce both
    findings AND a prioritized list of targeted HTTP requests to re-test.

    Returns the same analysis as _build_full_prompt plus a ``targeted_requests``
    array (top 20 most at-risk endpoints with suggested payloads).
    """
    confirmed_vulns = confirmed_vulns or []
    scan_coverage = scan_coverage or []

    # Reuse the same header-extraction logic from _build_full_prompt
    if endpoints:
        header_counts: dict[str, dict[str, int]] = {}
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

    # ── Auth section ──
    auth_section = _build_auth_section(auth_context)

    return f"""You are a security analyst reviewing web application traffic and scan results.
Analyze the data below and produce TWO outputs in a single JSON response.

=== DATA SUMMARY ===
- {len(slim_endpoints)} HTTP endpoints (passive traffic capture)
- {total_scans} injection payloads tested ({len(confirmed_vulns)} confirmed vulnerable)

=== TASK 1: Security Findings ===
Analyze the traffic and scan data for vulnerabilities, misconfigurations, and risks.

=== TASK 2: Targeted Re-test Requests ===
Based on ALL the evidence (traffic patterns, headers, response codes, confirmed vulns, scan gaps), identify the TOP 20 most at-risk endpoints that deserve deeper targeted testing. For each, suggest specific payloads to test.

Consider these risk signals:
- Endpoints that accept user input (POST/PUT/PATCH with body params)
- Endpoints missing auth headers or CSRF tokens
- Endpoints returning verbose errors or stack traces
- Endpoints near confirmed vulnerabilities (same host/path prefix)
- Endpoints not yet covered by scans
- Endpoints with dynamic parameters in query strings or paths
- Endpoints returning sensitive data (PII, tokens, internal IDs)

Respond ONLY with JSON (no markdown, no backticks):
{{
  "summary": "...",
  "findings": [
    {{
      "endpoint": "URL",
      "method": "GET/POST",
      "path": "/...",
      "risk": "critical/high/medium/low/info",
      "category": "Injection/Auth/...",
      "title": "...",
      "description": "...",
      "evidence": "...",
      "recommendation": "..."
    }}
  ],
  "targeted_requests": [
    {{
      "priority": 1,
      "method": "POST",
      "url": "https://example.com/api/users",
      "path": "/api/users",
      "risk_reason": "Why this endpoint is high risk based on the evidence seen",
      "suggested_payloads": [
        {{
          "injection_point": "body|query|header|path",
          "key": "parameter_name",
          "payload": "the actual payload string",
          "type": "sql|xss|ssti|auth|idor|path_traversal|command|ssrf"
        }}
      ]
    }}
  ]
}}

Rules for targeted_requests:
- Maximum 20 entries, sorted by priority (1 = highest risk)
- Each MUST have a risk_reason explaining WHY it's high risk based on observed evidence
- suggested_payloads should be specific and realistic (not generic)
- Include the full URL so the orchestrator can make the request directly
- Cover a variety of vulnerability types, not just SQL injection
- If an endpoint was already confirmed vulnerable, suggest DIFFERENT payloads to test for OTHER vuln types

Sort findings by risk (critical first).

=== COMMON RESPONSE HEADERS (apply to most endpoints) ===
{common_hdr_json}
{auth_section}
=== ENDPOINTS ===
{traffic_json}{vuln_section}{coverage_section}"""


def _build_retest_analysis_prompt(targeted_results: list[dict]) -> str:
    """Build a prompt for Phase 5 of auto-scan: asks Claude to analyze the
    responses from targeted re-test requests and produce final findings.

    ``targeted_results`` is a list of dicts, each containing:
      - method, url, path: the request that was made
      - risk_reason: why it was selected for re-testing
      - payload: the payload that was sent
      - injection_point, key, payload_type: payload details
      - status_code: HTTP response status
      - response_headers: dict of response headers
      - response_body: truncated response body
      - response_time_ms: how long the response took
      - error: any error that occurred during the request (optional)
    """
    results_json = json.dumps(targeted_results, indent=None, default=str)

    return f"""You are a security analyst reviewing the results of targeted re-test requests against a web application.

Each entry below is a request that was made because it was flagged as high-risk during an earlier analysis phase. Your job is to analyze EACH response for signs of actual vulnerability.

=== {len(targeted_results)} TARGETED RE-TEST RESULTS ===
{results_json}

=== ANALYSIS INSTRUCTIONS ===
For each result, check for:
1. **Injection indicators**: Error messages revealing DB/framework info, reflected payloads in response body, unexpected data returned
2. **Auth/access issues**: Accessing resources without proper auth, IDOR responses returning other users' data, privilege escalation indicators
3. **Timing anomalies**: Unusually slow responses that may indicate blind injection success (compare to baseline)
4. **Status code anomalies**: 500s (unhandled errors from payloads), 200s where 401/403 expected, 302 redirects to unexpected locations
5. **Response body differences**: Responses that differ significantly from expected behavior, verbose error messages, stack traces, internal paths
6. **Header anomalies**: Missing security headers, unexpected CORS headers, information disclosure via server headers

Compare patterns across results: if the same endpoint returns different status codes or body lengths for different payloads, that's a strong signal.

Respond ONLY with JSON (no markdown, no backticks):
{{
  "summary": "Overall assessment of the re-test results",
  "findings": [
    {{
      "endpoint": "URL",
      "method": "GET/POST",
      "path": "/...",
      "risk": "critical/high/medium/low/info",
      "status": "confirmed/suspected/informational",
      "category": "Injection/Auth/...",
      "title": "...",
      "description": "Detailed description of what was found",
      "evidence": "Specific evidence from the response (status code, body snippet, timing, etc.)",
      "payload_used": "The payload that triggered this finding",
      "recommendation": "..."
    }}
  ]
}}

Rules:
- Only include findings where there is ACTUAL evidence of a vulnerability or anomaly
- Mark as "confirmed" only if the evidence is clear (e.g., reflected XSS, SQL error message, auth bypass)
- Mark as "suspected" if the behavior is anomalous but not conclusive
- Mark as "informational" for interesting observations that need manual verification
- Sort by risk (critical first), then by status (confirmed first)
- Do NOT include entries where the application handled the payload correctly (returned expected error, blocked the request, etc.)"""


def _build_triage_prompt(endpoints: list[dict],
                          confirmed_vulns: list[dict] | None = None,
                          scan_coverage: list[dict] | None = None,
                          auth_context: dict | None = None) -> str:
    """Build a triage-mode prompt: analyze existing proxy traffic, identify
    file upload points and weak endpoints, rank by attack priority, and
    suggest specific injection payloads — without requiring a full crawl.
    """
    confirmed_vulns = confirmed_vulns or []
    scan_coverage = scan_coverage or []

    # Reuse the same header-extraction logic
    if endpoints:
        header_counts: dict[str, dict[str, int]] = {}
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

    auth_section = _build_auth_section(auth_context)

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

    return f"""You are a security triage analyst. The user has been browsing a web application through an intercepting proxy. Analyze the captured traffic below and perform a QUICK TRIAGE — identify the weakest endpoints and file upload points so the user can attack those first, without a full crawl.

=== DATA SUMMARY ===
- {len(slim_endpoints)} HTTP endpoints (from proxy traffic captured during browsing)
- {total_scans} injection payloads already tested ({len(confirmed_vulns)} confirmed vulnerable)

=== TASK 1: Identify File Upload Endpoints ===
Look for endpoints that accept file uploads:
- multipart/form-data content-types in request headers
- Paths containing: upload, file, attach, import, media, image, document, avatar, photo
- Request bodies with file-like form fields (filename, file, attachment, etc.)
- Endpoints returning upload-related responses

=== TASK 2: Rank ALL Endpoints by Attack Priority ===
Rank every endpoint from weakest/most-vulnerable to strongest. Consider:
- Endpoints accepting user input (POST/PUT/PATCH with params or body)
- Endpoints missing security headers (CSRF, auth)
- Endpoints near confirmed vulns (same path prefix)
- Endpoints NOT yet tested by the scanner
- Endpoints with verbose error responses or stack traces
- Endpoints returning sensitive data (tokens, PII, internal IDs)
- Dynamic parameters in query strings or paths
- Endpoints with permissive CORS or missing auth

=== TASK 3: Suggest Specific Payloads ===
For each prioritized endpoint, suggest the EXACT payloads to try, including which parameter to inject into and what type of injection.

Respond ONLY with JSON (no markdown, no backticks):
{{
  "summary": "Brief triage assessment of the application's attack surface",
  "upload_endpoints": [
    {{
      "url": "https://example.com/api/upload",
      "method": "POST",
      "reason": "Why this is identified as a file upload endpoint",
      "suggested_tests": ["Test 1: upload .php shell", "Test 2: path traversal filename", ...]
    }}
  ],
  "priority_targets": [
    {{
      "priority": 1,
      "url": "https://example.com/api/users",
      "method": "POST",
      "risk_reason": "Why this endpoint is high priority for attack — specific evidence from the traffic",
      "suggested_payloads": [
        {{
          "injection_point": "body|query|header|path",
          "key": "parameter_name",
          "payload": "the actual payload string",
          "type": "sql|xss|ssti|cmd|ssrf|idor|path_traversal|auth_bypass"
        }}
      ]
    }}
  ]
}}

Rules:
- upload_endpoints: list ALL endpoints that look like they handle file uploads, even if uncertain (mark confidence in reason)
- priority_targets: maximum 20, sorted by priority (1 = weakest/most exploitable)
- Each priority_target MUST have a risk_reason citing specific evidence from the captured traffic
- suggested_payloads should be SPECIFIC and REALISTIC — not generic template payloads
- Cover a variety of vulnerability types across the targets
- If an endpoint was already confirmed vulnerable, suggest payloads for OTHER vuln types
- Focus on endpoints the scanner HASN'T tested yet — those are the blind spots

=== COMMON RESPONSE HEADERS (apply to most endpoints) ===
{common_hdr_json}
{auth_section}
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
                      scan_coverage: list[dict] | None = None,
                      auth_context: dict | None = None) -> dict:
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
        full_prompt = _build_full_prompt(endpoints, confirmed_vulns, scan_coverage, auth_context)
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
            _debug("TIMEOUT after 10 minutes -- killing process")
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
            log.error("claude subprocess failed (rc=%d): %s", rc, _safe_ascii(raw_err[:500]))
            return {"error": f"Claude process exited with code {rc}: {raw_err[:500]}"}

        if not raw_out:
            return {"error": "Claude returned empty output"}

        log.info("Claude raw output (first 500 chars): %s", _safe_ascii(raw_out[:500]))
        return _parse_claude_output(raw_out)

    except FileNotFoundError:
        _debug("FileNotFoundError -- claude CLI not on PATH")
        return {"error": "Claude CLI not found. Make sure 'claude' is installed and in your PATH."}
    except Exception as e:
        _debug(f"Exception: {e}")
        log.error("claude subprocess error: %s", e, exc_info=True)
        return {"error": str(e)}


async def run_claude_with_prompt(prompt: str, model: str = "opus") -> dict:
    """Run an arbitrary prompt through the Claude CLI and return parsed JSON.

    This is the public entry point for the auto-scan orchestrator. It handles
    CLI invocation, timeout, and output parsing — callers just supply the prompt
    string (built via _build_targeted_prompt or _build_retest_analysis_prompt).
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

        prompt_bytes = prompt.encode("utf-8")
        prompt_size_kb = len(prompt_bytes) / 1024
        _debug(f"[run_claude_with_prompt] Prompt size: {prompt_size_kb:.1f} KB, model: {model_arg}")

        args = [
            claude_cmd,
            "--model", model_arg,
            "--output-format", "json",
            "-p",
        ]

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

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=prompt_bytes), timeout=600
            )
        except asyncio.TimeoutError:
            _debug("[run_claude_with_prompt] TIMEOUT after 10 minutes")
            proc.kill()
            await proc.wait()
            return {"error": "Claude analysis timed out after 10 minutes."}

        rc = proc.returncode
        raw_out = stdout.decode("utf-8", errors="replace").strip()
        raw_err = stderr.decode("utf-8", errors="replace").strip()

        _debug(f"[run_claude_with_prompt] Exit code: {rc}, stdout: {len(raw_out)} chars")

        if rc != 0:
            log.error("claude subprocess failed (rc=%d): %s", rc, _safe_ascii(raw_err[:500]))
            return {"error": f"Claude process exited with code {rc}: {raw_err[:500]}"}

        if not raw_out:
            return {"error": "Claude returned empty output"}

        return _parse_claude_output(raw_out)

    except FileNotFoundError:
        return {"error": "Claude CLI not found. Make sure 'claude' is installed and in your PATH."}
    except Exception as e:
        log.error("run_claude_with_prompt error: %s", e, exc_info=True)
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
                log.info("Parsed outer wrapper, inner result (first 300 chars): %s", _safe_ascii(inner_raw[:300]))

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




# ── Injection Suggestion Fallbacks ────────────────────────────────

_FALLBACK_SUGGESTIONS = {
    "param": [
        {"payload": "' OR '1'='1", "type": "sqli", "description": "Classic SQL injection tautology"},
        {"payload": "1 UNION SELECT null,null,null--", "type": "sqli", "description": "UNION-based column enumeration"},
        {"payload": "<script>alert(1)</script>", "type": "xss", "description": "Reflected XSS probe"},
        {"payload": "{{7*7}}", "type": "ssti", "description": "Server-side template injection probe"},
        {"payload": "; ls -la", "type": "cmd", "description": "Unix command injection via semicolon"},
        {"payload": "../../../etc/passwd", "type": "traversal", "description": "Path traversal to /etc/passwd"},
    ],
    "header": [
        {"payload": "127.0.0.1\r\nX-Injected: true", "type": "header_injection", "description": "CRLF header injection"},
        {"payload": "() { :; }; /bin/cat /etc/passwd", "type": "cmd", "description": "Shellshock via header value"},
        {"payload": "{{7*7}}", "type": "ssti", "description": "SSTI probe in header value"},
        {"payload": "' OR '1'='1", "type": "sqli", "description": "SQL injection in header-derived value"},
        {"payload": "<script>alert(document.domain)</script>", "type": "xss", "description": "XSS via header reflection"},
        {"payload": "file:///etc/passwd", "type": "ssrf", "description": "SSRF via file protocol in header"},
    ],
    "body": [
        {"payload": "' OR 1=1--", "type": "sqli", "description": "SQL injection in body parameter"},
        {"payload": "{\"$gt\": \"\"}", "type": "nosql", "description": "MongoDB NoSQL operator injection"},
        {"payload": "<img src=x onerror=alert(1)>", "type": "xss", "description": "XSS via image error handler"},
        {"payload": "{{config.__class__.__init__.__globals__}}", "type": "ssti", "description": "Jinja2 SSTI config leak"},
        {"payload": "| cat /etc/passwd", "type": "cmd", "description": "Piped command injection"},
        {"payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>", "type": "xxe", "description": "XXE entity injection"},
    ],
    "path": [
        {"payload": "..%2f..%2f..%2fetc%2fpasswd", "type": "traversal", "description": "URL-encoded path traversal"},
        {"payload": "....//....//etc/passwd", "type": "traversal", "description": "Double-dot filter bypass"},
        {"payload": "%00.php", "type": "null_byte", "description": "Null byte extension bypass"},
        {"payload": "admin'--", "type": "sqli", "description": "SQL injection in URL path segment"},
        {"payload": "{{7*7}}", "type": "ssti", "description": "SSTI probe in path"},
        {"payload": ";id", "type": "cmd", "description": "Command injection in path segment"},
    ],
}


async def _run_haiku_suggestions(text: str, context: dict) -> dict:
    """Spawn Claude CLI with haiku model for fast injection suggestions.

    Returns {"suggestions": [...]} on success or {"error": "..."} on failure.
    Uses a 30-second timeout for speed.
    """
    import sys

    field_type = context.get("field_type", "param")
    field_name = context.get("field_name", "unknown")
    method = context.get("method", "GET")
    url = context.get("url", "")
    full_body = (context.get("full_body") or "")[:500]
    full_headers = context.get("full_headers") or {}

    # Build compact context snippet
    context_snippet = f"Method: {method}, URL: {url}"
    if full_body:
        context_snippet += f", Body preview: {full_body[:200]}"
    if full_headers:
        header_keys = list(full_headers.keys())[:10]
        context_snippet += f", Headers present: {', '.join(header_keys)}"

    prompt = (
        "You are a penetration testing assistant. Given this HTTP request context, "
        "suggest 6-8 injection payloads to test for the highlighted value.\n\n"
        f"Highlighted text: '{text}'\n"
        f"Field type: {field_type}\n"
        f"Field name: {field_name}\n"
        f"Request: {method} {url}\n"
        f"Context: {context_snippet}\n\n"
        "Return ONLY a JSON array of objects with keys: "
        "\"payload\" (the injection string), "
        "\"type\" (e.g. sqli, xss, cmd, ssti, nosql, traversal, ssrf, xxe, idor), "
        "\"description\" (1-line explanation).\n"
        "Be specific to the context — consider the field name, position, and request method. "
        "Include a variety of attack types relevant to this specific parameter. "
        "Return ONLY the JSON array, no other text."
    )

    try:
        claude_cmd = _find_claude_cli()
        if not claude_cmd:
            return {"error": "Claude CLI not found"}

        prompt_bytes = _safe_ascii(prompt).encode("utf-8")

        args = [
            claude_cmd,
            "--model", _MODEL_MAP.get("haiku", "haiku"),
            "--output-format", "json",
            "-p",
        ]

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

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=prompt_bytes), timeout=30
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"error": "Suggestion request timed out (30s)"}

        rc = proc.returncode
        raw_out = stdout.decode("utf-8", errors="replace").strip()

        if rc != 0 or not raw_out:
            return {"error": f"Claude CLI failed (rc={rc})"}

        # Parse output — may be wrapped in {"result": "..."} from --output-format json
        suggestions = _parse_suggestions_output(raw_out)
        if suggestions is not None:
            return {"suggestions": suggestions}

        return {"error": "Could not parse suggestions from Claude output"}

    except FileNotFoundError:
        return {"error": "Claude CLI not found"}
    except Exception as e:
        log.error("haiku suggestions error: %s", e, exc_info=True)
        return {"error": str(e)}


def _parse_suggestions_output(raw: str) -> list | None:
    """Parse Claude output into a list of suggestion dicts.

    Handles: --output-format json wrapper, direct JSON arrays, code fences,
    and embedded arrays in text.
    """
    import re

    def _try_parse_array(text: str) -> list | None:
        text = text.strip()
        # Try direct parse
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass
        # Strip code fences
        stripped = _strip_code_fences(text)
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass
        # Find first [ ... ] via bracket matching
        start = text.find("[")
        if start >= 0:
            depth = 0
            for i in range(start, len(text)):
                if text[i] == "[":
                    depth += 1
                elif text[i] == "]":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start:i + 1])
                        except json.JSONDecodeError:
                            break
        return None

    # Step 1: Try as --output-format json wrapper
    try:
        outer = json.loads(raw)
        if isinstance(outer, dict) and "result" in outer:
            inner = str(outer["result"]).strip()
            result = _try_parse_array(inner)
            if result is not None:
                return result
        if isinstance(outer, list):
            return outer
    except (json.JSONDecodeError, TypeError):
        pass

    # Step 2: Try raw text
    return _try_parse_array(raw)


# ── Endpoints ────────────────────────────────────────────────────

@router.post("/ai/suggest-injections")
async def ai_suggest_injections(data: dict = None):
    """Fast AI-powered injection suggestions for highlighted text in the interceptor."""
    data = data or {}
    text = (data.get("text") or "").strip()
    context = data.get("context") or {}

    if not text:
        return JSONResponse(status_code=400, content={"error": "text is required"})

    field_type = context.get("field_type", "param")

    # Try Claude CLI (haiku) first
    result = await _run_haiku_suggestions(text, context)

    if "suggestions" in result:
        return result

    # Fallback to hardcoded suggestions
    log.warning("AI suggestions failed (%s), using fallback for field_type=%s",
                result.get("error", "unknown"), field_type)
    fallback = _FALLBACK_SUGGESTIONS.get(field_type, _FALLBACK_SUGGESTIONS["param"])
    return {"suggestions": fallback, "fallback": True}


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


@router.post("/ai/analyze-request")
async def ai_analyze_request(data: dict = None):
    """Start AI analysis using a logged request's auth context.

    Accepts { method, url, headers, body, model?, host_filter? }.
    Stores the auth headers so the analysis (and auto-scan) can use them,
    then triggers the same analysis flow as /ai/analyze.
    """
    global _ai_status, _auth_context
    data = data or {}

    if _ai_status["running"]:
        return JSONResponse(status_code=409, content={"error": "Analysis already in progress"})

    url = (data.get("url") or "").strip()
    if not url:
        return JSONResponse(status_code=400, content={"error": "url is required"})

    # Build and store auth context
    auth_ctx = {
        "method": data.get("method", "GET"),
        "url": url,
        "headers": data.get("headers") or {},
        "body": data.get("body") or "",
    }
    set_auth_context(auth_ctx)

    # Also push auth headers to auto_scan module
    try:
        from api.auto_scan import set_auth_context as auto_scan_set_auth
        auto_scan_set_auth(auth_ctx["headers"])
    except Exception:
        pass

    model = data.get("model", "sonnet")
    host_filter = (data.get("host_filter") or "").strip()
    workspace_id = _get_workspace()

    # If no host_filter provided, derive from the request URL
    if not host_filter:
        try:
            from urllib.parse import urlparse
            host_filter = urlparse(url).netloc or ""
        except Exception:
            pass

    _ai_status = {
        "running": True,
        "error": None,
        "phase": "collecting",
        "endpoint_count": 0,
    }

    async def run_analysis():
        global _ai_status
        try:
            logs = await get_request_logs(session_id=workspace_id, limit=2000)
            endpoints = _prepare_traffic_payload(logs, host_filter, auth_context=auth_ctx)
            _ai_status["endpoint_count"] = len(endpoints)

            raw_scans = await get_scan_results_by_workspace(workspace_id, limit=1000)
            confirmed_vulns, scan_coverage = _prepare_scan_payload(raw_scans)

            if not endpoints and not confirmed_vulns and not scan_coverage:
                _ai_status["running"] = False
                _ai_status["error"] = "No traffic or scan data found. Browse some sites or run scans first."
                _ai_status["phase"] = "done"
                return

            _ai_status["phase"] = "analyzing"
            result = await _run_claude(endpoints, model,
                                       confirmed_vulns=confirmed_vulns,
                                       scan_coverage=scan_coverage,
                                       auth_context=auth_ctx)

            if "error" in result and "findings" not in result:
                _ai_status["running"] = False
                _ai_status["error"] = result["error"]
                _ai_status["phase"] = "done"
                return

            findings = result.get("findings", [])
            summary = result.get("summary", "")
            raw_response = json.dumps(result, indent=2, default=str)

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
            log.info("AI analysis (with auth context) complete: %d findings", len(findings))

        except Exception as e:
            log.error("AI analysis (auth) failed: %s", e, exc_info=True)
            _ai_status["running"] = False
            _ai_status["error"] = str(e)
            _ai_status["phase"] = "done"

    asyncio.create_task(run_analysis())
    return {"status": "started", "model": model, "host_filter": host_filter, "auth_context": True}


@router.get("/ai/status")
async def ai_status():
    """Poll analysis progress."""
    return _ai_status


@router.get("/ai/results")
async def ai_results(limit: int = 20):
    """Fetch saved results for the active workspace."""
    workspace_id = _get_workspace()
    return await get_ai_analysis_results(workspace_id, limit)


@router.get("/ai/export")
async def ai_export_json():
    """Export AI analysis results as a downloadable JSON file."""
    workspace_id = _get_workspace()
    results = await get_ai_analysis_results(workspace_id, limit=100)
    # Parse findings JSON strings into actual objects
    for r in results:
        if isinstance(r.get("findings"), str):
            try:
                r["findings"] = json.loads(r["findings"])
            except (json.JSONDecodeError, TypeError):
                pass
    content = json.dumps(results, indent=2, default=str)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=ai_analysis_export.json"},
    )


@router.get("/ai/export/markdown")
async def ai_export_markdown():
    """Export AI analysis results as a downloadable Markdown report."""
    workspace_id = _get_workspace()
    results = await get_ai_analysis_results(workspace_id, limit=100)

    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    md = "# AI Security Analysis Report\n\n"

    for r in results:
        findings = r.get("findings") or []
        if isinstance(findings, str):
            try:
                findings = json.loads(findings)
            except (json.JSONDecodeError, TypeError):
                findings = []

        model_label = (r.get("model") or "opus").capitalize()
        host_label = r.get("host_filter") or "All traffic"
        created = r.get("created_at") or ""

        risk_counts: dict[str, int] = {}
        for f in findings:
            risk = (f.get("risk") or "info").lower()
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        risk_line = " | ".join(
            f"{count} {risk.upper()}"
            for risk, count in sorted(risk_counts.items(), key=lambda x: risk_order.get(x[0], 9))
        )

        md += f"## Analysis — {host_label}\n\n"
        md += f"- **Model:** Claude {model_label}\n"
        md += f"- **Date:** {created}\n"
        md += f"- **Endpoints analyzed:** {r.get('endpoint_count', 0)}\n"
        md += f"- **Host filter:** {host_label}\n"
        md += f"- **Findings:** {risk_line or 'None'}\n\n"

        summary = r.get("summary") or ""
        if summary:
            md += f"### Summary\n\n{summary}\n\n"

        if findings:
            md += "### Findings\n\n"
            sorted_findings = sorted(
                findings,
                key=lambda f: risk_order.get((f.get("risk") or "info").lower(), 9),
            )
            for i, f in enumerate(sorted_findings, 1):
                risk = (f.get("risk") or "INFO").upper()
                md += f"#### {i}. [{risk}] {f.get('title', 'Untitled')}\n\n"
                if f.get("method") or f.get("path") or f.get("endpoint"):
                    md += f"**Endpoint:** `{f.get('method', '')} {f.get('path') or f.get('endpoint', '')}`\n\n"
                if f.get("category"):
                    md += f"**Category:** {f['category']}\n\n"
                if f.get("description"):
                    md += f"**Description:** {f['description']}\n\n"
                if f.get("evidence"):
                    md += f"**Evidence:** {f['evidence']}\n\n"
                if f.get("recommendation"):
                    md += f"**Recommendation:** {f['recommendation']}\n\n"
                md += "---\n\n"

        md += "\n"

    md += "*Generated by Endpoint Security Tool — AI Analysis*\n"

    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=ai_analysis_export.md"},
    )


@router.get("/ai/export/csv")
async def ai_export_csv():
    """Export AI analysis findings as a downloadable CSV file."""
    workspace_id = _get_workspace()
    results = await get_ai_analysis_results(workspace_id, limit=100)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "analysis_date", "model", "host_filter", "risk", "category",
        "title", "method", "path", "endpoint", "description",
        "evidence", "recommendation",
    ])

    for r in results:
        findings = r.get("findings") or []
        if isinstance(findings, str):
            try:
                findings = json.loads(findings)
            except (json.JSONDecodeError, TypeError):
                findings = []
        for f in findings:
            writer.writerow([
                r.get("created_at", ""),
                r.get("model", ""),
                r.get("host_filter", ""),
                f.get("risk", ""),
                f.get("category", ""),
                f.get("title", ""),
                f.get("method", ""),
                f.get("path", ""),
                f.get("endpoint", ""),
                f.get("description", ""),
                f.get("evidence", ""),
                f.get("recommendation", ""),
            ])

    content = output.getvalue()
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ai_analysis_export.csv"},
    )


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


# ── Triage Endpoints ────────────────────────────────────────────────


@router.post("/ai/triage")
async def ai_triage(data: dict = None):
    """Quick AI Triage: analyze existing proxy traffic to identify upload
    points and weak endpoints, rank by attack priority, and suggest
    specific payloads — without requiring a full crawl first.
    """
    global _ai_status
    data = data or {}

    if _ai_status["running"]:
        return JSONResponse(status_code=409, content={"error": "Analysis already in progress"})

    model = data.get("model", "sonnet")
    host_filter = (data.get("host_filter") or "").strip()
    auth_context = data.get("auth_context") or _auth_context
    workspace_id = _get_workspace()

    _ai_status = {
        "running": True,
        "error": None,
        "phase": "collecting",
        "endpoint_count": 0,
    }

    async def run_triage():
        global _ai_status
        try:
            # Collect traffic
            logs = await get_request_logs(session_id=workspace_id, limit=2000)
            endpoints = _prepare_traffic_payload(logs, host_filter, auth_context=auth_context)
            _ai_status["endpoint_count"] = len(endpoints)

            # Collect existing scan results
            raw_scans = await get_scan_results_by_workspace(workspace_id, limit=1000)
            confirmed_vulns, scan_coverage = _prepare_scan_payload(raw_scans)

            if not endpoints:
                _ai_status["running"] = False
                _ai_status["error"] = "No traffic found. Browse some sites first so the proxy captures endpoints."
                _ai_status["phase"] = "done"
                return

            # Build triage prompt and call Claude
            _ai_status["phase"] = "analyzing"
            prompt = _build_triage_prompt(endpoints, confirmed_vulns, scan_coverage, auth_context)
            result = await run_claude_with_prompt(prompt, model=model)

            if "error" in result and "priority_targets" not in result:
                _ai_status["running"] = False
                _ai_status["error"] = result["error"]
                _ai_status["phase"] = "done"
                return

            # Normalize the response
            summary = result.get("summary", "")
            upload_endpoints = result.get("upload_endpoints", [])
            priority_targets = result.get("priority_targets", [])
            findings = result.get("findings", [])

            raw_response = json.dumps(result, indent=2, default=str)

            # Save to DB with "triage:" prefix on model to distinguish
            await save_ai_analysis(
                workspace_id=workspace_id,
                model=f"triage:{model}",
                host_filter=host_filter,
                endpoint_count=len(endpoints),
                findings=findings or priority_targets,
                summary=summary,
                raw_response=raw_response,
            )

            _ai_status["running"] = False
            _ai_status["phase"] = "done"
            log.info("AI triage complete: %d upload endpoints, %d priority targets",
                     len(upload_endpoints), len(priority_targets))

        except Exception as e:
            log.error("AI triage failed: %s", e, exc_info=True)
            _ai_status["running"] = False
            _ai_status["error"] = str(e)
            _ai_status["phase"] = "done"

    asyncio.create_task(run_triage())
    return {"status": "started", "model": model, "host_filter": host_filter}


@router.get("/ai/triage/status")
async def ai_triage_status():
    """Poll triage progress (reuses the shared _ai_status dict)."""
    return _ai_status


@router.post("/ai/triage/execute")
async def ai_triage_execute(data: dict = None):
    """Execute suggested payloads from the triage against target endpoints.

    Accepts {targets: [{method, url, payloads: [{injection_point, key, payload, type}]}], model?}
    Sends each payload, then passes results through Claude for analysis.
    """
    import time
    import httpx
    from urllib.parse import urlparse
    from config import SCAN_DEFAULT_TIMEOUT, SCAN_RESPONSE_CAP, PROXY_HOST, PROXY_PORT, DEFAULT_HEADERS

    global _ai_status
    data = data or {}

    if _ai_status["running"]:
        return JSONResponse(status_code=409, content={"error": "Analysis already in progress"})

    targets = data.get("targets", [])
    if not targets:
        return JSONResponse(status_code=400, content={"error": "targets is required"})

    ai_model = data.get("model", "sonnet")

    _ai_status = {
        "running": True,
        "error": None,
        "phase": "executing",
        "endpoint_count": sum(max(1, len(t.get("payloads", []))) for t in targets),
    }

    async def run_execute():
        global _ai_status
        try:
            # Build default headers
            try:
                from api.routes import get_default_headers
                headers = await get_default_headers()
            except Exception:
                headers = dict(DEFAULT_HEADERS)
            headers["x-ept-scan"] = "1"

            proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
            targeted_results = []

            async with httpx.AsyncClient(
                verify=False, timeout=SCAN_DEFAULT_TIMEOUT, proxy=proxy_url
            ) as client:
                for target in targets:
                    method = target.get("method", "GET").upper()
                    url = target.get("url", "")
                    payloads = target.get("payloads", [])

                    if not payloads:
                        payloads = [{"injection_point": "none", "key": "", "payload": "", "type": "recon"}]

                    for pl in payloads:
                        payload_str = pl.get("payload", "")
                        injection_point = pl.get("injection_point", "query")
                        key = pl.get("key", "")

                        req_params = {}
                        req_body = ""
                        req_headers = dict(headers)
                        req_url = url

                        if injection_point in ("query", "params") and key and payload_str:
                            req_params[key] = payload_str
                        elif injection_point == "body" and key and payload_str:
                            try:
                                req_body = json.dumps({key: payload_str})
                                req_headers["Content-Type"] = "application/json"
                            except Exception:
                                req_body = f"{key}={payload_str}"
                        elif injection_point == "header" and key and payload_str:
                            req_headers[key] = payload_str
                        elif injection_point == "path" and payload_str:
                            req_url = url.rstrip("/") + "/" + payload_str

                        start_time = time.time()
                        error = None
                        status_code = 0
                        resp_headers = {}
                        resp_body = ""

                        try:
                            if method == "GET":
                                resp = await client.get(req_url, params=req_params, headers=req_headers)
                            else:
                                resp = await client.request(
                                    method, req_url,
                                    params=req_params,
                                    headers=req_headers,
                                    content=req_body.encode("utf-8") if req_body else b"",
                                )
                            elapsed = round((time.time() - start_time) * 1000, 2)
                            status_code = resp.status_code
                            resp_headers = dict(resp.headers)
                            resp_body = resp.text[:SCAN_RESPONSE_CAP]
                        except Exception as e:
                            elapsed = round((time.time() - start_time) * 1000, 2)
                            error = str(e)

                        targeted_results.append({
                            "method": method,
                            "url": req_url,
                            "path": urlparse(req_url).path,
                            "risk_reason": target.get("risk_reason", ""),
                            "payload": payload_str,
                            "injection_point": injection_point,
                            "key": key,
                            "payload_type": pl.get("type", "unknown"),
                            "status_code": status_code,
                            "response_headers": resp_headers,
                            "response_body": resp_body,
                            "response_time_ms": elapsed,
                            **({"error": error} if error else {}),
                        })

            if not targeted_results:
                _ai_status["running"] = False
                _ai_status["phase"] = "done"
                _ai_status["error"] = "No requests were executed"
                return

            # Analyze results with Claude
            _ai_status["phase"] = "analyzing"
            prompt = _build_retest_analysis_prompt(targeted_results)
            analysis = await run_claude_with_prompt(prompt, model=ai_model)

            findings = analysis.get("findings", [])
            summary = analysis.get("summary", "")

            # Save to DB
            workspace_id = _get_workspace()
            raw_response = json.dumps({
                "summary": summary,
                "findings": findings,
                "targeted_results": targeted_results,
            }, indent=2, default=str)

            await save_ai_analysis(
                workspace_id=workspace_id,
                model=f"triage-exec:{ai_model}",
                host_filter="",
                endpoint_count=len(targeted_results),
                findings=findings,
                summary=summary,
                raw_response=raw_response,
            )

            _ai_status["running"] = False
            _ai_status["phase"] = "done"
            log.info("Triage execute complete: %d findings from %d requests",
                     len(findings), len(targeted_results))

        except Exception as e:
            log.error("Triage execute failed: %s", e, exc_info=True)
            _ai_status["running"] = False
            _ai_status["error"] = str(e)
            _ai_status["phase"] = "done"

    asyncio.create_task(run_execute())
    return {"status": "started", "targets": len(targets), "model": ai_model}
