"""
Auto-Scan orchestrator — 5-phase automated scanning pipeline.

Phases:
  1. crawl     — Discover URLs via Playwright spider
  2. inject    — Run injection scanners against discovered endpoints
  3. upload    — Test file upload vulnerabilities
  4. ai        — Claude AI analysis + targeted request suggestions
  5. targeted  — Execute Claude's suggested requests and re-analyze

Rate-limited via an async semaphore + configurable delay to avoid
overwhelming the target or getting firewall-blacklisted.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

import httpx

from fastapi import APIRouter, BackgroundTasks

from config import (
    AUTO_SCAN_DEFAULT_CONCURRENT,
    AUTO_SCAN_DEFAULT_DELAY,
    AUTO_SCAN_DEFAULT_DEPTH,
    AUTO_SCAN_DEFAULT_MAX_PAGES,
    SCAN_DEFAULT_TIMEOUT,
    SCAN_RESPONSE_CAP,
    PROXY_HOST,
    PROXY_PORT,
    DEFAULT_HEADERS,
)

from storage.db import save_auto_scan_session, update_auto_scan_session

from api.claude_analysis import (
    _build_targeted_prompt,
    _build_retest_analysis_prompt,
    run_claude_with_prompt,
    _prepare_traffic_payload,
    _prepare_scan_payload,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/auto-scan", tags=["auto-scan"])


# ── Auth context for authenticated scanning ────────────────────────
_auto_scan_auth_headers: dict | None = None


def set_auth_context(headers: dict | None):
    """Store auth headers (Authorization, Cookie, etc.) for auto-scan phases."""
    global _auto_scan_auth_headers
    _auto_scan_auth_headers = headers


def get_auth_context() -> dict | None:
    """Return stored auth headers, if any."""
    return _auto_scan_auth_headers


# ── Rate limiter ────────────────────────────────────────────────────


class RateLimiter:
    """Async rate limiter: caps concurrency and enforces delay between requests."""

    def __init__(self, max_concurrent: int = 5, delay: float = 0.5):
        self._sem = asyncio.Semaphore(max_concurrent)
        self._delay = delay
        self._last_request = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        await self._sem.acquire()
        async with self._lock:
            now = time.monotonic()
            wait = self._delay - (now - self._last_request)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()

    def release(self):
        self._sem.release()


# ── Global scan state ───────────────────────────────────────────────

_state = {
    "running": False,
    "error": None,
    "current_phase": "",
    "completed_phases": [],
    "skipped_phases": [],
    "phase_detail": "",
    "paused": False,
    "endpoints_found": 0,
    "vulns_found": 0,
    "requests_sent": 0,
    "event_log": [],
    "last_event_id": 0,
}

_control = {"signal": "run"}  # "run" | "pause" | "stop"

_results = {
    "crawl": None,
    "inject": None,
    "upload": None,
    "ai": None,
    "targeted": None,
}

_session_id: int | None = None


def _reset_state():
    global _session_id
    _state.update({
        "running": False,
        "error": None,
        "current_phase": "",
        "completed_phases": [],
        "skipped_phases": [],
        "phase_detail": "",
        "paused": False,
        "endpoints_found": 0,
        "vulns_found": 0,
        "requests_sent": 0,
        "event_log": [],
        "last_event_id": 0,
    })
    _control["signal"] = "run"
    _results.update({k: None for k in _results})
    _session_id = None


_EVENT_LOG_MAX = 500


def _safe_ascii(s: str) -> str:
    """Encode string to ASCII-safe form, replacing non-ASCII chars to avoid cp1252 crashes."""
    return s.encode("ascii", errors="replace").decode("ascii")


def _emit_event(phase: str, message: str, detail: str = ""):
    """Append a timestamped event to the event log. Caps at _EVENT_LOG_MAX entries."""
    _state["last_event_id"] += 1
    event = {
        "id": _state["last_event_id"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": phase,
        "message": _safe_ascii(message),
        "detail": _safe_ascii(detail),
    }
    _state["event_log"].append(event)
    # Cap the log size
    if len(_state["event_log"]) > _EVENT_LOG_MAX:
        _state["event_log"] = _state["event_log"][-_EVENT_LOG_MAX:]


# ── Helpers ─────────────────────────────────────────────────────────


async def _check_control():
    """Pause-loop and stop-check. Returns True if we should stop."""
    while _control["signal"] == "pause":
        _state["paused"] = True
        await asyncio.sleep(0.5)
    _state["paused"] = False
    return _control["signal"] == "stop"


def _get_active_workspace() -> str:
    from api.routes import get_active_workspace
    return get_active_workspace()


async def _get_default_headers() -> dict:
    try:
        from api.routes import get_default_headers
        return await get_default_headers()
    except Exception:
        return dict(DEFAULT_HEADERS)


# ── Phase 1: Crawl ─────────────────────────────────────────────────


async def _phase_crawl(
    target_url: str,
    max_depth: int,
    max_pages: int,
    auth_headers: dict | None = None,
) -> dict:
    """Discover URLs using the Playwright spider.

    Returns a dict with:
      - urls: list of all visited/discovered URLs (frontend pages)
      - forms: list of form dicts extracted from pages
    """
    _state["current_phase"] = "crawl"
    _state["phase_detail"] = "Starting crawler..."
    _emit_event("crawl", "Starting crawl", f"Target: {target_url}, depth={max_depth}, max_pages={max_pages}")

    from crawler.spider import Spider
    spider = Spider()

    # Run crawl in a background wrapper so we can update status
    crawl_task = asyncio.create_task(
        spider.crawl(target_url, max_depth, max_pages, extra_headers=auth_headers)
    )

    prev_pages = 0
    prev_discovered = set()
    prev_forms = 0

    while not crawl_task.done():
        if await _check_control():
            _emit_event("crawl", "Crawl stopped by user")
            spider.stop()
            crawl_task.cancel()
            return {"urls": [], "forms": []}

        cur_pages = spider._pages_crawled
        if cur_pages > prev_pages:
            for _ in range(cur_pages - prev_pages):
                prev_pages += 1
                _emit_event("crawl", f"Page crawled ({prev_pages}/{max_pages})")

        new_urls = spider.discovered - prev_discovered
        for url in new_urls:
            _emit_event("crawl", "URL discovered", url)
        prev_discovered = set(spider.discovered)

        cur_forms = len(spider.forms) if spider.forms else 0
        if cur_forms > prev_forms:
            _emit_event("crawl", f"Forms found: {cur_forms} total (+{cur_forms - prev_forms} new)")
            prev_forms = cur_forms

        _state["phase_detail"] = f"Crawled {spider._pages_crawled}/{max_pages} pages"
        _state["endpoints_found"] = len(spider.discovered)
        await asyncio.sleep(1)

    # Await the task to propagate exceptions
    try:
        await crawl_task
    except asyncio.CancelledError:
        return {"urls": [], "forms": []}

    # Emit any remaining discoveries from the final iteration
    new_urls = spider.discovered - prev_discovered
    for url in new_urls:
        _emit_event("crawl", "URL discovered", url)

    urls = list(spider.visited | spider.discovered)
    forms = list(spider.forms) if spider.forms else []
    _state["endpoints_found"] = len(urls)
    _state["phase_detail"] = f"Found {len(urls)} URLs, {len(forms)} forms"
    _emit_event("crawl", "Crawl complete", f"Total URLs found: {len(urls)}, pages crawled: {spider._pages_crawled}, forms: {len(forms)}")

    _results["crawl"] = {"urls": urls, "forms": forms}
    return {"urls": urls, "forms": forms}


# ── Endpoint extraction from proxy logs ────────────────────────────

# Content-types that indicate a backend API response (not a page load)
_API_CONTENT_TYPES = (
    "application/json",
    "application/xml",
    "text/xml",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "application/graphql",
    "application/grpc",
    "text/plain",  # many APIs return text/plain
)

# Path prefixes that strongly indicate backend routes
_API_PATH_PATTERNS = (
    "/api/", "/api-", "/v1/", "/v2/", "/v3/", "/rest/",
    "/graphql", "/gql", "/rpc/", "/ws/", "/webhook",
    "/auth/", "/oauth/", "/token", "/login", "/logout",
    "/admin/api", "/backend/", "/_api/", "/ajax/",
)

# File extensions that indicate static frontend assets — never inject these
_STATIC_EXTENSIONS = (
    ".html", ".htm", ".css", ".js", ".jsx", ".ts", ".tsx",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".map", ".mp4", ".mp3", ".pdf", ".zip",
)


def _is_backend_endpoint(log_entry: dict) -> bool:
    """Determine whether a proxy log entry represents a backend API call
    rather than a frontend page/asset load."""
    method = (log_entry.get("method") or "GET").upper()
    path = (log_entry.get("path") or "").lower()
    ct = (log_entry.get("content_type") or "").lower().split(";")[0].strip()
    status = log_entry.get("status_code", 0)

    # Static assets are never backend endpoints
    if any(path.endswith(ext) for ext in _STATIC_EXTENSIONS):
        return False

    # Mutating methods are almost always backend calls
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return True

    # Path-based heuristic: common API path patterns
    if any(pat in path for pat in _API_PATH_PATTERNS):
        return True

    # Content-type heuristic: JSON/XML responses are backend
    if ct and any(ct.startswith(api_ct) for api_ct in _API_CONTENT_TYPES):
        # But skip if it's HTML disguised as text
        if ct == "text/plain":
            body = (log_entry.get("response_body") or "")[:200].strip().lower()
            if body.startswith("<!doctype") or body.startswith("<html"):
                return False
        return True

    # Responses returning HTML are frontend pages
    if ct.startswith("text/html"):
        return False

    # Non-200 status on GET with no content-type — likely an API 404/403
    if method == "GET" and status >= 400 and not ct:
        return True

    return False


def _parse_request_body_params(body: str, content_type: str) -> dict:
    """Extract injectable parameters from a request body."""
    params = {}
    ct = (content_type or "").lower()

    if not body:
        return params

    # JSON body
    if "json" in ct or body.strip().startswith(("{", "[")):
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                # Flatten one level — these are the injectable keys
                for k, v in parsed.items():
                    params[k] = str(v) if not isinstance(v, str) else v
        except (json.JSONDecodeError, ValueError):
            pass
    # URL-encoded body
    elif "form-urlencoded" in ct or "=" in body:
        try:
            qs = parse_qs(body, keep_blank_values=True)
            params = {k: v[0] if len(v) == 1 else v[-1] for k, v in qs.items()}
        except Exception:
            pass

    return params


async def _extract_backend_endpoints(
    target_url: str,
    crawled_urls: list[str],
    forms: list[dict],
) -> list[dict]:
    """After the crawl, extract actual backend API endpoints from proxy logs
    and form actions. These are what we should inject against — not the
    frontend pages that the crawler visited.

    Returns a list of endpoint config dicts ready for injection:
      {"url": ..., "method": ..., "params": ..., "body_params": ...,
       "headers": ..., "source": "proxy"|"form"}
    """
    from storage.db import get_request_logs

    workspace = _get_active_workspace()
    target_host = urlparse(target_url).netloc

    _emit_event("crawl", "Extracting backend endpoints from proxy traffic",
                f"Filtering for host: {target_host}")

    # Fetch all proxy logs for the target domain captured during crawl
    logs = await get_request_logs(
        session_id=workspace,
        host_filter=target_host,
        limit=2000,
    )

    _emit_event("crawl", f"Analyzing {len(logs)} proxy-captured requests",
                f"Classifying backend vs frontend...")

    # Deduplicate by method+path and classify
    seen = set()
    backend_endpoints = []
    frontend_count = 0
    static_count = 0

    for entry in logs:
        method = (entry.get("method") or "GET").upper()
        path = entry.get("path") or ""
        url = entry.get("url") or ""
        dedup_key = f"{method} {path}"

        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        if not _is_backend_endpoint(entry):
            ct = (entry.get("content_type") or "").lower()
            if any(path.lower().endswith(ext) for ext in _STATIC_EXTENSIONS):
                static_count += 1
            else:
                frontend_count += 1
            continue

        # Build a rich endpoint config from the proxy log
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Query string params
        query_params = {}
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            query_params = {k: v[0] if len(v) == 1 else v[-1] for k, v in qs.items()}

        # Body params (for POST/PUT/PATCH)
        req_ct = ""
        req_headers = entry.get("request_headers") or {}
        if isinstance(req_headers, str):
            try:
                req_headers = json.loads(req_headers)
            except Exception:
                req_headers = {}
        req_ct = req_headers.get("content-type", "")

        body_params = {}
        raw_body = entry.get("request_body") or ""
        if method in ("POST", "PUT", "PATCH") and raw_body:
            body_params = _parse_request_body_params(raw_body, req_ct)

        backend_endpoints.append({
            "url": base_url,
            "method": method,
            "params": query_params,
            "body_params": body_params,
            "content_type": req_ct,
            "source": "proxy",
        })

    # Add form actions as additional backend endpoints
    form_seen = set()
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        if not action:
            continue

        dedup_key = f"{method} {action}"
        if dedup_key in seen or dedup_key in form_seen:
            continue
        form_seen.add(dedup_key)
        seen.add(dedup_key)

        # Build params from form inputs
        form_params = {}
        for inp in form.get("inputs", []):
            name = inp.get("name", "")
            if name:
                form_params[name] = inp.get("value", "test")

        backend_endpoints.append({
            "url": action,
            "method": method,
            "params": form_params if method == "GET" else {},
            "body_params": form_params if method != "GET" else {},
            "content_type": "application/x-www-form-urlencoded" if method != "GET" else "",
            "source": "form",
        })

    _emit_event("crawl",
                f"Endpoint classification complete: {len(backend_endpoints)} backend, "
                f"{frontend_count} frontend pages, {static_count} static assets skipped",
                "Backend endpoints will be used for injection testing")

    # Log each backend endpoint so the user can see exactly what will be tested
    for ep in backend_endpoints:
        src = ep["source"]
        param_count = len(ep["params"]) + len(ep.get("body_params", {}))
        _emit_event("crawl",
                    f"[{src.upper()}] {ep['method']} {urlparse(ep['url']).path}",
                    f"{param_count} injectable params" if param_count else "no params (path-only)")

    # If no backend endpoints found, fall back to crawled URLs but warn loudly
    if not backend_endpoints:
        _emit_event("crawl",
                    "WARNING: No backend API endpoints detected in proxy traffic",
                    "Falling back to crawled URLs — results may target frontend routes")
        for url in crawled_urls:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            query_params = {}
            if parsed.query:
                qs = parse_qs(parsed.query, keep_blank_values=True)
                query_params = {k: v[0] if len(v) == 1 else v[-1] for k, v in qs.items()}
            if f"GET {parsed.path}" not in seen:
                seen.add(f"GET {parsed.path}")
                backend_endpoints.append({
                    "url": base,
                    "method": "GET",
                    "params": query_params,
                    "body_params": {},
                    "content_type": "",
                    "source": "fallback",
                })

    return backend_endpoints


# ── Phase 2: Inject ────────────────────────────────────────────────


async def _phase_inject(
    endpoint_configs: list[dict],
    rate_limiter: RateLimiter,
) -> list[dict]:
    """Run injection scanners against backend API endpoints. Returns findings list.

    endpoint_configs: list of dicts from _extract_backend_endpoints(), each with
      url, method, params, body_params, content_type, source.
    """
    _state["current_phase"] = "inject"
    _state["phase_detail"] = "Preparing injection tests..."

    from api.routes import _load_injectors, INJECTORS
    _load_injectors()

    if not endpoint_configs:
        _state["phase_detail"] = "No backend endpoints to test"
        _emit_event("inject", "No backend endpoints to test")
        _results["inject"] = {"findings": []}
        return []

    # Use a focused set of injectors for auto-scan (skip oob, jwt, quick)
    auto_injector_keys = ["sql", "xss", "cmd", "ssti", "traversal", "mongo"]
    injector_keys = [k for k in auto_injector_keys if k in INJECTORS]

    total_endpoints = len(endpoint_configs)
    total_payloads = total_endpoints * len(injector_keys)
    _emit_event("inject", "Starting injection tests",
                f"{total_endpoints} backend endpoints × {len(injector_keys)} injectors (~{total_payloads} test sets)")

    # Merge auth headers into each endpoint config so injectors send them
    auth_hdrs = get_auth_context() or {}

    findings = []
    control_for_injectors = {"signal": "run"}

    for ep_idx, ep in enumerate(endpoint_configs):
        if await _check_control():
            break

        # Sync the injector-level control with our auto-scan control
        control_for_injectors["signal"] = _control["signal"]

        # Build per-endpoint headers with auth context
        ep_headers = dict(auth_hdrs)

        # Determine which parameters to inject into
        # Merge query params and body params for injection targeting
        all_params = dict(ep.get("params", {}))
        body_params = ep.get("body_params", {})

        # Determine injection points based on endpoint characteristics
        injection_points = ["paths"]  # always try path injection
        if all_params:
            injection_points.append("params")
        if body_params and ep["method"] in ("POST", "PUT", "PATCH"):
            injection_points.append("body")
            # For POST endpoints, inject body params too
            # The injector uses "params" dict for query params; we merge body
            # params in so they get tested as well
            all_params.update(body_params)

        source_label = f"[{ep.get('source', '?').upper()}]"
        _emit_event("inject", f"Testing endpoint {ep_idx + 1}/{total_endpoints}",
                     f"{source_label} {ep['method']} {ep['url']} ({len(all_params)} params)")

        for inj_key in injector_keys:
            if await _check_control():
                break

            _state["phase_detail"] = (
                f"Testing endpoint {ep_idx + 1}/{total_endpoints} "
                f"with {inj_key}"
            )

            injector = INJECTORS[inj_key]()
            # Use quick payloads for auto-scan to keep request count manageable
            injector._payload_override = injector.generate_quick_payloads(
                {"url": ep["url"], "method": ep["method"], "params": all_params}
            )

            async def on_result(result, idx, total):
                _state["requests_sent"] += 1
                if result.is_vulnerable:
                    _state["vulns_found"] += 1
                    _emit_event("inject", f"Vulnerability found ({result.confidence})",
                                f"{inj_key.upper()} in {result.injection_point}:{result.original_param} -- payload: {result.payload}")

                # Rate-limit each request
                await rate_limiter.acquire()
                rate_limiter.release()

            try:
                results = await injector.test_endpoint(
                    url=ep["url"],
                    method=ep["method"],
                    params=all_params,
                    headers=ep_headers if ep_headers else None,
                    injection_points=injection_points,
                    timeout=SCAN_DEFAULT_TIMEOUT,
                    on_result=on_result,
                    control=control_for_injectors,
                )

                for r in results:
                    if r.is_vulnerable:
                        findings.append({
                            "risk": _confidence_to_risk(r.confidence),
                            "method": ep["method"],
                            "path": urlparse(ep["url"]).path,
                            "endpoint": ep["url"],
                            "title": f"{inj_key.upper()} injection ({r.injection_point}: {r.original_param})",
                            "category": f"{inj_key.upper()} Injection",
                            "description": r.details,
                            "evidence": f"Payload: {r.payload} -> Status {r.response_code}",
                            "recommendation": f"Sanitize {r.original_param} parameter against {inj_key} injection",
                        })
            except Exception as e:
                log.warning("Injector %s failed on %s: %s", inj_key, _safe_ascii(ep["url"]), e)

    _state["phase_detail"] = f"Found {len(findings)} vulnerabilities"
    _emit_event("inject", "Injection phase complete",
                f"{len(findings)} vulnerabilities found, {_state['requests_sent']} requests sent")
    _results["inject"] = {"findings": findings}
    return findings


def _confidence_to_risk(confidence: str) -> str:
    return {"high": "high", "medium": "medium", "low": "low"}.get(confidence, "info")


# ── Phase 3: Upload ────────────────────────────────────────────────


async def _phase_upload(
    endpoint_configs: list[dict],
    rate_limiter: RateLimiter,
) -> list[dict]:
    """Scan for file upload vulnerabilities. Returns findings list.

    Uses backend endpoint configs to find likely upload targets — endpoints
    with upload-related paths or that accepted multipart content during crawl.
    """
    _state["current_phase"] = "upload"
    _state["phase_detail"] = "Scanning for upload endpoints..."

    # Look for upload patterns in backend endpoint URLs and content types
    upload_keywords = ["upload", "file", "attach", "import", "media", "image", "document", "avatar", "photo"]
    upload_urls = []
    seen = set()
    for ep in endpoint_configs:
        url = ep.get("url", "")
        ct = (ep.get("content_type") or "").lower()
        path_lower = urlparse(url).path.lower()
        if url in seen:
            continue
        # Match by path keywords or by multipart content-type from the crawl
        if any(kw in path_lower for kw in upload_keywords) or "multipart" in ct:
            seen.add(url)
            upload_urls.append(url)

    findings = []

    if not upload_urls:
        _state["phase_detail"] = "No upload endpoints detected"
        _emit_event("upload", "No upload endpoints detected in backend routes")
        _results["upload"] = {"findings": []}
        return []

    _emit_event("upload", "Starting upload tests", f"{len(upload_urls)} backend upload endpoints found")

    headers = await _get_default_headers()
    headers["x-ept-scan"] = "1"
    # Merge auth context headers so uploads go through auth gates
    auth_hdrs = get_auth_context() or {}
    if auth_hdrs:
        headers.update({k: v for k, v in auth_hdrs.items()
                        if k.lower() not in ("host", "content-length", "content-type",
                                              "transfer-encoding")})
    proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"

    # Test each upload endpoint with dangerous file types
    test_files = [
        ("test.php", b"<?php echo 'test'; ?>", "application/x-php"),
        ("test.html", b"<script>alert(1)</script>", "text/html"),
        ("test.svg", b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>', "image/svg+xml"),
        ("../../../etc/passwd", b"path traversal test", "application/octet-stream"),
        ("test.jsp", b"<% out.println(\"test\"); %>", "application/x-jsp"),
    ]

    for url in upload_urls:
        if await _check_control():
            break

        _emit_event("upload", f"Testing upload endpoint", urlparse(url).path)

        for filename, content, content_type in test_files:
            if await _check_control():
                break

            await rate_limiter.acquire()
            try:
                _state["requests_sent"] += 1
                _state["phase_detail"] = f"Testing {urlparse(url).path} with {filename}"
                _emit_event("upload", f"Sending test file: {filename}", f"-> {urlparse(url).path}")

                async with httpx.AsyncClient(
                    verify=False, timeout=SCAN_DEFAULT_TIMEOUT, proxy=proxy_url
                ) as client:
                    files = {"file": (filename, content, content_type)}
                    resp = await client.post(url, files=files, headers=headers)

                    # Check if the upload was accepted (not blocked)
                    if resp.status_code in (200, 201, 202):
                        risk = "high" if filename.endswith((".php", ".jsp")) else "medium"
                        findings.append({
                            "risk": risk,
                            "method": "POST",
                            "path": urlparse(url).path,
                            "endpoint": url,
                            "title": f"Potentially unsafe file upload accepted: {filename}",
                            "category": "File Upload",
                            "description": (
                                f"The endpoint accepted a {filename} upload with "
                                f"content-type {content_type}. Status: {resp.status_code}."
                            ),
                            "evidence": f"Upload of {filename} returned status {resp.status_code}",
                            "recommendation": (
                                "Validate uploaded file types server-side. "
                                "Block executable file extensions and verify MIME types."
                            ),
                        })
                        _state["vulns_found"] += 1
                        _emit_event("upload", f"Upload accepted ({risk} risk)",
                                    f"{filename} accepted at {urlparse(url).path} -- status {resp.status_code}")
            except Exception as e:
                log.debug("Upload test failed for %s: %s", _safe_ascii(url), e)
            finally:
                rate_limiter.release()

    _state["phase_detail"] = f"Found {len(findings)} upload issues"
    _emit_event("upload", "Upload phase complete", f"{len(findings)} issues found")
    _results["upload"] = {"findings": findings}
    return findings


# ── Phase 4: AI Analysis ───────────────────────────────────────────


async def _phase_ai(
    urls: list[str],
    inject_findings: list[dict],
    ai_model: str,
) -> dict | None:
    """Run Claude AI analysis. Returns AI response dict with findings + targeted_requests."""
    _state["current_phase"] = "ai"
    _state["phase_detail"] = "Preparing data for AI analysis..."
    _emit_event("ai", "Starting AI analysis", f"Model: {ai_model}")

    if await _check_control():
        return None

    # Build endpoint list from captured traffic
    from storage.db import get_request_logs
    workspace = _get_active_workspace()
    logs = await get_request_logs(session_id=workspace, limit=500)

    # Filter to target domain
    target_hosts = set()
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc:
            target_hosts.add(parsed.netloc)

    endpoints = _prepare_traffic_payload(
        logs,
        host_filter=list(target_hosts)[0] if target_hosts else "",
    )

    _emit_event("ai", f"Prepared {len(endpoints)} endpoints for analysis",
                f"From {len(logs)} captured traffic logs")

    # Build confirmed vulns + coverage from injection results
    from storage.db import get_scan_results_by_workspace
    scan_rows = await get_scan_results_by_workspace(workspace, limit=1000)
    confirmed_vulns, scan_coverage = _prepare_scan_payload(scan_rows)

    _state["phase_detail"] = f"Sending {len(endpoints)} endpoints to Claude ({ai_model})..."

    if await _check_control():
        return None

    # Build auth context for the AI prompt if available
    auth_hdrs = get_auth_context()
    from api.claude_analysis import get_auth_context as get_ai_auth
    ai_auth = get_ai_auth()
    prompt = _build_targeted_prompt(endpoints, confirmed_vulns, scan_coverage,
                                    auth_context=ai_auth)

    _emit_event("ai", "Prompt built", f"{len(prompt)} chars, sending to Claude ({ai_model})...")
    _emit_event("ai", "Waiting for Claude response", "This may take a few minutes...")

    ai_result = await run_claude_with_prompt(prompt, model=ai_model)

    if ai_result.get("error"):
        _state["phase_detail"] = f"AI error: {ai_result['error']}"
        _emit_event("ai", "AI analysis error", ai_result["error"])
        log.error("AI analysis failed: %s", ai_result["error"])
        _results["ai"] = {"summary": f"Error: {ai_result['error']}", "findings": [], "targeted_requests": []}
        return ai_result

    _emit_event("ai", "Response received, parsing results")

    # Normalize the response
    ai_data = {
        "summary": ai_result.get("summary", ""),
        "findings": ai_result.get("findings", []),
        "targeted_requests": [],
    }

    # Map targeted_requests from Claude's format to the frontend format
    for tr in ai_result.get("targeted_requests", []):
        ai_data["targeted_requests"].append({
            "risk": _priority_to_risk(tr.get("priority", 10)),
            "method": tr.get("method", "GET"),
            "url": tr.get("url", ""),
            "path": tr.get("path", ""),
            "reason": tr.get("risk_reason", ""),
            # Keep the full data for Phase 5
            "_suggested_payloads": tr.get("suggested_payloads", []),
        })

    _state["phase_detail"] = (
        f"AI found {len(ai_data['findings'])} issues, "
        f"suggested {len(ai_data['targeted_requests'])} targets"
    )
    _state["vulns_found"] += len(ai_data["findings"])

    _emit_event("ai", "AI analysis complete",
                f"{len(ai_data['findings'])} findings, {len(ai_data['targeted_requests'])} targeted requests generated")

    _results["ai"] = ai_data
    return ai_data


def _priority_to_risk(priority: int) -> str:
    if priority <= 3:
        return "critical"
    elif priority <= 7:
        return "high"
    elif priority <= 13:
        return "medium"
    return "low"


# ── Phase 5: Targeted Re-test ──────────────────────────────────────


async def _phase_targeted(
    ai_data: dict,
    rate_limiter: RateLimiter,
    ai_model: str,
) -> list[dict]:
    """Execute Claude's suggested targeted requests and analyze responses."""
    _state["current_phase"] = "targeted"
    _state["phase_detail"] = "Executing targeted requests..."

    targeted_requests = ai_data.get("targeted_requests", [])
    if not targeted_requests:
        _state["phase_detail"] = "No targeted requests to execute"
        _emit_event("targeted", "No targeted requests to execute")
        _results["targeted"] = {"findings": []}
        return []

    headers = await _get_default_headers()
    headers["x-ept-scan"] = "1"
    # Merge auth context headers so targeted requests pass auth gates
    auth_hdrs = get_auth_context() or {}
    if auth_hdrs:
        headers.update({k: v for k, v in auth_hdrs.items()
                        if k.lower() not in ("host", "content-length", "content-type",
                                              "transfer-encoding")})
    proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"

    targeted_results = []
    total = sum(max(1, len(tr.get("_suggested_payloads", []))) for tr in targeted_requests)
    done = 0

    _emit_event("targeted", f"Executing {total} targeted requests",
                f"From {len(targeted_requests)} AI-suggested targets")

    async with httpx.AsyncClient(
        verify=False, timeout=SCAN_DEFAULT_TIMEOUT, proxy=proxy_url
    ) as client:
        for tr in targeted_requests:
            if await _check_control():
                break

            payloads = tr.get("_suggested_payloads", [])
            if not payloads:
                # Make a baseline request even if no payloads suggested
                payloads = [{"injection_point": "none", "key": "", "payload": "", "type": "recon"}]

            for pl in payloads:
                if await _check_control():
                    break

                await rate_limiter.acquire()
                try:
                    _state["requests_sent"] += 1
                    done += 1
                    _state["phase_detail"] = f"Targeted request {done}/{total}"

                    method = tr.get("method", "GET").upper()
                    url = tr.get("url", "")
                    payload_str = pl.get("payload", "")
                    injection_point = pl.get("injection_point", "query")
                    key = pl.get("key", "")

                    _emit_event("targeted", f"Sending {method} request ({done}/{total})",
                                f"{url} [{injection_point}:{key}]" if key else url)

                    # Build the request based on injection point
                    req_params = {}
                    req_body = ""
                    req_headers = dict(headers)

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
                        # Append payload to URL path
                        url = url.rstrip("/") + "/" + payload_str

                    start_time = time.time()
                    error = None
                    status_code = 0
                    resp_headers = {}
                    resp_body = ""

                    try:
                        if method == "GET":
                            resp = await client.get(url, params=req_params, headers=req_headers)
                        else:
                            resp = await client.request(
                                method, url,
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
                        "url": url,
                        "path": tr.get("path", urlparse(url).path),
                        "risk_reason": tr.get("reason", ""),
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
                finally:
                    rate_limiter.release()

    if not targeted_results:
        _results["targeted"] = {"findings": []}
        return []

    # Pass results through Claude for analysis
    _state["phase_detail"] = f"AI analyzing {len(targeted_results)} targeted responses..."
    _emit_event("targeted", f"Sending {len(targeted_results)} responses to Claude for analysis",
                "Waiting for AI response...")

    if await _check_control():
        _results["targeted"] = {"findings": []}
        return []

    prompt = _build_retest_analysis_prompt(targeted_results)
    analysis = await run_claude_with_prompt(prompt, model=ai_model)

    findings = analysis.get("findings", [])
    confirmed = len([f for f in findings if f.get("status") == "confirmed"])
    _state["vulns_found"] += confirmed
    _state["phase_detail"] = f"Targeted analysis found {len(findings)} issues"
    _emit_event("targeted", "Targeted phase complete",
                f"{len(findings)} issues found ({confirmed} confirmed)")

    _results["targeted"] = {"findings": findings}
    return findings


# ── Pipeline orchestrator ───────────────────────────────────────────


async def _run_pipeline(config: dict):
    """Main scan pipeline — runs all 5 phases sequentially."""
    global _session_id

    workspace = _get_active_workspace()

    try:
        _session_id = await save_auto_scan_session(workspace, config, {
            "status": "running",
            "phase": "crawl",
        })
    except Exception as e:
        log.error("Failed to save auto-scan session: %s", e)
        _session_id = None

    rate_limiter = RateLimiter(
        max_concurrent=config.get("max_concurrent", AUTO_SCAN_DEFAULT_CONCURRENT),
        delay=config.get("delay", AUTO_SCAN_DEFAULT_DELAY),
    )

    target_url = config["target_url"]
    enable_upload = config.get("enable_upload", True)
    enable_ai = config.get("enable_ai", True)
    enable_retest = config.get("enable_retest", True)
    ai_model = config.get("ai_model", "opus")
    auth_headers = get_auth_context()

    _emit_event("pipeline", "Auto-scan started", f"Target: {target_url}")

    try:
        # ── Phase 1: Crawl ──
        crawl_result = await _phase_crawl(
            target_url,
            max_depth=config.get("max_depth", AUTO_SCAN_DEFAULT_DEPTH),
            max_pages=config.get("max_pages", AUTO_SCAN_DEFAULT_MAX_PAGES),
            auth_headers=auth_headers,
        )

        if _control["signal"] == "stop":
            raise _ScanStopped()

        _state["completed_phases"].append("crawl")

        crawled_urls = crawl_result["urls"]
        crawled_forms = crawl_result["forms"]

        if not crawled_urls:
            crawled_urls = [target_url]
            _state["endpoints_found"] = 1

        # ── Extract backend endpoints from proxy traffic ──
        # The crawler visited frontend pages through the proxy, which
        # captured all the actual backend API calls made by those pages.
        # THOSE are our injection targets — not the frontend routes.
        backend_endpoints = await _extract_backend_endpoints(
            target_url, crawled_urls, crawled_forms,
        )

        _state["endpoints_found"] = len(backend_endpoints)
        _emit_event("pipeline",
                     f"Target selection: {len(backend_endpoints)} backend endpoints identified",
                     f"From {len(crawled_urls)} crawled pages — frontend routes excluded from testing")

        await _update_session("running", "inject")

        # ── Phase 2: Inject ──
        inject_findings = await _phase_inject(backend_endpoints, rate_limiter)

        if _control["signal"] == "stop":
            raise _ScanStopped()

        _state["completed_phases"].append("inject")
        await _update_session("running", "upload")

        # ── Phase 3: Upload ──
        if enable_upload:
            await _phase_upload(backend_endpoints, rate_limiter)

            if _control["signal"] == "stop":
                raise _ScanStopped()

            _state["completed_phases"].append("upload")
        else:
            _state["skipped_phases"].append("upload")

        await _update_session("running", "ai")

        # ── Phase 4: AI Analysis ──
        ai_data = None
        if enable_ai:
            ai_data = await _phase_ai(crawled_urls, inject_findings, ai_model)

            if _control["signal"] == "stop":
                raise _ScanStopped()

            _state["completed_phases"].append("ai")
        else:
            _state["skipped_phases"].append("ai")
            _state["skipped_phases"].append("targeted")

        await _update_session("running", "targeted")

        # ── Phase 5: Targeted Re-test ──
        if enable_ai and enable_retest and ai_data:
            await _phase_targeted(ai_data, rate_limiter, ai_model)

            if _control["signal"] == "stop":
                raise _ScanStopped()

            _state["completed_phases"].append("targeted")
        elif "targeted" not in _state["skipped_phases"]:
            _state["skipped_phases"].append("targeted")

        # Done!
        _state["running"] = False
        _state["current_phase"] = ""
        _state["phase_detail"] = "Scan complete"
        _emit_event("pipeline", "Auto-scan complete",
                    f"{_state['vulns_found']} vulns, {_state['requests_sent']} requests, {_state['endpoints_found']} endpoints")
        await _update_session("completed", "done")

    except _ScanStopped:
        _state["running"] = False
        _state["phase_detail"] = "Scan stopped by user"
        _emit_event("pipeline", "Auto-scan stopped by user")
        await _update_session("stopped", _state.get("current_phase", ""))
    except Exception as e:
        log.error("Auto-scan pipeline error: %s", e, exc_info=True)
        _state["running"] = False
        _state["error"] = str(e)
        _state["phase_detail"] = f"Error: {e}"
        _emit_event("pipeline", "Auto-scan error", str(e))
        await _update_session("failed", _state.get("current_phase", ""))


class _ScanStopped(Exception):
    pass


async def _update_session(status: str, phase: str):
    if _session_id is not None:
        try:
            await update_auto_scan_session(
                _session_id, status, phase,
                {
                    "status": status,
                    "phase": phase,
                    "endpoints_found": _state["endpoints_found"],
                    "vulns_found": _state["vulns_found"],
                    "requests_sent": _state["requests_sent"],
                    "results": {k: v for k, v in _results.items() if v is not None},
                },
            )
        except Exception as e:
            log.warning("Failed to update auto-scan session: %s", e)


# ── API Endpoints ───────────────────────────────────────────────────


@router.post("")
async def start_auto_scan(config: dict, background_tasks: BackgroundTasks):
    """Start the automated scan pipeline."""
    if _state["running"]:
        return {"error": "A scan is already running. Stop it first."}

    target_url = (config.get("target_url") or "").strip()
    if not target_url:
        return {"error": "target_url is required"}

    # Set auth context (cleared if not provided so stale context doesn't leak)
    set_auth_context(config.get("auth_headers") or None)

    _reset_state()
    _state["running"] = True

    background_tasks.add_task(_run_pipeline, config)
    return {"status": "started", "target_url": target_url}


@router.get("/status")
async def auto_scan_status():
    """Return current scan progress."""
    out = {k: v for k, v in _state.items() if k != "event_log"}
    # Include the most recent event message for quick status summary
    if _state["event_log"]:
        last = _state["event_log"][-1]
        out["last_event"] = last["message"] + (f" -- {last['detail']}" if last.get("detail") else "")
    else:
        out["last_event"] = ""
    return out


@router.get("/events")
async def auto_scan_events(since_id: int = 0):
    """Return event log entries with ID > since_id for incremental polling."""
    events = [e for e in _state["event_log"] if e["id"] > since_id]
    return {"events": events, "last_id": _state["last_event_id"]}


@router.post("/pause")
async def auto_scan_pause():
    """Toggle pause/resume."""
    if _control["signal"] == "pause":
        _control["signal"] = "run"
        _state["paused"] = False
        return {"signal": "run"}
    _control["signal"] = "pause"
    _state["paused"] = True
    return {"signal": "pause"}


@router.post("/stop")
async def auto_scan_stop():
    """Stop the running scan."""
    _control["signal"] = "stop"
    return {"signal": "stop"}


@router.get("/results")
async def auto_scan_results():
    """Return results keyed by phase."""
    return {k: v for k, v in _results.items() if v is not None}
