"""
Shared test harness — auth, backoff, concurrency, HTTP client.

Used by the route_tester main.py to send requests against discovered routes.
Handles:
  - Login via credentials from local backend + POST to target /auth/login-with-password
  - Exponential backoff on 429 / 503
  - Concurrent requests via asyncio.Semaphore
  - Result collection and reporting
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

log = logging.getLogger(__name__)

# ── Defaults ──────────────────────────────────────────────────────────────
DEFAULT_BACKEND = "http://127.0.0.1:8000"
DEFAULT_CONCURRENCY = 5
DEFAULT_TIMEOUT = 15.0
RESPONSE_CAP = 10_000

BACKOFF_BASE = 1.0          # initial wait on 429/503
BACKOFF_FACTOR = 2.0        # multiplier each retry
BACKOFF_MAX_RETRIES = 5     # give up after this many
BACKOFF_CODES = {429, 503}  # status codes that trigger backoff

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


@dataclass
class TestResult:
    """Result of a single test request."""
    route_url: str = ""
    method: str = ""
    test_type: str = ""         # aql, graph, python, ssti, cmd, oob, fuzz, idor, size
    payload: str = ""
    injection_point: str = ""   # path, query, header, body
    target_key: str = ""        # which param/field was injected
    status_code: int = 0
    response_body: str = ""
    response_time_ms: float = 0.0
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    is_vulnerable: bool = False
    confidence: str = "low"
    details: str = ""
    evidence: list = field(default_factory=list)
    error: str = ""


class Harness:
    """Manages auth, HTTP client, backoff, and concurrency for route testing."""

    def __init__(
        self,
        backend_url: str = DEFAULT_BACKEND,
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.backend_url = backend_url.rstrip("/")
        self.concurrency = concurrency
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(concurrency)
        self._auth_headers: dict = {}
        self._workspace_id: str = ""
        self._target_base: str = ""

    # ── Auth ──────────────────────────────────────────────────────────

    async def login(self, workspace_id: str, api_base: str = "https://api.etain.app"):
        """Fetch credentials from local backend, POST to /auth/login-with-password."""
        self._workspace_id = workspace_id
        self._target_base = api_base.rstrip("/")

        _p(f"Activating workspace {workspace_id}...")
        async with httpx.AsyncClient(base_url=self.backend_url, timeout=10) as c:
            await c.post("/api/workspaces/active", json={"id": workspace_id})
            r = await c.get("/api/credentials")
            r.raise_for_status()
            credentials = r.json()

        cred = None
        for c in credentials:
            if c.get("username") and c.get("password"):
                cred = c
                break
        if not cred and credentials:
            cred = credentials[0]
        if not cred:
            _p("No credentials found", error=True)
            return False

        email = cred.get("username", "").strip()
        password = cred.get("password", "").strip()
        if not email or not password:
            _p("Incomplete credentials", error=True)
            return False

        login_url = f"{self._target_base}/auth/login-with-password"
        _p(f"Logging in as '{email}' via {login_url}...")

        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            r = await client.post(
                login_url,
                json={"email": email, "password": password},
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": USER_AGENT,
                },
            )

        if r.status_code >= 400:
            _p(f"  Login failed: {r.status_code} {r.text[:300]}", error=True)
            return False

        # Extract token — check common response shapes
        try:
            data = r.json()
        except Exception:
            data = {}

        token = None
        # Flat fields
        for key in ("token", "access_token", "accessToken", "jwt", "id_token"):
            if data.get(key):
                token = data[key]
                break
        # Nested under a wrapper
        if not token:
            for wrapper in ("session", "data", "auth", "result", "user"):
                inner = data.get(wrapper)
                if isinstance(inner, dict):
                    for key in ("token", "access_token", "accessToken", "jwt", "id_token"):
                        if inner.get(key):
                            token = inner[key]
                            break
                if token:
                    break

        if token:
            self._auth_headers["Authorization"] = f"Bearer {token}"
            _p(f"  Bearer token acquired ({len(token)} chars)")
        else:
            # Cookie-based auth — grab set-cookie headers
            raw_cookies = r.headers.get("set-cookie", "")
            if raw_cookies:
                self._auth_headers["Cookie"] = raw_cookies.split(";")[0]
                _p(f"  Session cookie acquired")
            else:
                _p(f"  Warning: no token or cookie in login response", error=True)
                _p(f"  Response keys: {list(data.keys())}")
                _p(f"  Response body: {r.text[:300]}")
                return False

        self._auth_headers["User-Agent"] = USER_AGENT
        self._auth_headers["Accept"] = "application/json"
        _p(f"  Auth ready")
        return True

    @property
    def auth_headers(self) -> dict:
        """Return a copy of auth headers (safe to modify)."""
        return {k: v for k, v in self._auth_headers.items() if not k.startswith("_")}

    # ── HTTP with backoff ─────────────────────────────────────────────

    async def request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        params: dict | None = None,
        body: str = "",
        timeout: float | None = None,
    ) -> dict:
        """Send a request with concurrency limiting and exponential backoff.

        Returns dict with: status_code, body, response_time_ms, headers, error
        """
        merged_headers = dict(self.auth_headers)
        if headers:
            merged_headers.update(headers)

        timeout = timeout or self.timeout

        async with self._semaphore:
            return await self._request_with_backoff(
                method, url, merged_headers, params or {}, body, timeout
            )

    async def _request_with_backoff(
        self, method: str, url: str, headers: dict,
        params: dict, body: str, timeout: float,
    ) -> dict:
        """Send request. Only retry on 429/503 (rate limit). Everything else returns immediately."""
        start = time.time()
        wait = BACKOFF_BASE

        for attempt in range(BACKOFF_MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(
                    verify=False, timeout=timeout, follow_redirects=True
                ) as client:
                    if method.upper() == "GET":
                        resp = await client.get(url, params=params, headers=headers)
                    else:
                        resp = await client.request(
                            method, url, params=params, headers=headers,
                            content=body.encode("utf-8") if body else b"",
                        )
                    elapsed = round((time.time() - start) * 1000, 2)

                    # Only backoff on rate-limit / service-unavailable
                    if resp.status_code in BACKOFF_CODES and attempt < BACKOFF_MAX_RETRIES:
                        await asyncio.sleep(wait)
                        wait *= BACKOFF_FACTOR
                        start = time.time()
                        continue

                    return {
                        "status_code": resp.status_code,
                        "body": resp.text[:RESPONSE_CAP],
                        "response_time_ms": elapsed,
                        "headers": dict(resp.headers),
                        "error": "",
                    }
            except Exception as e:
                elapsed = round((time.time() - start) * 1000, 2)
                return {
                    "status_code": 0,
                    "body": "",
                    "response_time_ms": elapsed,
                    "headers": {},
                    "error": str(e),
                }

    # ── Batch execution ───────────────────────────────────────────────

    async def run_batch(
        self,
        tasks: list[dict],
        on_result=None,
    ) -> list[TestResult]:
        """Run a batch of test tasks concurrently.

        Each task dict has: method, url, headers, params, body, test_type,
        payload, injection_point, target_key, analyze_fn

        on_result: async callback(result, index, total)
        """
        total = len(tasks)
        results: list[TestResult] = []
        completed = 0

        async def _run_one(task: dict, idx: int):
            nonlocal completed
            resp = await self.request(
                method=task.get("method", "GET"),
                url=task.get("url", ""),
                headers=task.get("headers"),
                params=task.get("params"),
                body=task.get("body", ""),
            )

            analyze_fn = task.get("analyze_fn")
            baseline = task.get("baseline", {})
            payload = task.get("payload", "")

            if analyze_fn and baseline:
                analysis = analyze_fn(baseline, resp, payload)
            else:
                analysis = {
                    "is_vulnerable": False,
                    "confidence": "low",
                    "details": "",
                    "evidence": [],
                }

            result = TestResult(
                route_url=task.get("route_url", task.get("url", "")),
                method=task.get("method", "GET"),
                test_type=task.get("test_type", "unknown"),
                payload=payload,
                injection_point=task.get("injection_point", ""),
                target_key=task.get("target_key", ""),
                status_code=resp["status_code"],
                response_body=resp["body"],
                response_time_ms=resp["response_time_ms"],
                request_headers=task.get("headers", {}),
                request_body=task.get("body", ""),
                is_vulnerable=analysis.get("is_vulnerable", False),
                confidence=analysis.get("confidence", "low"),
                details=analysis.get("details", ""),
                evidence=analysis.get("evidence", []),
                error=resp.get("error", ""),
            )

            results.append(result)
            completed += 1

            if on_result:
                await on_result(result, completed, total)

        # Run all tasks concurrently (semaphore handles throttling)
        await asyncio.gather(*[_run_one(t, i) for i, t in enumerate(tasks)])
        return results


# ── Helpers ───────────────────────────────────────────────────────────────

def resolve_url(route_url: str, ids: dict) -> str:
    """Replace {id} placeholders in a route URL with real discovered IDs.

    ids should map resource types to ID values, e.g.:
    {"organisation": "01KHH...", "workspace": "01KJF...", "data-point": "01KJF..."}

    For URLs like /organisations/{id}/data-points/{id}, IDs are resolved
    positionally based on the resource name in the preceding path segment.
    """
    import re
    parts = route_url.split("/")
    resolved = []
    for i, part in enumerate(parts):
        if part == "{id}":
            # Look at previous segment for resource type hint
            if i > 0:
                resource = parts[i - 1].rstrip("s")  # "organisations" → "organisation"
                # Try direct match, then common variations
                real_id = (
                    ids.get(resource)
                    or ids.get(resource + "s")
                    or ids.get(resource.replace("-", "_"))
                    or ids.get(resource.replace("_", "-"))
                )
                if real_id:
                    if isinstance(real_id, list):
                        resolved.append(real_id[0])
                    else:
                        resolved.append(real_id)
                    continue
            # Fallback: use first available ID
            for v in ids.values():
                if isinstance(v, list) and v:
                    resolved.append(v[0])
                    break
                elif isinstance(v, str):
                    resolved.append(v)
                    break
            else:
                resolved.append("UNKNOWN_ID")
        else:
            resolved.append(part)
    return "/".join(resolved)


def _p(msg: str, error: bool = False):
    import sys
    prefix = "[!]" if error else "[*]"
    print(f"{prefix} {msg}", file=sys.stderr if error else sys.stdout)
