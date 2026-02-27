#!/usr/bin/env python3
"""
deep_crawl.py - Deep spider a workspace to discover all accessible endpoints.

Launches a headless browser, authenticates (supports OAuth/SSO), crawls every
page, clicks every interactive element, and intercepts all network requests to
map frontend actions to backend API calls.

Usage:
    python scripts/deep_crawl.py
    python scripts/deep_crawl.py --max-pages 50 --max-depth 5
    python scripts/deep_crawl.py -b http://127.0.0.1:8000 -o results.json

Requires the backend to be running (the Electron app does this automatically).
"""

import argparse
import asyncio
import json
import os
import re
import sys
from collections import OrderedDict
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
from playwright.async_api import async_playwright

STATIC_EXT = frozenset((
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
))
SETTLE_MS = 1500
NAV_TIMEOUT_MS = 15000

# Matches path segments that are IDs: UUIDs, ULIDs, MongoDB ObjectIds,
# hex strings (8+ chars), and plain numbers.
_ID_RE = re.compile(
    r'/('
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    r'|[0-9A-Z]{26}'           # ULID (like 01KJFQ3NBZMD4KJ1CAHN3TBKYD)
    r'|[0-9a-f]{24}'           # MongoDB ObjectId
    r'|[0-9a-f]{8,16}'         # hex IDs
    r'|\d+'                    # plain numeric IDs
    r')(?=/|$)',
    re.IGNORECASE,
)


# Captures the path segment BEFORE an ID (the resource type) + the ID itself.
# e.g. /workspaces/01KJFQ3... → ("workspaces", "01KJFQ3...")
_RESOURCE_ID_RE = re.compile(
    r'/([a-z][a-z0-9_-]*)/('
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    r'|[0-9A-Z]{26}'
    r'|[0-9a-f]{24}'
    r'|[0-9a-f]{8,16}'
    r')(?=/|$|\?)',
    re.IGNORECASE,
)

# Common JSON keys that hold IDs worth collecting.
_ID_KEYS_RE = re.compile(
    r'^(?:id|.*_id|.*Id|uuid|uid|key|ref|oid)$'
)
# Keys that hint at the resource type for a given ID value.
_TYPE_HINT_KEYS = {
    "workspace_id": "workspace", "workspaceId": "workspace",
    "org_id": "organisation", "orgId": "organisation",
    "organisation_id": "organisation", "organisationId": "organisation",
    "organization_id": "organisation", "organizationId": "organisation",
    "user_id": "user", "userId": "user",
    "schema_id": "schema", "schemaId": "schema",
    "template_id": "template", "templateId": "template",
    "document_id": "document", "documentId": "document",
    "item_id": "item", "itemId": "item",
    "role_id": "role", "roleId": "role",
    "job_id": "job", "jobId": "job",
    "flow_id": "flow", "flowId": "flow",
    "folder_id": "folder", "folderId": "folder",
    "member_id": "member", "memberId": "member",
    "data_point_id": "data-point", "dataPointId": "data-point",
    "dashboard_id": "dashboard", "dashboardId": "dashboard",
    "widget_id": "widget", "widgetId": "widget",
    "upload_id": "upload", "uploadId": "upload",
    "entity_vid": "entity", "entityVid": "entity",
    "batch_id": "batch", "batchId": "batch",
}


def _route_pattern(url: str) -> str:
    """Collapse ID-like path segments into {id} for dedup.

    /workspace/01KJFQ3NBZMD4KJ1CAHN3TBKYD/settings  →  /workspace/{id}/settings
    /api/users/42                                     →  /api/users/{id}
    """
    p = urlparse(url)
    norm_path = _ID_RE.sub('/{id}', p.path)
    return f"{p.scheme}://{p.netloc}{norm_path}"


# ───────────────────────────────── crawler ──────────────────────────────────

class DeepCrawler:
    def __init__(self, workspace_id: str, start_url: str, backend_url: str,
                 max_pages: int = 200, max_depth: int = 10):
        self.workspace_id = workspace_id
        self.start_url = start_url
        self.backend = backend_url.rstrip("/")
        self.max_pages = max_pages
        self.max_depth = max_depth

        self.credentials: list[dict] = []
        self.target_domain = urlparse(start_url).netloc
        self.allowed_domains: set[str] = set()

        # endpoint recording
        self.endpoints: OrderedDict[str, dict] = OrderedDict()

        # ID collection: resource_type → set of concrete IDs
        # e.g. {"workspace": {"01KJF...", "01KHH..."}, "organisation": {"01KHH..."}}
        self.discovered_ids: dict[str, set[str]] = {}

        # crawl state
        self.visited: set[str] = set()          # exact URLs visited
        self.visited_patterns: set[str] = set() # route patterns visited
        self.queue: list[tuple[str, int]] = []

        # network interception
        self._clicking = False  # flag: are we in a click right now?

    # ── backend api ──────────────────────────────────────────────────────

    async def _api(self, method: str, path: str, **kw):
        async with httpx.AsyncClient(base_url=self.backend, timeout=10) as c:
            r = await getattr(c, method)(path, **kw)
            r.raise_for_status()
            return r.json()

    async def setup(self):
        await self._api("post", "/api/workspaces/active",
                        json={"id": self.workspace_id})
        _p(f"Workspace: {self.workspace_id}")

        self.credentials = await self._api("get", "/api/credentials")
        _p(f"Credentials: {len(self.credentials)}")

        self.allowed_domains.add(self.target_domain)
        base = self.target_domain
        if not base.startswith("api."):
            self.allowed_domains.add(f"api.{base}")
        _p(f"Target: {self.start_url}")
        _p(f"Crawl domains: {', '.join(sorted(self.allowed_domains))}")

    # ── helpers ──────────────────────────────────────────────────────────

    def _get_cred(self) -> dict | None:
        for c in self.credentials:
            if c.get("username") and c.get("password"):
                return c
        return self.credentials[0] if self.credentials else None

    def _is_allowed(self, url: str) -> bool:
        return urlparse(url).netloc in self.allowed_domains

    def _should_visit(self, url: str) -> bool:
        """True if the URL represents a NEW route pattern we haven't explored."""
        if not self._is_allowed(url):
            return False
        return _route_pattern(url) not in self.visited_patterns

    def _collect_ids_from_url(self, url: str):
        """Extract resource IDs from URL path segments."""
        for match in _RESOURCE_ID_RE.finditer(url):
            resource = match.group(1).rstrip("s")  # "workspaces" → "workspace"
            id_val = match.group(2)
            self.discovered_ids.setdefault(resource, set()).add(id_val)

    def _collect_ids_from_json(self, data, depth: int = 0):
        """Extract IDs from JSON response bodies."""
        if depth > 6:
            return
        if isinstance(data, dict):
            for key, val in data.items():
                if isinstance(val, str) and len(val) >= 8 and _ID_KEYS_RE.match(key):
                    rtype = _TYPE_HINT_KEYS.get(key, key.replace("_id", "")
                                                         .replace("Id", ""))
                    self.discovered_ids.setdefault(rtype, set()).add(val)
                elif isinstance(val, (dict, list)):
                    self._collect_ids_from_json(val, depth + 1)
        elif isinstance(data, list):
            for item in data[:20]:
                if isinstance(item, (dict, list)):
                    self._collect_ids_from_json(item, depth + 1)

    def _record(self, url: str, method: str, source: str):
        p = urlparse(url)
        if any(p.path.lower().endswith(e) for e in STATIC_EXT):
            return
        clean = p._replace(fragment="").geturl()
        key = f"{method.upper()} {clean}"
        if key not in self.endpoints:
            self.endpoints[key] = {
                "url": clean, "method": method.upper(), "source": source,
            }
        # Always extract IDs from every URL we see
        self._collect_ids_from_url(url)

    # ── network interception (always-on) ─────────────────────────────────

    def _on_request(self, request):
        url = request.url
        if url.startswith(("data:", "blob:", "chrome")):
            return
        rtype = request.resource_type
        if rtype in ("script", "stylesheet", "image", "font", "media", "other"):
            return

        method = request.method
        # Record ALL xhr/fetch directly to endpoints — this is the main
        # discovery mechanism and captures API calls from page loads, SPA
        # route transitions, lazy data fetches, etc.
        if rtype in ("xhr", "fetch"):
            source = "button-click" if self._clicking else "xhr"
            self._record(url, method, source)
        elif rtype == "document":
            self._record(url, method, "navigation")

    # ── login (supports OAuth / SSO / direct forms) ─────────────────────

    async def _login(self, page):
        """Walk through whatever login flow the site uses."""
        cred = self._get_cred()
        if not cred:
            _p("  No credentials with username+password, skipping login")
            return

        username = cred.get("username", "")
        password = cred.get("password", "")
        if not username or not password:
            _p("  Incomplete credentials, skipping login")
            return

        _p(f"  Authenticating as '{username}'")

        # ── Step 1: find the login entry point ──
        for attempt in range(5):
            if await page.query_selector('input[type="password"]:visible'):
                break
            if await page.query_selector(
                'input[type="email"]:visible, input[name="loginfmt"]:visible'
            ):
                break

            best_btn = None
            all_btns = await page.query_selector_all('a:visible, button:visible')
            for btn in all_btns:
                text = (await btn.inner_text()).strip().lower()
                href = (await btn.get_attribute("href") or "").lower()

                if "email" in text and any(w in text for w in
                        ("login", "log in", "sign in", "signin", "continue")):
                    best_btn = btn
                    break
                if not best_btn and any(w in text for w in
                        ("log in", "login", "sign in", "signin")):
                    best_btn = btn
                if not best_btn and any(w in href for w in
                        ("login", "signin", "auth")):
                    best_btn = btn

            if best_btn:
                btn_text = (await best_btn.inner_text()).strip()
                _p(f"  Clicking: '{btn_text}' (attempt {attempt + 1})...")
                await best_btn.click()
                try:
                    await page.wait_for_load_state("domcontentloaded",
                                                   timeout=NAV_TIMEOUT_MS)
                except Exception:
                    pass
                await page.wait_for_timeout(2000)
            else:
                _p("  No login form or button found — may already be authenticated")
                return

        # ── Step 2: email / username field (multi-step like Microsoft) ──
        email_input = await page.query_selector(
            'input[type="email"]:visible, input[name="loginfmt"]:visible, '
            'input[name="login"]:visible, input[name="email"]:visible, '
            'input[name="username"]:visible'
        )
        if email_input:
            _p("  Filling email/username...")
            await email_input.fill(username)
            await email_input.dispatch_event("input")
            await email_input.dispatch_event("change")
            await page.wait_for_timeout(1000)

            try:
                next_btn = await page.query_selector(
                    '#idSIButton9:visible, '
                    'input[type="submit"]:visible, button[type="submit"]:visible, '
                    'button:has-text("Next"):visible, button:has-text("Continue"):visible, '
                    'button:has-text("Sign in"):visible, button:has-text("Log in"):visible'
                )
                if next_btn:
                    for _ in range(10):
                        disabled = await next_btn.get_attribute("disabled")
                        if disabled is None:
                            break
                        await page.wait_for_timeout(500)
                    await next_btn.click(timeout=5000)
                else:
                    await email_input.press("Enter")
                await page.wait_for_timeout(3000)
            except Exception as e:
                _p(f"  Submit after email failed ({e}), trying Enter key...")
                try:
                    await email_input.press("Enter")
                    await page.wait_for_timeout(3000)
                except Exception:
                    pass

        # ── Step 3: password field ──
        pw_input = None
        for _ in range(8):
            pw_input = await page.query_selector(
                'input[type="password"]:visible, input[name="passwd"]:visible, '
                'input[name="password"]:visible'
            )
            if pw_input:
                break
            await page.wait_for_timeout(1000)

        if pw_input:
            _p("  Filling password...")
            if not email_input:
                user_field = await page.query_selector(
                    'input[type="text"]:visible, input[type="email"]:visible, '
                    'input[name*="user"]:visible, input[name*="email"]:visible'
                )
                if user_field:
                    await user_field.fill(username)

            await pw_input.fill(password)
            await pw_input.dispatch_event("input")
            await pw_input.dispatch_event("change")
            await page.wait_for_timeout(1000)

            try:
                submit = await page.query_selector(
                    '#idSIButton9:visible, '
                    'input[type="submit"]:visible, button[type="submit"]:visible, '
                    'button:has-text("Sign in"):visible, '
                    'button:has-text("Log in"):visible, '
                    'button:has-text("Submit"):visible'
                )
                if submit:
                    for _ in range(10):
                        disabled = await submit.get_attribute("disabled")
                        if disabled is None:
                            break
                        await page.wait_for_timeout(500)
                    await submit.click(timeout=5000)
                else:
                    await pw_input.press("Enter")
                await page.wait_for_timeout(3000)
            except Exception as e:
                _p(f"  Submit after password failed ({e}), trying Enter key...")
                try:
                    await pw_input.press("Enter")
                    await page.wait_for_timeout(3000)
                except Exception:
                    pass
        else:
            _p("  No password field appeared")
            return

        # ── Step 4: consent / "stay signed in?" prompts ──
        for _ in range(5):
            try:
                consent = await page.query_selector(
                    '#idSIButton9:visible, #idBtn_Back:visible, '
                    'button:has-text("Yes"):visible, button:has-text("Accept"):visible, '
                    'button:has-text("Continue"):visible, input[type="submit"]:visible'
                )
                if consent and ("microsoftonline" in page.url
                                or "google" in page.url
                                or "okta" in page.url
                                or "auth0" in page.url):
                    _p("  Handling SSO prompt...")
                    await consent.click(timeout=5000)
                    await page.wait_for_timeout(2000)
                else:
                    break
            except Exception:
                break

        # ── Step 5: wait for redirect back to our domain ──
        _p("  Waiting for redirect back to target...")
        for i in range(20):
            current = urlparse(page.url).netloc
            if current in self.allowed_domains:
                break
            if self.target_domain in current:
                self.allowed_domains.add(current)
                break
            if i == 19:
                _p(f"  Timed out waiting for redirect (stuck on {page.url})")
            await page.wait_for_timeout(1000)

        _p(f"  Login complete — now at: {page.url}")

    # ── page crawling ────────────────────────────────────────────────────

    async def _collect_clickables(self, page):
        sels = [
            "a[href]", "button:visible", '[role="button"]:visible',
            "[onclick]:visible", 'input[type="submit"]:visible',
            'input[type="button"]:visible', "[data-action]:visible",
        ]
        elements = []
        seen = set()
        for sel in sels:
            try:
                for el in await page.query_selector_all(sel):
                    try:
                        box = await el.bounding_box()
                    except Exception:
                        continue
                    if box and box["width"] > 0 and box["height"] > 0:
                        key = (round(box["x"]), round(box["y"]),
                               round(box["width"]), round(box["height"]))
                        if key not in seen:
                            seen.add(key)
                            elements.append(el)
            except Exception:
                continue
        return elements

    def _enqueue(self, url: str, depth: int):
        """Add a URL to the crawl queue if its route pattern is new."""
        if self._should_visit(url):
            self.queue.append((url, depth))

    async def _extract_links(self, page, url: str, depth: int):
        """Pull links from the DOM — handles normal hrefs, hash routes, etc."""
        for link in await page.query_selector_all("a[href]"):
            try:
                href = await link.get_attribute("href")
            except Exception:
                continue
            if not href or href.startswith(("javascript:", "mailto:", "tel:")):
                continue

            # Handle hash-routed SPAs:  #/route  or  /#/route
            if href.startswith("#"):
                # Build full URL with the hash for SPA navigation
                base = urlparse(url)
                abs_url = f"{base.scheme}://{base.netloc}{base.path}{href}"
                self._record(abs_url, "GET", "link")
                self._enqueue(abs_url, depth + 1)
                continue

            abs_url = urljoin(url, href)
            self._record(abs_url, "GET", "link")
            if self._is_allowed(abs_url):
                self._enqueue(abs_url, depth + 1)

        # Forms
        for form in await page.query_selector_all("form"):
            try:
                action = await form.get_attribute("action") or url
                method = (await form.get_attribute("method") or "GET").upper()
                self._record(urljoin(url, action), method, "form")
            except Exception:
                continue

    async def crawl_page(self, page, url: str, depth: int):
        """Visit a page, extract everything, click everything."""
        pattern = _route_pattern(url)
        if pattern in self.visited_patterns or depth > self.max_depth:
            return
        if len(self.visited_patterns) >= self.max_pages:
            return

        self.visited.add(url)
        self.visited_patterns.add(pattern)
        count = len(self.visited_patterns)
        _p(f"  [{count}/{self.max_pages}] d={depth} {url}")

        try:
            await page.goto(url, wait_until="domcontentloaded",
                            timeout=NAV_TIMEOUT_MS)
            # Wait for SPA rendering / lazy loads
            await page.wait_for_timeout(SETTLE_MS)
        except Exception as e:
            _p(f"    Failed: {e}")
            return

        self._record(url, "GET", "navigation")

        # ── extract links + forms from DOM ──
        await self._extract_links(page, url, depth)

        # ── click every interactive element ──
        clickables = await self._collect_clickables(page)
        origin = page.url

        for el in clickables:
            try:
                if not await el.is_visible():
                    continue
                self._clicking = True
                await el.click(timeout=2000, no_wait_after=True)
                await page.wait_for_timeout(SETTLE_MS)
                self._clicking = False
            except Exception:
                self._clicking = False
                continue

            # If click caused SPA navigation, record + enqueue, then go back
            if page.url != origin:
                new_url = page.url
                self._record(new_url, "GET", "button-click")
                self._enqueue(new_url, depth + 1)

                # Re-extract links from the new view before going back
                await self._extract_links(page, new_url, depth + 1)

                try:
                    await page.goto(origin, wait_until="domcontentloaded",
                                    timeout=NAV_TIMEOUT_MS)
                    await page.wait_for_timeout(SETTLE_MS)
                except Exception:
                    break

    # ── Phase 2: API deep crawl ─────────────────────────────────────────

    async def _extract_auth(self, context, page) -> dict:
        """Pull cookies + bearer tokens from the browser session."""
        headers = {}

        # Cookies
        cookies = await context.cookies()
        if cookies:
            headers["Cookie"] = "; ".join(
                f"{c['name']}={c['value']}" for c in cookies
            )

        # Try to find a bearer token in localStorage / sessionStorage
        try:
            token = await page.evaluate("""() => {
                for (const store of [localStorage, sessionStorage]) {
                    for (let i = 0; i < store.length; i++) {
                        const key = store.key(i);
                        const val = store.getItem(key);
                        if (/token|auth|jwt|bearer|access/i.test(key) && val && val.length > 20) {
                            // Strip wrapping quotes if JSON-encoded
                            try { return JSON.parse(val); } catch(e) { return val; }
                        }
                    }
                }
                return null;
            }""")
            if token:
                headers["Authorization"] = f"Bearer {token}"
                _p(f"  Found bearer token in browser storage")
        except Exception:
            pass

        return headers

    def _extract_urls_from_json(self, data, base_url: str,
                                 depth: int = 0) -> set[str]:
        """Recursively pull URLs and path-like strings from a JSON response."""
        urls: set[str] = set()
        if depth > 8:
            return urls

        if isinstance(data, dict):
            for key, val in data.items():
                if isinstance(val, str):
                    if val.startswith("http"):
                        urls.add(val)
                    elif (val.startswith("/") and len(val) > 1
                          and not val.startswith("//")):
                        p = urlparse(base_url)
                        urls.add(f"{p.scheme}://{p.netloc}{val}")
                elif isinstance(val, (dict, list)):
                    urls.update(self._extract_urls_from_json(
                        val, base_url, depth + 1))
        elif isinstance(data, list):
            # Only scan first 20 items — rest are likely same-shaped data
            for item in data[:20]:
                if isinstance(item, (dict, list)):
                    urls.update(self._extract_urls_from_json(
                        item, base_url, depth + 1))
                elif isinstance(item, str) and item.startswith("http"):
                    urls.add(item)

        return urls

    def _parse_openapi(self, spec: dict, base_url: str):
        """Extract every route + method from an OpenAPI / Swagger spec."""
        p = urlparse(base_url)
        api_base = f"{p.scheme}://{p.netloc}"

        # Some specs define servers with a base path
        servers = spec.get("servers", [])
        if servers and isinstance(servers[0], dict):
            server_url = servers[0].get("url", "")
            if server_url.startswith("http"):
                api_base = server_url.rstrip("/")
            elif server_url.startswith("/"):
                api_base = f"{p.scheme}://{p.netloc}{server_url.rstrip('/')}"

        # Swagger 2.0 basePath
        base_path = spec.get("basePath", "")
        if base_path and base_path != "/":
            api_base = f"{p.scheme}://{p.netloc}{base_path.rstrip('/')}"

        paths = spec.get("paths", {})
        count = 0
        for route, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            full_url = f"{api_base}{route}"
            for method in methods:
                if method.lower() in ("get", "post", "put", "patch",
                                       "delete", "head", "options"):
                    self._record(full_url, method.upper(), "openapi")
                    count += 1
        return count

    def _openapi_routes(self) -> list[dict]:
        """Return only the openapi-sourced endpoints, separated from live ones."""
        return [ep for ep in self.endpoints.values()
                if ep["source"] == "openapi"]

    # Regex to pull URLs and /api-like paths from HTML / text
    _URL_RE = re.compile(r'https?://[^\s"\'<>]+')
    _PATH_RE = re.compile(r'["\'](/(?:api|v[0-9]|auth|graphql)[^\s"\'<>]*)["\']')

    def _extract_urls_from_html(self, html: str, base_url: str) -> set[str]:
        """Pull API-like URLs and paths from raw HTML/text content."""
        urls: set[str] = set()
        p = urlparse(base_url)
        for match in self._URL_RE.findall(html):
            clean = match.rstrip(".,;)")
            urls.add(clean)
        for match in self._PATH_RE.findall(html):
            urls.add(f"{p.scheme}://{p.netloc}{match}")
        return urls

    # Paths that are documentation / spec / infrastructure — mine them for
    # routes but never record them as actual API endpoints.
    _DOC_PATHS = frozenset((
        "/openapi.json", "/openapi.yaml", "/openapi",
        "/swagger.json", "/swagger.yaml", "/swagger",
        "/docs", "/docs/", "/redoc", "/redoc/",
        "/api-docs", "/api-docs/", "/api/docs", "/api/docs/",
        "/api-docs.json", "/api-docs.yaml",
        "/docs/openapi.json", "/docs/swagger.json",
        "/v1/docs", "/v2/docs", "/v3/docs",
        "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
        "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
        "/api/v1/docs", "/api/v2/docs",
        "/api/openapi.json", "/api/swagger.json",
        "/schema", "/schema/", "/.well-known/openapi",
        "/graphql", "/graphql/schema",
        "/health", "/healthz", "/health/live", "/health/ready",
        "/status", "/readyz", "/livez",
        "/ping", "/version", "/info",
    ))

    def _is_doc_url(self, url: str) -> bool:
        return urlparse(url).path.rstrip("/") in {
            p.rstrip("/") for p in self._DOC_PATHS
        }

    async def _api_deep_crawl(self, auth_headers: dict):
        """Phase 2: call discovered API endpoints and mine responses."""
        _p("\n--- Phase 2: API deep crawl ---\n")

        # Seed with all GET API endpoints from Phase 1
        api_queue: list[str] = []
        for ep in list(self.endpoints.values()):
            if (ep["method"] == "GET"
                    and self._is_allowed(ep["url"])
                    and "api." in urlparse(ep["url"]).netloc):
                api_queue.append(ep["url"])

        # Probe common doc/spec/discovery paths on every API domain
        for domain in sorted(self.allowed_domains):
            if "api." in domain:
                for path in self._DOC_PATHS:
                    api_queue.append(f"https://{domain}{path}")

        visited_api: set[str] = set()  # route patterns we've called
        total_new = 0

        async with httpx.AsyncClient(
            timeout=10, verify=False, headers=auth_headers,
            follow_redirects=True
        ) as client:
            while api_queue:
                url = api_queue.pop(0)

                if not self._is_allowed(url):
                    continue

                pattern = _route_pattern(url)
                if pattern in visited_api:
                    continue
                visited_api.add(pattern)

                _p(f"  API [{len(visited_api)}] {url}")
                try:
                    r = await client.get(url)
                except Exception:
                    continue

                if r.status_code >= 400:
                    continue

                # Only record as an endpoint if it's NOT a doc/infra path
                is_doc = self._is_doc_url(url)
                if not is_doc:
                    self._record(url, "GET", "api-crawl")

                content_type = r.headers.get("content-type", "")
                new_urls: set[str] = set()

                if "json" in content_type:
                    try:
                        data = r.json()
                        if isinstance(data, dict) and (
                            "openapi" in data or "swagger" in data
                            or "paths" in data
                        ):
                            n = self._parse_openapi(data, url)
                            _p(f"    ^ OpenAPI spec: {n} routes extracted")
                        else:
                            new_urls = self._extract_urls_from_json(data, url)
                            self._collect_ids_from_json(data)
                    except Exception:
                        pass
                else:
                    # HTML / text — only extract URLs on our domains
                    text = r.text
                    if text:
                        new_urls = {
                            u for u in self._extract_urls_from_html(text, url)
                            if self._is_allowed(u)
                        }

                for new_url in new_urls:
                    if not self._is_allowed(new_url):
                        continue
                    new_pattern = _route_pattern(new_url)
                    if new_pattern in visited_api:
                        continue
                    before = len(self.endpoints)
                    self._record(new_url, "GET", "api-discovery")
                    if len(self.endpoints) > before:
                        total_new += 1
                    api_queue.append(new_url)

        _p(f"\n  Phase 2 complete: called {len(visited_api)} API patterns, "
           f"discovered {total_new} new endpoints")

    # ── main loop ────────────────────────────────────────────────────────

    async def run(self):
        await self.setup()

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 720},
            )
            page = await context.new_page()
            page.on("request", self._on_request)

            _p(f"\nNavigating to {self.start_url}")
            try:
                await page.goto(self.start_url, wait_until="domcontentloaded",
                                timeout=NAV_TIMEOUT_MS)
                await page.wait_for_timeout(SETTLE_MS)
            except Exception as e:
                _p(f"Can't reach {self.start_url}: {e}", error=True)
                await browser.close()
                sys.exit(1)

            # ── authenticate ──
            await self._login(page)

            post_login_domain = urlparse(page.url).netloc
            if post_login_domain not in self.allowed_domains:
                self.allowed_domains.add(post_login_domain)
                _p(f"  Added domain: {post_login_domain}")

            # ── Phase 1: browser crawl ──
            self._enqueue(page.url, 0)
            if self.start_url != page.url:
                self._enqueue(self.start_url, 0)

            _p(f"\n--- Phase 1: Browser crawl "
               f"(max {self.max_pages} pages, depth {self.max_depth}) ---\n")
            while self.queue and len(self.visited_patterns) < self.max_pages:
                next_url, depth = self.queue.pop(0)
                if self._should_visit(next_url):
                    await self.crawl_page(page, next_url, depth)

            phase1_count = len(self.endpoints)
            _p(f"\n  Phase 1 complete: {phase1_count} endpoints from browser")

            # ── extract auth for Phase 2 ──
            auth_headers = await self._extract_auth(context, page)

            await context.close()
            await browser.close()

        # ── Phase 2: API deep crawl (no browser needed) ──
        await self._api_deep_crawl(auth_headers)

        _p(f"\n  Total: {len(self.endpoints)} endpoints")

    @staticmethod
    def _dedup_key(url: str) -> str:
        """Normalize a URL for final dedup: collapse IDs + strip query params."""
        p = urlparse(url)
        norm_path = _ID_RE.sub('/{id}', p.path)
        # Also normalize OpenAPI-style {param_name} → {id}
        norm_path = re.sub(r'\{[^}]+\}', '{id}', norm_path)
        return f"{p.scheme}://{p.netloc}{norm_path}"

    def results(self) -> dict:
        # ── Build discovered_ids summary ──
        ids_summary = {}
        for rtype in sorted(self.discovered_ids):
            ids_sorted = sorted(self.discovered_ids[rtype])
            ids_summary[rtype] = ids_sorted

        # ── Merge endpoints into deduplicated route patterns ──
        merged: dict[str, dict] = {}
        for ep in self.endpoints.values():
            norm_url = self._dedup_key(ep["url"])
            method = ep["method"]
            key = f"{method} {norm_url}"

            if key not in merged:
                merged[key] = {
                    "url": norm_url,
                    "method": method,
                    "sources": [],
                }
            src = ep["source"]
            if src not in merged[key]["sources"]:
                merged[key]["sources"].append(src)

        routes = sorted(merged.values(), key=lambda r: r["url"])

        return {
            "workspace_id": self.workspace_id,
            "crawl_date": datetime.now(timezone.utc).isoformat(),
            "start_url": self.start_url,
            "target_domains": sorted(self.allowed_domains),
            "discovered_ids": ids_summary,
            "routes": routes,
            "total": len(routes),
        }


# ───────────────────────────────── helpers ──────────────────────────────────

def _p(msg: str, error: bool = False):
    prefix = "[!]" if error else "[*]"
    print(f"{prefix} {msg}", file=sys.stderr if error else sys.stdout)


# ──────────────────────────── interactive pickers ───────────────────────────

async def pick_workspace(backend_url: str) -> str:
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
        last = ws.get("last_opened_at", "")[:10]
        print(f"    {i}) {name}  ({ws_id})  last opened: {last}")

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


async def pick_start_url(backend_url: str, workspace_id: str) -> str:
    async with httpx.AsyncClient(base_url=backend_url, timeout=10) as c:
        await c.post("/api/workspaces/active", json={"id": workspace_id})
        r = await c.get("/api/sitemap")
        r.raise_for_status()
        urls: list[str] = r.json()

    if not urls:
        _p("Sitemap is empty for this workspace. Add URLs first.", error=True)
        sys.exit(1)

    bases = list(dict.fromkeys(
        f"{urlparse(u).scheme}://{urlparse(u).netloc}"
        for u in urls if urlparse(u).scheme and urlparse(u).netloc
    ))

    if not bases:
        _p("No valid URLs in sitemap.", error=True)
        sys.exit(1)

    print("\n  Base URLs:\n")
    for i, base in enumerate(bases, 1):
        print(f"    {i}) {base}")

    print()
    while True:
        try:
            choice = input("  Start crawl from [1]: ").strip()
            idx = int(choice) - 1 if choice else 0
            if 0 <= idx < len(bases):
                _p(f"Start URL: {bases[idx]}")
                return bases[idx]
        except (ValueError, EOFError):
            pass
        print(f"    Enter a number between 1 and {len(bases)}")


# ──────────────────────────────── cli entry ─────────────────────────────────

async def main():
    ap = argparse.ArgumentParser(
        description="Deep-crawl a workspace and discover all accessible endpoints.",
    )
    ap.add_argument("--workspace", "-w", default=None,
                    help="Workspace ID (omit to pick interactively)")
    ap.add_argument("--url", "-u", default=None,
                    help="Start URL (omit to pick from sitemap)")
    ap.add_argument("--backend", "-b", default="http://127.0.0.1:8000",
                    help="Backend API URL (default: http://127.0.0.1:8000)")
    ap.add_argument("--output", "-o", default=None,
                    help="Output JSON path (default: deep_crawl_<ws>.json)")
    ap.add_argument("--max-pages", type=int, default=200)
    ap.add_argument("--max-depth", type=int, default=10)
    args = ap.parse_args()

    backend = args.backend.rstrip("/")
    ws_id = args.workspace or await pick_workspace(backend)
    start_url = args.url or await pick_start_url(backend, ws_id)

    crawler = DeepCrawler(
        ws_id, start_url, backend,
        max_pages=args.max_pages, max_depth=args.max_depth,
    )
    await crawler.run()

    results = crawler.results()
    notes_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "notes")
    os.makedirs(notes_dir, exist_ok=True)
    out = args.output or os.path.join(notes_dir, f"deep_crawl_{ws_id[:8]}.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    _p(f"\nDone — {results['total']} unique routes written to {out}")


if __name__ == "__main__":
    asyncio.run(main())
