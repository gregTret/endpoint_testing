"""
Centralised configuration — all tunables in one place.
Override via environment variables where noted.
"""

import os
from pathlib import Path

# ── Network ────────────────────────────────────────────────────────
PROXY_HOST = os.getenv("PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.getenv("PROXY_PORT", "8080"))
BACKEND_HOST = os.getenv("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = int(os.getenv("BACKEND_PORT", "8000"))

# ── Storage ────────────────────────────────────────────────────────
DB_PATH = Path(os.getenv("DB_PATH", str(Path(__file__).parent / "storage" / "sessions.db")))

# ── Proxy / Interception ──────────────────────────────────────────
PROXY_QUEUE_MAX = 10_000
LOG_BODY_CAP = 50_000          # max chars stored per request/response body
LOG_OPTIONS_REQUESTS = False   # set True to capture OPTIONS (CORS preflight) requests

# ── Polling ────────────────────────────────────────────────────────
QUEUE_POLL_INTERVAL = 0.05     # seconds between proxy-queue drain cycles
QUEUE_POLL_ERROR_DELAY = 0.1

# ── Crawler ────────────────────────────────────────────────────────
CRAWL_PAGE_TIMEOUT = 15_000    # ms — playwright page.goto timeout
CRAWL_DEFAULT_DEPTH = 5
CRAWL_DEFAULT_MAX_PAGES = 100

# ── Scanning ───────────────────────────────────────────────────────
SCAN_DEFAULT_TIMEOUT = 10.0    # seconds per request
SCAN_RESPONSE_CAP = 10_000     # max chars kept per scan response
REPLAY_TIMEOUT = 15.0

# ── HTML parsing ───────────────────────────────────────────────────
HTML_PARSER = "lxml"           # falls back to "html.parser" if lxml missing
