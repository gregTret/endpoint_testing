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

# ── Default request headers ──────────────────────────────────────
# Applied to all outgoing requests (scans, repeater, replay).
# Workspace settings override these.
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# ── OOB Callback ─────────────────────────────────────────────────
OOB_DEFAULT_URL = "https://deviation.cc"
OOB_POLL_INTERVAL = 2.0        # seconds between polls
OOB_POLL_DURATION = 15.0       # total seconds to poll after injection

# ── Auto Scan ─────────────────────────────────────────────────────
AUTO_SCAN_DEFAULT_CONCURRENT = 5
AUTO_SCAN_DEFAULT_DELAY = 0.5   # seconds between requests
AUTO_SCAN_DEFAULT_DEPTH = 3
AUTO_SCAN_DEFAULT_MAX_PAGES = 50

# ── HTML parsing ───────────────────────────────────────────────────
HTML_PARSER = "lxml"           # falls back to "html.parser" if lxml missing
