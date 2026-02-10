import asyncio
import logging
import queue
import threading
from datetime import datetime, timezone

from mitmproxy import http

from config import LOG_BODY_CAP, LOG_OPTIONS_REQUESTS

log = logging.getLogger(__name__)


class InterceptAddon:
    """mitmproxy addon that captures every HTTP request/response pair
    and optionally pauses flows for user inspection (intercept mode)."""

    def __init__(self, log_queue: queue.Queue, workspace_getter=None, intercept_state=None) -> None:
        self.log_queue = log_queue
        self._workspace_getter = workspace_getter or (lambda: "default")
        self._intercept_state = intercept_state
        self._id_counter = 0
        self._lock = threading.Lock()

    def _next_id(self) -> int:
        with self._lock:
            self._id_counter += 1
            return self._id_counter

    # Marker header added by the injector / replay — these requests
    # are already stored in scan_results so we skip logging them.
    _SCAN_MARKER = "x-ept-scan"

    async def request(self, flow: http.HTTPFlow) -> None:
        # Detect and strip the scan marker before forwarding to the target
        if self._SCAN_MARKER in flow.request.headers:
            flow.metadata["is_scan"] = True
            del flow.request.headers[self._SCAN_MARKER]
        flow.metadata["log_id"] = self._next_id()
        flow.metadata["start_time"] = datetime.now(timezone.utc).timestamp()

        # ── Intercept mode ────────────────────────────────────────
        # When auto_drop_options is on, OPTIONS requests bypass intercept
        # but are still forwarded to the target (preserves CORS).
        is_auto_skip = (
            self._intercept_state
            and self._intercept_state.auto_drop_options
            and flow.request.method == "OPTIONS"
        )
        if (
            self._intercept_state
            and self._intercept_state.enabled
            and self._intercept_state.intercept_requests
            and not flow.metadata.get("is_scan")
            and not is_auto_skip
        ):
            from proxy.intercept_state import INTERCEPT_TIMEOUT, POLL_INTERVAL

            pf = self._intercept_state.add_pending(flow, "request")
            self._notify_intercept(pf)

            # Poll the threading.Event — yields to the event loop between checks
            # so mitmproxy stays responsive.  threading.Event is truly thread-safe
            # (unlike asyncio.Event which breaks across event loops).
            elapsed = 0.0
            while not pf.event.is_set():
                if elapsed >= INTERCEPT_TIMEOUT:
                    log.warning("intercept timeout for %s — auto-forwarding", flow.request.pretty_url)
                    pf.decision = "forward"
                    break
                await asyncio.sleep(POLL_INTERVAL)
                elapsed += POLL_INTERVAL

            if pf.decision == "drop":
                flow.kill()
                return

            # Apply modifications
            if pf.modified_request:
                mods = pf.modified_request
                if "method" in mods:
                    flow.request.method = mods["method"]
                if "url" in mods:
                    flow.request.url = mods["url"]
                if "headers" in mods:
                    flow.request.headers.clear()
                    for k, v in mods["headers"].items():
                        flow.request.headers[k] = v
                if "body" in mods:
                    flow.request.set_text(mods["body"])

    async def response(self, flow: http.HTTPFlow) -> None:
        # ── Intercept mode (response phase) ───────────────────────
        is_auto_skip = (
            self._intercept_state
            and self._intercept_state.auto_drop_options
            and flow.request.method == "OPTIONS"
        )
        if (
            self._intercept_state
            and self._intercept_state.enabled
            and self._intercept_state.intercept_responses
            and not flow.metadata.get("is_scan")
            and not is_auto_skip
        ):
            from proxy.intercept_state import INTERCEPT_TIMEOUT, POLL_INTERVAL

            pf = self._intercept_state.add_pending(flow, "response")
            self._notify_intercept(pf)

            elapsed = 0.0
            while not pf.event.is_set():
                if elapsed >= INTERCEPT_TIMEOUT:
                    log.warning("intercept timeout for response %s — auto-forwarding", flow.request.pretty_url)
                    pf.decision = "forward"
                    break
                await asyncio.sleep(POLL_INTERVAL)
                elapsed += POLL_INTERVAL

            if pf.decision == "drop":
                flow.kill()
                return

            if pf.modified_response:
                mods = pf.modified_response
                if "status_code" in mods:
                    flow.response.status_code = int(mods["status_code"])
                if "headers" in mods:
                    flow.response.headers.clear()
                    for k, v in mods["headers"].items():
                        flow.response.headers[k] = v
                if "body" in mods:
                    flow.response.set_text(mods["body"])

        # ── Normal logging ────────────────────────────────────────
        if flow.metadata.get("is_scan"):
            return
        if not LOG_OPTIONS_REQUESTS and flow.request.method == "OPTIONS":
            return
        start_time = flow.metadata.get("start_time", 0)
        end_time = datetime.now(timezone.utc).timestamp()
        duration_ms = round((end_time - start_time) * 1000, 2) if start_time else 0

        try:
            response_body = flow.response.get_text(strict=False) or ""
        except Exception:
            response_body = "<binary content>"

        try:
            request_body = flow.request.get_text(strict=False) or ""
        except Exception:
            request_body = ""

        entry = {
            "id": flow.metadata.get("log_id", 0),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.host,
            "path": flow.request.path,
            "request_headers": dict(flow.request.headers),
            "request_body": request_body[:LOG_BODY_CAP],
            "status_code": flow.response.status_code,
            "response_headers": dict(flow.response.headers),
            "response_body": response_body[:LOG_BODY_CAP],
            "content_type": flow.response.headers.get("content-type", ""),
            "duration_ms": duration_ms,
            "session_id": self._workspace_getter(),
        }

        try:
            self.log_queue.put_nowait(entry)
        except queue.Full:
            log.warning("log queue full — dropping entry for %s", entry["url"])

    def error(self, flow: http.HTTPFlow) -> None:
        """Log errored flows."""
        if flow.metadata.get("is_scan"):
            return
        error_msg = flow.error.msg if flow.error else "Unknown"
        entry = {
            "id": flow.metadata.get("log_id", 0),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.host,
            "path": flow.request.path,
            "request_headers": dict(flow.request.headers),
            "request_body": "",
            "status_code": 0,
            "response_headers": {},
            "response_body": f"Error: {error_msg}",
            "content_type": "",
            "duration_ms": 0,
            "session_id": self._workspace_getter(),
        }
        try:
            self.log_queue.put_nowait(entry)
        except queue.Full:
            log.warning("log queue full — dropping error entry for %s", entry["url"])

    def _notify_intercept(self, pf) -> None:
        """Push an intercept notification onto the log queue for FastAPI to pick up."""
        notification = {
            "_intercept_notification": True,
            "flow_id": pf.flow_id,
            "phase": pf.phase,
        }
        try:
            self.log_queue.put_nowait(notification)
        except queue.Full:
            pass
