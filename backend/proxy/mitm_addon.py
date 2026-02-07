import logging
import queue
import threading
from datetime import datetime, timezone

from mitmproxy import http

from config import LOG_BODY_CAP

log = logging.getLogger(__name__)


class InterceptAddon:
    """mitmproxy addon that captures every HTTP request/response pair."""

    def __init__(self, log_queue: queue.Queue) -> None:
        self.log_queue = log_queue
        self._id_counter = 0
        self._lock = threading.Lock()

    def _next_id(self) -> int:
        with self._lock:
            self._id_counter += 1
            return self._id_counter

    def request(self, flow: http.HTTPFlow) -> None:
        flow.metadata["log_id"] = self._next_id()
        flow.metadata["start_time"] = datetime.now(timezone.utc).timestamp()

    def response(self, flow: http.HTTPFlow) -> None:
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
        }

        try:
            self.log_queue.put_nowait(entry)
        except queue.Full:
            log.warning("log queue full — dropping entry for %s", entry["url"])

    def error(self, flow: http.HTTPFlow) -> None:
        """Log errored flows."""
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
        }
        try:
            self.log_queue.put_nowait(entry)
        except queue.Full:
            log.warning("log queue full — dropping error entry for %s", entry["url"])
