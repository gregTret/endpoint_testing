"""Thread-safe intercept state shared between mitmproxy and FastAPI."""

import json as _json
import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from config import LOG_BODY_CAP

log = logging.getLogger(__name__)

INTERCEPT_TIMEOUT = 120  # seconds before auto-forwarding a stalled flow
POLL_INTERVAL = 0.05     # seconds between checks when waiting for a decision


@dataclass
class PendingFlow:
    """A proxy flow waiting for user decision."""

    flow_id: str
    flow: object  # mitmproxy.http.HTTPFlow
    phase: str  # "request" or "response"
    event: threading.Event = field(default_factory=threading.Event)
    decision: str = "forward"  # "forward" or "drop"
    modified_request: Optional[dict] = None
    modified_response: Optional[dict] = None
    created_at: float = field(
        default_factory=lambda: datetime.now(timezone.utc).timestamp()
    )


class InterceptState:
    """Manages intercept on/off and the queue of pending flows."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._enabled = False
        self._auto_drop_options = True
        self._intercept_requests = True
        self._intercept_responses = True
        self._pending: dict[str, PendingFlow] = {}

    @property
    def enabled(self) -> bool:
        with self._lock:
            return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        with self._lock:
            self._enabled = value
            if not value:
                # Release all pending flows immediately
                for pf in self._pending.values():
                    pf.decision = "forward"
                    pf.event.set()
                self._pending.clear()

    @property
    def auto_drop_options(self) -> bool:
        with self._lock:
            return self._auto_drop_options

    @auto_drop_options.setter
    def auto_drop_options(self, value: bool) -> None:
        with self._lock:
            self._auto_drop_options = value

    @property
    def intercept_requests(self) -> bool:
        with self._lock:
            return self._intercept_requests

    @intercept_requests.setter
    def intercept_requests(self, value: bool) -> None:
        with self._lock:
            self._intercept_requests = value

    @property
    def intercept_responses(self) -> bool:
        with self._lock:
            return self._intercept_responses

    @intercept_responses.setter
    def intercept_responses(self, value: bool) -> None:
        with self._lock:
            self._intercept_responses = value

    def add_pending(self, flow, phase: str) -> PendingFlow:
        """Create a pending flow entry. Called from the mitmproxy thread."""
        flow_id = uuid.uuid4().hex[:12]
        pf = PendingFlow(flow_id=flow_id, flow=flow, phase=phase)
        with self._lock:
            self._pending[flow_id] = pf
        return pf

    def get_pending(self, flow_id: str) -> Optional[PendingFlow]:
        with self._lock:
            return self._pending.get(flow_id)

    def get_all_pending(self) -> list[dict]:
        """Return JSON-safe list of all pending flows."""
        with self._lock:
            return [self._serialize(pf) for pf in self._pending.values()]

    def resolve(
        self, flow_id: str, decision: str, modifications: dict | None = None
    ) -> bool:
        """Resolve a pending flow. Called from FastAPI thread."""
        with self._lock:
            pf = self._pending.get(flow_id)
            if not pf:
                return False
            pf.decision = decision
            if modifications and pf.phase == "request":
                pf.modified_request = modifications
            elif modifications and pf.phase == "response":
                pf.modified_response = modifications
            del self._pending[flow_id]

        # threading.Event.set() is truly thread-safe — works across any threads
        pf.event.set()
        return True

    # ── JSON file-upload detection ────────────────────────────────

    _FILENAME_KEYS = frozenset({"filename", "file_name", "fileName"})
    _MIMETYPE_KEYS = frozenset({"mime_type", "content_type", "mimeType", "contentType", "type"})
    _SIZE_KEYS = frozenset({"file_size", "size", "fileSize", "content_length"})

    @staticmethod
    def _looks_like_file_object(obj: dict) -> bool:
        """Return True if a dict looks like a JSON file-upload descriptor."""
        if not isinstance(obj, dict):
            return False
        keys = set(obj.keys())
        has_filename = bool(keys & InterceptState._FILENAME_KEYS)
        has_mime = bool(keys & InterceptState._MIMETYPE_KEYS)
        has_size = bool(keys & InterceptState._SIZE_KEYS)
        return has_filename and (has_mime or has_size)

    @staticmethod
    def _extract_json_file_objects(parsed) -> list[dict] | None:
        """Walk parsed JSON and return file-upload-like objects with their paths."""
        results: list[dict] = []

        def _walk(node, path=""):
            if isinstance(node, dict):
                if InterceptState._looks_like_file_object(node):
                    results.append({"json_path": path or "(root)", "fields": node})
                    return
                for key, val in node.items():
                    _walk(val, f"{path}.{key}" if path else key)
            elif isinstance(node, list):
                for i, val in enumerate(node):
                    _walk(val, f"{path}[{i}]")

        _walk(parsed)
        return results if results else None

    # ── serialisation ─────────────────────────────────────────────

    def _serialize(self, pf: PendingFlow) -> dict:
        flow = pf.flow
        data: dict = {
            "flow_id": pf.flow_id,
            "phase": pf.phase,
            "created_at": pf.created_at,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.host,
            "path": flow.request.path,
        }

        req_body = ""
        try:
            req_body = flow.request.get_text(strict=False) or ""
        except Exception:
            req_body = "<binary content>"

        if pf.phase == "request":
            data["headers"] = dict(flow.request.headers)
            data["body"] = req_body[:LOG_BODY_CAP]

            # Detect multipart/form-data and parse into structured parts
            content_type = flow.request.headers.get("content-type", "")
            try:
                from proxy.multipart import is_multipart, parse_multipart, extract_boundary

                if is_multipart(content_type):
                    parts = parse_multipart(content_type, flow.request.content)
                    data["is_multipart"] = True
                    data["multipart_parts"] = parts
                    data["multipart_boundary"] = extract_boundary(content_type)
                else:
                    data["is_multipart"] = False
            except Exception:
                data["is_multipart"] = False

            # Detect JSON file uploads (application/json with file-like objects)
            if not data.get("is_multipart"):
                data["is_json_upload"] = False
                if content_type.lower().strip().startswith("application/json"):
                    try:
                        parsed = _json.loads(req_body)
                        file_objects = self._extract_json_file_objects(parsed)
                        if file_objects:
                            data["is_json_upload"] = True
                            data["json_upload_files"] = file_objects
                    except Exception:
                        pass
        elif pf.phase == "response":
            data["request_headers"] = dict(flow.request.headers)
            data["request_body"] = req_body[:LOG_BODY_CAP]

            resp_body = ""
            try:
                resp_body = flow.response.get_text(strict=False) or ""
            except Exception:
                resp_body = "<binary content>"

            data["status_code"] = flow.response.status_code
            data["headers"] = dict(flow.response.headers)
            data["body"] = resp_body[:LOG_BODY_CAP]

        return data
