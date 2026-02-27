"""
Upload Recorder — mitmproxy addon that captures HTTP traffic and tags file uploads.

Usage:
    As mitmproxy addon:   mitmdump -s recorder.py --set output=capture.json
    Standalone:           python recorder.py --listen-port 8888 --output capture.json
"""

import argparse
import base64
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mitmproxy import http


# ── Constants ────────────────────────────────────────────────────────────────

BODY_CAP = 50_000  # max bytes for response body storage
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{100,}={0,2}$")

# Keys that indicate a JSON object represents a file
_FILENAME_KEYS = frozenset({"filename", "file_name", "fileName", "name"})
_DATA_KEYS = frozenset({"data", "content", "file", "base64", "fileData", "file_data"})


# ── Multipart helpers (self-contained, mirrors backend/proxy/multipart.py) ───


def _is_multipart(content_type: str) -> bool:
    return content_type.lower().strip().startswith("multipart/form-data")


def _extract_boundary(content_type: str) -> Optional[str]:
    match = re.search(r'boundary=("?)(.+?)\1(?:;|$)', content_type)
    return match.group(2).strip() if match else None


def _is_text_content(content_type: str, filename: Optional[str]) -> bool:
    ct = content_type.lower()
    text_types = ("text/", "application/json", "application/xml",
                  "application/x-www-form-urlencoded")
    if any(ct.startswith(t) for t in text_types):
        return True
    if not filename and ct in ("", "text/plain"):
        return True
    return False


def _parse_multipart(content_type: str, raw_body: bytes) -> list[dict]:
    """Parse multipart/form-data into structured parts."""
    boundary = _extract_boundary(content_type)
    if not boundary:
        return []

    delimiter = f"--{boundary}".encode()
    parts_raw = raw_body.split(delimiter)
    results = []

    for part_data in parts_raw:
        stripped = part_data.strip()
        if not stripped or stripped == b"--":
            continue
        if stripped.endswith(b"--"):
            stripped = stripped[:-2].rstrip()

        header_body_split = re.split(b"\r?\n\r?\n", stripped, maxsplit=1)
        if len(header_body_split) < 2:
            continue

        header_block, body = header_body_split
        header_block = header_block.lstrip(b"\r\n")

        part_headers = {}
        for line in re.split(b"\r?\n", header_block):
            line_str = line.decode("utf-8", errors="replace")
            if ":" in line_str:
                key, val = line_str.split(":", 1)
                part_headers[key.strip().lower()] = val.strip()

        disposition = part_headers.get("content-disposition", "")
        name_match = re.search(r'name="([^"]*)"', disposition)
        filename_match = re.search(r'filename="([^"]*)"', disposition)

        name = name_match.group(1) if name_match else ""
        filename = filename_match.group(1) if filename_match else None

        part_ct = part_headers.get(
            "content-type",
            "text/plain" if not filename else "application/octet-stream",
        )

        if body.endswith(b"\r\n"):
            body = body[:-2]

        is_binary = not _is_text_content(part_ct, filename)

        part = {
            "name": name,
            "filename": filename,
            "content_type": part_ct,
            "is_binary": is_binary,
            "size": len(body),
        }

        if is_binary:
            part["content_b64"] = base64.b64encode(body).decode("ascii")
            part["content_text"] = None
        else:
            try:
                part["content_text"] = body.decode("utf-8")
            except UnicodeDecodeError:
                part["content_b64"] = base64.b64encode(body).decode("ascii")
                part["content_text"] = None
                part["is_binary"] = True
            else:
                part["content_b64"] = None

        results.append(part)

    return results


# ── JSON upload detection (mirrors intercept_state.py patterns) ──────────────


def _looks_like_file_object(obj: dict) -> bool:
    """Return True if a dict looks like a JSON file-upload descriptor."""
    if not isinstance(obj, dict):
        return False
    keys = set(obj.keys())
    has_name = bool(keys & _FILENAME_KEYS)
    has_data = bool(keys & _DATA_KEYS)
    return has_name and has_data


def _looks_like_base64_blob(value) -> bool:
    """Check if a string value looks like base64-encoded file data."""
    if not isinstance(value, str):
        return False
    return bool(BASE64_RE.match(value))


def _extract_json_file_objects(parsed) -> list[dict]:
    """Walk parsed JSON and return file-upload-like objects with their paths."""
    results: list[dict] = []

    def _walk(node, path=""):
        if isinstance(node, dict):
            if _looks_like_file_object(node):
                results.append({"json_path": path or "(root)", "fields": node})
                return
            for key, val in node.items():
                child_path = f"{path}.{key}" if path else key
                # Check for standalone base64 blobs (e.g. {"avatar": "aGVsbG8..."})
                if _looks_like_base64_blob(val):
                    results.append({
                        "json_path": child_path,
                        "fields": {key: "<base64 blob>"},
                    })
                else:
                    _walk(val, child_path)
        elif isinstance(node, list):
            for i, val in enumerate(node):
                _walk(val, f"{path}[{i}]")

    _walk(parsed)
    return results


# ── Mitmproxy Addon ─────────────────────────────────────────────────────────


class UploadRecorder:
    """Mitmproxy addon that captures all HTTP traffic and tags file uploads."""

    def __init__(self):
        self._flows: list[dict] = []
        self._output_path: str = "capture.json"

    def load(self, loader):
        loader.add_option(
            name="output",
            typespec=str,
            default="capture.json",
            help="Output file path for captured flows",
        )

    def configure(self, updates):
        from mitmproxy import ctx
        if "output" in updates:
            self._output_path = ctx.options.output

    def response(self, flow: http.HTTPFlow):
        """Called for every completed request/response pair."""
        entry = self._serialize_flow(flow)
        self._detect_upload(entry, flow)
        self._flows.append(entry)
        self._save()

    def _serialize_flow(self, flow: http.HTTPFlow) -> dict:
        """Serialize a flow into a JSON-safe dict."""
        # Request body — text or base64 for binary
        req_body = ""
        req_body_b64 = None
        is_req_binary = False
        try:
            raw_req = flow.request.content or b""
            try:
                req_body = raw_req.decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                req_body_b64 = base64.b64encode(raw_req).decode("ascii")
                is_req_binary = True
        except Exception:
            req_body = ""

        # Response body — text or base64, capped
        resp_body = ""
        resp_body_b64 = None
        is_resp_binary = False
        resp_status = 0
        resp_headers = {}
        if flow.response:
            resp_status = flow.response.status_code
            resp_headers = dict(flow.response.headers)
            try:
                raw_resp = flow.response.content or b""
                raw_resp = raw_resp[:BODY_CAP]
                try:
                    resp_body = raw_resp.decode("utf-8")
                except (UnicodeDecodeError, ValueError):
                    resp_body_b64 = base64.b64encode(raw_resp).decode("ascii")
                    is_resp_binary = True
            except Exception:
                resp_body = ""

        content_type = flow.request.headers.get("content-type", "")

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.host,
            "path": flow.request.path,
            "request_headers": dict(flow.request.headers),
            "request_body": req_body if not is_req_binary else None,
            "request_body_b64": req_body_b64,
            "content_type": content_type,
            "status_code": resp_status,
            "response_headers": resp_headers,
            "response_body": resp_body if not is_resp_binary else None,
            "response_body_b64": resp_body_b64,
            "is_upload": False,
            "upload_type": None,
            "file_field_name": None,
            "file_parts": [],
        }

    def _detect_upload(self, entry: dict, flow: http.HTTPFlow):
        """Check if the flow is a file upload and tag it accordingly."""
        content_type = entry["content_type"]

        # 1) Multipart/form-data uploads
        if _is_multipart(content_type):
            raw_body = flow.request.content or b""
            parts = _parse_multipart(content_type, raw_body)

            # Find parts that have a filename — those are file uploads
            file_parts = [p for p in parts if p.get("filename")]
            if file_parts:
                entry["is_upload"] = True
                entry["upload_type"] = "multipart"
                entry["file_field_name"] = file_parts[0]["name"]
                entry["file_parts"] = [
                    {
                        "name": p["name"],
                        "filename": p["filename"],
                        "content_type": p["content_type"],
                        "size": p["size"],
                    }
                    for p in file_parts
                ]
                # Store ALL multipart parts (file + non-file) for replay context
                entry["all_multipart_parts"] = parts
            return

        # 2) JSON body with file-like objects or base64 blobs
        if content_type.lower().strip().startswith("application/json"):
            body_text = entry.get("request_body")
            if not body_text:
                return
            try:
                parsed = json.loads(body_text)
            except (json.JSONDecodeError, TypeError):
                return

            file_objects = _extract_json_file_objects(parsed)
            if file_objects:
                entry["is_upload"] = True
                entry["upload_type"] = "json"
                entry["file_field_name"] = file_objects[0]["json_path"]
                entry["file_parts"] = [
                    {
                        "name": fo["json_path"],
                        "filename": fo["fields"].get("filename")
                                    or fo["fields"].get("file_name")
                                    or fo["fields"].get("fileName")
                                    or fo["fields"].get("name"),
                        "content_type": fo["fields"].get("content_type")
                                        or fo["fields"].get("mime_type")
                                        or fo["fields"].get("mimeType")
                                        or fo["fields"].get("type")
                                        or "unknown",
                        "size": None,
                    }
                    for fo in file_objects
                ]

    def _save(self):
        """Persist all captured flows to the output JSON file."""
        try:
            Path(self._output_path).write_text(
                json.dumps(self._flows, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception as exc:
            from mitmproxy import ctx
            ctx.log.error(f"Failed to save capture: {exc}")

    def done(self):
        """Called when mitmproxy shuts down."""
        self._save()
        from mitmproxy import ctx
        ctx.log.info(
            f"Upload recorder saved {len(self._flows)} flows "
            f"to {self._output_path}"
        )


# mitmproxy addon entry point (for `mitmdump -s recorder.py`)
addons = [UploadRecorder()]


# ── Standalone launcher ──────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Launch mitmproxy with the UploadRecorder addon"
    )
    parser.add_argument(
        "--listen-port", type=int, default=8888,
        help="Proxy listen port (default: 8888)",
    )
    parser.add_argument(
        "--output", type=str, default="capture.json",
        help="Output file for captured flows (default: capture.json)",
    )
    args = parser.parse_args()

    # Launch mitmproxy DumpMaster programmatically
    import asyncio
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.options import Options

    async def run():
        opts = Options(listen_host="127.0.0.1", listen_port=args.listen_port)
        master = DumpMaster(opts)

        recorder = UploadRecorder()
        master.addons.add(recorder)
        # Set _output_path AFTER addons.add() — the mitmproxy lifecycle calls
        # configure() during add(), which resets _output_path to the default.
        recorder._output_path = args.output

        print(f"[upload-recorder] Proxy listening on 127.0.0.1:{args.listen_port}")
        print(f"[upload-recorder] Saving traffic to {args.output}")
        print("[upload-recorder] Press Ctrl+C to stop")

        try:
            await master.run()
        except KeyboardInterrupt:
            pass
        finally:
            master.shutdown()

    asyncio.run(run())
