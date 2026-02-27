"""
Upload Injector — replays a captured upload with 90+ attack presets
and classifies each response to detect file-upload vulnerabilities.

Supports two modes:
  - **multipart**: traditional multipart/form-data uploads (single request)
  - **json_flow**: multi-step presigned-URL flows (batch-initiate → PUT blob → complete)

Same override-test_endpoint pattern as OOBInjector.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import json
import logging
import re
import time
from datetime import datetime, timezone

import httpx

from config import SCAN_DEFAULT_TIMEOUT, SCAN_RESPONSE_CAP, PROXY_HOST, PROXY_PORT, DEFAULT_HEADERS
from injectors.base import BaseInjector, _DROP_HEADERS, _SCAN_MARKER
from injectors.upload_classifier import classify_upload_response, classification_to_report
from injectors.upload_presets import get_presets, get_presets_by_category, list_categories
from models.scan_config import ScanResult, VulnerabilityReport
from proxy.multipart import parse_multipart, rebuild_multipart, extract_boundary
from storage.db import get_request_log_by_id, get_request_logs_in_range

log = logging.getLogger(__name__)

RESPONSE_SNIPPET_CAP = 500

# Keys in JSON bodies that indicate a file descriptor object
_FILE_DESCRIPTOR_KEYS = {"filename", "file_name", "fileName"}
_MIME_DESCRIPTOR_KEYS = {"mime_type", "mimeType", "mime", "content_type", "contentType"}

# URL patterns for flow step detection
_BLOB_URL_RE = re.compile(r"blob\.core\.windows\.net|\.s3[\.-]|storage\.googleapis\.com|presigned", re.I)
_COMPLETE_URL_RE = re.compile(r"/(?:complete|finalize|confirm|finish|commit|close)", re.I)

# Azure headers to propagate to step 2 (PUT blob)
_AZURE_HEADERS = {"x-ms-blob-type", "x-ms-version", "x-ms-blob-content-type",
                  "x-ms-date", "x-ms-blob-content-disposition"}


class UploadInjector(BaseInjector):
    """File-upload vulnerability scanner using attack presets."""

    name = "upload"
    description = "Upload — tests file upload endpoints with 90+ attack presets"

    def __init__(
        self,
        log_id: int | None = None,
        categories: list[str] | None = None,
        callback_url: str | None = None,
    ) -> None:
        super().__init__()
        self._log_id = log_id
        self._categories = categories
        self._callback_url = callback_url

    # ── Not used — test_endpoint is fully overridden ──────────────

    def generate_payloads(self, context: dict) -> list[str]:
        return []

    def analyze_response(self, baseline, test_response, payload):
        return VulnerabilityReport()

    # ── Main scan loop ────────────────────────────────────────────

    async def test_endpoint(
        self,
        url: str = "",
        method: str = "POST",
        params: dict | None = None,
        headers: dict | None = None,
        body: str = "",
        injection_points: list[str] | None = None,
        target_keys: list[str] | None = None,
        timeout: float = SCAN_DEFAULT_TIMEOUT,
        on_result=None,
        control: dict | None = None,
    ) -> list[ScanResult]:
        ctrl = control or {"signal": "run"}
        results: list[ScanResult] = []

        # 1. Fetch the original log entry
        if not self._log_id:
            err = self._error_result(url, "No log_id provided for upload scan")
            if on_result:
                await on_result(err, 1, 1)
            return [err]

        entry = await get_request_log_by_id(self._log_id)
        if not entry:
            err = self._error_result(url, f"Log entry {self._log_id} not found")
            if on_result:
                await on_result(err, 1, 1)
            return [err]

        # 2. Detect mode
        mode = self._detect_mode(entry)
        target_url = entry["url"]
        log.info("Upload scan mode: %s (log #%d, %s %s)", mode, self._log_id, entry["method"], target_url)

        if mode == "unknown":
            ct = self._get_content_type(entry) or "(none)"
            err = self._error_result(
                target_url,
                f"This request (Content-Type: {ct}) is not a file upload. "
                f"Select either a multipart/form-data upload or a JSON upload-initiation request "
                f"(one whose body contains file descriptors with filename + mime_type fields).",
            )
            if on_result:
                await on_result(err, 1, 1)
            return [err]

        if mode == "json_no_descriptors":
            err = self._error_result(
                target_url,
                "This JSON request does not contain file descriptor objects. "
                "The upload scanner needs a JSON body with objects containing "
                "'filename' + 'mime_type' (or similar keys like file_name, mimeType, contentType). "
                "Make sure you right-clicked the batch-initiate / upload-start request.",
            )
            if on_result:
                await on_result(err, 1, 1)
            return [err]

        # 3. Load presets
        presets_list = self._load_presets()
        if not presets_list:
            err = self._error_result(target_url, "No presets matched the selected categories")
            if on_result:
                await on_result(err, 1, 1)
            return [err]

        # 4. Merge default headers with original request headers
        merged_headers = await self._merge_headers(entry)

        # 5. Dispatch by mode
        if mode == "json_flow":
            results = await self._run_json_flow(
                entry, presets_list, merged_headers, timeout, ctrl, on_result,
            )
        else:
            results = await self._run_multipart(
                entry, presets_list, merged_headers, timeout, ctrl, on_result,
            )

        self.results.extend(results)
        return results

    # ── Mode detection ────────────────────────────────────────────

    def _detect_mode(self, entry: dict) -> str:
        """Determine scan mode: 'multipart', 'json_flow', or 'unknown'.

        - If the request has multipart/form-data content → multipart
        - If the request has JSON content with file descriptor objects → json_flow
        - Otherwise → unknown (will show a clear error)
        """
        ct = self._get_content_type(entry)
        if "multipart/form-data" in ct.lower():
            return "multipart"

        if "json" in ct.lower():
            body = entry.get("request_body", "")
            if body and self._has_file_descriptors(body):
                return "json_flow"
            return "json_no_descriptors"

        return "unknown"

    @staticmethod
    def _get_content_type(entry: dict) -> str:
        req_headers = entry.get("request_headers", {})
        if isinstance(req_headers, str):
            try:
                req_headers = json.loads(req_headers)
            except Exception:
                return ""
        for k, v in req_headers.items():
            if k.lower() == "content-type":
                return v
        return ""

    @staticmethod
    def _has_file_descriptors(body: str) -> bool:
        """Check if JSON body contains objects with filename + mime_type keys."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return False

        def _check(obj):
            if isinstance(obj, dict):
                keys_lower = {k.lower() for k in obj}
                has_fname = bool(keys_lower & {k.lower() for k in _FILE_DESCRIPTOR_KEYS})
                has_mime = bool(keys_lower & {k.lower() for k in _MIME_DESCRIPTOR_KEYS})
                if has_fname and has_mime:
                    return True
                for v in obj.values():
                    if _check(v):
                        return True
            elif isinstance(obj, list):
                for item in obj:
                    if _check(item):
                        return True
            return False

        return _check(data)

    # ── Preset loading ────────────────────────────────────────────

    def _load_presets(self) -> list[dict]:
        if self._categories:
            presets_list = []
            for cat in self._categories:
                presets_list.extend(get_presets_by_category(cat, self._callback_url))
        else:
            presets_list = get_presets(self._callback_url)
        return presets_list

    # ── Header merging ────────────────────────────────────────────

    async def _merge_headers(self, entry: dict) -> dict:
        try:
            from api.routes import get_default_headers
            defaults = await get_default_headers()
        except Exception:
            defaults = dict(DEFAULT_HEADERS)

        orig_headers = entry.get("request_headers", {})
        if isinstance(orig_headers, str):
            try:
                orig_headers = json.loads(orig_headers)
            except Exception:
                orig_headers = {}

        merged = dict(defaults)
        merged.update(orig_headers)
        return merged

    # ══════════════════════════════════════════════════════════════
    #  MULTIPART MODE (existing logic)
    # ══════════════════════════════════════════════════════════════

    async def _run_multipart(
        self,
        entry: dict,
        presets_list: list[dict],
        merged_headers: dict,
        timeout: float,
        ctrl: dict,
        on_result,
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        target_url = entry["url"]
        target_method = entry["method"]

        file_field, file_info, non_file_fields, boundary = self._extract_multipart_info(entry)
        if not file_field:
            err = self._error_result(
                target_url,
                "Could not identify file field in the multipart request. "
                "Ensure the request has multipart/form-data content type.",
            )
            if on_result:
                await on_result(err, 1, 1)
            return [err]

        total = len(presets_list)

        baseline_status, baseline_snippets = await self._send_baseline(
            target_url, target_method, merged_headers,
            file_field, file_info, non_file_fields, boundary, timeout,
        )

        proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
        idx = 0
        async with httpx.AsyncClient(verify=False, timeout=timeout, proxy=proxy_url) as client:
            for preset in presets_list:
                while ctrl.get("signal") == "pause":
                    await asyncio.sleep(0.5)
                if ctrl.get("signal") == "stop":
                    log.info("upload scan stopped by user at %d/%d", idx, total)
                    break

                result = await self._test_single_preset(
                    client, target_url, target_method, merged_headers,
                    file_field, non_file_fields, boundary,
                    preset, baseline_status, baseline_snippets,
                )
                results.append(result)
                idx += 1
                if on_result:
                    await on_result(result, idx, total)

        return results

    # ── Multipart info extraction ─────────────────────────────────

    def _extract_multipart_info(
        self, entry: dict,
    ) -> tuple[str | None, dict | None, dict, str]:
        """Extract file field name, file info, non-file fields, and boundary.

        Tries multipart_meta column first, falls back to parsing request_body.
        Returns (file_field, file_info, non_file_fields, boundary).
        """
        # Try multipart_meta column (structured metadata that survives truncation)
        meta_raw = entry.get("multipart_meta")
        if meta_raw:
            try:
                meta = json.loads(meta_raw) if isinstance(meta_raw, str) else meta_raw
                file_field = meta.get("file_field")
                non_file_fields = meta.get("non_file_fields", {})
                boundary = meta.get("boundary", "----EPTUploadBoundary")
                file_parts = meta.get("file_parts", [])
                file_info = file_parts[0] if file_parts else {}
                if file_field:
                    return file_field, file_info, non_file_fields, boundary
            except (json.JSONDecodeError, TypeError):
                pass

        # Fall back to parsing request_body
        req_headers = entry.get("request_headers", {})
        if isinstance(req_headers, str):
            try:
                req_headers = json.loads(req_headers)
            except Exception:
                req_headers = {}

        content_type = ""
        for k, v in req_headers.items():
            if k.lower() == "content-type":
                content_type = v
                break

        if not content_type or "multipart/form-data" not in content_type.lower():
            return None, None, {}, ""

        boundary = extract_boundary(content_type) or ""
        if not boundary:
            return None, None, {}, ""

        req_body = entry.get("request_body", "")
        if not req_body:
            return None, None, {}, boundary

        try:
            if isinstance(req_body, str):
                raw_bytes = req_body.encode("utf-8", errors="surrogateescape")
            else:
                raw_bytes = req_body
            parts = parse_multipart(content_type, raw_bytes)
        except Exception as exc:
            log.warning("Failed to parse multipart body: %s", exc)
            return None, None, {}, boundary

        file_field = None
        file_info = None
        non_file_fields = {}

        for part in parts:
            if part.get("filename") is not None:
                if file_field is None:
                    file_field = part["name"]
                    file_info = {
                        "name": part["name"],
                        "filename": part["filename"],
                        "content_type": part.get("content_type", "application/octet-stream"),
                        "size": part.get("size", 0),
                    }
            else:
                text = part.get("content_text", "")
                if text is None and part.get("content_b64"):
                    text = base64.b64decode(part["content_b64"]).decode("utf-8", errors="replace")
                non_file_fields[part["name"]] = text or ""

        return file_field, file_info, non_file_fields, boundary

    # ── Baseline request ──────────────────────────────────────────

    async def _send_baseline(
        self,
        url: str,
        method: str,
        headers: dict,
        file_field: str,
        file_info: dict | None,
        non_file_fields: dict,
        boundary: str,
        timeout: float,
    ) -> tuple[int | None, list[str]]:
        """Send a baseline upload to establish success indicators."""
        clean_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in _DROP_HEADERS
        }
        clean_headers.update(_SCAN_MARKER)

        baseline_boundary = f"----EPTBaseline{int(time.time() * 1000)}"
        parts = []
        for name, value in non_file_fields.items():
            parts.append({
                "name": name,
                "filename": None,
                "content_type": "text/plain",
                "is_binary": False,
                "content_text": value,
                "content_b64": None,
            })
        parts.append({
            "name": file_field,
            "filename": file_info.get("filename", "test.txt") if file_info else "test.txt",
            "content_type": file_info.get("content_type", "text/plain") if file_info else "text/plain",
            "is_binary": False,
            "content_text": "baseline test content",
            "content_b64": None,
        })

        body = rebuild_multipart(parts, baseline_boundary)
        clean_headers["content-type"] = f"multipart/form-data; boundary={baseline_boundary}"

        proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
        try:
            async with httpx.AsyncClient(verify=False, timeout=timeout, proxy=proxy_url) as client:
                resp = await client.request(
                    method, url, content=body, headers=clean_headers,
                )
                resp_body = resp.text[:RESPONSE_SNIPPET_CAP]
                snippets = [resp_body[:200]] if resp_body else []
                return resp.status_code, snippets
        except Exception as e:
            log.warning("Baseline upload failed: %s", e)
            return None, []

    # ── Single preset test (multipart) ────────────────────────────

    async def _test_single_preset(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        headers: dict,
        file_field: str,
        non_file_fields: dict,
        boundary: str,
        preset: dict,
        baseline_status: int | None,
        baseline_snippets: list[str],
    ) -> ScanResult:
        """Send one upload preset and classify the response."""
        preset_boundary = f"----EPTUpload{int(time.time() * 1000)}"
        filename = preset["filename"]
        content_type = preset["content_type"]
        content: bytes = preset["content"]

        parts = []
        for name, value in non_file_fields.items():
            parts.append({
                "name": name,
                "filename": None,
                "content_type": "text/plain",
                "is_binary": False,
                "content_text": value,
                "content_b64": None,
            })
        parts.append({
            "name": file_field,
            "filename": filename,
            "content_type": content_type,
            "is_binary": preset.get("is_binary", False),
            "content_text": None,
            "content_b64": base64.b64encode(content).decode("ascii"),
        })

        body = rebuild_multipart(parts, preset_boundary)

        clean_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in _DROP_HEADERS
        }
        clean_headers.update(_SCAN_MARKER)
        clean_headers["content-type"] = f"multipart/form-data; boundary={preset_boundary}"

        sent_headers_str = json.dumps(clean_headers, indent=2)

        start = time.time()
        try:
            resp = await client.request(method, url, content=body, headers=clean_headers)
            elapsed = round((time.time() - start) * 1000, 2)
            resp_body = resp.text[:SCAN_RESPONSE_CAP]

            classification, details = classify_upload_response(
                resp.status_code, resp_body, filename,
                baseline_status, baseline_snippets,
            )
            report = classification_to_report(
                classification, details, preset["category"],
            )

            return ScanResult(
                timestamp=datetime.now(timezone.utc).isoformat(),
                target_url=url,
                injector_type="upload",
                payload=f'[{preset["category"]}] {preset["name"]} \u2192 {filename}',
                injection_point="multipart_file",
                original_param=file_field,
                response_code=resp.status_code,
                response_body=resp_body,
                response_time_ms=elapsed,
                request_headers=sent_headers_str,
                request_body=f"(multipart: {filename} [{content_type}], {len(content)} bytes)",
                is_vulnerable=report.is_vulnerable,
                confidence=report.confidence,
                details=report.details,
            )
        except Exception as e:
            log.debug("Upload preset %s failed: %s", preset["id"], e)
            return ScanResult(
                timestamp=datetime.now(timezone.utc).isoformat(),
                target_url=url,
                injector_type="upload",
                payload=f'[{preset["category"]}] {preset["name"]} \u2192 {filename}',
                injection_point="multipart_file",
                original_param=file_field,
                response_code=0,
                response_body=str(e),
                request_headers=sent_headers_str,
                request_body=f"(multipart: {filename} [{content_type}])",
                is_vulnerable=False,
                confidence="low",
                details=f"Request failed: {e}",
            )

    # ══════════════════════════════════════════════════════════════
    #  JSON FLOW MODE (multi-step presigned-URL uploads)
    # ══════════════════════════════════════════════════════════════

    async def _run_json_flow(
        self,
        entry: dict,
        presets_list: list[dict],
        merged_headers: dict,
        timeout: float,
        ctrl: dict,
        on_result,
    ) -> list[ScanResult]:
        """Orchestrate a multi-step upload flow scan."""
        results: list[ScanResult] = []
        target_url = entry["url"]

        # Extract flow template from the source request + nearby logs
        flow_template = await self._extract_json_flow_info(entry)
        if not flow_template:
            err = self._error_result(
                target_url,
                "Could not build flow template. Ensure the JSON body contains "
                "file descriptor objects (filename + mime_type) and steps 2/3 "
                "(PUT blob + POST complete) are visible in nearby log entries.",
            )
            if on_result:
                await on_result(err, 1, 1)
            return [err]

        total = len(presets_list)
        proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
        idx = 0

        # Steps 1 and 3 go through the proxy (same origin, need auth).
        # Step 2 goes directly to the blob/presigned URL (external, SAS-authenticated).
        async with httpx.AsyncClient(verify=False, timeout=timeout, proxy=proxy_url) as proxy_client, \
                   httpx.AsyncClient(verify=False, timeout=timeout) as direct_client:
            for preset in presets_list:
                while ctrl.get("signal") == "pause":
                    await asyncio.sleep(0.5)
                if ctrl.get("signal") == "stop":
                    log.info("upload flow scan stopped by user at %d/%d", idx, total)
                    break

                result = await self._test_single_flow_preset(
                    proxy_client, direct_client,
                    flow_template, merged_headers, preset, timeout,
                )
                results.append(result)
                idx += 1
                if on_result:
                    await on_result(result, idx, total)

        return results

    # ── Flow template extraction ──────────────────────────────────

    async def _extract_json_flow_info(self, entry: dict) -> dict | None:
        """Parse the initiation request and find steps 2+3 in nearby logs.

        Returns a flow template dict or None if the flow can't be reconstructed:
        {
            "step1_url": str,
            "step1_method": str,
            "step1_body": dict,           # original parsed JSON
            "file_descriptors_path": str,  # dot path to the file list, e.g. "files"
            "descriptor_keys": {           # mapping of canonical → actual key names
                "filename": "filename",
                "mime_type": "mime_type",
                "file_size": "file_size",
            },
            "step2_entry": dict | None,    # captured PUT-to-blob log entry
            "step2_azure_headers": dict,   # Azure-specific headers from step 2
            "step3_entry": dict | None,    # captured POST-to-complete log entry
            "step3_url_template": str,     # URL with {uploadId} placeholder
            "step3_body_template": dict,   # body with {batch_id} placeholder
        }
        """
        body_str = entry.get("request_body", "")
        try:
            body = json.loads(body_str)
        except (json.JSONDecodeError, TypeError):
            log.warning("Flow extraction failed: could not parse JSON body")
            return None

        # Find the file descriptor array and key mappings
        desc_path, desc_keys = self._find_file_descriptors(body)
        if not desc_path:
            log.warning("Flow extraction failed: no file descriptors found in JSON")
            return None

        # Search nearby log entries for steps 2 and 3
        source_id = entry["id"]
        session_id = entry.get("session_id", "default")
        step2_entry, step3_entry = await self._find_flow_steps(source_id, session_id)

        # Extract Azure headers from step 2
        step2_azure_headers = {}
        if step2_entry:
            s2_headers = step2_entry.get("request_headers", {})
            if isinstance(s2_headers, str):
                try:
                    s2_headers = json.loads(s2_headers)
                except Exception:
                    s2_headers = {}
            for k, v in s2_headers.items():
                if k.lower() in _AZURE_HEADERS:
                    step2_azure_headers[k] = v

        # Build step 3 URL template (replace the uploadId with a placeholder)
        step3_url_template = ""
        step3_body_template = {}
        if step3_entry:
            step3_url_template = self._build_step3_url_template(step3_entry, entry)
            s3_body = step3_entry.get("request_body", "")
            try:
                step3_body_template = json.loads(s3_body) if s3_body else {}
            except (json.JSONDecodeError, TypeError):
                step3_body_template = {}

        template = {
            "step1_url": entry["url"],
            "step1_method": entry["method"],
            "step1_body": body,
            "file_descriptors_path": desc_path,
            "descriptor_keys": desc_keys,
            "step2_entry": step2_entry,
            "step2_azure_headers": step2_azure_headers,
            "step3_entry": step3_entry,
            "step3_url_template": step3_url_template,
            "step3_body_template": step3_body_template,
        }

        log.info(
            "Flow template built: step2=%s, step3=%s, desc_path=%s",
            "found" if step2_entry else "MISSING",
            "found" if step3_entry else "MISSING",
            desc_path,
        )
        return template

    def _find_file_descriptors(self, body) -> tuple[str | None, dict | None]:
        """Walk JSON body to find the array of file descriptor objects.

        Returns (dot_path, key_mapping) or (None, None).
        dot_path is the path to the array (e.g. "files").
        key_mapping maps canonical names to actual key names found in the object.
        """
        def _search(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    cur_path = f"{path}.{k}" if path else k
                    result = _search(v, cur_path)
                    if result:
                        return result
            elif isinstance(obj, list) and len(obj) > 0:
                # Check if list items are file descriptor objects
                first = obj[0]
                if isinstance(first, dict):
                    keys_lower = {k.lower(): k for k in first}
                    fname_key = None
                    mime_key = None
                    size_key = None
                    for canonical, actual in keys_lower.items():
                        if canonical in {"filename", "file_name"}:
                            fname_key = actual
                        elif canonical in {"mime_type", "mimetype", "mime", "content_type", "contenttype"}:
                            mime_key = actual
                        elif canonical in {"file_size", "filesize", "size", "content_length"}:
                            size_key = actual
                    if fname_key and mime_key:
                        return path, {
                            "filename": fname_key,
                            "mime_type": mime_key,
                            "file_size": size_key,
                        }
            return None

        result = _search(body)
        if result:
            return result
        return None, None

    async def _find_flow_steps(
        self, source_id: int, session_id: str,
    ) -> tuple[dict | None, dict | None]:
        """Search nearby log entries for step 2 (PUT to blob) and step 3 (POST to complete).

        Looks at entries with IDs in [source_id+1, source_id+50] — uses a
        wide window since other proxy traffic may be interleaved.
        """
        nearby = await get_request_logs_in_range(
            source_id + 1, source_id + 50, session_id,
        )

        step2 = None  # PUT to blob/presigned URL
        step3 = None  # POST to complete endpoint

        for entry in nearby:
            method = entry.get("method", "").upper()
            url = entry.get("url", "")

            # Step 2: PUT to a blob/presigned URL
            if method == "PUT" and _BLOB_URL_RE.search(url) and not step2:
                step2 = entry
                continue

            # Step 3: POST to a complete/finalize endpoint
            if method == "POST" and _COMPLETE_URL_RE.search(url) and not step3:
                step3 = entry
                continue

            if step2 and step3:
                break

        return step2, step3

    @staticmethod
    def _build_step3_url_template(step3_entry: dict, step1_entry: dict) -> str:
        """Build a URL template for step 3 with {uploadId} placeholder.

        Examines the step 3 URL for path segments that look like UUIDs or
        IDs, and replaces them with {uploadId}.
        """
        url = step3_entry.get("url", "")
        # Common pattern: .../upload/<uuid>/complete
        # Replace UUID-like segments before /complete with {uploadId}
        result = re.sub(
            r"(/upload(?:s)?/)([0-9a-fA-F-]{8,})(/(?:complete|finalize|confirm|finish|commit|close))",
            r"\1{uploadId}\3",
            url,
        )
        if result != url:
            return result

        # Fallback: replace any UUID-like segment adjacent to /complete
        result = re.sub(
            r"/([0-9a-fA-F-]{20,})(/(?:complete|finalize|confirm|finish|commit|close))",
            r"/{uploadId}\2",
            url,
        )
        if result != url:
            return result

        # If no UUID found, return as-is (user may need to adjust)
        return url

    # ── Single flow preset execution ──────────────────────────────

    async def _test_single_flow_preset(
        self,
        proxy_client: httpx.AsyncClient,
        direct_client: httpx.AsyncClient,
        flow_template: dict,
        headers: dict,
        preset: dict,
        timeout: float,
    ) -> ScanResult:
        """Execute the 3-step flow for one preset and classify the combined result."""
        filename = preset["filename"]
        content_type = preset["content_type"]
        content: bytes = preset["content"]
        target_url = flow_template["step1_url"]

        # Clean headers for steps 1 & 3 (same-origin, need auth)
        clean_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in _DROP_HEADERS
        }
        clean_headers.update(_SCAN_MARKER)

        step_statuses = []
        step_details = []
        overall_start = time.time()

        # ── Step 1: POST batch-initiate with swapped file metadata ──
        try:
            step1_body = self._build_step1_body(flow_template, preset)
            step1_headers = dict(clean_headers)
            step1_headers["content-type"] = "application/json"
            step1_json_str = json.dumps(step1_body)

            resp1 = await proxy_client.request(
                flow_template["step1_method"],
                flow_template["step1_url"],
                content=step1_json_str.encode("utf-8"),
                headers=step1_headers,
            )
            step_statuses.append(resp1.status_code)
            resp1_body = resp1.text[:SCAN_RESPONSE_CAP]

            if resp1.status_code >= 400:
                step_details.append(f"Step1(initiate): HTTP {resp1.status_code} — rejected")
                return self._build_flow_result(
                    target_url, preset, step_statuses, step_details,
                    resp1.status_code, resp1_body, overall_start, step1_json_str,
                )

            step_details.append(f"Step1(initiate): HTTP {resp1.status_code} — accepted")

            # Parse response to extract SAS URL, uploadId, batchId
            sas_url, upload_id, batch_id = self._parse_initiate_response(resp1_body)
            if not sas_url:
                step_details.append("Step1: Could not extract SAS URL from response")
                return self._build_flow_result(
                    target_url, preset, step_statuses, step_details,
                    resp1.status_code, resp1_body, overall_start, step1_json_str,
                )

        except Exception as e:
            step_statuses.append(0)
            step_details.append(f"Step1(initiate): Error — {e}")
            return self._build_flow_result(
                target_url, preset, step_statuses, step_details,
                0, str(e), overall_start, "",
            )

        # ── Step 2: PUT file content to SAS URL (direct, no proxy) ──
        try:
            step2_headers = dict(flow_template["step2_azure_headers"])
            step2_headers["x-ms-blob-content-type"] = content_type
            # Don't send auth cookies — SAS token in URL handles auth
            step2_headers.update(_SCAN_MARKER)

            resp2 = await direct_client.put(
                sas_url,
                content=content,
                headers=step2_headers,
            )
            step_statuses.append(resp2.status_code)

            if resp2.status_code >= 400:
                step_details.append(f"Step2(PUT blob): HTTP {resp2.status_code} — rejected")
                return self._build_flow_result(
                    target_url, preset, step_statuses, step_details,
                    resp2.status_code, resp2.text[:RESPONSE_SNIPPET_CAP],
                    overall_start, step1_json_str,
                )

            step_details.append(f"Step2(PUT blob): HTTP {resp2.status_code} — accepted")

        except Exception as e:
            step_statuses.append(0)
            step_details.append(f"Step2(PUT blob): Error — {e}")
            return self._build_flow_result(
                target_url, preset, step_statuses, step_details,
                0, str(e), overall_start, step1_json_str,
            )

        # ── Step 3: POST complete (through proxy, needs auth) ──
        step3_resp_body = ""
        if flow_template["step3_url_template"]:
            try:
                step3_url = flow_template["step3_url_template"].replace(
                    "{uploadId}", upload_id or "",
                )
                step3_body = copy.deepcopy(flow_template["step3_body_template"])
                # Inject the batch_id from step 1 response
                if batch_id:
                    step3_body["batch_id"] = batch_id
                step3_headers = dict(clean_headers)
                step3_headers["content-type"] = "application/json"
                step3_json_str = json.dumps(step3_body)

                resp3 = await proxy_client.request(
                    "POST", step3_url,
                    content=step3_json_str.encode("utf-8"),
                    headers=step3_headers,
                )
                step_statuses.append(resp3.status_code)
                step3_resp_body = resp3.text[:RESPONSE_SNIPPET_CAP]

                if resp3.status_code >= 400:
                    step_details.append(f"Step3(complete): HTTP {resp3.status_code} — rejected")
                else:
                    step_details.append(f"Step3(complete): HTTP {resp3.status_code} — accepted")

            except Exception as e:
                step_statuses.append(0)
                step_details.append(f"Step3(complete): Error — {e}")
        else:
            step_details.append("Step3(complete): skipped — no template URL found")

        # Build combined response body for display
        combined_resp = resp1_body
        if step3_resp_body:
            combined_resp = f"[Step1] {resp1_body}\n[Step3] {step3_resp_body}"

        return self._build_flow_result(
            target_url, preset, step_statuses, step_details,
            step_statuses[-1] if step_statuses else 0,
            combined_resp, overall_start, step1_json_str,
        )

    # ── Flow helpers ──────────────────────────────────────────────

    def _build_step1_body(self, flow_template: dict, preset: dict) -> dict:
        """Deep-copy step 1 body and swap file metadata with preset values."""
        body = copy.deepcopy(flow_template["step1_body"])
        desc_path = flow_template["file_descriptors_path"]
        keys = flow_template["descriptor_keys"]

        # Navigate to the file descriptors array using the dot path.
        # If any segment is missing, stop — don't silently skip.
        file_list = body
        if desc_path:
            for part in desc_path.split("."):
                if isinstance(file_list, dict) and part in file_list:
                    file_list = file_list[part]
                elif isinstance(file_list, list):
                    try:
                        file_list = file_list[int(part)]
                    except (ValueError, IndexError):
                        log.warning("Flow body nav: index '%s' out of range in path '%s'", part, desc_path)
                        break
                else:
                    log.warning("Flow body nav: key '%s' not found in path '%s'", part, desc_path)
                    break

        if isinstance(file_list, list) and len(file_list) > 0:
            desc = file_list[0]
            if isinstance(desc, dict):
                swapped = False
                if keys.get("filename"):
                    desc[keys["filename"]] = preset["filename"]
                    swapped = True
                if keys.get("mime_type"):
                    desc[keys["mime_type"]] = preset["content_type"]
                    swapped = True
                if keys.get("file_size"):
                    desc[keys["file_size"]] = len(preset["content"])
                if not swapped:
                    log.warning("Flow body: descriptor keys %s not found in object %s", keys, list(desc.keys()))
        else:
            log.warning(
                "Flow body: expected list at path '%s', got %s. "
                "Preset metadata NOT swapped — scan will send original values.",
                desc_path, type(file_list).__name__,
            )

        return body

    @staticmethod
    def _parse_initiate_response(body: str) -> tuple[str | None, str | None, str | None]:
        """Extract SAS URL, uploadId, and batchId from initiate response JSON.

        Handles various response shapes:
        - {uploads: [{uploadId, sasUrl}], batchId}
        - {upload_id, sas_url, batch_id}
        - {data: {uploads: [...]}}
        """
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return None, None, None

        sas_url = None
        upload_id = None
        batch_id = None

        # Key names that are specifically about upload/presigned URLs — trust
        # the key name alone (no domain check needed).
        _SPECIFIC_URL_KEYS = {
            "sas_url", "sasurl", "presigned_url", "presignedurl",
            "upload_url", "uploadurl", "signed_url", "signedurl",
        }

        def _extract(obj):
            nonlocal sas_url, upload_id, batch_id
            if isinstance(obj, dict):
                for k, v in obj.items():
                    kl = k.lower().replace("-", "_")
                    # Upload/presigned URL — trust specific key names outright
                    if kl in _SPECIFIC_URL_KEYS and isinstance(v, str) and v.startswith("http"):
                        if not sas_url:
                            sas_url = v
                    # Generic "url" — only accept if it looks like a storage URL
                    elif kl == "url" and isinstance(v, str) and not sas_url:
                        if _BLOB_URL_RE.search(v):
                            sas_url = v
                    elif kl in ("upload_id", "uploadid"):
                        upload_id = str(v)
                    elif kl in ("batch_id", "batchid"):
                        batch_id = str(v)
                    elif kl == "id" and not upload_id:
                        upload_id = str(v)
                    if isinstance(v, (dict, list)):
                        _extract(v)
            elif isinstance(obj, list):
                for item in obj:
                    _extract(item)

        _extract(data)
        return sas_url, upload_id, batch_id

    def _build_flow_result(
        self,
        target_url: str,
        preset: dict,
        step_statuses: list[int],
        step_details: list[str],
        final_status: int,
        resp_body: str,
        start_time: float,
        request_body: str,
    ) -> ScanResult:
        """Classify the multi-step flow result and build a ScanResult."""
        elapsed = round((time.time() - start_time) * 1000, 2)
        filename = preset["filename"]
        content_type = preset["content_type"]

        classification, details = self._classify_flow(step_statuses, step_details)
        report = classification_to_report(classification, details, preset["category"])

        flow_summary = " | ".join(step_details)

        return ScanResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            target_url=target_url,
            injector_type="upload",
            payload=f'[{preset["category"]}] {preset["name"]} \u2192 {filename}',
            injection_point="json_file_meta",
            original_param="file_descriptor",
            response_code=final_status,
            response_body=resp_body,
            response_time_ms=elapsed,
            request_headers="",
            request_body=f"(flow: {filename} [{content_type}], {len(preset['content'])} bytes)\n{flow_summary}",
            is_vulnerable=report.is_vulnerable,
            confidence=report.confidence,
            details=report.details,
        )

    @staticmethod
    def _classify_flow(
        step_statuses: list[int],
        step_details: list[str],
    ) -> tuple[str, str]:
        """Classify the combined result of a multi-step upload flow.

        Returns (classification, details) like the single-request classifier.
        """
        details_str = " | ".join(step_details)

        # Check for errors first
        if any(s == 0 for s in step_statuses):
            return "error", f"Flow error: {details_str}"
        if any(s >= 500 for s in step_statuses):
            return "error", f"Server error in flow: {details_str}"

        num_steps = len(step_statuses)

        # Step 1 rejected (4xx)
        if num_steps >= 1 and step_statuses[0] >= 400:
            return "rejected", f"Initiation rejected: {details_str}"

        # Step 1 accepted, step 2 rejected
        if num_steps >= 2 and step_statuses[1] >= 400:
            return "rejected", f"Blob storage rejected content: {details_str}"

        # Steps 1+2 accepted, step 3 rejected
        if num_steps >= 3 and step_statuses[2] >= 400:
            return "uncertain", f"Upload completed but finalization rejected: {details_str}"

        # All steps succeeded
        if num_steps >= 3 and all(200 <= s < 400 for s in step_statuses):
            return "accepted", f"Full flow accepted: {details_str}"

        # Steps 1+2 succeeded, step 3 skipped — can't confirm finalization
        if num_steps >= 2 and num_steps < 3 and all(200 <= s < 400 for s in step_statuses[:2]):
            return "uncertain", f"Initiation + blob accepted but not finalized (step 3 missing): {details_str}"

        # Step 1 only succeeded
        if num_steps >= 1 and 200 <= step_statuses[0] < 400:
            return "uncertain", f"Initiation accepted, flow incomplete: {details_str}"

        return "uncertain", f"Unclear flow result: {details_str}"

    # ── Helpers ───────────────────────────────────────────────────

    def _error_result(self, url: str, message: str) -> ScanResult:
        return ScanResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            target_url=url or "(unknown)",
            injector_type="upload",
            payload="(setup)",
            is_vulnerable=False,
            confidence="low",
            details=message,
        )
