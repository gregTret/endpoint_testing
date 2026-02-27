"""
Upload Tester — Core test engine that replays file uploads with malicious presets.

Reads an upload profile (from analyzer.py output), iterates over all presets,
builds upload requests (multipart or JSON), executes prerequisite flows
(CSRF token extraction, session cookies), and classifies each response.

Usage:
    from tester import run_tests
    results = asyncio.run(run_tests(profile_path, concurrency=3, delay=0.5))
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

import httpx

from presets import get_presets, get_presets_by_category

log = logging.getLogger("upload-tester")

# ── Constants ────────────────────────────────────────────────────────────────

REQUEST_TIMEOUT = 30.0
RESPONSE_SNIPPET_CAP = 500

# Patterns indicating the server accepted the upload
ACCEPT_PATTERNS = [
    re.compile(r'"(?:success|ok|status)"\s*:\s*(?:true|"(?:ok|success|uploaded|complete)")', re.I),
    re.compile(r'"(?:url|path|file_?(?:url|path|id)|id|key|location)"\s*:', re.I),
    re.compile(r"(?:upload(?:ed)?|saved|created|stored)\s+successfully", re.I),
]

# Patterns indicating the server rejected the upload
REJECT_PATTERNS = [
    re.compile(r"\b(?:invalid|not\s+allowed|forbidden|unsupported|blocked|rejected|disallowed)\b", re.I),
    re.compile(r"\b(?:file\s+type|extension|format)\s+(?:is\s+)?not\s+(?:allowed|supported|permitted)\b", re.I),
    re.compile(r"\b(?:bad\s+request|validation\s+(?:error|failed))\b", re.I),
]

# Patterns indicating a WAF or security layer blocked the request
WAF_PATTERNS = [
    re.compile(r"\b(?:waf|web\s+application\s+firewall|security\s+block|access\s+denied)\b", re.I),
    re.compile(r"\b(?:cloudflare|akamai|imperva|modsecurity|sucuri)\b", re.I),
]

# High-risk preset categories — if these are accepted, flag as dangerous
HIGH_RISK_CATEGORIES = {
    "Webshell", "Python Execution", "Out-of-Band", "Path Traversal",
}

MEDIUM_RISK_CATEGORIES = {
    "Polyglot", "SVG", "SVG (React/Flask)", "MIME Mismatch",
    "Filename Injection", "Extension Bypass",
}


# ── Multipart builder ────────────────────────────────────────────────────────


def _build_multipart_body(
    file_field: str,
    filename: str,
    content_type: str,
    content: bytes,
    additional_fields: dict,
    boundary: str,
) -> bytes:
    """Build a multipart/form-data body from parts.

    Mirrors backend/proxy/multipart.py:rebuild_multipart structure.
    """
    parts: list[bytes] = []

    # Non-file fields first
    for name, value in additional_fields.items():
        part = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n'
            f"\r\n"
            f"{value}\r\n"
        ).encode("utf-8")
        parts.append(part)

    # File field
    file_header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n"
        f"\r\n"
    ).encode("utf-8")
    parts.append(file_header + content + b"\r\n")

    # Final boundary
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))

    return b"".join(parts)


def _build_json_body(
    file_field: str,
    filename: str,
    content_type: str,
    content: bytes,
    additional_fields: dict,
) -> str:
    """Build a JSON body replacing the file field with a file descriptor object."""
    body = dict(additional_fields)

    # Set the file field — supports dot-notation paths (e.g. "data.file")
    file_obj = {
        "filename": filename,
        "content_type": content_type,
        "data": base64.b64encode(content).decode("ascii"),
    }

    parts = file_field.split(".")
    target = body
    for part in parts[:-1]:
        if part not in target or not isinstance(target[part], dict):
            target[part] = {}
        target = target[part]
    target[parts[-1]] = file_obj

    return json.dumps(body)


# ── Prerequisite execution ────────────────────────────────────────────────────


async def _execute_prerequisites(
    client: httpx.AsyncClient,
    prerequisites: list[dict],
    auth_headers: dict,
) -> dict:
    """Execute prerequisite requests and extract tokens/cookies.

    Returns a dict of extra headers/values to merge into the upload request.
    """
    extracted = {}

    for prereq in prerequisites:
        prereq_type = prereq.get("type", "")
        url = prereq.get("url", "")
        method = prereq.get("method", "GET").upper()
        extract_config = prereq.get("extract")

        if not url:
            continue

        try:
            resp = await client.request(
                method,
                url,
                headers=auth_headers,
                timeout=REQUEST_TIMEOUT,
            )
        except Exception as exc:
            log.warning("Prerequisite %s %s failed: %s", method, url, exc)
            continue

        if not extract_config:
            continue

        field = extract_config.get("field", "")
        source = extract_config.get("from", "")
        pattern = extract_config.get("pattern")

        # Extract from response header
        if source == "header":
            val = resp.headers.get(field)
            if val:
                extracted[field] = val

        # Extract from Set-Cookie
        elif source == "cookie":
            if pattern:
                for cookie_header in resp.headers.get_list("set-cookie"):
                    m = re.search(pattern, cookie_header)
                    if m:
                        extracted[f"_cookie_{field}"] = m.group(1)
                        break
            else:
                # Grab all cookies set
                for cookie_header in resp.headers.get_list("set-cookie"):
                    name_val = cookie_header.split(";", 1)[0].strip()
                    if "=" in name_val:
                        extracted[f"_cookie_{name_val.split('=', 1)[0]}"] = name_val

        # Extract from response body
        elif source == "body":
            body_text = resp.text
            if pattern:
                m = re.search(pattern, body_text)
                if m:
                    extracted[field] = m.group(1)
            else:
                # Fallback: look for common CSRF patterns
                for pat_str in [
                    r'name=["\']?(?:csrf|_csrf|xsrf|_token)["\']?\s+value=["\']?([^"\'>\s]+)',
                    r'(?:csrf|xsrf|_token)["\']?\s*[:=]\s*["\']([^"\']+)',
                ]:
                    m = re.search(pat_str, body_text, re.I)
                    if m:
                        extracted[field] = m.group(1)
                        break

    return extracted


def _merge_extracted_into_headers(auth_headers: dict, extracted: dict) -> dict:
    """Merge extracted tokens into the auth headers dict."""
    merged = dict(auth_headers)

    # Merge cookie values
    cookie_parts = []
    existing_cookie = merged.get("cookie") or merged.get("Cookie") or ""
    if existing_cookie:
        cookie_parts.append(existing_cookie)

    for key, val in extracted.items():
        if key.startswith("_cookie_"):
            cookie_name = key[len("_cookie_"):]
            if "=" in val:
                cookie_parts.append(val)
            else:
                cookie_parts.append(f"{cookie_name}={val}")
        elif key.lower() not in ("_cookie",):
            # Set as a request header (CSRF tokens, etc.)
            merged[key] = val

    if cookie_parts:
        merged["Cookie"] = "; ".join(cookie_parts)

    return merged


# ── Response analysis ─────────────────────────────────────────────────────────


def _classify_response(
    status_code: int,
    body: str,
    filename: str,
    success_indicators: dict,
) -> tuple[str, str]:
    """Classify an upload response. Returns (result, details)."""
    details_parts = []

    # Check for errors first
    if status_code == 0:
        return "error", "Request failed (timeout or connection error)"
    if status_code >= 500:
        return "error", f"Server error (HTTP {status_code})"

    # Check for WAF/security blocks
    if status_code == 403:
        for pat in WAF_PATTERNS:
            if pat.search(body):
                return "rejected", f"WAF/security block detected (HTTP 403)"
        return "rejected", f"Forbidden (HTTP 403)"

    # Check against success indicators from the profile
    indicator_status_codes = success_indicators.get("status_codes", [])
    indicator_snippets = success_indicators.get("body_snippets", [])

    status_match = status_code in indicator_status_codes if indicator_status_codes else False

    # Check for rejection patterns
    for pat in REJECT_PATTERNS:
        m = pat.search(body[:2000])
        if m:
            details_parts.append(f"Rejection pattern: '{m.group()}'")
            return "rejected", "; ".join(details_parts) or f"Rejected (HTTP {status_code})"

    # Check for explicit accept patterns
    accept_signals = 0

    if status_match:
        accept_signals += 1
        details_parts.append(f"Status {status_code} matches original upload")

    # Check if the filename appears in the response (suggests it was stored)
    if filename and filename in body:
        accept_signals += 1
        details_parts.append("Filename reflected in response")

    for pat in ACCEPT_PATTERNS:
        if pat.search(body[:2000]):
            accept_signals += 1
            details_parts.append(f"Accept pattern matched")
            break

    # Check body snippets from original successful upload
    for snippet in indicator_snippets:
        # Extract a key pattern from the snippet to match against
        key_match = re.search(r'"(\w+)"\s*:', snippet)
        if key_match and key_match.group(1) in body:
            accept_signals += 1
            details_parts.append(f"Response structure matches original")
            break

    if accept_signals >= 2:
        return "accepted", "; ".join(details_parts) or f"Upload accepted (HTTP {status_code})"
    if accept_signals == 1:
        # Borderline — check status code range for extra signal
        if 200 <= status_code < 300:
            return "accepted", "; ".join(details_parts) or f"Upload likely accepted (HTTP {status_code})"
        return "uncertain", "; ".join(details_parts) or f"Uncertain result (HTTP {status_code})"

    # No clear signals
    if 200 <= status_code < 300:
        return "uncertain", f"HTTP {status_code} but no clear accept/reject indicators"
    if 400 <= status_code < 500:
        return "rejected", f"Client error (HTTP {status_code})"

    return "uncertain", f"Unclear response (HTTP {status_code})"


# ── Core test runner ──────────────────────────────────────────────────────────


async def _test_single_preset(
    client: httpx.AsyncClient,
    profile: dict,
    preset: dict,
    auth_headers: dict,
    semaphore: asyncio.Semaphore,
    delay: float,
) -> dict:
    """Test a single preset against a single profile endpoint."""
    async with semaphore:
        endpoint_url = profile["endpoint_url"]
        method = profile.get("method", "POST").upper()
        upload_type = profile.get("upload_type", "multipart")
        file_field = profile.get("file_field_name", "file")
        additional_fields = dict(profile.get("additional_fields", {}))
        success_indicators = profile.get("response_success_indicators", {})

        filename = preset["filename"]
        content_type = preset["content_type"]
        content = preset["content"]  # bytes, already decoded by presets module

        result = {
            "preset_id": preset["id"],
            "preset_name": preset["name"],
            "preset_category": preset["category"],
            "filename": filename,
            "content_type": content_type,
            "endpoint_url": endpoint_url,
            "status_code": 0,
            "result": "error",
            "response_snippet": "",
            "details": "",
        }

        try:
            if upload_type == "multipart":
                boundary = f"----EPTUploadTest{int(time.time() * 1000)}"
                body = _build_multipart_body(
                    file_field, filename, content_type, content,
                    additional_fields, boundary,
                )
                headers = {
                    **auth_headers,
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                }
                resp = await client.request(
                    method, endpoint_url,
                    content=body,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT,
                )

            elif upload_type == "json":
                json_body = _build_json_body(
                    file_field, filename, content_type, content,
                    additional_fields,
                )
                headers = {
                    **auth_headers,
                    "Content-Type": "application/json",
                }
                resp = await client.request(
                    method, endpoint_url,
                    content=json_body.encode("utf-8"),
                    headers=headers,
                    timeout=REQUEST_TIMEOUT,
                )

            else:
                result["details"] = f"Unknown upload type: {upload_type}"
                return result

            resp_body = resp.text[:RESPONSE_SNIPPET_CAP * 2]
            classification, details = _classify_response(
                resp.status_code, resp_body, filename, success_indicators,
            )

            result["status_code"] = resp.status_code
            result["result"] = classification
            result["response_snippet"] = resp_body[:RESPONSE_SNIPPET_CAP]
            result["details"] = details

        except httpx.TimeoutException:
            result["details"] = "Request timed out"
        except httpx.ConnectError as exc:
            result["details"] = f"Connection failed: {exc}"
        except Exception as exc:
            result["details"] = f"Unexpected error: {exc}"

        if delay > 0:
            await asyncio.sleep(delay)

        return result


async def _test_profile(
    profile: dict,
    presets_list: list[dict],
    concurrency: int,
    delay: float,
    on_result: Optional[Callable] = None,
) -> list[dict]:
    """Run all presets against a single upload profile."""
    semaphore = asyncio.Semaphore(concurrency)
    auth_headers = dict(profile.get("auth_headers", {}))
    prerequisites = profile.get("prerequisites", [])

    results = []

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        limits=httpx.Limits(
            max_connections=concurrency + 2,
            max_keepalive_connections=concurrency,
        ),
    ) as client:
        # Execute prerequisites to gather tokens/cookies
        if prerequisites:
            log.info("Executing %d prerequisite(s)...", len(prerequisites))
            extracted = await _execute_prerequisites(
                client, prerequisites, auth_headers,
            )
            auth_headers = _merge_extracted_into_headers(auth_headers, extracted)

        # Test all presets
        tasks = [
            _test_single_preset(
                client, profile, preset, auth_headers, semaphore, delay,
            )
            for preset in presets_list
        ]

        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            if on_result:
                on_result(result)

    return results


async def run_tests(
    profile_path: str,
    concurrency: int = 3,
    delay: float = 0.5,
    categories: Optional[list[str]] = None,
    callback_url: Optional[str] = None,
    on_result: Optional[Callable] = None,
) -> list[dict]:
    """Run upload tests for all profiles in a profile file.

    Args:
        profile_path: Path to the upload profile JSON (analyzer output).
        concurrency: Max concurrent requests.
        delay: Delay in seconds between requests.
        categories: If set, only test presets from these categories.
        callback_url: OOB callback URL for {{CALLBACK}} replacement.
        on_result: Optional callback invoked with each result dict.

    Returns:
        List of test result dicts.
    """
    profile_data = json.loads(Path(profile_path).read_text(encoding="utf-8"))
    profiles = profile_data.get("profiles", [])

    if not profiles:
        log.warning("No upload profiles found in %s", profile_path)
        return []

    # Load presets
    if categories:
        presets_list = []
        for cat in categories:
            presets_list.extend(get_presets_by_category(cat, callback_url))
        if not presets_list:
            log.warning("No presets found for categories: %s", categories)
            return []
    else:
        presets_list = get_presets(callback_url)

    log.info(
        "Testing %d profile(s) with %d preset(s) (concurrency=%d, delay=%.1fs)",
        len(profiles), len(presets_list), concurrency, delay,
    )

    all_results = []

    for i, profile in enumerate(profiles, 1):
        log.info(
            "[%d/%d] Testing %s %s (%s)",
            i, len(profiles),
            profile.get("method", "POST"),
            profile.get("endpoint_url", "?"),
            profile.get("upload_type", "?"),
        )

        results = await _test_profile(
            profile, presets_list, concurrency, delay, on_result,
        )
        all_results.extend(results)

    return all_results
