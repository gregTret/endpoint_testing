"""
Upload Analyzer — Reads a recorder capture file and produces upload test profiles.

Identifies file upload endpoints, extracts replay requirements (auth, CSRF,
additional fields), and detects prerequisite requests needed before uploads.

Usage:
    python analyzer.py --input capture.json --output upload_profile.json
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


# ── Constants ────────────────────────────────────────────────────────────────

# Auth-related headers to capture
AUTH_HEADERS = {
    "authorization", "cookie", "x-csrf-token", "x-xsrf-token",
    "x-api-key", "x-auth-token", "x-session-id",
}

# Patterns that indicate CSRF tokens in response bodies
CSRF_BODY_PATTERNS = [
    re.compile(r'name=["\']?(?:csrf|_csrf|xsrf|_token|csrfmiddlewaretoken|__RequestVerificationToken)["\']?\s+(?:value|content)=["\']?([^"\'>\s]+)', re.I),
    re.compile(r'(?:csrf|xsrf|_token|csrfmiddlewaretoken)["\']?\s*[:=]\s*["\']([^"\']+)', re.I),
]

# CSRF-related response header names
CSRF_HEADER_NAMES = {"x-csrf-token", "x-xsrf-token", "csrf-token", "xsrf-token"}

# Cookie names that look like CSRF tokens
CSRF_COOKIE_PATTERNS = re.compile(r"(?:csrf|xsrf|_token)", re.I)

# Auth-like endpoint patterns
AUTH_ENDPOINT_PATTERNS = re.compile(
    r"(?:login|signin|sign-in|auth|authenticate|oauth|token|session|sso)",
    re.I,
)

# How far back (seconds) to look for prerequisite requests
PREREQ_WINDOW_SECONDS = 60

# Patterns that suggest a GET is fetching the upload page / form
UPLOAD_PAGE_PATTERNS = re.compile(
    r"(?:upload|attach|import|media|file|document|image|photo|avatar|profile)",
    re.I,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse an ISO timestamp, returning None on failure."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        return None


def _extract_host(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or ""


def _extract_auth_headers(headers: dict) -> dict:
    """Pull auth-relevant headers from a request."""
    result = {}
    for key, val in headers.items():
        if key.lower() in AUTH_HEADERS:
            result[key] = val
    return result


def _find_csrf_in_headers(resp_headers: dict) -> Optional[dict]:
    """Check response headers for CSRF tokens."""
    for key, val in resp_headers.items():
        if key.lower() in CSRF_HEADER_NAMES:
            return {"field": key, "from": "header", "pattern": None, "value": val}
    return None


def _find_csrf_in_cookies(resp_headers: dict) -> Optional[dict]:
    """Check Set-Cookie headers for CSRF-looking cookies."""
    for key, val in resp_headers.items():
        if key.lower() == "set-cookie" and CSRF_COOKIE_PATTERNS.search(val):
            cookie_name = val.split("=", 1)[0].strip()
            return {
                "field": cookie_name,
                "from": "cookie",
                "pattern": f"{cookie_name}=([^;]+)",
                "value": None,
            }
    return None


def _find_csrf_in_body(body: Optional[str]) -> Optional[dict]:
    """Search response body for CSRF token patterns."""
    if not body:
        return None
    for pat in CSRF_BODY_PATTERNS:
        m = pat.search(body)
        if m:
            return {
                "field": "csrf_token",
                "from": "body",
                "pattern": pat.pattern,
                "value": m.group(1),
            }
    return None


def _is_auth_endpoint(url: str) -> bool:
    return bool(AUTH_ENDPOINT_PATTERNS.search(url))


def _is_upload_related_page(url: str) -> bool:
    return bool(UPLOAD_PAGE_PATTERNS.search(url))


# ── Profile building ─────────────────────────────────────────────────────────


def _build_success_indicators(flow: dict) -> dict:
    """Extract response patterns that indicate a successful upload."""
    status = flow.get("status_code", 0)
    resp_body = flow.get("response_body") or ""

    indicators = {
        "status_codes": [],
        "body_snippets": [],
    }

    # Success status codes
    if 200 <= status < 300:
        indicators["status_codes"].append(status)

    # Look for common success patterns in response body
    success_patterns = [
        re.compile(r'"(?:success|ok|status)"\s*:\s*(?:true|"(?:ok|success|uploaded|complete)")', re.I),
        re.compile(r'"(?:url|path|file_?(?:url|path|id)|id|key)"\s*:', re.I),
        re.compile(r'"(?:message)"\s*:\s*"[^"]*(?:upload|success|created|saved)[^"]*"', re.I),
    ]
    for pat in success_patterns:
        m = pat.search(resp_body[:5000])
        if m:
            # Grab some surrounding context
            start = max(0, m.start() - 20)
            end = min(len(resp_body), m.end() + 50)
            indicators["body_snippets"].append(resp_body[start:end].strip())

    return indicators


def _extract_additional_fields_multipart(flow: dict) -> dict:
    """Extract non-file multipart fields and their values."""
    all_parts = flow.get("all_multipart_parts", [])
    file_parts = flow.get("file_parts", [])
    file_names_set = {fp.get("name") for fp in file_parts}

    fields = {}
    for part in all_parts:
        name = part.get("name", "")
        if name and name not in file_names_set and not part.get("filename"):
            fields[name] = part.get("content_text") or part.get("content_b64") or ""
    return fields


def _extract_additional_fields_json(flow: dict) -> dict:
    """Extract non-file JSON keys and their values."""
    body_text = flow.get("request_body")
    if not body_text:
        return {}
    try:
        parsed = json.loads(body_text)
    except (json.JSONDecodeError, TypeError):
        return {}

    if not isinstance(parsed, dict):
        return {}

    file_paths = set()
    for fp in flow.get("file_parts", []):
        # The "name" field from file_parts contains the JSON path
        file_paths.add(fp.get("name", ""))

    fields = {}
    for key, val in parsed.items():
        if key not in file_paths:
            # Only include simple scalar values, skip nested file objects
            if isinstance(val, (str, int, float, bool)) or val is None:
                fields[key] = val
    return fields


def _find_prerequisites(
    upload_flow: dict,
    all_flows: list[dict],
    flow_index: int,
) -> list[dict]:
    """Look backwards from an upload flow to find prerequisite requests."""
    prerequisites = []
    upload_host = _extract_host(upload_flow["url"])
    upload_ts = _parse_timestamp(upload_flow["timestamp"])

    seen_types = set()  # avoid duplicate prereq types

    # Walk backwards through flows before this one
    for i in range(flow_index - 1, -1, -1):
        prev = all_flows[i]
        prev_host = _extract_host(prev["url"])

        # Only same host
        if prev_host != upload_host:
            continue

        # Only within time window
        prev_ts = _parse_timestamp(prev["timestamp"])
        if upload_ts and prev_ts:
            delta = (upload_ts - prev_ts).total_seconds()
            if delta > PREREQ_WINDOW_SECONDS:
                break
            if delta < 0:
                continue

        # Skip other upload flows
        if prev.get("is_upload"):
            continue

        resp_headers = prev.get("response_headers", {})
        resp_body = prev.get("response_body")
        prev_method = prev.get("method", "")
        prev_url = prev.get("url", "")

        # 1) CSRF token fetch
        if "csrf" not in seen_types:
            csrf = (
                _find_csrf_in_headers(resp_headers)
                or _find_csrf_in_cookies(resp_headers)
                or _find_csrf_in_body(resp_body)
            )
            if csrf:
                seen_types.add("csrf")
                prerequisites.append({
                    "type": "csrf_fetch",
                    "url": prev_url,
                    "method": prev_method,
                    "extract": {
                        "field": csrf["field"],
                        "from": csrf["from"],
                        "pattern": csrf["pattern"],
                    },
                })

        # 2) Auth / login request
        if "auth" not in seen_types and prev_method == "POST" and _is_auth_endpoint(prev_url):
            seen_types.add("auth")
            prerequisites.append({
                "type": "auth",
                "url": prev_url,
                "method": prev_method,
                "extract": {
                    "field": "session_cookie",
                    "from": "cookie",
                    "pattern": None,
                },
            })

        # 3) Upload page fetch (GET to the same upload-ish path)
        if "page_fetch" not in seen_types and prev_method == "GET" and _is_upload_related_page(prev_url):
            extract = None
            # Check if the upload page also provides a CSRF token
            csrf = _find_csrf_in_body(resp_body)
            if csrf:
                extract = {
                    "field": csrf["field"],
                    "from": csrf["from"],
                    "pattern": csrf["pattern"],
                }
            seen_types.add("page_fetch")
            prerequisites.append({
                "type": "page_fetch",
                "url": prev_url,
                "method": prev_method,
                "extract": extract,
            })

        # 4) OPTIONS preflight
        if "preflight" not in seen_types and prev_method == "OPTIONS":
            upload_path = urlparse(upload_flow["url"]).path
            prev_path = urlparse(prev_url).path
            if prev_path == upload_path:
                seen_types.add("preflight")
                prerequisites.append({
                    "type": "preflight",
                    "url": prev_url,
                    "method": "OPTIONS",
                    "extract": None,
                })

    return prerequisites


def _build_content_type_template(flow: dict) -> str:
    """Build a content-type template, replacing the multipart boundary with a placeholder."""
    ct = flow.get("content_type", "")
    if flow.get("upload_type") == "multipart":
        # Replace the actual boundary with a placeholder
        return re.sub(
            r"boundary=[^\s;]+",
            "boundary={{BOUNDARY}}",
            ct,
        )
    return ct


def _original_file_info(flow: dict) -> Optional[dict]:
    """Extract info about the original uploaded file."""
    file_parts = flow.get("file_parts", [])
    if not file_parts:
        return None
    fp = file_parts[0]
    return {
        "name": fp.get("filename"),
        "type": fp.get("content_type", "unknown"),
        "size": fp.get("size"),
    }


# ── Main analysis ────────────────────────────────────────────────────────────


def analyze(capture_path: str) -> dict:
    """Analyze a capture file and return upload test profiles."""
    data = json.loads(Path(capture_path).read_text(encoding="utf-8"))

    if not isinstance(data, list):
        print("[error] Capture file does not contain a JSON array of flows.")
        sys.exit(1)

    # Find all upload flows
    upload_indices = [i for i, f in enumerate(data) if f.get("is_upload")]

    if not upload_indices:
        print("[info] No file upload flows detected in the capture.")
        return {"profiles": []}

    profiles = []

    for idx in upload_indices:
        flow = data[idx]

        upload_type = flow.get("upload_type", "unknown")

        # Extract additional (non-file) fields
        if upload_type == "multipart":
            additional_fields = _extract_additional_fields_multipart(flow)
        elif upload_type == "json":
            additional_fields = _extract_additional_fields_json(flow)
        else:
            additional_fields = {}

        # Auth headers from the upload request itself
        auth_headers = _extract_auth_headers(flow.get("request_headers", {}))

        # Content-type template
        ct_template = _build_content_type_template(flow)

        # Original file info
        original_file = _original_file_info(flow)

        # Success indicators from the response
        success_indicators = _build_success_indicators(flow)

        # Find prerequisite requests
        prerequisites = _find_prerequisites(flow, data, idx)

        profile = {
            "endpoint_url": flow["url"],
            "method": flow["method"],
            "upload_type": upload_type,
            "file_field_name": flow.get("file_field_name"),
            "additional_fields": additional_fields,
            "auth_headers": auth_headers,
            "content_type_template": ct_template,
            "original_file": original_file,
            "response_success_indicators": success_indicators,
            "prerequisites": prerequisites,
        }

        profiles.append(profile)

    return {"profiles": profiles}


def _print_summary(result: dict):
    """Print a human-readable summary of detected upload endpoints."""
    profiles = result.get("profiles", [])
    count = len(profiles)

    print()
    print(f"{'=' * 60}")
    print(f"  Upload Analyzer — {count} endpoint(s) detected")
    print(f"{'=' * 60}")

    if not profiles:
        print("  No file upload endpoints found.")
        print()
        return

    for i, p in enumerate(profiles, 1):
        print()
        print(f"  [{i}] {p['method']} {p['endpoint_url']}")
        print(f"      Type:         {p['upload_type']}")
        print(f"      File field:   {p['file_field_name']}")

        if p.get("original_file"):
            of = p["original_file"]
            size_str = f"{of['size']} bytes" if of.get("size") else "unknown size"
            print(f"      Original:     {of.get('name', '?')} ({of.get('type', '?')}, {size_str})")

        if p.get("additional_fields"):
            fields_str = ", ".join(p["additional_fields"].keys())
            print(f"      Extra fields: {fields_str}")

        if p.get("auth_headers"):
            auth_str = ", ".join(p["auth_headers"].keys())
            print(f"      Auth:         {auth_str}")

        if p.get("prerequisites"):
            print(f"      Prerequisites ({len(p['prerequisites'])}):")
            for pr in p["prerequisites"]:
                extract_info = ""
                if pr.get("extract"):
                    extract_info = f" -> extract {pr['extract']['field']} from {pr['extract']['from']}"
                print(f"        - [{pr['type']}] {pr['method']} {pr['url']}{extract_info}")

        si = p.get("response_success_indicators", {})
        if si.get("status_codes"):
            print(f"      Success:      status {si['status_codes']}")
        if si.get("body_snippets"):
            print(f"      Body hints:   {len(si['body_snippets'])} pattern(s)")

    print()
    print(f"{'=' * 60}")
    print()


# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze recorded HTTP traffic for file upload endpoints"
    )
    parser.add_argument(
        "--input", type=str, default="capture.json",
        help="Path to the recorder capture file (default: capture.json)",
    )
    parser.add_argument(
        "--output", type=str, default="upload_profile.json",
        help="Output path for the upload profile (default: upload_profile.json)",
    )
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"[error] Capture file not found: {args.input}")
        sys.exit(1)

    result = analyze(args.input)

    Path(args.output).write_text(
        json.dumps(result, indent=2, default=str),
        encoding="utf-8",
    )

    _print_summary(result)
    print(f"  Profile saved to: {args.output}")
    print()
