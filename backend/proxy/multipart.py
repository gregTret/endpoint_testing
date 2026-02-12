"""Multipart form-data parser and rebuilder for intercept file-upload editing."""

import base64
import re
from typing import Optional


def is_multipart(content_type: str) -> bool:
    """Return True if the content-type indicates multipart/form-data."""
    return content_type.lower().strip().startswith("multipart/form-data")


def extract_boundary(content_type: str) -> Optional[str]:
    """Extract the boundary string from a multipart content-type header."""
    match = re.search(r'boundary=("?)(.+?)\1(?:;|$)', content_type)
    if match:
        return match.group(2).strip()
    return None


def _is_text_content(content_type: str, filename: Optional[str]) -> bool:
    """Heuristic: treat as text if no filename and content-type is text-like."""
    ct = content_type.lower()
    text_types = ("text/", "application/json", "application/xml", "application/x-www-form-urlencoded")
    if any(ct.startswith(t) for t in text_types):
        return True
    # Non-file fields with no explicit content-type default to text
    if not filename and ct in ("", "text/plain"):
        return True
    return False


def parse_multipart(content_type: str, raw_body: bytes) -> list[dict]:
    """Parse a multipart/form-data body into structured parts.

    Returns a list of dicts, each with:
      - name: form field name
      - filename: original filename or None
      - content_type: MIME type of the part
      - content_b64: base64-encoded content (for binary parts)
      - content_text: text content (for text parts)
      - is_binary: whether content is binary
      - size: byte length of the part content
    """
    boundary = extract_boundary(content_type)
    if not boundary:
        raise ValueError("No boundary found in content-type header")

    delimiter = f"--{boundary}".encode()
    end_delimiter = f"--{boundary}--".encode()

    # Split body on boundary markers
    parts_raw = raw_body.split(delimiter)
    results = []

    for part_data in parts_raw:
        # Skip preamble, epilogue, and end marker
        stripped = part_data.strip()
        if not stripped or stripped == b"--" or stripped.startswith(end_delimiter):
            continue
        # Remove trailing -- if this is the last part
        if stripped.endswith(b"--"):
            stripped = stripped[:-2].rstrip()

        # Split headers from body (separated by \r\n\r\n or \n\n)
        header_body_split = re.split(b"\r?\n\r?\n", stripped, maxsplit=1)
        if len(header_body_split) < 2:
            continue

        header_block, body = header_body_split

        # Strip leading \r\n from header block (left over from boundary split)
        header_block = header_block.lstrip(b"\r\n")

        # Parse part headers
        part_headers = {}
        for line in re.split(b"\r?\n", header_block):
            line_str = line.decode("utf-8", errors="replace")
            if ":" in line_str:
                key, val = line_str.split(":", 1)
                part_headers[key.strip().lower()] = val.strip()

        # Extract Content-Disposition fields
        disposition = part_headers.get("content-disposition", "")
        name_match = re.search(r'name="([^"]*)"', disposition)
        filename_match = re.search(r'filename="([^"]*)"', disposition)

        name = name_match.group(1) if name_match else ""
        filename = filename_match.group(1) if filename_match else None

        part_ct = part_headers.get("content-type", "text/plain" if not filename else "application/octet-stream")

        # Strip trailing \r\n from body
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
                # Fall back to base64 if text decode fails
                part["content_b64"] = base64.b64encode(body).decode("ascii")
                part["content_text"] = None
                part["is_binary"] = True
            else:
                part["content_b64"] = None

        results.append(part)

    return results


def rebuild_multipart(parts: list[dict], boundary: str) -> bytes:
    """Reconstruct a valid multipart/form-data body from structured parts.

    Each part dict should have: name, filename (or None), content_type,
    content_b64 or content_text, is_binary.
    """
    delimiter = f"--{boundary}".encode()
    end_delimiter = f"--{boundary}--".encode()
    crlf = b"\r\n"

    body_parts = []

    for part in parts:
        body_parts.append(delimiter)
        body_parts.append(crlf)

        # Content-Disposition header
        disposition = f'form-data; name="{part["name"]}"'
        if part.get("filename"):
            disposition += f'; filename="{part["filename"]}"'
        body_parts.append(f"Content-Disposition: {disposition}".encode())
        body_parts.append(crlf)

        # Content-Type header
        ct = part.get("content_type", "application/octet-stream")
        body_parts.append(f"Content-Type: {ct}".encode())
        body_parts.append(crlf)

        # Empty line separating headers from body
        body_parts.append(crlf)

        # Part content
        if part.get("is_binary") and part.get("content_b64"):
            body_parts.append(base64.b64decode(part["content_b64"]))
        elif part.get("content_text") is not None:
            body_parts.append(part["content_text"].encode("utf-8"))
        elif part.get("content_b64"):
            # Fallback: content_b64 present even if not marked binary
            body_parts.append(base64.b64decode(part["content_b64"]))
        else:
            body_parts.append(b"")

        body_parts.append(crlf)

    # Final boundary
    body_parts.append(end_delimiter)
    body_parts.append(crlf)

    return b"".join(body_parts)
