"""
Upload response classifier — determines whether the server accepted, rejected,
or blocked a file upload attempt, and maps the result to a VulnerabilityReport.

Extracted from tools/upload_tester/tester.py.
"""

from __future__ import annotations

import re

from models.scan_config import VulnerabilityReport

# ── Pattern sets ──────────────────────────────────────────────────────────────

ACCEPT_PATTERNS = [
    re.compile(r'"(?:success|ok|status)"\s*:\s*(?:true|"(?:ok|success|uploaded|complete)")', re.I),
    re.compile(r'"(?:url|path|file_?(?:url|path|id)|id|key|location)"\s*:', re.I),
    re.compile(r"(?:upload(?:ed)?|saved|created|stored)\s+successfully", re.I),
]

REJECT_PATTERNS = [
    re.compile(r"\b(?:invalid|not\s+allowed|forbidden|unsupported|blocked|rejected|disallowed)\b", re.I),
    re.compile(r"\b(?:file\s+type|extension|format)\s+(?:is\s+)?not\s+(?:allowed|supported|permitted)\b", re.I),
    re.compile(r"\b(?:bad\s+request|validation\s+(?:error|failed))\b", re.I),
]

WAF_PATTERNS = [
    re.compile(r"\b(?:waf|web\s+application\s+firewall|security\s+block|access\s+denied)\b", re.I),
    re.compile(r"\b(?:cloudflare|akamai|imperva|modsecurity|sucuri)\b", re.I),
]

# ── Risk tiers ────────────────────────────────────────────────────────────────

HIGH_RISK_CATEGORIES = {
    "Webshell", "Python Execution", "Out-of-Band", "Path Traversal",
}

MEDIUM_RISK_CATEGORIES = {
    "Polyglot", "SVG", "SVG (React/Flask)", "MIME Mismatch",
    "Filename Injection", "Extension Bypass",
}


# ── Core classifier ──────────────────────────────────────────────────────────


def classify_upload_response(
    status_code: int,
    body: str,
    filename: str,
    baseline_status: int | None = None,
    baseline_snippets: list[str] | None = None,
) -> tuple[str, str]:
    """Classify an upload response.

    Returns ``(classification, details)`` where classification is one of:
    ``accepted``, ``rejected``, ``uncertain``, ``error``.
    """
    baseline_snippets = baseline_snippets or []
    details_parts: list[str] = []

    # Errors
    if status_code == 0:
        return "error", "Request failed (timeout or connection error)"
    if status_code >= 500:
        return "error", f"Server error (HTTP {status_code})"

    # WAF / 403
    if status_code == 403:
        for pat in WAF_PATTERNS:
            if pat.search(body):
                return "rejected", "WAF/security block detected (HTTP 403)"
        return "rejected", "Forbidden (HTTP 403)"

    # Status-code match against baseline
    status_match = baseline_status is not None and status_code == baseline_status

    # Rejection patterns
    for pat in REJECT_PATTERNS:
        m = pat.search(body[:2000])
        if m:
            details_parts.append(f"Rejection pattern: '{m.group()}'")
            return "rejected", "; ".join(details_parts) or f"Rejected (HTTP {status_code})"

    # Accept signals
    accept_signals = 0

    if status_match:
        accept_signals += 1
        details_parts.append(f"Status {status_code} matches baseline upload")

    if filename and filename in body:
        accept_signals += 1
        details_parts.append("Filename reflected in response")

    for pat in ACCEPT_PATTERNS:
        if pat.search(body[:2000]):
            accept_signals += 1
            details_parts.append("Accept pattern matched")
            break

    for snippet in baseline_snippets:
        key_match = re.search(r'"(\w+)"\s*:', snippet)
        if key_match and key_match.group(1) in body:
            accept_signals += 1
            details_parts.append("Response structure matches baseline")
            break

    if accept_signals >= 2:
        return "accepted", "; ".join(details_parts) or f"Upload accepted (HTTP {status_code})"
    if accept_signals == 1:
        if 200 <= status_code < 300:
            return "accepted", "; ".join(details_parts) or f"Upload likely accepted (HTTP {status_code})"
        return "uncertain", "; ".join(details_parts) or f"Uncertain result (HTTP {status_code})"

    # No clear signals
    if 200 <= status_code < 300:
        return "uncertain", f"HTTP {status_code} but no clear accept/reject indicators"
    if 400 <= status_code < 500:
        return "rejected", f"Client error (HTTP {status_code})"

    return "uncertain", f"Unclear response (HTTP {status_code})"


# ── Map classification to VulnerabilityReport ─────────────────────────────────


def classification_to_report(
    classification: str,
    details: str,
    preset_category: str,
) -> VulnerabilityReport:
    """Convert a classification result to a ``VulnerabilityReport``."""
    if classification == "accepted":
        if preset_category in HIGH_RISK_CATEGORIES:
            return VulnerabilityReport(
                is_vulnerable=True, confidence="high", details=details,
            )
        if preset_category in MEDIUM_RISK_CATEGORIES:
            return VulnerabilityReport(
                is_vulnerable=True, confidence="medium", details=details,
            )
        # Edge Cases or unknown category — still accepted, low confidence
        return VulnerabilityReport(
            is_vulnerable=True, confidence="low", details=details,
        )

    if classification == "uncertain":
        return VulnerabilityReport(
            is_vulnerable=False, confidence="low",
            details=f"{details} — needs manual review",
        )

    # rejected / error
    return VulnerabilityReport(is_vulnerable=False, confidence="low", details=details)
