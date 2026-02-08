import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone

import httpx

from config import SCAN_DEFAULT_TIMEOUT, SCAN_RESPONSE_CAP, PROXY_HOST, PROXY_PORT
from models.scan_config import ScanResult, VulnerabilityReport

log = logging.getLogger(__name__)

# Headers that should never be used as injection targets
_SKIP_HEADERS = frozenset({"host", "content-type", "content-length", "transfer-encoding"})

# Headers managed by httpx — sending them alongside httpx's own values
# can produce duplicates that confuse servers / reverse proxies
_DROP_HEADERS = frozenset({
    "host", "content-length", "transfer-encoding", "connection",
    "accept-encoding",
})

# Marker header so the mitmproxy addon skips logging scan traffic
_SCAN_MARKER = {"x-ept-scan": "1"}


class BaseInjector(ABC):
    """
    Abstract base class for all injection testing modules.

    Subclass and implement:
      - generate_payloads()
      - analyze_response()

    The base class handles request sending, baseline comparison,
    and result collection.
    """

    name: str = "base"
    description: str = ""

    def __init__(self) -> None:
        self.results: list[ScanResult] = []

    # ── Abstract interface ────────────────────────────────────────────

    @abstractmethod
    def generate_payloads(self, context: dict) -> list[str]:
        """Return a list of injection payloads to try."""
        ...

    @abstractmethod
    def analyze_response(
        self, baseline: dict, test_response: dict, payload: str,
    ) -> VulnerabilityReport:
        """Compare *test_response* against *baseline* and report findings."""
        ...

    # ── Public API ────────────────────────────────────────────────────

    async def test_endpoint(
        self,
        url: str,
        method: str = "GET",
        params: dict | None = None,
        headers: dict | None = None,
        body: str = "",
        injection_points: list[str] | None = None,
        target_keys: list[str] | None = None,
        timeout: float = SCAN_DEFAULT_TIMEOUT,
        on_result=None,
        control: dict | None = None,
    ) -> list[ScanResult]:
        """Run every payload × every injectable field and return results.

        *target_keys*: if provided, only inject into these specific
        param names / header names / JSON body key paths.  Empty = all.

        *on_result*: optional async callback(result, index, total) called
        after each individual test completes, for real-time progress.

        *control*: mutable dict with a ``signal`` key. Checked between
        each request.  ``"pause"`` suspends, ``"stop"`` aborts.
        """
        params = params or {}
        headers = headers or {}
        injection_points = injection_points or ["params"]
        results: list[ScanResult] = []
        ctrl = control or {"signal": "run"}

        baseline = await self._send_request(url, method, params, headers, body, timeout)
        payloads = self.generate_payloads(
            {"url": url, "method": method, "params": params},
        )

        # Build the list of (injection_point, param_name) targets so
        # we test *every* param, header, and JSON body field individually.
        targets = _build_targets(injection_points, params, headers, body, target_keys)
        total = len(payloads) * len(targets)

        proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
        idx = 0
        async with httpx.AsyncClient(verify=False, timeout=timeout, proxy=proxy_url) as client:
            for payload in payloads:
                for point, key in targets:
                    # ── Check control signal ──────────────────
                    while ctrl.get("signal") == "pause":
                        await asyncio.sleep(0.5)
                    if ctrl.get("signal") == "stop":
                        log.info("scan stopped by user at %d/%d", idx, total)
                        self.results.extend(results)
                        return results
                    # ──────────────────────────────────────────

                    result = await self._test_single(
                        client, url, method, params, headers, body,
                        payload, point, key, baseline,
                    )
                    results.append(result)
                    idx += 1
                    if on_result:
                        await on_result(result, idx, total)

        self.results.extend(results)
        return results

    # ── Internals ─────────────────────────────────────────────────────

    async def _test_single(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        params: dict,
        headers: dict,
        body: str,
        payload: str,
        injection_point: str,
        target_key: str,
        baseline: dict,
    ) -> ScanResult:
        """Send one request with *payload* injected at *target_key*."""
        mod_params = dict(params)
        # Strip headers that httpx auto-generates to avoid duplicates
        mod_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in _DROP_HEADERS
        }
        mod_headers.update(_SCAN_MARKER)
        mod_body = body
        send_json = False

        if injection_point == "params" and target_key in mod_params:
            mod_params[target_key] = payload
        elif injection_point == "headers" and target_key in mod_headers:
            mod_headers[target_key] = payload
        elif injection_point == "body":
            # JSON-aware: replace a single key inside a JSON body
            mod_body, send_json = _inject_into_body(body, target_key, payload)

        # Capture what we're about to send so it's visible in results
        sent_body = mod_body
        if send_json:
            try:
                sent_body = json.dumps(json.loads(mod_body), indent=2)
            except Exception:
                pass
        sent_headers_str = json.dumps(mod_headers, indent=2)

        start = time.time()
        try:
            if method.upper() == "GET":
                resp = await client.get(url, params=mod_params, headers=mod_headers)
            else:
                # Always use content= (raw body) so the Content-Type from
                # captured headers is used as-is — no conflicts with json=
                resp = await client.request(
                    method, url,
                    params=mod_params,
                    headers=mod_headers,
                    content=mod_body.encode("utf-8") if mod_body else b"",
                )
            elapsed = round((time.time() - start) * 1000, 2)
            resp_body = resp.text[:SCAN_RESPONSE_CAP]

            report = self.analyze_response(
                baseline,
                {
                    "status_code": resp.status_code,
                    "body": resp_body,
                    "response_time_ms": elapsed,
                    "headers": dict(resp.headers),
                },
                payload,
            )

            return ScanResult(
                timestamp=datetime.now(timezone.utc).isoformat(),
                target_url=url,
                injector_type=self.name,
                payload=payload,
                injection_point=injection_point,
                original_param=target_key,
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
            log.debug("request failed for payload %r: %s", payload, e)
            return ScanResult(
                timestamp=datetime.now(timezone.utc).isoformat(),
                target_url=url,
                injector_type=self.name,
                payload=payload,
                injection_point=injection_point,
                original_param=target_key,
                response_code=0,
                response_body=str(e),
                request_headers=sent_headers_str,
                request_body=sent_body,
                is_vulnerable=False,
                confidence="low",
                details=f"Request failed: {e}",
            )

    async def _send_request(
        self, url: str, method: str, params: dict,
        headers: dict, body: str, timeout: float,
    ) -> dict:
        """Fire a baseline (unmodified) request."""
        clean_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in _DROP_HEADERS
        }
        clean_headers.update(_SCAN_MARKER)
        proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
        start = time.time()
        try:
            async with httpx.AsyncClient(verify=False, timeout=timeout, proxy=proxy_url) as client:
                if method.upper() == "GET":
                    resp = await client.get(url, params=params, headers=clean_headers)
                else:
                    resp = await client.request(
                        method, url, params=params, headers=clean_headers,
                        content=body.encode("utf-8") if body else b"",
                    )
                elapsed = round((time.time() - start) * 1000, 2)
                return {
                    "status_code": resp.status_code,
                    "body": resp.text[:SCAN_RESPONSE_CAP],
                    "response_time_ms": elapsed,
                    "headers": dict(resp.headers),
                }
        except Exception as e:
            log.warning("baseline request failed: %s", e)
            return {"status_code": 0, "body": "", "response_time_ms": 0, "headers": {}}


def _build_targets(
    injection_points: list[str], params: dict, headers: dict,
    body: str = "", target_keys: list[str] | None = None,
) -> list[tuple[str, str]]:
    """
    Expand injection points into (point, key) pairs.

    If *target_keys* is provided and non-empty, only include keys
    that appear in that list.  Otherwise test everything.
    """
    # None = no filter (inject all), [] = explicitly empty (inject nothing)
    if target_keys is not None and len(target_keys) == 0:
        return []
    allowed = set(target_keys) if target_keys is not None else None
    targets: list[tuple[str, str]] = []

    for point in injection_points:
        if point == "params":
            if params:
                for k in params:
                    if allowed is None or k in allowed:
                        targets.append(("params", k))
            else:
                targets.append(("params", "q"))
        elif point == "headers":
            for k in headers:
                if k.lower() not in _SKIP_HEADERS:
                    if allowed is None or k in allowed:
                        targets.append(("headers", k))
        elif point == "body":
            body_keys = _extract_body_keys(body)
            if body_keys:
                for k in body_keys:
                    if allowed is None or k in allowed:
                        targets.append(("body", k))
            else:
                targets.append(("body", "__raw__"))

    return targets or [("params", "q")]


def _extract_body_keys(body: str) -> list[str]:
    """
    If *body* is valid JSON, return all top-level keys (flat)
    and dot-notation paths for nested objects.
    Returns empty list for non-JSON bodies.
    """
    if not body or not body.strip():
        return []
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, dict):
        return []

    keys: list[str] = []
    _walk_keys(data, "", keys)
    return keys


def _walk_keys(obj: dict, prefix: str, out: list[str]) -> None:
    """Recursively collect dot-notation paths for all leaf values."""
    for k, v in obj.items():
        path = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
        if isinstance(v, dict):
            _walk_keys(v, path, out)
        else:
            out.append(path)


def _inject_into_body(body: str, target_key: str, payload: str) -> tuple[str, bool]:
    """
    Replace a single key in a JSON body with *payload*.
    Returns (modified_body, is_json).
    For __raw__ or non-JSON, replaces the entire body.
    """
    if target_key == "__raw__":
        return payload, False

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return payload, False

    if not isinstance(data, dict):
        return payload, False

    # Handle dot-notation for nested keys: "user.name" → data["user"]["name"]
    # If the payload is valid JSON (object/array), inject it as a parsed
    # value so {"$ne": null} becomes an actual object, not a string.
    try:
        parsed_payload = json.loads(payload)
    except (json.JSONDecodeError, TypeError, ValueError):
        parsed_payload = payload
    _set_nested(data, target_key, parsed_payload)
    return json.dumps(data), True


def _set_nested(obj: dict, dotpath: str, value) -> None:
    """Set a value in a nested dict using dot-notation path."""
    parts = dotpath.split(".")
    current = obj
    for part in parts[:-1]:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return  # path doesn't exist — skip silently
    if isinstance(current, dict):
        current[parts[-1]] = value
