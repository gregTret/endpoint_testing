import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone

import httpx

from config import SCAN_DEFAULT_TIMEOUT, SCAN_RESPONSE_CAP
from models.scan_config import ScanResult, VulnerabilityReport

log = logging.getLogger(__name__)

# Headers that should never be used as injection targets
_SKIP_HEADERS = frozenset({"host", "content-type", "content-length", "transfer-encoding"})


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
        timeout: float = SCAN_DEFAULT_TIMEOUT,
    ) -> list[ScanResult]:
        """Run every payload × every injectable field and return results."""
        params = params or {}
        headers = headers or {}
        injection_points = injection_points or ["params"]
        results: list[ScanResult] = []

        baseline = await self._send_request(url, method, params, headers, body, timeout)
        payloads = self.generate_payloads(
            {"url": url, "method": method, "params": params},
        )

        # Build the list of (injection_point, param_name) targets so
        # we test *every* param/header — not just the first one.
        targets = _build_targets(injection_points, params, headers)

        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            for payload in payloads:
                for point, key in targets:
                    result = await self._test_single(
                        client, url, method, params, headers, body,
                        payload, point, key, baseline,
                    )
                    results.append(result)

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
        mod_headers = dict(headers)
        mod_body = body

        if injection_point == "params" and target_key in mod_params:
            mod_params[target_key] = payload
        elif injection_point == "headers" and target_key in mod_headers:
            mod_headers[target_key] = payload
        elif injection_point == "body":
            mod_body = payload

        start = time.time()
        try:
            if method.upper() == "GET":
                resp = await client.get(url, params=mod_params, headers=mod_headers)
            else:
                resp = await client.request(
                    method, url,
                    params=mod_params,
                    headers=mod_headers,
                    content=mod_body,
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
                is_vulnerable=False,
                confidence="low",
                details=f"Request failed: {e}",
            )

    async def _send_request(
        self, url: str, method: str, params: dict,
        headers: dict, body: str, timeout: float,
    ) -> dict:
        """Fire a baseline (unmodified) request."""
        start = time.time()
        try:
            async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
                if method.upper() == "GET":
                    resp = await client.get(url, params=params, headers=headers)
                else:
                    resp = await client.request(
                        method, url, params=params, headers=headers, content=body,
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
) -> list[tuple[str, str]]:
    """
    Expand injection points into (point, key) pairs so every
    param and every injectable header gets tested individually.
    """
    targets: list[tuple[str, str]] = []
    for point in injection_points:
        if point == "params":
            if params:
                targets.extend(("params", k) for k in params)
            else:
                # No params — still send payloads as a single query param
                targets.append(("params", "q"))
        elif point == "headers":
            for k in headers:
                if k.lower() not in _SKIP_HEADERS:
                    targets.append(("headers", k))
        elif point == "body":
            targets.append(("body", "body"))
    return targets or [("params", "q")]
