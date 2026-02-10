"""
QuickScan Injector — runs a small set of critical payloads from every
registered injector type against the target endpoint.

Automatically includes any new injector added to the INJECTORS registry
in routes.py.  JWT is excluded (it requires a custom token-extraction flow).
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

import httpx

from config import SCAN_DEFAULT_TIMEOUT, SCAN_RESPONSE_CAP, PROXY_HOST, PROXY_PORT
from injectors.base import BaseInjector, _build_targets, _DROP_HEADERS, _SCAN_MARKER, _inject_into_body, _normalize_url_params
from models.scan_config import ScanResult, VulnerabilityReport
from storage.db import get_payload_config

log = logging.getLogger(__name__)

# Injector types that use a custom test_endpoint() and can't participate
# in the generic quick-payload loop.
_SKIP_TYPES = frozenset({"jwt", "quick", "oob"})


class QuickScanInjector(BaseInjector):
    """Composite scanner — pulls critical payloads from all injector types."""

    name = "quick"
    description = "Quick scan — tests a few critical payloads from every injector type"

    def __init__(self, injector_registry: dict | None = None, workspace_id: str | None = None) -> None:
        super().__init__()
        self._registry = injector_registry or {}
        self._workspace_id = workspace_id

    # ── Not used directly (test_endpoint is overridden) ──────────────

    def generate_payloads(self, context: dict) -> list[str]:
        return []

    def generate_quick_payloads(self, context: dict) -> list[str]:
        return []

    def analyze_response(self, baseline, test_response, payload):
        return VulnerabilityReport()

    # ── Main loop ────────────────────────────────────────────────────

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
        params = params or {}
        headers = headers or {}
        injection_points = injection_points or ["params"]
        ctrl = control or {"signal": "run"}

        # Merge any query params embedded in the URL into the params dict
        url, params = _normalize_url_params(url, params)

        # 1. Baseline request (shared across all sub-injectors)
        baseline = await self._send_request(url, method, params, headers, body, timeout)

        # 2. Build injection targets
        targets = _build_targets(injection_points, params, headers, body, target_keys)

        # 3. Collect (sub_injector_instance, payload) pairs
        work: list[tuple[BaseInjector, str]] = []
        context = {"url": url, "method": method, "params": params}

        for key, cls in self._registry.items():
            if key in _SKIP_TYPES:
                continue
            sub = cls()
            # Load per-injector payload config when workspace is set
            overrides = await get_payload_config(self._workspace_id, key) if self._workspace_id else []
            if overrides:
                quick_payloads = [r["payload_text"] for r in overrides if r["enabled"] and r["is_quick"]]
            else:
                quick_payloads = sub.generate_quick_payloads(context)
            for p in quick_payloads:
                work.append((sub, p))

        total = len(work) * len(targets)
        results: list[ScanResult] = []
        idx = 0

        proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
        async with httpx.AsyncClient(verify=False, timeout=timeout, proxy=proxy_url) as client:
            for sub_injector, payload in work:
                for point, key in targets:
                    # ── Control signals ──
                    while ctrl.get("signal") == "pause":
                        await asyncio.sleep(0.5)
                    if ctrl.get("signal") == "stop":
                        log.info("quickscan stopped at %d/%d", idx, total)
                        self.results.extend(results)
                        return results

                    result = await self._test_single_delegated(
                        client, sub_injector, url, method,
                        params, headers, body, payload, point, key, baseline,
                    )
                    results.append(result)
                    idx += 1
                    if on_result:
                        await on_result(result, idx, total)

        self.results.extend(results)
        return results

    # ── Helper: send one request and delegate analysis ───────────────

    async def _test_single_delegated(
        self,
        client: httpx.AsyncClient,
        sub_injector: BaseInjector,
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
        """Like base._test_single but uses *sub_injector*.analyze_response()."""
        mod_params = dict(params)
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
            mod_body, send_json = _inject_into_body(body, target_key, payload)

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
                resp = await client.request(
                    method, url,
                    params=mod_params,
                    headers=mod_headers,
                    content=mod_body.encode("utf-8") if mod_body else b"",
                )
            elapsed = round((time.time() - start) * 1000, 2)
            resp_body = resp.text[:SCAN_RESPONSE_CAP]

            report = sub_injector.analyze_response(
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
                injector_type=sub_injector.name,
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
            log.debug("quickscan request failed for payload %r: %s", payload, e)
            return ScanResult(
                timestamp=datetime.now(timezone.utc).isoformat(),
                target_url=url,
                injector_type=sub_injector.name,
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
