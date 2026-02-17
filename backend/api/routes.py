import asyncio
import json
import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks
from fastapi.responses import JSONResponse

from config import REPLAY_TIMEOUT, CRAWL_DEFAULT_DEPTH, CRAWL_DEFAULT_MAX_PAGES, PROXY_HOST, PROXY_PORT
from config import OOB_DEFAULT_URL, DEFAULT_HEADERS
from storage.db import (
    get_request_logs,
    get_request_log_by_id,
    clear_request_logs,
    save_scan_result,
    get_scan_results,
    get_scan_results_by_workspace,
    delete_scan_history_by_workspace,
    save_sitemap_url,
    save_sitemap_urls_bulk,
    get_sitemap_urls,
    delete_sitemap_url,
    delete_sitemap_urls_by_prefix,
    save_repeater_entry,
    get_repeater_history,
    delete_repeater_history,
    delete_repeater_entry,
    export_session,
    save_credential,
    get_credentials,
    update_credential,
    delete_credential,
    create_workspace,
    list_workspaces,
    delete_workspace,
    update_workspace_opened,
    rename_workspace,
    get_payload_config,
    save_payload_config,
    delete_payload_config,
    get_workspace_setting,
    set_workspace_setting,
    get_oob_results_by_workspace,
    delete_oob_results_by_workspace,
)

from api.claude_analysis import router as ai_router
from api.auto_scan import router as auto_scan_router

log = logging.getLogger(__name__)
router = APIRouter()
router.include_router(ai_router)
router.include_router(auto_scan_router)

# ── Injector registry (lazy-loaded for fast startup) ──────────────
_injectors_loaded = False
INJECTORS = {}


def _load_injectors():
    global _injectors_loaded, INJECTORS
    if _injectors_loaded:
        return
    from injectors.sql_injector import SQLInjector
    from injectors.aql_injector import AQLInjector
    from injectors.xss_injector import XSSInjector
    from injectors.mongo_injector import MongoInjector
    from injectors.jwt_injector import JWTInjector
    from injectors.ssti_injector import SSTIInjector
    from injectors.cmd_injector import CmdInjector
    from injectors.path_traversal_injector import PathTraversalInjector
    from injectors.quick_scan_injector import QuickScanInjector
    from injectors.oob_injector import OOBInjector
    INJECTORS.update({
        "sql": SQLInjector,
        "aql": AQLInjector,
        "xss": XSSInjector,
        "mongo": MongoInjector,
        "jwt": JWTInjector,
        "ssti": SSTIInjector,
        "cmd": CmdInjector,
        "traversal": PathTraversalInjector,
        "quick": QuickScanInjector,
        "oob": OOBInjector,
    })
    _injectors_loaded = True

# Spider reference — created lazily on first crawl request
_spider = None

# Active workspace — all data is scoped to this
_active_workspace: str = "default"

# Scan status tracking
_scan_status: dict = {"running": False, "error": None, "completed": 0, "total": 0, "scan_id": ""}

# Scan control: "run" | "pause" | "stop"
_scan_control: dict = {"signal": "run"}

# OOB post-scan recheck state
_oob_recheck_status: dict = {"active": False, "ends_at": 0, "scan_id": "", "found": 0}

# OOB scan registry — accumulates scan contexts across OOB scans (keyed by workspace_id)
_oob_scan_registry: dict[str, list[dict]] = {}


def _get_spider():
    """Lazy-init the Spider on first use (defers playwright import)."""
    global _spider
    if _spider is None:
        from crawler.spider import Spider
        _spider = Spider()
    return _spider


def get_active_workspace() -> str:
    """Return the active workspace ID (used by mitm addon via main.py)."""
    return _active_workspace


# ──────────────────────────── Health ────────────────────────────────


@router.get("/health")
async def health():
    return {"status": "ok"}


# ──────────────────────────── Workspaces ────────────────────────────


@router.get("/workspaces")
async def workspaces_list():
    return await list_workspaces()


@router.post("/workspaces")
async def workspaces_create(data: dict):
    import uuid
    name = (data.get("name") or "").strip()
    if not name:
        return JSONResponse(status_code=400, content={"error": "Workspace name is required"})
    ws_id = uuid.uuid4().hex[:8]
    ws = await create_workspace(ws_id, name)
    return ws


# Static paths BEFORE parameterised paths to avoid FastAPI matching "active" as {ws_id}
@router.post("/workspaces/active")
async def workspaces_set_active(data: dict):
    global _active_workspace
    ws_id = data.get("id", "default")
    _active_workspace = ws_id
    await update_workspace_opened(ws_id)
    log.info("active workspace set to %s", ws_id)
    return {"active": ws_id}


@router.get("/workspaces/active")
async def workspaces_get_active():
    return {"active": _active_workspace}


@router.delete("/workspaces/{ws_id}")
async def workspaces_delete(ws_id: str):
    await delete_workspace(ws_id)
    return {"status": "deleted"}


@router.put("/workspaces/{ws_id}")
async def workspaces_rename(ws_id: str, data: dict):
    await rename_workspace(ws_id, data.get("name", ""))
    return {"status": "renamed"}


# ──────────────────────────── Request Logs ────────────────────────────


@router.get("/logs")
async def list_logs(
    session_id: str = None,
    limit: int = 500,
    method: str = None,
    host: str = None,
    status: int = None,
    search: str = None,
):
    sid = session_id or _active_workspace
    return await get_request_logs(
        session_id=sid,
        limit=limit,
        method_filter=method,
        host_filter=host,
        status_filter=status,
        search=search,
    )


@router.get("/logs/{log_id}")
async def get_log(log_id: int):
    entry = await get_request_log_by_id(log_id)
    if not entry:
        return JSONResponse(status_code=404, content={"error": "Log not found"})
    return entry


@router.delete("/logs")
async def delete_logs(session_id: str = None):
    await clear_request_logs(session_id or _active_workspace)
    return {"status": "cleared"}


# ──────────────────────────── Crawling ────────────────────────────


@router.post("/crawl")
async def start_crawl(
    url: str,
    max_depth: int = CRAWL_DEFAULT_DEPTH,
    max_pages: int = CRAWL_DEFAULT_MAX_PAGES,
    background_tasks: BackgroundTasks = None,
):
    spider = _get_spider()
    if spider.running:
        return JSONResponse(status_code=409, content={"error": "Crawl already in progress"})

    background_tasks.add_task(spider.crawl, url, max_depth, max_pages)
    return {"status": "started", "target": url}


@router.get("/crawl/status")
async def crawl_status():
    spider = _get_spider()
    return spider.status


@router.post("/crawl/stop")
async def stop_crawl():
    spider = _get_spider()
    spider.stop()
    return {"status": "stopping"}


@router.get("/crawl/results")
async def crawl_results():
    spider = _get_spider()
    return {
        "visited": list(spider.visited),
        "discovered": list(spider.discovered),
        "forms": spider.forms,
    }


# ──────────────────────────── Injection Scanning ────────────────────────────


@router.get("/injectors")
async def list_injectors():
    _load_injectors()
    return [
        {"name": inst.name, "description": inst.description}
        for inst in [cls() for cls in INJECTORS.values()]
    ]


# ── Payload Config (per-workspace injector payloads) ────────────────


_PAYLOAD_EXCLUDED_TYPES = frozenset({"jwt", "quick", "oob"})


@router.get("/injectors/{injector_type}/payloads")
async def get_injector_payloads(injector_type: str):
    _load_injectors()
    if injector_type in _PAYLOAD_EXCLUDED_TYPES:
        return JSONResponse(status_code=400, content={"error": f"Payload config not supported for '{injector_type}'"})
    if injector_type not in INJECTORS:
        return JSONResponse(status_code=404, content={"error": f"Unknown injector: {injector_type}"})

    overrides = await get_payload_config(_active_workspace, injector_type)
    if overrides:
        return {
            "injector_type": injector_type,
            "is_customized": True,
            "payloads": overrides,
        }

    # Return defaults from the injector class
    injector = INJECTORS[injector_type]()
    context = {"url": "", "method": "GET", "params": {}}
    full = injector.generate_payloads(context)
    quick = injector.generate_quick_payloads(context)
    quick_set = set(quick)
    payloads = [
        {
            "payload_text": p,
            "enabled": True,
            "is_quick": p in quick_set,
            "sort_order": i,
        }
        for i, p in enumerate(full)
    ]
    return {
        "injector_type": injector_type,
        "is_customized": False,
        "payloads": payloads,
    }


@router.put("/injectors/{injector_type}/payloads")
async def put_injector_payloads(injector_type: str, body: dict):
    _load_injectors()
    if injector_type in _PAYLOAD_EXCLUDED_TYPES:
        return JSONResponse(status_code=400, content={"error": f"Payload config not supported for '{injector_type}'"})
    if injector_type not in INJECTORS:
        return JSONResponse(status_code=404, content={"error": f"Unknown injector: {injector_type}"})

    payloads = body.get("payloads", [])
    await save_payload_config(_active_workspace, injector_type, payloads)
    return {"ok": True}


@router.delete("/injectors/{injector_type}/payloads")
async def reset_injector_payloads(injector_type: str):
    _load_injectors()
    if injector_type in _PAYLOAD_EXCLUDED_TYPES:
        return JSONResponse(status_code=400, content={"error": f"Payload config not supported for '{injector_type}'"})
    if injector_type not in INJECTORS:
        return JSONResponse(status_code=404, content={"error": f"Unknown injector: {injector_type}"})

    await delete_payload_config(_active_workspace, injector_type)
    return {"ok": True}


async def _oob_recheck_loop(scan_id: str, recheck_info: dict, workspace_id: str):
    """Poll the OOB server for delayed callbacks after the initial scan ends."""
    import httpx

    global _oob_recheck_status
    oob_base_url = recheck_info["oob_base_url"]
    scan_key = recheck_info["scan_key"]
    token_map = recheck_info["token_map"]
    token_target_map = recheck_info["token_target_map"]
    url = recheck_info["url"]
    seen_tokens = set(recheck_info["seen_tokens"])
    start_time = recheck_info["start_time"]

    try:
        for _ in range(5):
            if not _oob_recheck_status["active"]:
                break
            await asyncio.sleep(60)
            if not _oob_recheck_status["active"]:
                break

            try:
                async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                    resp = await client.get(
                        f"{oob_base_url}/api/callbacks/{scan_key}",
                        params={"since": start_time},
                    )
                    if resp.status_code != 200:
                        continue
                    callbacks = resp.json()
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

                result = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "target_url": url,
                    "injector_type": f"oob:{sub_type}",
                    "payload": payload_str,
                    "injection_point": inj_point,
                    "original_param": inj_key,
                    "response_code": 0,
                    "is_vulnerable": True,
                    "confidence": "high",
                    "details": (
                        f"OOB callback received (delayed)! Type: {sub_type} | "
                        f"Source IP: {source_ip} | Callback at: {cb_time}"
                    ),
                    "session_id": scan_id,
                    "workspace_id": workspace_id,
                }
                await save_scan_result(result)
                _oob_recheck_status["found"] += 1
                log.info("OOB recheck found delayed callback: %s token=%s", sub_type, cb_token)
    finally:
        _oob_recheck_status["active"] = False
        log.info("OOB recheck loop finished for scan %s (found %d)", scan_id, _oob_recheck_status["found"])


@router.post("/scan")
async def start_scan(config: dict, background_tasks: BackgroundTasks):
    from models.scan_config import ScanConfig
    config = ScanConfig(**config)

    _load_injectors()
    global _scan_status, _oob_recheck_status
    import uuid

    # Cancel any active OOB recheck from a previous scan
    _oob_recheck_status["active"] = False

    injector_cls = INJECTORS.get(config.injector_type)
    if not injector_cls:
        return JSONResponse(
            status_code=400,
            content={
                "error": f"Unknown injector: {config.injector_type}. "
                f"Available: {list(INJECTORS.keys())}"
            },
        )

    if config.injector_type == "quick":
        injector = injector_cls(injector_registry=INJECTORS, workspace_id=_active_workspace)
    elif config.injector_type == "oob":
        oob_url = await get_workspace_setting(_active_workspace, "oob_server_url") or OOB_DEFAULT_URL
        raw_types = await get_workspace_setting(_active_workspace, "oob_enabled_types")
        enabled_types = json.loads(raw_types) if raw_types else None
        injector = injector_cls(oob_base_url=oob_url, enabled_types=enabled_types)
    else:
        injector = injector_cls()

    # Apply per-workspace payload overrides
    if config.injector_type not in _PAYLOAD_EXCLUDED_TYPES:
        overrides = await get_payload_config(_active_workspace, config.injector_type)
        if overrides:
            injector._payload_override = [r["payload_text"] for r in overrides if r["enabled"]]

    points = config.injection_points or ["params"]
    scan_id = uuid.uuid4().hex[:12]
    _scan_status = {
        "running": True,
        "error": None,
        "completed": 0,
        "total": 0,
        "scan_id": scan_id,
    }
    _scan_control["signal"] = "run"

    async def on_result(result, idx, total):
        """Called after each individual test — saves result and updates progress."""
        _scan_status["total"] = total
        _scan_status["completed"] = idx
        d = result.model_dump()
        d["session_id"] = scan_id
        d["workspace_id"] = _active_workspace
        await save_scan_result(d)

    async def run_scan():
        global _scan_status, _oob_recheck_status
        try:
            log.info("scan %s started: %s against %s", scan_id, config.injector_type, config.target_url)
            results = await injector.test_endpoint(
                url=config.target_url,
                method=config.method,
                params=config.params,
                headers=config.headers,
                body=config.body,
                injection_points=points,
                target_keys=config.target_keys if config.target_keys is not None else None,
                timeout=config.timeout,
                on_result=on_result,
                control=_scan_control,
            )
            log.info("scan %s completed: %d results", scan_id, len(results))
            _scan_status["running"] = False

            # Register OOB scan context for manual recheck + spawn auto-recheck loop
            recheck_info = getattr(injector, "_recheck_info", None)
            if recheck_info:
                ws = _active_workspace
                if ws not in _oob_scan_registry:
                    _oob_scan_registry[ws] = []
                _oob_scan_registry[ws].append({**recheck_info, "scan_id": scan_id})
                log.info("OOB scan registered: scan_key=%s (%d total for workspace %s)",
                         recheck_info["scan_key"], len(_oob_scan_registry[ws]), ws)

                _oob_recheck_status = {
                    "active": True,
                    "ends_at": time.time() + 5 * 60,
                    "scan_id": scan_id,
                    "found": 0,
                }
                asyncio.create_task(_oob_recheck_loop(scan_id, recheck_info, ws))
                log.info("OOB recheck loop started for scan %s", scan_id)
        except Exception as e:
            log.error("scan %s failed: %s", scan_id, e, exc_info=True)
            _scan_status["running"] = False
            _scan_status["error"] = str(e)

    background_tasks.add_task(run_scan)
    return {
        "status": "scan_started",
        "injector": config.injector_type,
        "target": config.target_url,
        "scan_id": scan_id,
    }


@router.get("/scan/status")
async def scan_status():
    remaining = max(0, _oob_recheck_status["ends_at"] - time.time()) if _oob_recheck_status["active"] else 0
    return {
        **_scan_status,
        "control": _scan_control["signal"],
        "oob_recheck": _oob_recheck_status["active"],
        "oob_recheck_remaining": round(remaining),
        "oob_recheck_found": _oob_recheck_status["found"],
    }


@router.post("/scan/pause")
async def scan_pause():
    if _scan_control["signal"] == "pause":
        _scan_control["signal"] = "run"
        return {"signal": "run"}
    _scan_control["signal"] = "pause"
    return {"signal": "pause"}


@router.post("/scan/stop")
async def scan_stop():
    _scan_control["signal"] = "stop"
    return {"signal": "stop"}


@router.get("/scan/results")
async def scan_results(session_id: str = "default", limit: int = 200):
    return await get_scan_results(session_id, limit)


@router.get("/scan/history")
async def scan_history(limit: int = 500):
    """Return all scan results for the active workspace (persistent history)."""
    return await get_scan_results_by_workspace(_active_workspace, limit)


@router.delete("/scan/history")
async def clear_scan_history():
    """Delete all scan results for the active workspace."""
    await delete_scan_history_by_workspace(_active_workspace)
    return {"ok": True}


# ──────────────────────────── Site Map ────────────────────────────────────


@router.get("/sitemap")
async def sitemap_list():
    """Return all persisted site map URLs for the active workspace."""
    return await get_sitemap_urls(_active_workspace)


@router.post("/sitemap")
async def sitemap_add(body: dict):
    """Add one or more URLs to the site map."""
    urls = body.get("urls", [])
    url = body.get("url")
    if url:
        urls.append(url)
    if urls:
        await save_sitemap_urls_bulk(urls, _active_workspace)
    return {"ok": True, "count": len(urls)}


@router.delete("/sitemap")
async def sitemap_remove(url: str = "", prefix: str = ""):
    """Remove a single URL or all URLs matching a prefix."""
    if prefix:
        await delete_sitemap_urls_by_prefix(prefix, _active_workspace)
    elif url:
        await delete_sitemap_url(url, _active_workspace)
    return {"ok": True}


# ──────────────────────────── Repeater History ───────────────────────────


@router.get("/repeater/history")
async def repeater_history_list(limit: int = 50):
    return await get_repeater_history(_active_workspace, limit)


@router.post("/repeater/history")
async def repeater_history_add(entry: dict):
    row_id = await save_repeater_entry(entry, _active_workspace)
    return {"ok": True, "id": row_id}


@router.delete("/repeater/history")
async def repeater_history_clear(entry_id: int = 0):
    if entry_id:
        await delete_repeater_entry(entry_id)
    else:
        await delete_repeater_history(_active_workspace)
    return {"ok": True}


# ──────────────────────────── Session / Export ────────────────────────────


@router.post("/session/export")
async def export_session_data(session_id: str = None):
    return await export_session(session_id or _active_workspace)


# ──────────────────────────── Replay ────────────────────────────


@router.post("/replay/{log_id}")
async def replay_request(log_id: int):
    """Re-send a previously captured request."""
    import httpx

    entry = await get_request_log_by_id(log_id)
    if not entry:
        return JSONResponse(status_code=404, content={"error": "Log not found"})

    try:
        proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
        defaults = await get_default_headers()
        replay_headers = dict(defaults)
        replay_headers.update({
            k: v for k, v in entry["request_headers"].items()
            if k.lower() not in ("host", "content-length", "transfer-encoding")
        })
        replay_headers["x-ept-scan"] = "1"
        async with httpx.AsyncClient(verify=False, timeout=REPLAY_TIMEOUT, proxy=proxy_url) as client:
            resp = await client.request(
                method=entry["method"],
                url=entry["url"],
                headers=replay_headers,
                content=entry["request_body"] or None,
            )
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:50000],
            }
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": str(e)})


@router.post("/send")
async def send_single_request(data: dict):
    """Send a single request exactly as configured in the injector form."""
    import httpx

    url = data.get("url", "")
    method = data.get("method", "GET")
    headers = data.get("headers", {})
    body = data.get("body", "")

    if not url:
        return JSONResponse(status_code=400, content={"error": "URL is required"})

    defaults = await get_default_headers()
    clean_headers = dict(defaults)
    clean_headers.update({
        k: v for k, v in headers.items()
        if k.lower() not in ("host", "content-length", "transfer-encoding",
                              "connection", "accept-encoding")
    })
    clean_headers["x-ept-scan"] = "1"

    try:
        proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
        async with httpx.AsyncClient(verify=False, timeout=REPLAY_TIMEOUT, proxy=proxy_url) as client:
            if method.upper() == "GET":
                resp = await client.get(url, headers=clean_headers)
            else:
                resp = await client.request(
                    method, url, headers=clean_headers,
                    content=body.encode("utf-8") if body else b"",
                )
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:50000],
                "request_method": method,
                "request_url": url,
                "request_headers": clean_headers,
                "request_body": body,
            }
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": str(e)})


# ──────────────────────────── Credentials ────────────────────────────


@router.get("/credentials")
async def list_credentials(site: str = None):
    return await get_credentials(workspace_id=_active_workspace, site_filter=site)


@router.post("/credentials")
async def create_credential(cred: dict):
    cred_id = await save_credential(cred, workspace_id=_active_workspace)
    return {"id": cred_id, "status": "saved"}


@router.put("/credentials/{cred_id}")
async def edit_credential(cred_id: int, cred: dict):
    await update_credential(cred_id, cred)
    return {"status": "updated"}


@router.delete("/credentials/{cred_id}")
async def remove_credential(cred_id: int):
    await delete_credential(cred_id)
    return {"status": "deleted"}


# ──────────────────────────── Intercept ────────────────────────────

_intercept_state = None


def set_intercept_state(state):
    global _intercept_state
    _intercept_state = state


def get_intercept_state():
    return _intercept_state


@router.get("/intercept/status")
async def intercept_status():
    if not _intercept_state:
        return {"enabled": False, "pending_count": 0, "auto_drop_options": True}
    return {
        "enabled": _intercept_state.enabled,
        "pending_count": len(_intercept_state.get_all_pending()),
        "auto_drop_options": _intercept_state.auto_drop_options,
    }


@router.post("/intercept/toggle")
async def intercept_toggle(data: dict):
    if not _intercept_state:
        return JSONResponse(status_code=500, content={"error": "Intercept not available"})
    enabled = data.get("enabled", not _intercept_state.enabled)
    _intercept_state.enabled = enabled
    return {"enabled": _intercept_state.enabled}


@router.get("/intercept/pending")
async def intercept_pending():
    if not _intercept_state:
        return []
    return _intercept_state.get_all_pending()


@router.post("/intercept/decide")
async def intercept_decide(data: dict):
    if not _intercept_state:
        return JSONResponse(status_code=500, content={"error": "Intercept not available"})
    flow_id = data.get("flow_id")
    decision = data.get("decision", "forward")
    modifications = data.get("modifications")
    if not flow_id:
        return JSONResponse(status_code=400, content={"error": "flow_id required"})
    ok = _intercept_state.resolve(flow_id, decision, modifications)
    if not ok:
        return JSONResponse(status_code=404, content={"error": "Flow not found or already resolved"})
    return {"ok": True}


# ──────────────────────────── Proxy Settings ──────────────────────────


@router.get("/settings/proxy")
async def get_proxy_settings():
    if not _intercept_state:
        return {
            "auto_drop_options": True,
            "intercept_requests": True,
            "intercept_responses": True,
        }
    return {
        "auto_drop_options": _intercept_state.auto_drop_options,
        "intercept_requests": _intercept_state.intercept_requests,
        "intercept_responses": _intercept_state.intercept_responses,
    }


@router.post("/settings/proxy")
async def update_proxy_settings(data: dict):
    if not _intercept_state:
        return JSONResponse(status_code=500, content={"error": "Proxy not available"})
    if "auto_drop_options" in data:
        _intercept_state.auto_drop_options = bool(data["auto_drop_options"])
    if "intercept_requests" in data:
        _intercept_state.intercept_requests = bool(data["intercept_requests"])
    if "intercept_responses" in data:
        _intercept_state.intercept_responses = bool(data["intercept_responses"])
    return {
        "auto_drop_options": _intercept_state.auto_drop_options,
        "intercept_requests": _intercept_state.intercept_requests,
        "intercept_responses": _intercept_state.intercept_responses,
    }


# ──────────────────────────── OOB Settings ──────────────────────────


@router.get("/settings/oob")
async def get_oob_settings():
    url = await get_workspace_setting(_active_workspace, "oob_server_url") or OOB_DEFAULT_URL
    raw_types = await get_workspace_setting(_active_workspace, "oob_enabled_types")
    enabled_types = json.loads(raw_types) if raw_types else ["cmd", "ssrf", "xxe", "ssti", "sqli"]
    return {"oob_server_url": url, "oob_enabled_types": enabled_types}


@router.post("/settings/oob")
async def update_oob_settings(data: dict):
    url = (data.get("oob_server_url") or "").strip().rstrip("/")
    if not url:
        return JSONResponse(status_code=400, content={"error": "URL is required"})
    await set_workspace_setting(_active_workspace, "oob_server_url", url)
    if "oob_enabled_types" in data:
        await set_workspace_setting(_active_workspace, "oob_enabled_types", json.dumps(data["oob_enabled_types"]))
    raw_types = await get_workspace_setting(_active_workspace, "oob_enabled_types")
    enabled_types = json.loads(raw_types) if raw_types else ["cmd", "ssrf", "xxe", "ssti", "sqli"]
    return {"oob_server_url": url, "oob_enabled_types": enabled_types}


@router.post("/settings/oob/test")
async def test_oob_connection(data: dict = None):
    """Proxied health check — backend calls OOB server to avoid CSP issues."""
    import httpx
    url = (data or {}).get("oob_server_url") or await get_workspace_setting(_active_workspace, "oob_server_url") or OOB_DEFAULT_URL
    url = url.rstrip("/")
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            resp = await client.get(f"{url}/api/health")
            if resp.status_code == 200:
                return {"ok": True, "status": resp.json()}
            return JSONResponse(status_code=502, content={"ok": False, "error": f"Server returned {resp.status_code}"})
    except Exception as e:
        return JSONResponse(status_code=502, content={"ok": False, "error": str(e)})


# ──────────────────────────── Default Headers Settings ──────────────────


async def get_default_headers() -> dict:
    """Return merged default headers: config defaults + workspace overrides.

    Used by injectors and repeater to set realistic headers on outgoing
    requests so they don't leak tool fingerprints (e.g. python-httpx UA).
    """
    raw = await get_workspace_setting(_active_workspace, "default_headers")
    if raw:
        try:
            return {**DEFAULT_HEADERS, **json.loads(raw)}
        except (json.JSONDecodeError, TypeError):
            pass
    return dict(DEFAULT_HEADERS)


@router.get("/settings/headers")
async def get_header_settings():
    headers = await get_default_headers()
    return {"headers": headers}


@router.post("/settings/headers")
async def update_header_settings(data: dict):
    headers = data.get("headers")
    if headers is None:
        # Reset to defaults
        await set_workspace_setting(_active_workspace, "default_headers", "")
        return {"headers": dict(DEFAULT_HEADERS)}
    if not isinstance(headers, dict):
        return JSONResponse(status_code=400, content={"error": "headers must be a JSON object"})
    await set_workspace_setting(_active_workspace, "default_headers", json.dumps(headers))
    return {"headers": headers}


# ──────────────────────────── OOB Tab Endpoints ──────────────────────────


@router.get("/oob/results")
async def oob_results(limit: int = 500):
    """Return OOB-only scan results for the active workspace."""
    return await get_oob_results_by_workspace(_active_workspace, limit)


@router.delete("/oob/results")
async def oob_clear_results():
    """Delete all OOB scan results for the active workspace."""
    await delete_oob_results_by_workspace(_active_workspace)
    return {"ok": True}


@router.delete("/oob/registry")
async def oob_clear_registry():
    """Clear the in-memory OOB scan registry for the active workspace."""
    _oob_scan_registry.pop(_active_workspace, None)
    return {"ok": True}


@router.get("/oob/status")
async def oob_status():
    """Return OOB registry info and recheck status."""
    entries = _oob_scan_registry.get(_active_workspace, [])
    remaining = max(0, _oob_recheck_status["ends_at"] - time.time()) if _oob_recheck_status["active"] else 0
    return {
        "registry_count": len(entries),
        "recheck_active": _oob_recheck_status["active"],
        "recheck_remaining": round(remaining),
        "recheck_found": _oob_recheck_status["found"],
    }


@router.post("/oob/check")
async def oob_manual_check():
    """Manually recheck ALL stored OOB scan keys for new callbacks."""
    import httpx

    entries = _oob_scan_registry.get(_active_workspace, [])
    if not entries:
        return {"checked": 0, "found": 0, "details": []}

    total_found = 0
    details = []

    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        for entry in entries:
            oob_base_url = entry["oob_base_url"]
            scan_key = entry["scan_key"]
            token_map = entry["token_map"]
            token_target_map = entry["token_target_map"]
            url = entry["url"]
            seen_tokens = entry["seen_tokens"]
            start_time = entry["start_time"]
            scan_id = entry["scan_id"]

            try:
                resp = await client.get(
                    f"{oob_base_url}/api/callbacks/{scan_key}",
                    params={"since": start_time},
                )
                if resp.status_code != 200:
                    continue
                callbacks = resp.json()
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

                result = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "target_url": url,
                    "injector_type": f"oob:{sub_type}",
                    "payload": payload_str,
                    "injection_point": inj_point,
                    "original_param": inj_key,
                    "response_code": 0,
                    "is_vulnerable": True,
                    "confidence": "high",
                    "details": (
                        f"OOB callback received (delayed)! Type: {sub_type} | "
                        f"Source IP: {source_ip} | Callback at: {cb_time}"
                    ),
                    "session_id": scan_id,
                    "workspace_id": _active_workspace,
                }
                await save_scan_result(result)
                total_found += 1
                details.append({
                    "scan_key": scan_key,
                    "sub_type": sub_type,
                    "token": cb_token,
                    "source_ip": source_ip,
                })
                log.info("OOB manual check found callback: %s token=%s", sub_type, cb_token)

    return {"checked": len(entries), "found": total_found, "details": details}
