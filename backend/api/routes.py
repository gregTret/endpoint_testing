import logging

import httpx
from fastapi import APIRouter, BackgroundTasks
from fastapi.responses import JSONResponse

from config import REPLAY_TIMEOUT, CRAWL_DEFAULT_DEPTH, CRAWL_DEFAULT_MAX_PAGES, PROXY_HOST, PROXY_PORT
from models.scan_config import ScanConfig
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
)
from injectors.sql_injector import SQLInjector
from injectors.aql_injector import AQLInjector
from injectors.xss_injector import XSSInjector
from injectors.mongo_injector import MongoInjector
from injectors.jwt_injector import JWTInjector
from injectors.ssti_injector import SSTIInjector
from injectors.cmd_injector import CmdInjector
from injectors.path_traversal_injector import PathTraversalInjector
from injectors.quick_scan_injector import QuickScanInjector

log = logging.getLogger(__name__)
router = APIRouter()

# ── Injector registry (extensible) ────────────────────────────────
INJECTORS = {
    "sql": SQLInjector,
    "aql": AQLInjector,
    "xss": XSSInjector,
    "mongo": MongoInjector,
    "jwt": JWTInjector,
    "ssti": SSTIInjector,
    "cmd": CmdInjector,
    "traversal": PathTraversalInjector,
    "quick": QuickScanInjector,
}

# Spider reference — set by main.py at startup
_spider = None

# Active workspace — all data is scoped to this
_active_workspace: str = "default"

# Scan status tracking
_scan_status: dict = {"running": False, "error": None, "completed": 0, "total": 0, "scan_id": ""}

# Scan control: "run" | "pause" | "stop"
_scan_control: dict = {"signal": "run"}


def set_spider(spider) -> None:
    global _spider
    _spider = spider


def get_active_workspace() -> str:
    """Return the active workspace ID (used by mitm addon via main.py)."""
    return _active_workspace


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
    if not _spider:
        return JSONResponse(status_code=500, content={"error": "Spider not initialized"})
    if _spider.running:
        return JSONResponse(status_code=409, content={"error": "Crawl already in progress"})

    background_tasks.add_task(_spider.crawl, url, max_depth, max_pages)
    return {"status": "started", "target": url}


@router.get("/crawl/status")
async def crawl_status():
    if _spider:
        return _spider.status
    return {"running": False, "status": "not initialized"}


@router.post("/crawl/stop")
async def stop_crawl():
    if _spider:
        _spider.stop()
        return {"status": "stopping"}
    return {"status": "not running"}


@router.get("/crawl/results")
async def crawl_results():
    if _spider:
        return {
            "visited": list(_spider.visited),
            "discovered": list(_spider.discovered),
            "forms": _spider.forms,
        }
    return {"visited": [], "discovered": [], "forms": []}


# ──────────────────────────── Injection Scanning ────────────────────────────


@router.get("/injectors")
async def list_injectors():
    return [
        {"name": inst.name, "description": inst.description}
        for inst in [cls() for cls in INJECTORS.values()]
    ]


# ── Payload Config (per-workspace injector payloads) ────────────────


_PAYLOAD_EXCLUDED_TYPES = frozenset({"jwt", "quick"})


@router.get("/injectors/{injector_type}/payloads")
async def get_injector_payloads(injector_type: str):
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
    if injector_type in _PAYLOAD_EXCLUDED_TYPES:
        return JSONResponse(status_code=400, content={"error": f"Payload config not supported for '{injector_type}'"})
    if injector_type not in INJECTORS:
        return JSONResponse(status_code=404, content={"error": f"Unknown injector: {injector_type}"})

    payloads = body.get("payloads", [])
    await save_payload_config(_active_workspace, injector_type, payloads)
    return {"ok": True}


@router.delete("/injectors/{injector_type}/payloads")
async def reset_injector_payloads(injector_type: str):
    if injector_type in _PAYLOAD_EXCLUDED_TYPES:
        return JSONResponse(status_code=400, content={"error": f"Payload config not supported for '{injector_type}'"})
    if injector_type not in INJECTORS:
        return JSONResponse(status_code=404, content={"error": f"Unknown injector: {injector_type}"})

    await delete_payload_config(_active_workspace, injector_type)
    return {"ok": True}


@router.post("/scan")
async def start_scan(config: ScanConfig, background_tasks: BackgroundTasks):
    global _scan_status
    import uuid

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
        global _scan_status
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
    return {**_scan_status, "control": _scan_control["signal"]}


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
    entry = await get_request_log_by_id(log_id)
    if not entry:
        return JSONResponse(status_code=404, content={"error": "Log not found"})

    try:
        proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
        replay_headers = {
            k: v for k, v in entry["request_headers"].items()
            if k.lower() not in ("host", "content-length", "transfer-encoding")
        }
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
    url = data.get("url", "")
    method = data.get("method", "GET")
    headers = data.get("headers", {})
    body = data.get("body", "")

    if not url:
        return JSONResponse(status_code=400, content={"error": "URL is required"})

    clean_headers = {
        k: v for k, v in headers.items()
        if k.lower() not in ("host", "content-length", "transfer-encoding",
                              "connection", "accept-encoding")
    }
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
