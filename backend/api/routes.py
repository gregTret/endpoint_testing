import logging

import httpx
from fastapi import APIRouter, BackgroundTasks
from fastapi.responses import JSONResponse

from config import REPLAY_TIMEOUT, CRAWL_DEFAULT_DEPTH, CRAWL_DEFAULT_MAX_PAGES
from models.scan_config import ScanConfig
from storage.db import (
    get_request_logs,
    get_request_log_by_id,
    clear_request_logs,
    save_scan_result,
    get_scan_results,
    export_session,
    save_credential,
    get_credentials,
    update_credential,
    delete_credential,
)
from injectors.sql_injector import SQLInjector
from injectors.aql_injector import AQLInjector
from injectors.xss_injector import XSSInjector
from injectors.mongo_injector import MongoInjector

log = logging.getLogger(__name__)
router = APIRouter()

# ── Injector registry (extensible) ────────────────────────────────
INJECTORS = {
    "sql": SQLInjector,
    "aql": AQLInjector,
    "xss": XSSInjector,
    "mongo": MongoInjector,
}

# Spider reference — set by main.py at startup
_spider = None

# Scan status tracking
_scan_status: dict = {"running": False, "error": None, "completed": 0, "total": 0, "scan_id": ""}


def set_spider(spider) -> None:
    global _spider
    _spider = spider


# ──────────────────────────── Request Logs ────────────────────────────


@router.get("/logs")
async def list_logs(
    session_id: str = "default",
    limit: int = 500,
    method: str = None,
    host: str = None,
    status: int = None,
    search: str = None,
):
    return await get_request_logs(
        session_id=session_id,
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
async def delete_logs(session_id: str = "default"):
    await clear_request_logs(session_id)
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

    injector = injector_cls()
    points = config.injection_points or ["params"]
    scan_id = uuid.uuid4().hex[:12]
    _scan_status = {
        "running": True,
        "error": None,
        "completed": 0,
        "total": 0,
        "scan_id": scan_id,
    }

    async def on_result(result, idx, total):
        """Called after each individual test — saves result and updates progress."""
        _scan_status["total"] = total
        _scan_status["completed"] = idx
        d = result.model_dump()
        d["session_id"] = scan_id
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
                target_keys=config.target_keys or None,
                timeout=config.timeout,
                on_result=on_result,
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
    return _scan_status


@router.get("/scan/results")
async def scan_results(session_id: str = "default", limit: int = 200):
    return await get_scan_results(session_id, limit)


# ──────────────────────────── Session / Export ────────────────────────────


@router.post("/session/export")
async def export_session_data(session_id: str = "default"):
    return await export_session(session_id)


# ──────────────────────────── Replay ────────────────────────────


@router.post("/replay/{log_id}")
async def replay_request(log_id: int):
    """Re-send a previously captured request."""
    entry = await get_request_log_by_id(log_id)
    if not entry:
        return JSONResponse(status_code=404, content={"error": "Log not found"})

    try:
        async with httpx.AsyncClient(verify=False, timeout=REPLAY_TIMEOUT) as client:
            resp = await client.request(
                method=entry["method"],
                url=entry["url"],
                headers={
                    k: v for k, v in entry["request_headers"].items()
                    if k.lower() not in ("host", "content-length", "transfer-encoding")
                },
                content=entry["request_body"] or None,
            )
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:50000],
            }
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": str(e)})


# ──────────────────────────── Credentials ────────────────────────────


@router.get("/credentials")
async def list_credentials(site: str = None):
    return await get_credentials(site_filter=site)


@router.post("/credentials")
async def create_credential(cred: dict):
    cred_id = await save_credential(cred)
    return {"id": cred_id, "status": "saved"}


@router.put("/credentials/{cred_id}")
async def edit_credential(cred_id: int, cred: dict):
    await update_credential(cred_id, cred)
    return {"status": "updated"}


@router.delete("/credentials/{cred_id}")
async def remove_credential(cred_id: int):
    await delete_credential(cred_id)
    return {"status": "deleted"}
