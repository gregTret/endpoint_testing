import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import QUEUE_POLL_INTERVAL, QUEUE_POLL_ERROR_DELAY
from proxy.proxy_manager import ProxyManager
from api.routes import router, get_active_workspace, set_intercept_state
from api.websocket import ws_router, manager
from storage.db import init_db, save_request_log

# ── Logging ────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Shared instances ───────────────────────────────────────────────
proxy = ProxyManager(workspace_getter=get_active_workspace)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start proxy + queue poller on boot, tear down on shutdown."""
    # Start proxy thread first — mitmproxy imports happen in the background
    # thread while we init the database in parallel.
    try:
        proxy.start()
    except Exception as e:
        log.error("failed to start proxy: %s", e)

    await init_db()
    log.info("database initialised")

    # Spider is created lazily on first crawl request (defers playwright import)
    set_intercept_state(proxy.intercept_state)
    poll_task = asyncio.create_task(_poll_proxy_queue())
    yield
    proxy.stop()
    poll_task.cancel()
    try:
        await poll_task
    except asyncio.CancelledError:
        pass


async def _poll_proxy_queue() -> None:
    """Move intercepted traffic from mitmproxy's thread-safe queue
    into SQLite and broadcast over WebSocket."""
    while True:
        try:
            while not proxy.log_queue.empty():
                entry = proxy.log_queue.get_nowait()

                # Intercept notifications are not log entries — broadcast and skip DB
                if entry.get("_intercept_notification"):
                    pf = proxy.intercept_state.get_pending(entry["flow_id"])
                    if pf:
                        flow_data = proxy.intercept_state._serialize(pf)
                        await manager.broadcast({
                            "type": "intercepted_flow",
                            "data": flow_data,
                        })
                    continue

                await save_request_log(entry)
                await manager.broadcast({"type": "request_log", "data": entry})
            await asyncio.sleep(QUEUE_POLL_INTERVAL)
        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("queue poll error: %s", e)
            await asyncio.sleep(QUEUE_POLL_ERROR_DELAY)


app = FastAPI(title="Endpoint Security Tool", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")
app.include_router(ws_router)
