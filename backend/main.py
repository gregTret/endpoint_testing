import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import QUEUE_POLL_INTERVAL, QUEUE_POLL_ERROR_DELAY
from proxy.proxy_manager import ProxyManager
from crawler.spider import Spider
from api.routes import router, set_spider, get_active_workspace
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
spider = Spider()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start proxy + queue poller on boot, tear down on shutdown."""
    await init_db()
    log.info("database initialised")

    try:
        proxy.start()
    except Exception as e:
        log.error("failed to start proxy: %s", e)

    set_spider(spider)
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
