import asyncio
import logging
import queue
import threading

from config import PROXY_HOST, PROXY_PORT, PROXY_QUEUE_MAX

log = logging.getLogger(__name__)


class ProxyManager:
    """Manages a mitmproxy instance running in a dedicated background thread."""

    def __init__(
        self,
        listen_host: str = PROXY_HOST,
        listen_port: int = PROXY_PORT,
        workspace_getter=None,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.log_queue: queue.Queue = queue.Queue(maxsize=PROXY_QUEUE_MAX)
        self._workspace_getter = workspace_getter or (lambda: "default")
        # Lazy import — InterceptState is lightweight, but kept here
        # so it's available immediately for routes to reference.
        from proxy.intercept_state import InterceptState
        self.intercept_state = InterceptState()
        self.master = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self.running = False

    def start(self) -> None:
        """Start mitmproxy in a background thread."""
        if self.running:
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="mitmproxy")
        self._thread.start()
        self.running = True
        log.info("mitmproxy starting on %s:%s", self.listen_host, self.listen_port)

    def _run(self) -> None:
        """Internal: run the mitmproxy event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._start_proxy())
        finally:
            self._loop.close()
            self.running = False

    async def _start_proxy(self) -> None:
        """Async init — DumpMaster requires a running event loop.
        Heavy mitmproxy imports happen here, inside the background thread."""
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster
        from proxy.mitm_addon import InterceptAddon

        opts = options.Options(
            listen_host=self.listen_host,
            listen_port=self.listen_port,
            ssl_insecure=True,
        )
        self.master = DumpMaster(opts, with_dumper=False)
        addon = InterceptAddon(
            self.log_queue,
            workspace_getter=self._workspace_getter,
            intercept_state=self.intercept_state,
        )
        self.master.addons.add(addon)

        try:
            await self.master.run()
        except Exception as e:
            log.error("mitmproxy stopped: %s", e)

    def stop(self) -> None:
        """Shutdown mitmproxy gracefully (thread-safe)."""
        if self.master and self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self._async_shutdown(), self._loop)
        self.running = False

    async def _async_shutdown(self) -> None:
        if self.master:
            self.master.shutdown()
