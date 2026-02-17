import logging

from playwright.async_api import async_playwright
from urllib.parse import urlparse

from config import PROXY_HOST, PROXY_PORT, CRAWL_PAGE_TIMEOUT, CRAWL_DEFAULT_DEPTH, CRAWL_DEFAULT_MAX_PAGES
from crawler.link_extractor import extract_links, extract_forms, filter_same_domain

log = logging.getLogger(__name__)


class Spider:
    """Playwright-based web spider that crawls a target site through the proxy."""

    def __init__(
        self,
        proxy_host: str = PROXY_HOST,
        proxy_port: int = PROXY_PORT,
    ) -> None:
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.visited: set[str] = set()
        self.discovered: set[str] = set()
        self.forms: list[dict] = []
        self.max_depth: int = CRAWL_DEFAULT_DEPTH
        self.max_pages: int = CRAWL_DEFAULT_MAX_PAGES
        self.running: bool = False
        self._status: str = "idle"
        self._pages_crawled: int = 0

    @property
    def status(self) -> dict:
        return {
            "running": self.running,
            "status": self._status,
            "pages_crawled": self._pages_crawled,
            "links_discovered": len(self.discovered),
            "forms_found": len(self.forms),
        }

    async def crawl(
        self,
        start_url: str,
        max_depth: int = CRAWL_DEFAULT_DEPTH,
        max_pages: int = CRAWL_DEFAULT_MAX_PAGES,
        extra_headers: dict | None = None,
    ) -> None:
        """Kick off a crawl from *start_url*.

        *extra_headers* — optional dict of HTTP headers (e.g. Authorization,
        Cookie) to send with every page request so the crawler can reach
        authenticated areas of the target site.
        """
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited.clear()
        self.discovered.clear()
        self.forms.clear()
        self._pages_crawled = 0
        self.running = True
        self._status = "starting"

        domain = urlparse(start_url).netloc
        log.info("crawl starting: %s (depth=%d, max=%d)", start_url, max_depth, max_pages)

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                proxy={"server": f"http://{self.proxy_host}:{self.proxy_port}"},
            )
            ctx = await browser.new_context(
                ignore_https_errors=True,
                extra_http_headers=extra_headers or {},
            )
            try:
                await self._crawl_page(ctx, start_url, domain, 0)
            except Exception as e:
                log.error("crawl error: %s", e)
                self._status = f"error: {e}"
            finally:
                await browser.close()
                self.running = False
                self._status = "complete"
                log.info("crawl complete: %d pages, %d links", self._pages_crawled, len(self.discovered))

    async def _crawl_page(self, ctx, url: str, domain: str, depth: int) -> None:
        if depth > self.max_depth:
            return
        if self._pages_crawled >= self.max_pages:
            return
        if url in self.visited:
            return
        if not self.running:
            return

        self.visited.add(url)
        self._status = f"crawling: {url}"
        self._pages_crawled += 1

        page = None
        try:
            page = await ctx.new_page()
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=CRAWL_PAGE_TIMEOUT)

            if resp and resp.ok:
                html = await page.content()
                links = extract_links(html, url)
                same = filter_same_domain(links, domain)
                self.discovered.update(same)
                self.forms.extend(extract_forms(html, url))

                for link in same:
                    if link not in self.visited and self._pages_crawled < self.max_pages:
                        await self._crawl_page(ctx, link, domain, depth + 1)
        except Exception as e:
            log.debug("error crawling %s: %s", url, e)
        finally:
            if page:
                await page.close()

    def stop(self) -> None:
        self.running = False
        self.max_pages = 0
