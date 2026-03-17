import asyncio
import json
import os
import time
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import List, Optional, Set
from urllib.parse import urljoin, urldefrag, urlparse, parse_qs

from playwright.async_api import async_playwright, BrowserContext, Page, TimeoutError as PlaywrightTimeoutError

UA = "MyHeadlessCrawler/0.1 (+https://example.com/contact)"


def normalize(url: str) -> str:
    return urldefrag(url)[0]


@dataclass
class CrawlConfig:
    seeds: List[str]
    concurrency: int = 3
    max_pages: int = 100
    same_origin_only: bool = True
    wait_until: str = "domcontentloaded"
    output_path: str = "results.jsonl"
    per_host_delay: float = 0.5
    headless: bool = True
    keep_fragments: bool = True
    verbose: bool = False
    page_task_timeout: float = 30.0


class JSONLWriter:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self._lock = asyncio.Lock()

    async def write(self, item: dict):
        line = json.dumps(item, ensure_ascii=False)
        async with self._lock:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._append_line, line)

    def _append_line(self, line: str):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


class BrowserCrawler:
    def __init__(self, cfg: CrawlConfig):
        self.cfg = cfg
        # Queue holds tuples of (url, depth) to mirror static crawler depth tracking
        self.queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        self.seen: Set[str] = set()
        self.writer = JSONLWriter(cfg.output_path)
        self._host_last_time = {}
        # Precompute allowed origins from seeds to enforce strict same-origin crawling
        self.allowed_origins = self._build_allowed_origins(cfg.seeds)
        if self.cfg.verbose:
            print(f"allowed_origins: {sorted(self.allowed_origins)}")

    def _build_allowed_origins(self, seeds: List[str]) -> Set[str]:
        allowed: Set[str] = set()
        for s in seeds:
            u = urlparse(s)
            scheme = u.scheme or "http"
            netloc = u.netloc
            if not netloc:
                continue
            # Extract host and port 
            host_port = netloc.split("@")[-1]  # strip potential userinfo
            if ":" in host_port:
                host, port = host_port.rsplit(":", 1)
                port_part = f":{port}"
            else:
                host = host_port
                port_part = ""
            variants = {host}
            # Add localhost aliases if applicable
            if host in {"localhost", "127.0.0.1", "::1"}:
                variants.update({"localhost", "127.0.0.1", "::1"})
            for h in variants:
                allowed.add(f"{scheme}://{h}{port_part}")
        return allowed

    async def run(self):
        for s in self.cfg.seeds:
            await self.queue.put((self._normalize(s), 0))

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.cfg.headless)
            context = await browser.new_context(user_agent=UA)
            # Set conservative navigation timeout to avoid indefinite waits
            try:
                await context.set_default_navigation_timeout(20000)
            except Exception:
                pass

            # Block any network requests outside allowed origins when same_origin_only is True
            if self.cfg.same_origin_only:
                async def guard_route(route, request):
                    try:
                        req_url = request.url
                        req_origin = f"{urlparse(req_url).scheme}://{urlparse(req_url).netloc}"
                        # Only block cross-origin top-level navigations
                        if request.is_navigation_request() and req_origin not in self.allowed_origins:
                            try:
                                await route.abort()
                            except Exception:
                                # If abort fails for any reason fall back to continue to avoid deadlocks
                                await route.continue_()
                            if self.cfg.verbose:
                                print(f"aborted cross-origin navigation: {req_url}")
                        else:
                            await route.continue_()
                    except Exception:
                        # attempt to continue to avoid hanging the request routing
                        try:
                            await route.continue_()
                        except Exception:
                            pass

                await context.route("**/*", guard_route)

            workers = [asyncio.create_task(self.worker(context)) for _ in range(self.cfg.concurrency)]
            await self.queue.join()
            for w in workers:
                w.cancel()
            await context.close()
            await browser.close()

    async def worker(self, context: BrowserContext):

        while True:
            try:
                url, depth = await asyncio.wait_for(self.queue.get(), timeout=3)
            except asyncio.TimeoutError:
                return
            # If already seen this URL or hit the page limit mark as done and skip.
            if url in self.seen or len(self.seen) >= self.cfg.max_pages:
                self.queue.task_done()
                continue
            self.seen.add(url)
            try:
                await asyncio.wait_for(self.handle_url(context, url, depth), timeout=self.cfg.page_task_timeout)
            except asyncio.TimeoutError:
                print(f"worker timeout processing {url} after {self.cfg.page_task_timeout}s")
            except Exception as e:
                print(f"worker error {url}: {e}")
            finally:
                self.queue.task_done()

    async def handle_url(self, context: BrowserContext, url: str, depth: int):
        await self._respect_per_host_delay(url)
        page = await context.new_page()
        page.set_default_timeout(20000)
        started = time.time()
        try:
            if self.cfg.verbose:
                print(f"navigating: {url} (wait_until={self.cfg.wait_until})")
            # Navigate with fallback
            resp = None
            try:
                resp = await page.goto(url, wait_until=self.cfg.wait_until)
            except PlaywrightTimeoutError:
                try:
                    if self.cfg.verbose:
                        print(f"goto timeout with wait_until={self.cfg.wait_until} for {url}, retrying with domcontentloaded")
                    resp = await page.goto(url, wait_until="domcontentloaded")
                except PlaywrightTimeoutError:
                    if self.cfg.verbose:
                        print(f"goto timeout with domcontentloaded for {url}; skipping")
                    return

            status = resp.status if resp else None
            if status and (status < 200 or status >= 400):
                if self.cfg.verbose:
                    print(f"non-2xx/3xx {status}: {url}")
                return

            # Enforce final URL origin remains within allowed origins if required
            final_url = page.url
            if self.cfg.same_origin_only:
                final_origin = f"{urlparse(final_url).scheme}://{urlparse(final_url).netloc}"
                if final_origin not in self.allowed_origins:
                    if self.cfg.verbose:
                        print(f"skip out-of-scope final origin: {final_origin} for {final_url}")
                    return



            # Discover links
            links = await page.eval_on_selector_all(
                "a[href]",
                "els => els.map(a => a.getAttribute('href')).filter(Boolean)",
            )
            out_links: list[str] = []
            for href in links:
                # Stop enqueuing if we've reached the page budget
                if len(self.seen) >= self.cfg.max_pages:
                    break
                nxt = self._normalize(urljoin(final_url, href))
                if nxt in self.seen:
                    continue
                if self.cfg.same_origin_only:
                    nxt_origin = f"{urlparse(nxt).scheme}://{urlparse(nxt).netloc}"
                    if nxt_origin not in self.allowed_origins:
                        continue
                out_links.append(nxt)
                await self.queue.put((nxt, depth + 1))
            if self.cfg.verbose:
                print(f"enqueued anchors from: {final_url}")

            # Extract dynamic forms from the live DOM
            raw_forms = await page.eval_on_selector_all(
                "form",
                """
                els => els.map(f => ({
                  method: (f.getAttribute('method') || 'GET').toUpperCase(),
                  action: (f.getAttribute('action') || ''),
                  inputs: Array.from(f.querySelectorAll('input[name]')).map(i => ({
                    name: i.getAttribute('name'),
                    type: (i.getAttribute('type') || 'text').toLowerCase(),
                    value: i.getAttribute('value')
                  })),
                  selects: Array.from(f.querySelectorAll('select[name]')).map(s => ({
                    name: s.getAttribute('name')
                  })),
                  textareas: Array.from(f.querySelectorAll('textarea[name]')).map(t => ({
                    name: t.getAttribute('name')
                  }))
                }))
                """,
            )
            forms: list[dict] = []
            try:
                for rf in raw_forms or []:
                    fields = []
                    for inp in rf.get("inputs", []) or []:
                        name = inp.get("name")
                        if not name:
                            continue
                        fields.append({
                            "name": name,
                            "type": (inp.get("type") or "text").lower(),
                            "value": inp.get("value")
                        })
                    for sel in rf.get("selects", []) or []:
                        name = sel.get("name")
                        if not name:
                            continue
                        fields.append({
                            "name": name,
                            "type": "select"
                        })
                    for ta in rf.get("textareas", []) or []:
                        name = ta.get("name")
                        if not name:
                            continue
                        fields.append({
                            "name": name,
                            "type": "textarea"
                        })
                    action_raw = rf.get("action") or ""
                    action_abs = urljoin(final_url, action_raw) if action_raw else final_url
                    forms.append({
                        "action": action_abs,
                        "method": (rf.get("method") or "GET").upper(),
                        "fields": fields,
                    })
            except Exception:
                # Be tolerant to DOM irregularities
                forms = []

            # Parse GET parameters from the final URL for schema parity
            try:
                from urllib.parse import urlparse as _uparse
                parsed_page = _uparse(final_url)
                get_params = parse_qs(parsed_page.query)
            except Exception:
                get_params = {}


            record = {
                "schema_version": 1,
                "source": "headless_crawler",
                "discovered_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "page": final_url,
                "depth": depth,
                "links": out_links,
                "get_params": get_params,
                "forms": forms,
                "mapped_to": final_url,
            }
            await self.writer.write(record)
            if self.cfg.verbose:
                print(f"saved schema record for: {final_url}")
        finally:
            # Ensure page gets closed promptly
            try:
                await asyncio.wait_for(page.close(), timeout=5)
            except Exception:
                pass

    async def _respect_per_host_delay(self, url: str):
        host = urlparse(url).netloc
        now = time.time()
        last = self._host_last_time.get(host, 0.0)
        delta = now - last
        if delta < self.cfg.per_host_delay:
            await asyncio.sleep(self.cfg.per_host_delay - delta)
        self._host_last_time[host] = time.time()

    async def _infinite_scroll(self, page: Page, steps: int, pause_s: float):
        for _ in range(steps):
            try:
                await page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
                await asyncio.sleep(pause_s)
            except Exception:
                break

    async def _click_repeated(self, page: Page, selector: str, times: int):
        clicks = 0
        while clicks < times:
            try:
                el = await page.query_selector(selector)
                if not el:
                    break
                await el.click()
                clicks += 1
                await asyncio.sleep(0.6)
            except Exception:
                break

    # Normalization
    def _normalize(self, url: str) -> str:
        if self.cfg.keep_fragments:
            return url
        return normalize(url)

    def _allow_and_unseen(self, url: str) -> bool:
        if url in self.seen:
            return False
        if self.cfg.same_origin_only:
            origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            if origin not in self.allowed_origins:
                return False
        return True


def playwright_main(seed: str):
    cfg = CrawlConfig(
        seeds=[seed],
        concurrency=3,
        max_pages=1000,
        same_origin_only=True,
        wait_until="domcontentloaded",
        output_path="static_crawl_results.ndjson",
        per_host_delay=0.5,
        headless=True,
        keep_fragments=True,
        verbose=True,
    )
    asyncio.run(BrowserCrawler(cfg).run())


def playwright_main_seeds(seeds: list[str]):
    """Run the headless crawler once with all provided seeds queued initially."""
    if not isinstance(seeds, list) or not seeds:
        return playwright_main("")
    cfg = CrawlConfig(
        seeds=seeds,
        concurrency=3,
        max_pages=1000,
        same_origin_only=True,
        wait_until="domcontentloaded",
        output_path="static_crawl_results.ndjson",
        per_host_delay=0.5,
        headless=True,
        keep_fragments=True,
        verbose=True,
    )
    asyncio.run(BrowserCrawler(cfg).run())

