from __future__ import annotations

import asyncio
import logging
from typing import List, Sequence, Optional
import aiohttp
from .base import PROXY_PATTERN

from .dynamic_html import DynamicHtmlScraper

logger = logging.getLogger("proXXy.scrapers.proxydb")


class ProxyDBScraper:
    name = "proxydb"

    def __init__(
        self,
        *,
        protocol: str = "http",
        anon_levels: Sequence[int] = (2, 4),
        country: str = "",
        pages: int = 1,
        timeout: float = 5.0,
        user_agent: Optional[str] = None,
        verify_ssl: bool = True,
    ) -> None:
        self.protocol = "https" if str(protocol).lower() == "https" else "http"
        self.anon_levels = tuple(int(a) for a in (anon_levels or (2, 4)))
        self.country = str(country or "")
        self.pages = max(1, int(pages))
        self.timeout = float(timeout)
        self.user_agent = user_agent
        self.verify_ssl = bool(verify_ssl)

    def _build_url(self, *, offset: int = 0) -> str:
        from urllib.parse import urlencode

        base = "https://proxydb.net/"
        params = {
            "protocol": self.protocol,
            "country": self.country,
        }
        # urlencode with doseq=True to repeat anonlvl
        items = list(params.items())
        for a in self.anon_levels:
            items.append(("anonlvl", str(int(a))))
        if offset > 0:
            items.append(("offset", str(int(offset))))
        return base + "?" + urlencode(items, doseq=True)

    def _extract_from_row(self, row) -> Optional[str]:
        # Prefer parsing the href like /IP/PORT#http
        href = row.css("td:nth-child(1) a::attr(href)").get()
        if href:
            try:
                h = href.strip().strip("/")
                parts = h.split("/")
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    port = parts[1].split("#", 1)[0].strip()
                    if ip and port.isdigit():
                        return f"{ip}:{port}"
            except Exception:
                pass
        # Fallback: use first two cells' text
        ip = (row.css("td:nth-child(1) ::text").get() or "").strip()
        port = (row.css("td:nth-child(2) ::text").get() or "").strip()
        if ip and port.isdigit():
            return f"{ip}:{port}"
        return None

    def _extract_from_html(self, html: str) -> List[str]:
        try:
            from parsel import Selector  # type: ignore
        except Exception:
            Selector = None  # type: ignore

        out: List[str] = []
        seen_local = set()
        if not html:
            return out

        if Selector is not None:
            try:
                sel = Selector(text=html)
                rows = sel.css("table tbody tr")
                if not rows:
                    rows = sel.css("table tr")
                for r in rows:
                    item = self._extract_from_row(r)
                    if item and item not in seen_local:
                        seen_local.add(item)
                        out.append(item)
            except Exception:
                pass

        # Fallback or supplement via regex pattern scan
        if not out:
            for m in PROXY_PATTERN.finditer(html):
                val = m.group(0)
                if val not in seen_local:
                    seen_local.add(val)
                    out.append(val)

        return out

    def scrape(self) -> List[str]:
        import math
        import re

        headers = {"User-Agent": self.user_agent} if self.user_agent else None

        logger.debug(
            "proxydb: starting (protocol=%s, pages=%d, verify_ssl=%s, ua=%s)",
            self.protocol,
            self.pages,
            self.verify_ssl,
            bool(self.user_agent),
        )

        step = 30
        fetch_attempted = 0
        fetch_ok = 0
        fetch_http_fail = 0
        fetch_err = 0

        async def _fetch_html(session: aiohttp.ClientSession, url: str) -> str:
            nonlocal fetch_attempted, fetch_ok, fetch_http_fail, fetch_err
            fetch_attempted += 1
            try:
                async with session.get(url) as resp:
                    if 200 <= resp.status < 400:
                        fetch_ok += 1
                        return await resp.text(errors="ignore")
                    fetch_http_fail += 1
            except Exception:
                fetch_err += 1
            return ""

        async def _run() -> List[str]:
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector, trust_env=False) as session:
                results: List[str] = []
                seen: set[str] = set()

                # First page
                first_html = await _fetch_html(session, self._build_url(offset=0))
                for item in self._extract_from_html(first_html):
                    if item not in seen:
                        seen.add(item)
                        results.append(item)

                total_count: Optional[int] = None
                if first_html:
                    m = re.search(r"Showing\s+\d+\s+to\s+\d+\s+of\s+([0-9,]+)\s+total\s+proxies", first_html, flags=re.IGNORECASE)
                    if m:
                        try:
                            total_count = int(m.group(1).replace(",", ""))
                        except Exception:
                            total_count = None

                if total_count is not None and total_count > 0:
                    total_pages = max(1, math.ceil(total_count / step))
                else:
                    total_pages = max(1, int(self.pages))

                remaining_offsets = [i * step for i in range(1, total_pages)]
                if remaining_offsets:
                    sem = asyncio.Semaphore(min(16, max(1, len(remaining_offsets))))

                    async def fetch_offset(off: int):
                        url = self._build_url(offset=off)
                        async with sem:
                            html = await _fetch_html(session, url)
                            if not html:
                                return
                            for item in self._extract_from_html(html):
                                if item not in seen:
                                    seen.add(item)
                                    results.append(item)

                    tasks = [asyncio.create_task(fetch_offset(off)) for off in remaining_offsets]
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)

                logger.info(
                    "proxydb: done total=%d unique fetches=%d ok=%d http_fail=%d err=%d",
                    len(results), fetch_attempted, fetch_ok, fetch_http_fail, fetch_err,
                )
                return results

        return asyncio.run(_run())
