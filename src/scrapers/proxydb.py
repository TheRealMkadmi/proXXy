from __future__ import annotations

import logging
from typing import List, Sequence, Optional
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
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import math
        import re
        import time
        import requests
 
        headers = {"User-Agent": self.user_agent} if self.user_agent else None
        sess = requests.Session()
        sess.trust_env = False
 
        logger.info("proxydb: starting (protocol=%s, pages=%d, verify_ssl=%s, ua=%s)",
                    self.protocol, self.pages, self.verify_ssl, bool(self.user_agent))
 
        # ProxyDB paginates in steps of 30
        step = 30
 
        def fetch(offset: int) -> str:
            url = self._build_url(offset=offset)
            t0 = time.perf_counter()
            try:
                logger.debug("proxydb.fetch: %s", url)
                resp = sess.get(url, headers=headers, timeout=self.timeout, verify=self.verify_ssl)
                dt = time.perf_counter() - t0
                if 200 <= resp.status_code < 400:
                    txt = resp.text or ""
                    logger.info("proxydb.fetch: %s -> %d (%d bytes) in %.2fs", url, resp.status_code, len(txt.encode('utf-8')), dt)
                    return txt
                logger.warning("proxydb.fetch: %s -> HTTP %d in %.2fs", url, resp.status_code, dt)
            except Exception as e:
                dt = time.perf_counter() - t0
                logger.warning("proxydb.fetch: %s -> error %s: %s in %.2fs", url, e.__class__.__name__, str(e)[:200], dt)
            return ""
 
        # First: fetch page 1 (offset 0)
        first_html = fetch(0)
        results: List[str] = []
        seen: set[str] = set()
 
        # Extract from first page
        first_items = self._extract_from_html(first_html)
        for item in first_items:
            if item not in seen:
                seen.add(item)
                results.append(item)
        logger.info("proxydb.parse: offset=0 -> %d items", len(first_items))
 
        # Try to parse total proxies, e.g.: "Showing 1 to 30 of 2,345 total proxies"
        total_count: Optional[int] = None
        if first_html:
            m = re.search(r"Showing\s+\d+\s+to\s+\d+\s+of\s+([0-9,]+)\s+total\s+proxies", first_html, flags=re.IGNORECASE)
            if m:
                try:
                    total_count = int(m.group(1).replace(",", ""))
                except Exception:
                    total_count = None
 
        # Determine how many pages to fetch. If total_count parsed, ignore self.pages to return full dataset.
        if total_count is not None and total_count > 0:
            total_pages = max(1, math.ceil(total_count / step))
        else:
            total_pages = max(1, int(self.pages))
        logger.info("proxydb: total_pages=%d (step=%d)", total_pages, step)
 
        # Prepare remaining offsets (we already fetched offset 0)
        remaining_offsets = [i * step for i in range(1, total_pages)]
        if remaining_offsets:
            max_workers = min(16, max(1, len(remaining_offsets)))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_map = {executor.submit(fetch, off): off for off in remaining_offsets}
                for fut in as_completed(future_map):
                    html = fut.result() or ""
                    if not html:
                        continue
                    items = self._extract_from_html(html)
                    added = 0
                    for item in items:
                        if item not in seen:
                            seen.add(item)
                            results.append(item)
                            added += 1
                    logger.info("proxydb.parse: offset=%d -> got=%d added=%d dupes=%d", future_map[fut], len(items), added, len(items)-added)
 
        logger.info("proxydb: done total=%d unique", len(results))
        return results
