from __future__ import annotations

from typing import List, Sequence, Optional
from .extractors.base import PROXY_PATTERN

from .dynamic_html import DynamicHtmlScraper


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

    def scrape(self) -> List[str]:
        from requests import get
        try:
            from parsel import Selector
        except Exception:
            Selector = None  # type: ignore

        out: List[str] = []
        seen = set()

        headers = {"User-Agent": self.user_agent} if self.user_agent else None

        # ProxyDB paginates in steps of 30
        step = 30
        for i in range(self.pages):
            offset = i * step
            url = self._build_url(offset=offset)
            try:
                resp = get(url, headers=headers, timeout=self.timeout, verify=self.verify_ssl)
                if resp.status_code < 200 or resp.status_code >= 400:
                    continue
                html = resp.text or ""
                if not html:
                    continue
                if Selector is None:
                    continue
                sel = Selector(text=html)
                rows = sel.css("table tbody tr")
                if not rows:
                    # Try a broader selection if tbody missing
                    rows = sel.css("table tr")
                before = len(out)
                for r in rows:
                    item = self._extract_from_row(r)
                    if item and item not in seen:
                        seen.add(item)
                        out.append(item)
                # Fallback: regex scan if table extraction failed to yield anything new
                if len(out) == before:
                    for m in PROXY_PATTERN.finditer(html):
                        val = m.group(0)
                        if val not in seen:
                            seen.add(val)
                            out.append(val)
            except Exception:
                continue

        return out
