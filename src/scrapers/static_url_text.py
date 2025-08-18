from __future__ import annotations

from typing import Dict, List, Any, Sequence

import utils
from .base import extract_proxies

class StaticUrlTextScraper:
    name = "static_url_text"

    def __init__(self, protocols: Sequence[str] = ("HTTP", "HTTPS")) -> None:
        self.protocols = tuple(p.upper() for p in protocols)
    # Text extraction is now handled via extract_proxies helper

    def scrape(self) -> List[str]:
        """Fetch proxies from text-only sources defined in proxy_sources.json.

        Note: proxy_sources.json contains only plain text URLs. Any HTML-based
        sources are implemented as dedicated scrapers (children of DynamicHtmlScraper)
        and do not go through this class.
        """
        raw = utils.proxy_sources() or {}
        subset: Dict[str, List[Any]] = {k.upper(): v for k, v in raw.items() if k.upper() in self.protocols}

        # Fetch content via requests (synchronous, small files)
        from requests import get
        out: List[str] = []
        seen = set()
        for proto, items in subset.items():
            for it in items:
                url: str = ""
                if isinstance(it, str):
                    url = it.strip()
                elif isinstance(it, dict):
                    url = str(it.get("url", "")).strip()
                if not url:
                    continue
                try:
                    resp = get(url, timeout=5)
                    if resp.status_code < 200 or resp.status_code >= 400:
                        continue
                    content = resp.text or ""
                    for p in extract_proxies(content):
                        if p not in seen:
                            seen.add(p)
                            out.append(p)
                except Exception:
                    continue
        return out
