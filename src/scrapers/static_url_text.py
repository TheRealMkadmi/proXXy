from __future__ import annotations

from typing import Dict, List, Any, Sequence, Mapping

import utils
from .extractors.text import TextExtractor
from .sources import normalize_sources

class StaticUrlTextScraper:
    name = "static_url_text"

    def __init__(self, protocols: Sequence[str] = ("HTTP", "HTTPS")) -> None:
        self.protocols = tuple(p.upper() for p in protocols)
        self._extractor = TextExtractor()

    def scrape(self) -> List[str]:
        raw = utils.proxy_sources() or {}
        # Filter to specified protocols only
        subset: Dict[str, List[Any]] = {k.upper(): v for k, v in raw.items() if k.upper() in self.protocols}
        # Normalize and fetch content via requests (synchronous, small files); reuse Scrapy settings later if needed
        from requests import get
        out: List[str] = []
        seen = set()
        norm = normalize_sources(subset)
        for proto, specs in norm.items():
            for spec in specs:
                try:
                    resp = get(spec.url, timeout=5)
                    if resp.status_code < 200 or resp.status_code >= 400:
                        continue
                    content = resp.text or ""
                    res = self._extractor.extract(content)
                    for p in res.proxies:
                        if p not in seen:
                            seen.add(p)
                            out.append(p)
                except Exception:
                    continue
        return out
