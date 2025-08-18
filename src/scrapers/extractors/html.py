from __future__ import annotations

from typing import Optional, Sequence
from .base import ExtractContext, ExtractResult, PROXY_PATTERN

try:
    from parsel import Selector
except Exception:  # pragma: no cover
    Selector = None  # type: ignore

class HtmlExtractor:
    def __init__(self, *, selectors: Optional[Sequence[str]] = None):
        self._selectors = list(selectors or [])

    def extract(self, content: str, *, context: Optional[ExtractContext] = None) -> ExtractResult:
        proxies = []
        seen = set()
        if Selector is not None and self._selectors:
            sel = Selector(text=content or "")
            texts: list[str] = []
            for s in self._selectors:
                try:
                    if s.strip().startswith("//") or s.strip().startswith(".//"):
                        nodes = sel.xpath(s)
                    else:
                        nodes = sel.css(s)
                    texts.extend([t.get() for t in nodes.xpath("string(.)")])
                except Exception:
                    continue
            content_parts = "\n".join(texts)
            for m in PROXY_PATTERN.finditer(content_parts):
                val = m.group(0)
                if val not in seen:
                    seen.add(val)
                    proxies.append(val)
        if not proxies:
            for m in PROXY_PATTERN.finditer(content or ""):
                val = m.group(0)
                if val not in seen:
                    seen.add(val)
                    proxies.append(val)
        return ExtractResult(proxies=proxies)
