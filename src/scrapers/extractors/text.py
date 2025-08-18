from __future__ import annotations

from typing import Optional
from .base import ExtractResult, ExtractContext, PROXY_PATTERN

class TextExtractor:
    def extract(self, content: str, *, context: Optional[ExtractContext] = None) -> ExtractResult:
        seen = set()
        proxies = []
        for m in PROXY_PATTERN.finditer(content or ""):
            val = m.group(0)
            if val not in seen:
                seen.add(val)
                proxies.append(val)
        return ExtractResult(proxies=proxies)
