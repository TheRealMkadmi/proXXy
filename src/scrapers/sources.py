from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Sequence, Mapping

from .extractors.text import TextExtractor
from .extractors.html import HtmlExtractor

SUPPORTED_TYPES = {"text", "html"}

@dataclass(frozen=True)
class SourceSpec:
    url: str
    protocol: str  # HTTP, HTTPS, SOCKS4, SOCKS5
    type: str = "text"
    selectors: Optional[List[str]] = None

    def create_extractor(self):
        t = (self.type or "text").lower()
        if t == "html" or (self.selectors and len(self.selectors) > 0):
            return HtmlExtractor(selectors=self.selectors)
        return TextExtractor()


def _infer_type(url: str, item: Any) -> str:
    if isinstance(item, dict):
        t = str(item.get("type", "text")).lower()
        if t in SUPPORTED_TYPES:
            return t
        if item.get("selectors"):
            return "html"
    lower = url.lower()
    if lower.endswith(".txt"):
        return "text"
    return "html" if any(ext in lower for ext in (".html", ".htm")) else "text"


def normalize_sources(sources: Mapping[str, Sequence[Any]]) -> Dict[str, List[SourceSpec]]:
    result: Dict[str, List[SourceSpec]] = {}
    for proto, items in (sources or {}).items():
        up = str(proto).upper()
        specs: List[SourceSpec] = []
        for it in items:
            if isinstance(it, str):
                t = _infer_type(it, None)
                specs.append(SourceSpec(url=it, protocol=up, type=t))
            elif isinstance(it, dict):
                url = str(it.get("url", "")).strip()
                if not url:
                    continue
                t = _infer_type(url, it)
                sels = it.get("selectors")
                if isinstance(sels, (list, tuple)):
                    sels = [str(s) for s in sels]
                else:
                    sels = None
                specs.append(SourceSpec(url=url, protocol=up, type=t, selectors=sels))
            else:
                continue
        if specs:
            result[up] = specs
    return result
