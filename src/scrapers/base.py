from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Protocol
import re

@dataclass(frozen=True)
class ScrapeReport:
    name: str
    total: int

class BaseProxyScraper(Protocol):
    name: str
    def scrape(self) -> List[str]:
        """Return list of proxies as 'ip:port' strings."""
        ...
    def report(self) -> ScrapeReport:
        return ScrapeReport(name=getattr(self, "name", self.__class__.__name__), total=len(self.scrape()))

# Shared proxy pattern and simple extraction utility
PROXY_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d+\b")

def extract_proxies(content: str) -> List[str]:
    seen = set()
    out: List[str] = []
    for m in PROXY_PATTERN.finditer(content or ""):
        v = m.group(0)
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out
