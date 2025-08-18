from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Protocol

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
