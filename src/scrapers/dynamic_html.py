from __future__ import annotations

from typing import List, Protocol

class DynamicHtmlScraper(Protocol):
    name: str
    def scrape(self) -> List[str]:
        """Return list of proxies as 'ip:port'. Implementations handle HTML/JS intricacies."""
        ...
