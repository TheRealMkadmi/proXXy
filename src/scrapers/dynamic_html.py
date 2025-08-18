from __future__ import annotations

from typing import List, Protocol

class DynamicHtmlScraper(Protocol):
        name: str
        def scrape(self) -> List[str]:
                """Return list of proxies as 'ip:port'.

                Design note:
                - Config-driven sources come exclusively from `proxy_sources.json` and are TEXT endpoints.
                - Any HTML or JS-driven sources must be implemented as classes that implement this protocol
                    and are invoked directly (they do NOT pass through the config layer).
                """
                ...
