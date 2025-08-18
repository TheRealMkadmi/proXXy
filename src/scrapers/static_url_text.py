from __future__ import annotations

import logging
import time
from typing import Dict, List, Any, Sequence

from .. import utils
from .base import extract_proxies

logger = logging.getLogger("proXXy.scrapers.static_url_text")

class StaticUrlTextScraper:
    name = "static_url_text"

    def __init__(self, protocols: Sequence[str] = ("HTTP", "HTTPS"), verify_ssl: bool = True) -> None:
        self.protocols = tuple(p.upper() for p in protocols)
        self.verify_ssl = bool(verify_ssl)
    # Text extraction is now handled via extract_proxies helper

    def scrape(self) -> List[str]:
        """Fetch proxies from text-only sources defined in proxy_sources.json.

        Note: proxy_sources.json contains only plain text URLs. Any HTML-based
        sources are implemented as dedicated scrapers (children of DynamicHtmlScraper)
        and do not go through this class.
        """
        import requests

        raw = utils.proxy_sources() or {}
        subset: Dict[str, List[Any]] = {k.upper(): v for k, v in raw.items() if k.upper() in self.protocols}

        if not subset:
            logger.warning("static_url_text: no matching protocols in proxy_sources.json (requested=%s)", ",".join(self.protocols))
            return []

        total_sources = sum(len(v) for v in subset.values() if isinstance(v, list))
        logger.info("static_url_text: starting scrape (protocols=%s, urls=%d, verify_ssl=%s)", ",".join(self.protocols), total_sources, self.verify_ssl)

        headers = {"User-Agent": "proXXy/1.0 (+https://github.com/)"}
        out: List[str] = []
        seen = set()
        sess = requests.Session()
        sess.trust_env = False

        for proto, items in subset.items():
            for it in items:
                url: str = ""
                if isinstance(it, str):
                    url = it.strip()
                elif isinstance(it, dict):
                    url = str(it.get("url", "")).strip()
                if not url:
                    logger.debug("static_url_text: skipping empty URL entry (%s)", proto)
                    continue

                t0 = time.perf_counter()
                try:
                    logger.debug("static_url_text.fetch: [%s] %s", proto, url)
                    resp = sess.get(url, timeout=5, headers=headers, verify=self.verify_ssl)
                    dt = time.perf_counter() - t0
                    status = resp.status_code
                    if not (200 <= status < 400):
                        logger.warning("static_url_text.fetch: [%s] %s -> HTTP %s in %.2fs", proto, url, status, dt)
                        continue

                    content = resp.text or ""
                    size = len(content.encode("utf-8"))
                    found = 0
                    for p in extract_proxies(content):
                        if p not in seen:
                            seen.add(p)
                            out.append(p)
                            found += 1

                    if found == 0:
                        logger.warning("static_url_text.parse: [%s] %s -> 0 proxies (status=%d, bytes=%d, %.2fs)", proto, url, status, size, dt)
                    else:
                        logger.info("static_url_text.parse: [%s] %s -> %d proxies (status=%d, bytes=%d, %.2fs)", proto, url, found, status, size, dt)
                    logger.debug("static_url_text.sample: [%s] %s -> first-bytes='%s'", proto, url, (content[:80].replace("\\n"," ") if content else ""))
                except Exception as e:
                    dt = time.perf_counter() - t0
                    logger.warning("static_url_text.fetch: [%s] %s -> error %s: %s in %.2fs", proto, url, e.__class__.__name__, str(e)[:200], dt)
                    continue

        logger.info("static_url_text: done (total=%d unique)", len(out))
        return out
