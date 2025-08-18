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
        logger.debug("static_url_text: starting scrape (protocols=%s, urls=%d, verify_ssl=%s)", ",".join(self.protocols), total_sources, self.verify_ssl)

        headers = {"User-Agent": "proXXy/1.0 (+https://github.com/)"}
        out: List[str] = []
        seen = set()
        sess = requests.Session()
        sess.trust_env = False

        # Suppress noisy TLS warnings when verify_ssl is disabled (debug convenience)
        if not self.verify_ssl:
            try:
                import urllib3  # type: ignore
                from urllib3.exceptions import InsecureRequestWarning  # type: ignore
                urllib3.disable_warnings(InsecureRequestWarning)
            except Exception:
                pass

        attempted = 0
        ok_urls = 0
        http_fail = 0
        err_urls = 0

        for proto, items in subset.items():
            for it in items:
                url: str = ""
                if isinstance(it, str):
                    url = it.strip()
                elif isinstance(it, dict):
                    url = str(it.get("url", "")).strip()
                if not url:
                    continue

                attempted += 1
                try:
                    resp = sess.get(url, timeout=5, headers=headers, verify=self.verify_ssl)
                    if not (200 <= resp.status_code < 400):
                        http_fail += 1
                        continue

                    content = resp.text or ""
                    for p in extract_proxies(content):
                        if p not in seen:
                            seen.add(p)
                            out.append(p)
                    ok_urls += 1
                except Exception:
                    err_urls += 1
                    continue

        logger.info(
            "static_url_text: done urls=%d ok=%d http_fail=%d err=%d total=%d unique",
            attempted, ok_urls, http_fail, err_urls, len(out)
        )
        return out
