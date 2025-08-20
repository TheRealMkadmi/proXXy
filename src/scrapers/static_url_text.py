from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Sequence

import aiohttp

from .. import utils
from .base import extract_proxies

logger = logging.getLogger("proXXy.scrapers.static_url_text")


class StaticUrlTextScraper:
    name = "static_url_text"

    def __init__(self, protocols: Sequence[str] = ("HTTP", "HTTPS"), verify_ssl: bool = True) -> None:
        self.protocols = tuple(p.upper() for p in protocols)
        self.verify_ssl = bool(verify_ssl)

    def scrape(self) -> List[str]:
        """Fetch proxies from text-only sources defined in proxy_sources.json using aiohttp."""
        raw = utils.proxy_sources() or {}
        subset: Dict[str, List[Any]] = {k.upper(): v for k, v in raw.items() if k.upper() in self.protocols}

        if not subset:
            logger.warning(
                "static_url_text: no matching protocols in proxy_sources.json (requested=%s)",
                ",".join(self.protocols),
            )
            return []

        async def _run() -> List[str]:
            total_sources = sum(len(v) for v in subset.values() if isinstance(v, list))
            logger.debug(
                "static_url_text: starting scrape (protocols=%s, urls=%d, verify_ssl=%s)",
                ",".join(self.protocols),
                total_sources,
                self.verify_ssl,
            )

            headers = {"User-Agent": "proXXy/1.0 (+https://github.com/)"}
            out: List[str] = []
            seen = set()

            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            timeout = aiohttp.ClientTimeout(total=5)
            sem = asyncio.Semaphore(16)

            async with aiohttp.ClientSession(headers=headers, timeout=timeout, connector=connector, trust_env=False) as session:
                attempted = 0
                ok_urls = 0
                http_fail = 0
                err_urls = 0

                tasks = []
                entries: List[tuple[str, str]] = []
                for proto, items in subset.items():
                    for it in items:
                        url = it.strip() if isinstance(it, str) else str(it.get("url", "")).strip() if isinstance(it, dict) else ""
                        if url:
                            entries.append((str(proto).upper(), url))

                async def fetch(proto: str, url: str):
                    nonlocal attempted, ok_urls, http_fail, err_urls
                    async with sem:
                        attempted += 1
                        try:
                            async with session.get(url) as resp:
                                if not (200 <= resp.status < 400):
                                    http_fail += 1
                                    return
                                text = await resp.text(errors="ignore")
                                prefix = ""
                                if proto == "SOCKS4":
                                    prefix = "socks4://"
                                elif proto == "SOCKS5":
                                    prefix = "socks5://"
                                for p in extract_proxies(text or ""):
                                    val = (prefix + p) if prefix else p
                                    if val not in seen:
                                        seen.add(val)
                                        out.append(val)
                                ok_urls += 1
                        except Exception:
                            err_urls += 1

                for proto, u in entries:
                    tasks.append(asyncio.create_task(fetch(proto, u)))

                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

                logger.info(
                    "static_url_text: done urls=%d ok=%d http_fail=%d err=%d total=%d unique",
                    attempted,
                    ok_urls,
                    http_fail,
                    err_urls,
                    len(out),
                )
                return out

        return asyncio.run(_run())
