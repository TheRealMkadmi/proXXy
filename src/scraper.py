"""
Programmatic proxy scraper module built on Scrapy.
Refactored to be imported and used from other Python code (no CLI/printing).
"""
from __future__ import annotations

import os
import re
import logging
import argparse
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Any

import utils
from scrapy import Spider, Request
from scrapy.crawler import CrawlerProcess

DEFAULT_OUTPUT_DIR = "output"
PROTOCOLS = ("HTTP", "HTTPS", "SOCKS4", "SOCKS5")

logger = logging.getLogger(__name__)

__all__ = [
    "ProxySpider",
    "ProxyScrapeResult",
    "run_proxy_scrape",
    "clean_proxy_files",
    "count_lines",
]


_PROXY_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d+\b")


@dataclass(frozen=True)
class ProxyScrapeResult:
    per_protocol: Dict[str, Set[str]]
    total: int
    output_files: Dict[str, str]
    wrote_to_files: bool


class ProxySpider(Spider):
    """
    Scrapy Spider that scrapes proxies from a collection of source URLs.

    Pass in a shared `result_container` dict to collect results after crawl finishes.
    """
    name = "proxy_spider"

    def __init__(
        self,
        sources: Optional[Dict[str, List[str]]] = None,
        result_container: Optional[Dict[str, Any]] = None,
        output_dir: str = DEFAULT_OUTPUT_DIR,
        write_files: bool = True,
        merge_existing: bool = True,
        user_agent: Optional[str] = None,
        request_timeout: int = 5,
        retry_times: int = 2,
        retry_http_codes: Optional[List[int]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.sources: Dict[str, List[str]] = sources or utils.proxy_sources()
        # Normalize protocols to expected keys
        self.sources = {
            proto.upper(): urls for proto, urls in self.sources.items()
            if proto.upper() in PROTOCOLS
        }
        self._results: Dict[str, Set[str]] = {p: set() for p in PROTOCOLS}
        self._result_container = result_container if result_container is not None else {}
        self._write_files = write_files
        self._merge_existing = merge_existing
        self._output_dir = output_dir
        self._user_agent = user_agent
        self._request_timeout = int(request_timeout)
        self._retry_times = int(retry_times)
        self._retry_http_codes = retry_http_codes or [500, 502, 503, 504, 408]

    def start_requests(self):
        headers = {"User-Agent": self._user_agent} if self._user_agent else None
        for protocol, urls in self.sources.items():
            for url in urls:
                yield Request(
                    url,
                    callback=self.parse,
                    meta={"protocol": protocol, "download_timeout": self._request_timeout},
                    headers=headers,
                )

    def parse(self, response):
        protocol = response.meta["protocol"]
        proxies = self.extract_proxies(response.text)
        if proxies:
            self._results[protocol].update(proxies)

    def extract_proxies(self, html_content: str) -> List[str]:
        return _PROXY_REGEX.findall(html_content)

    def closed(self, reason: str) -> None:
        # Persist results if requested
        output_files: Dict[str, str] = {}
        if self._write_files:
            _ensure_output_dir(self._output_dir)
            for proto, items in self._results.items():
                if not items:
                    continue
                path = os.path.join(self._output_dir, f"{proto}.txt")
                final_set: Set[str] = set(items)
                if self._merge_existing and os.path.isfile(path):
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            final_set.update(line.strip() for line in f if line.strip())
                    except OSError as e:
                        logger.warning("Failed reading existing file %s: %s", path, e)
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        for proxy in sorted(final_set):
                            f.write(proxy + "\n")
                    output_files[proto] = path
                except OSError as e:
                    logger.error("Failed writing proxies to %s: %s", path, e)

        total = sum(len(s) for s in self._results.values())
        # Expose results through the shared container
        self._result_container["per_protocol"] = self._results
        self._result_container["total"] = total
        self._result_container["output_files"] = output_files
        self._result_container["wrote_to_files"] = self._write_files


def run_proxy_scrape(
    *,
    sources: Optional[Dict[str, List[str]]] = None,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    write_files: bool = True,
    merge_existing: bool = True,
    user_agent: Optional[str] = None,
    request_timeout: int = 5,
    retry_times: int = 2,
    retry_http_codes: Optional[List[int]] = None,
    log_level: str = "ERROR",
) -> ProxyScrapeResult:
    """
    Run the proxy scraper synchronously and return ProxyScrapeResult.

    This function manages its own Scrapy reactor (CrawlerProcess) and blocks until
    the crawl finishes. No Twisted objects are exposed.
    """
    result_container: Dict[str, Any] = {}
    settings: Dict[str, Any] = {
        "LOG_LEVEL": log_level,
        "DOWNLOAD_TIMEOUT": request_timeout,
        "RETRY_ENABLED": retry_times > 0,
        "RETRY_TIMES": retry_times,
        "RETRY_HTTP_CODES": retry_http_codes or [500, 502, 503, 504, 408],
    }
    if user_agent:
        settings["USER_AGENT"] = user_agent

    process = CrawlerProcess(settings=settings)
    process.crawl(
        ProxySpider,
        sources=sources,
        result_container=result_container,
        output_dir=output_dir,
        write_files=write_files,
        merge_existing=merge_existing,
        user_agent=user_agent,
        request_timeout=request_timeout,
        retry_times=retry_times,
        retry_http_codes=retry_http_codes,
    )
    process.start()  # blocks until finished
    return ProxyScrapeResult(
        per_protocol=result_container.get("per_protocol", {p: set() for p in PROTOCOLS}),
        total=int(result_container.get("total", 0)),
        output_files=result_container.get("output_files", {}),
        wrote_to_files=bool(result_container.get("wrote_to_files", False)),
    )


def clean_proxy_files(
    output_dir: str = DEFAULT_OUTPUT_DIR,
    protocols: Optional[List[str]] = None,
) -> Dict[str, int]:
    """
    De-duplicate proxies in existing output files by protocol.
    Returns a dict mapping protocol -> final unique count.
    """
    protos = tuple(p.upper() for p in (protocols or PROTOCOLS))
    counts: Dict[str, int] = {}
    _ensure_output_dir(output_dir)
    for proto in protos:
        path = os.path.join(output_dir, f"{proto}.txt")
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                unique = {line.strip() for line in f if line.strip()}
            with open(path, "w", encoding="utf-8") as f:
                for proxy in sorted(unique):
                    f.write(proxy + "\n")
            counts[proto] = len(unique)
        except OSError as e:
            logger.error("Failed cleaning file %s: %s", path, e)
    return counts


def count_lines(file_path: str) -> int:
    """
    Count lines in a file. Returns 0 if the file does not exist or cannot be read.
    """
    if not os.path.isfile(file_path):
        logger.warning("File not found: %s", file_path)
        return 0
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return sum(1 for _ in f)
    except OSError as e:
        logger.error("Error reading file %s: %s", file_path, e)
        return 0


def _ensure_output_dir(output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="proxy-scraper",
        description="Scrape proxies using Scrapy and write protocol files to output directory.",
    )
    ap.add_argument("--protocols", default="HTTP,HTTPS", help="Comma-separated list of protocols to scrape (default: HTTP,HTTPS)")
    ap.add_argument("--output-dir", "-o", default=DEFAULT_OUTPUT_DIR, help="Directory to write protocol files (default: output)")
    ap.add_argument("--user-agent", help="Optional User-Agent header")
    ap.add_argument("--timeout", type=int, default=5, help="Per-request timeout seconds (default: 5)")
    ap.add_argument("--retry-times", type=int, default=1, help="Scrapy retry times (default: 1)")
    ap.add_argument("--log-level", default="WARNING", help="Scrapy log level (default: WARNING)")
    return ap.parse_args(argv)


def _main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    want = tuple(p.strip().upper() for p in args.protocols.split(",") if p.strip())
    if not want:
        want = ("HTTP", "HTTPS")

    # Filter sources to requested protocols
    try:
        sources_all = utils.proxy_sources()
        sources = {k.upper(): v for k, v in sources_all.items() if k.upper() in want}
    except Exception as e:
        logger.error("Failed to read proxy sources: %s", e)
        sources = {}

    res = run_proxy_scrape(
        sources=sources,
        output_dir=args.output_dir,
        write_files=True,
        merge_existing=True,
        user_agent=args.user_agent,
        request_timeout=int(args.timeout),
        retry_times=int(args.retry_times),
        log_level=str(args.log_level),
    )
    print(json.dumps({
        "total": res.total,
        "output_files": res.output_files,
        "wrote_to_files": res.wrote_to_files,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
