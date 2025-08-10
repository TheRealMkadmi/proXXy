import argparse
import concurrent.futures as futures
import os
import sys
import threading
import time
from typing import Iterable, List, Optional, Set, Tuple, Dict, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from loguru import logger

# Thread-local session for connection pooling without cross-thread sharing
_thread_local = threading.local()


def _get_session(timeout: float, verify_ssl: bool, user_agent: Optional[str] = None) -> requests.Session:
    sess: Optional[requests.Session] = getattr(_thread_local, "session", None)
    if sess is not None:
        return sess

    sess = requests.Session()
    # Large pools to support high concurrency within a thread
    adapter = HTTPAdapter(
        pool_connections=1024,
        pool_maxsize=1024,
        max_retries=Retry(total=0, connect=0, read=0, redirect=0, backoff_factor=0),
    )
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.verify = verify_ssl
    sess.headers.update({
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "keep-alive",
    })
    if user_agent:
        sess.headers["User-Agent"] = user_agent
    # Store timeout default on the session via a simple attribute for reuse
    sess.request_timeout = timeout  # type: ignore[attr-defined]
    _thread_local.session = sess
    return sess


def _normalize_proxy(line: str, default_scheme: str = "http") -> Optional[str]:
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    # If scheme missing, prepend default
    if "://" not in s:
        s = f"{default_scheme}://{s}"
    # Very light validation
    if s.split("://", 1)[0] not in ("http", "https"):
        return None
    return s


def _iter_proxies(source: Optional[str]) -> Iterable[str]:
    if source and source != "-":
        with open(source, "r", encoding="utf-8") as f:
            for line in f:
                p = _normalize_proxy(line)
                if p:
                    yield p
        return

    # Read from stdin
    if not sys.stdin.isatty():
        for line in sys.stdin:
            p = _normalize_proxy(line)
            if p:
                yield p
        return

    raise SystemExit("No proxies provided. Use --input FILE or pipe via STDIN.")


def _check_one(proxy: str, url: str, timeout: float, verify_ssl: bool, user_agent: Optional[str]) -> Tuple[str, bool, Optional[int], Optional[str], Optional[float], Optional[str]]:
    sess = _get_session(timeout, verify_ssl, user_agent)
    proxies = {"http": proxy, "https": proxy}
    try:
        t0 = time.monotonic()
        # Stream to avoid downloading full bodies; follow redirects; small timeout
        resp = sess.get(url, proxies=proxies, timeout=getattr(sess, "request_timeout", timeout), stream=True, allow_redirects=True)
        # Read a tiny chunk to trigger the connection/body without full download
        for _ in resp.iter_content(chunk_size=1):
            break
        ok = 200 <= resp.status_code < 400
        # Prefer server-reported elapsed if available, else fallback to measured
        elapsed = None
        try:
            elapsed = float(resp.elapsed.total_seconds()) if resp.elapsed is not None else None
        except Exception:
            elapsed = None
        if elapsed is None:
            elapsed = time.monotonic() - t0
        final_url = resp.url
        resp.close()
        return proxy, ok, resp.status_code, None, elapsed, final_url
    except Exception as e:
        return proxy, False, None, str(e), None, None


def check_proxies(
    proxies: Iterable[str],
    url: str,
    workers: int,
    timeout: float,
    verify_ssl: bool = True,
    user_agent: Optional[str] = None,
    total: Optional[int] = None,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    seen: Set[str] = set()
    results: List[Dict[str, Any]] = []
    submitted = 0
    peak_inflight = 0
    start = time.time()
    last_log = time.monotonic()
    completed = 0
    successes = 0

    def _next_unique(it) -> Optional[str]:
        for item in it:
            if item not in seen:
                seen.add(item)
                return item
        return None

    with futures.ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="proxychk") as ex:
        inflight: Set[futures.Future] = set()
        prox_iter = iter(proxies)
        # Prime the pump up to workers
        while len(inflight) < workers:
            nxt = _next_unique(prox_iter)
            if nxt is None:
                break
            inflight.add(ex.submit(_check_one, nxt, url, timeout, verify_ssl, user_agent))
            submitted += 1
            if len(inflight) > peak_inflight:
                peak_inflight = len(inflight)

        # Process and keep submitting as we go
        while inflight:
            done, _ = futures.wait(inflight, return_when=futures.FIRST_COMPLETED)
            for fut in done:
                inflight.remove(fut)
                proxy, ok, status, err, elapsed, final_url = fut.result()
                completed += 1
                if ok:
                    results.append({
                        "proxy": proxy,
                        "status": status,
                        "elapsed": elapsed,
                        "final_url": final_url,
                    })
                    successes += 1
                else:
                    logger.debug("failed: proxy={} err={}", proxy, err)
                # Try to submit next task to maintain concurrency
                nxt = _next_unique(prox_iter)
                if nxt is not None:
                    inflight.add(ex.submit(_check_one, nxt, url, timeout, verify_ssl, user_agent))
                    submitted += 1
                    if len(inflight) > peak_inflight:
                        peak_inflight = len(inflight)

                # Throttled progress logging
                now = time.monotonic()
                if now - last_log >= 1.0 or (total and completed and completed % 100 == 0):
                    elapsed = max(1e-6, time.time() - start)
                    rate = completed / elapsed
                    pct = (completed / total * 100.0) if total else None
                    if pct is not None:
                        logger.info("progress: {}/{} ({:.1f}%) done | live={} | rate={:.1f}/s | inflight={}", completed, total, pct, successes, rate, len(inflight))
                    else:
                        logger.info("progress: {} done | live={} | rate={:.1f}/s | inflight={}", completed, successes, rate, len(inflight))
                    last_log = now

    elapsed_total = time.time() - start
    # Sort live by fastest first (None elapsed pushed to end)
    results.sort(key=lambda r: (float('inf') if r.get('elapsed') is None else r["elapsed"]))
    live_sorted = [r["proxy"] for r in results]
    # Optional stats to stderr
    logger.success(
        "done: checked={} live={} elapsed={:.1f}s peak_workers={} rate={:.1f}/s",
        len(seen), len(live_sorted), elapsed_total, peak_inflight, (len(seen) / max(1e-6, elapsed_total)),
    )
    return live_sorted, results


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="proxy-checker",
        description="Validate HTTP/HTTPS proxies against a target URL quickly using requests and multithreading.",
    )
    ap.add_argument("--input", "-i", help="Path to proxies file (host:port or scheme://host:port). Use '-' or pipe via STDIN.")
    ap.add_argument("--url", "-u", default="https://www.netflix.com", help="Target URL to test. Default: %(default)s")
    ap.add_argument("--workers", "-w", type=int, default=2048, help="Max concurrent workers (threads). Default: %(default)s")
    ap.add_argument("--output", "-o", default="work.txt", help="Write live proxies to this file (default: work.txt). Also printed to stdout.")
    return ap.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    # Defaults for simplicity
    timeout = 5.0
    verify_ssl = True
    user_agent = None

    proxies = list(_iter_proxies(args.input))
    # Deduplicate while preserving order for accurate totals
    unique_proxies = list(dict.fromkeys(proxies))
    # Cap workers to number of proxies to avoid oversubscription on small lists
    workers = max(1, min(args.workers, len(unique_proxies)))

    logger.info(
        "start: total={} workers={} url='{}' timeout={} output='{}'",
        len(unique_proxies), workers, args.url, timeout, args.output,
    )
    live, details = check_proxies(unique_proxies, args.url, workers, timeout, verify_ssl, user_agent, total=len(unique_proxies))

    # Output live proxies
    for p in live:
        print(p)

    out_path = args.output
    out_name = os.path.basename(out_path).lower()
    strip_scheme = (out_name == "work.txt")
    def _strip_scheme(proxy: str) -> str:
        if "://" in proxy:
            return proxy.split("://", 1)[1]
        return proxy
    with open(out_path, "w", encoding="utf-8") as f:
        for p in live:
            f.write((_strip_scheme(p) if strip_scheme else p) + "\n")

    # Always write a simple CSV log with details for convenience
    import csv
    with open("results.csv", "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["proxy", "status", "elapsed_ms", "final_url"])
        for r in details:
            ms = int(round((r.get("elapsed") or 0) * 1000))
            writer.writerow([r.get("proxy"), r.get("status"), ms, r.get("final_url")])

    return 0
