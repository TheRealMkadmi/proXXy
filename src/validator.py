import concurrent.futures as futures
import os
import sys
import threading
import time
from typing import Iterable, List, Optional, Set, Tuple, Dict, Any, Callable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from loguru import logger

# Configure loguru level from env (defaults to INFO)
_LOG_LEVEL = os.getenv("PROXXY_VALIDATOR_LOG_LEVEL", os.getenv("PROXXY_LOG_LEVEL", "INFO"))
try:
    logger.remove()
except Exception:
    pass
logger.add(sys.stderr, level=_LOG_LEVEL, backtrace=False, diagnose=False, enqueue=True)

# Thread-local session for connection pooling without cross-thread sharing
_thread_local = threading.local()

OnLiveFn = Callable[[str, Dict[str, Any]], None]
OnResultFn = Callable[[Dict[str, Any]], None]


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
    sess.headers.update(
        {
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "keep-alive",
        }
    )
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


def _check_one(
    proxy: str, url: str, timeout: float, verify_ssl: bool, user_agent: Optional[str]
) -> Tuple[str, bool, Optional[int], Optional[str], Optional[float], Optional[str]]:
    sess = _get_session(timeout, verify_ssl, user_agent)
    proxies = {"http": proxy, "https": proxy}
    try:
        t0 = time.monotonic()
        # Stream to avoid downloading full bodies; follow redirects; small timeout
        resp = sess.get(
            url,
            proxies=proxies,
            timeout=getattr(sess, "request_timeout", timeout),
            stream=True,
            allow_redirects=True,
        )
        # Read a tiny chunk to trigger the connection/body without full download
        for _ in resp.iter_content(chunk_size=1):
            break
        ok = 200 <= resp.status_code < 300
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
    """
    Batch validation. Returns all live proxies only after completion.
    """
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
                    results.append(
                        {
                            "proxy": proxy,
                            "status": status,
                            "elapsed": elapsed,
                            "final_url": final_url,
                        }
                    )
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
                    elapsed_total = max(1e-6, time.time() - start)
                    rate = completed / elapsed_total
                    pct = (completed / total * 100.0) if total else None
                    if pct is not None:
                        logger.debug(
                            "progress: {}/{} ({:.1f}%) done | live={} | rate={:.1f}/s | inflight={}",
                            completed,
                            total,
                            pct,
                            successes,
                            rate,
                            len(inflight),
                        )
                    else:
                        logger.debug(
                            "progress: {} done | live={} | rate={:.1f}/s | inflight={}",
                            completed,
                            successes,
                            rate,
                            len(inflight),
                        )
                    last_log = now

    elapsed_total = time.time() - start
    # Sort live by fastest first (None elapsed pushed to end)
    results.sort(key=lambda r: (float("inf") if r.get("elapsed") is None else r["elapsed"]))
    live_sorted = [r["proxy"] for r in results]
    # Optional stats to stderr
    logger.success(
        "done: checked={} live={} elapsed={:.1f}s peak_workers={} rate={:.1f}/s",
        len(seen),
        len(live_sorted),
        elapsed_total,
        peak_inflight,
        (len(seen) / max(1e-6, elapsed_total)),
    )
    return live_sorted, results


def check_proxies_stream(
    proxies: Iterable[str],
    url: str,
    workers: int,
    timeout: float,
    on_live: OnLiveFn,
    on_result: Optional[OnResultFn] = None,
    verify_ssl: bool = True,
    user_agent: Optional[str] = None,
    total: Optional[int] = None,
    stop_event: Optional[threading.Event] = None,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """
    Streaming validation. Invokes on_live(proxy, details) immediately for each success.
    Also invokes optional on_result(details) for every completed probe (success or failure).
    Returns (live_list_sorted_by_latency, all_result_dicts) after completion or cancellation.
    """
    seen: Set[str] = set()
    results: List[Dict[str, Any]] = []
    submitted = 0
    peak_inflight = 0
    start = time.time()
    last_log = time.monotonic()
    completed = 0
    successes = 0
    live_out: List[str] = []

    def _next_unique(it) -> Optional[str]:
        for item in it:
            if item not in seen:
                seen.add(item)
                return item
        return None

    # Determine stop predicate with None-check to satisfy type-checkers and runtime duck-typing
    if stop_event is not None:
        should_stop = stop_event.is_set  # type: ignore[attr-defined]
    else:
        should_stop = lambda: False

    with futures.ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="proxychk") as ex:
        inflight: Set[futures.Future] = set()
        prox_iter = iter(proxies)
        # Prime the pump up to workers
        while len(inflight) < workers and not should_stop():
            nxt = _next_unique(prox_iter)
            if nxt is None:
                break
            inflight.add(ex.submit(_check_one, nxt, url, timeout, verify_ssl, user_agent))
            submitted += 1
            if len(inflight) > peak_inflight:
                peak_inflight = len(inflight)

        # Process and keep submitting as we go
        while inflight and not should_stop():
            done, _ = futures.wait(inflight, return_when=futures.FIRST_COMPLETED)
            for fut in done:
                inflight.remove(fut)
                proxy, ok, status, err, elapsed, final_url = fut.result()
                completed += 1

                details = {
                    "proxy": proxy,
                    "ok": ok,
                    "status": status,
                    "error": err,
                    "elapsed": elapsed,
                    "final_url": final_url,
                }

                if ok:
                    # Emit live immediately
                    try:
                        on_live(proxy, details)
                    except Exception:
                        # Do not let callbacks break the loop
                        pass
                    successes += 1
                    # Collect to return a sorted list at end
                    results.append(
                        {
                            "proxy": proxy,
                            "status": status,
                            "elapsed": elapsed,
                            "final_url": final_url,
                        }
                    )
                else:
                    # Keep failure info only if on_result requested
                    if on_result is None:
                        # Reduce memory footprint by skipping failures
                        pass
                    else:
                        results.append(
                            {
                                "proxy": proxy,
                                "status": status,
                                "elapsed": elapsed,
                                "final_url": final_url,
                                "error": err,
                            }
                        )

                if on_result is not None:
                    try:
                        on_result(details)
                    except Exception:
                        pass

                # Try to submit next task to maintain concurrency
                nxt = _next_unique(prox_iter)
                if nxt is not None and not should_stop():
                    inflight.add(ex.submit(_check_one, nxt, url, timeout, verify_ssl, user_agent))
                    submitted += 1
                    if len(inflight) > peak_inflight:
                        peak_inflight = len(inflight)

                # Throttled progress logging
                now = time.monotonic()
                if now - last_log >= 1.0 or (total and completed and completed % 100 == 0):
                    elapsed_total = max(1e-6, time.time() - start)
                    rate = completed / elapsed_total
                    pct = (completed / total * 100.0) if total else None
                    if pct is not None:
                        logger.debug(
                            "progress: {}/{} ({:.1f}%) done | live={} | rate={:.1f}/s | inflight={}",
                            completed,
                            total,
                            pct,
                            successes,
                            rate,
                            len(inflight),
                        )
                    else:
                        logger.debug(
                            "progress: {} done | live={} | rate={:.1f}/s | inflight={}",
                            completed,
                            successes,
                            rate,
                            len(inflight),
                        )
                    last_log = now

    # Sort successes by latency, extract proxies for return value
    results.sort(key=lambda r: (float("inf") if r.get("elapsed") is None else r["elapsed"]))
    live_out = [r["proxy"] for r in results if "proxy" in r and r.get("elapsed") is not None]
    elapsed_total = time.time() - start
    logger.success(
        "done(stream): checked~{} live={} elapsed={:.1f}s peak_workers={} rate~={:.1f}/s",
        len(seen),
        len(live_out),
        elapsed_total,
        peak_inflight,
        (max(1, completed) / max(1e-6, elapsed_total)),
    )
    return live_out, results