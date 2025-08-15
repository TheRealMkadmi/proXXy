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

# Minimal downloaded bytes to consider success (default 1; tune via env)
_MIN_BYTES = int(os.getenv("PROXXY_VALIDATOR_MIN_BYTES", "2048"))


# Enforced per-request timeout (seconds) applied to all proxy validations
_ENFORCED_TIMEOUT_SECONDS = 25.0

# Aggressive streaming reader tunables
_READ_WINDOW_SECONDS = float(os.getenv("PROXXY_VALIDATOR_READ_SECONDS", "1.0"))
_CHUNK_SIZE = int(os.getenv("PROXXY_VALIDATOR_CHUNK_SIZE", "2048"))
_TTFB_SECONDS = float(os.getenv("PROXXY_VALIDATOR_TTFB_SECONDS", "0.8"))
_DEFAULT_UA = os.getenv("PROXXY_VALIDATOR_USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

def _get_session(timeout: float, verify_ssl: bool, user_agent: Optional[str] = None) -> requests.Session:
    sess: Optional[requests.Session] = getattr(_thread_local, "session", None)
    if sess is not None:
        return sess

    sess = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=256,
        pool_maxsize=256,
        max_retries=Retry(total=0, connect=0, read=0, redirect=0, backoff_factor=0),
    )
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    # Honor verify flag to enforce TLS verification
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
    else:
        ua = os.getenv("PROXXY_VALIDATOR_USER_AGENT", _DEFAULT_UA)
        if ua:
            sess.headers["User-Agent"] = ua
    # Store enforced per-request timeout (connect, read) on the session
    sess.request_timeout = (_ENFORCED_TIMEOUT_SECONDS, _ENFORCED_TIMEOUT_SECONDS)  # type: ignore[attr-defined]
    _thread_local.session = sess
    return sess


def _check_one_requests(
    proxy: str, url: str, timeout: float, verify_ssl: bool, user_agent: Optional[str]
) -> Tuple[str, bool, Optional[int], Optional[str], Optional[float], Optional[str]]:
    """
    Validate via Python Requests (certifi/system depending on env).
    Success when:
    - HTTP status is 2xx/3xx
    - Downloaded body size >= _MIN_BYTES
    """
    sess = _get_session(timeout, verify_ssl, user_agent)
    proxies = {"http": proxy, "https": proxy}
    try:
        t0 = time.monotonic()
        resp = sess.get(
            url,
            proxies=proxies,
            timeout=getattr(sess, "request_timeout", (_ENFORCED_TIMEOUT_SECONDS, _ENFORCED_TIMEOUT_SECONDS)),
            stream=True,
            allow_redirects=True,
        )
        total = 0
        start_read = time.monotonic()
        seen_first = False
        try:
            for chunk in resp.iter_content(chunk_size=max(1, _CHUNK_SIZE)):
                now = time.monotonic()
                # TTFB guard: if no data within threshold, treat as failure
                if not seen_first and (now - start_read) >= float(_TTFB_SECONDS):
                    break
                if not chunk:
                    if (now - start_read) >= float(_READ_WINDOW_SECONDS):
                        break
                    continue
                if not seen_first:
                    seen_first = True
                total += len(chunk)
                if total >= max(1, _MIN_BYTES) or (now - start_read) >= float(_READ_WINDOW_SECONDS):
                    break
        except Exception:
            # treat read errors as failure
            pass
        ok = (200 <= resp.status_code < 400) and (total >= max(1, _MIN_BYTES))
        try:
            elapsed = float(resp.elapsed.total_seconds()) if resp.elapsed is not None else None
        except Exception:
            elapsed = None
        if elapsed is None:
            elapsed = time.monotonic() - t0
        final_url = resp.url
        status = resp.status_code
        resp.close()
        return proxy, ok, status, None if ok else f"http={status} bytes={total}", elapsed, final_url
    except Exception as e:
        return proxy, False, None, str(e), None, None


def _check_one(
    proxy: str, url: str, timeout: float, verify_ssl: bool, user_agent: Optional[str]
) -> Tuple[str, bool, Optional[int], Optional[str], Optional[float], Optional[str]]:
    # Single implementation: Requests only
    return _check_one_requests(proxy, url, timeout, verify_ssl, user_agent)


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

    max_workers = max(1, int(workers))
    with futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="proxychk") as ex:
        inflight: Set[futures.Future] = set()
        prox_iter = iter(proxies)
        while len(inflight) < max_workers:
            nxt = _next_unique(prox_iter)
            if nxt is None:
                break
            inflight.add(ex.submit(_check_one, nxt, url, timeout, verify_ssl, user_agent))
            submitted += 1
            if len(inflight) > peak_inflight:
                peak_inflight = len(inflight)

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
                nxt = _next_unique(prox_iter)
                if nxt is not None:
                    inflight.add(ex.submit(_check_one, nxt, url, timeout, verify_ssl, user_agent))
                    submitted += 1
                    if len(inflight) > peak_inflight:
                        peak_inflight = len(inflight)

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
    results.sort(key=lambda r: (float("inf") if r.get("elapsed") is None else r["elapsed"]))
    live_sorted = [r["proxy"] for r in results]
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
    Streaming validation. Invokes on_live for each success.
    Success = 2xx/3xx AND at least _MIN_BYTES bytes downloaded.
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

    if stop_event is not None:
        should_stop = stop_event.is_set  # type: ignore[attr-defined]
    else:
        should_stop = lambda: False

    max_workers = max(1, int(workers))
    with futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="proxychk") as ex:
        inflight: Set[futures.Future] = set()
        prox_iter = iter(proxies)
        while len(inflight) < max_workers and not should_stop():
            nxt = _next_unique(prox_iter)
            if nxt is None:
                break
            inflight.add(ex.submit(_check_one, nxt, url, timeout, verify_ssl, user_agent))
            submitted += 1
            if len(inflight) > peak_inflight:
                peak_inflight = len(inflight)

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
                    try:
                        on_live(proxy, details)
                    except Exception:
                        pass
                    successes += 1
                    results.append(
                        {
                            "proxy": proxy,
                            "status": status,
                            "elapsed": elapsed,
                            "final_url": final_url,
                        }
                    )
                else:
                    if on_result is not None:
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

                nxt = _next_unique(prox_iter)
                if nxt is not None and not should_stop():
                    inflight.add(ex.submit(_check_one, nxt, url, timeout, verify_ssl, user_agent))
                    submitted += 1
                    if len(inflight) > peak_inflight:
                        peak_inflight = len(inflight)

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