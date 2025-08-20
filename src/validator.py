import asyncio
import os
import sys
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

import aiohttp
from aiohttp_socks import ProxyConnector  # type: ignore[import-not-found]
from loguru import logger

# Logging setup (kept simple)
_LOG_LEVEL = os.getenv("PROXXY_VALIDATOR_LOG_LEVEL", os.getenv("PROXXY_LOG_LEVEL", "INFO"))
try:
    logger.remove()
except Exception:
    pass
_LOG_ENQUEUE = os.getenv("PROXXY_VALIDATOR_LOG_ENQUEUE", os.getenv("PROXXY_LOG_ENQUEUE", "0")).strip()
_ENQUEUE_BOOL = _LOG_ENQUEUE.lower() not in ("0", "false", "no", "off")
logger.add(sys.stderr, level=_LOG_LEVEL, backtrace=False, diagnose=False, enqueue=_ENQUEUE_BOOL)

OnLiveFn = Callable[[str, Dict[str, Any]], None]
OnResultFn = Callable[[Dict[str, Any]], None]

# Simple tunables
_DEFAULT_TARGET = os.getenv("PROXXY_VALIDATION_URL", "https://www.netflix.com/")
_DEFAULT_UA = os.getenv(
    "PROXXY_VALIDATOR_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
)
_MIN_BYTES = int(os.getenv("PROXXY_VALIDATOR_MIN_BYTES", "1024"))
_READ_WINDOW_SECONDS = float(os.getenv("PROXXY_VALIDATOR_READ_SECONDS", "2.5"))
_TTFB_SECONDS = float(os.getenv("PROXXY_VALIDATOR_TTFB_SECONDS", "2.0"))
_CHUNK_SIZE = int(os.getenv("PROXXY_VALIDATOR_CHUNK_SIZE", "8192"))


async def _validate_one(
    session: aiohttp.ClientSession,
    proxy: str,
    url: str,
    ttfb_seconds: float,
    read_seconds: float,
) -> Tuple[str, bool, Optional[int], Optional[str], Optional[float], Optional[str]]:
    t0 = time.monotonic()
    status: Optional[int] = None
    final_url: Optional[str] = None
    err: Optional[str] = None
    ok = False

    try:
        async with session.get(url, proxy=proxy, allow_redirects=True) as resp:
            status = resp.status
            final_url = str(resp.url)

            # Require 2xx/3xx
            if not (200 <= resp.status < 400):
                return proxy, False, status, f"http_status_{resp.status}", time.monotonic() - t0, final_url

            # Stream a bit and enforce TTFB + min bytes
            total = 0
            seen_first = False
            start_read = time.monotonic()
            async for chunk in resp.content.iter_chunked(max(1, _CHUNK_SIZE)):
                now = time.monotonic()
                if not seen_first and (now - start_read) >= ttfb_seconds:
                    err = "ttfb_timeout"
                    break
                if not chunk:
                    if (now - start_read) >= read_seconds:
                        break
                    continue
                seen_first = True
                total += len(chunk)
                if total >= max(1, _MIN_BYTES) or (now - start_read) >= read_seconds:
                    break

            ok = seen_first and total >= max(1, _MIN_BYTES)
            if not ok and err is None:
                err = f"bytes={total}"
    except asyncio.TimeoutError:
        err = "timeout"
    except aiohttp.ClientProxyConnectionError as e:
        err = f"proxy_connect:{e.__class__.__name__}"
    except aiohttp.ClientSSLError:
        err = "tls_verify"
    except aiohttp.ClientError as e:
        err = f"client:{e.__class__.__name__}"
    except Exception as e:
        err = str(e)

    elapsed = time.monotonic() - t0
    return proxy, ok, status, (None if ok else err), elapsed, final_url


async def _run_stream_async(
    proxies: Iterable[str],
    url: str,
    workers: int,
    timeout: float,
    on_live: OnLiveFn,
    on_result: Optional[OnResultFn],
    user_agent: Optional[str],
    total: Optional[int],
    stop_event: Optional[threading.Event],
    *,
    store_results: bool,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """
    Bounded worker-pool validator:
    - Exactly `workers` consumers pull from an asyncio.Queue (maxsize = workers * 2).
    - Avoids creating one Task per proxy (prevents memory/GC pressure).
    - Optionally stores results (disable in streaming to avoid O(n) memory growth).
    """
    seen: Set[str] = set()
    results: List[Dict[str, Any]] = []
    live_list: List[str] = []

    headers = {
        "Accept": "*/*",
        "Accept-Language": os.getenv("PROXXY_VALIDATOR_ACCEPT_LANGUAGE", "en-US,en;q=0.9"),
        "User-Agent": user_agent or _DEFAULT_UA,
        "Connection": "keep-alive",
    }

    # Concurrency bounded by number of consumers; also align connector limits
    workers = max(1, int(workers))
    timeout_cfg = aiohttp.ClientTimeout(total=float(max(0.1, timeout)), connect=float(min(timeout, 5.0)))
    connector = aiohttp.TCPConnector(limit=workers, limit_per_host=workers)

    start = time.time()
    last_log = time.monotonic()
    completed = 0

    async with aiohttp.ClientSession(headers=headers, timeout=timeout_cfg, connector=connector, trust_env=False) as session:
        q: asyncio.Queue[Optional[str]] = asyncio.Queue(maxsize=max(1, workers * 2))

        async def consume():
            nonlocal completed, last_log
            while True:
                try:
                    p = await q.get()
                except Exception:
                    break
                if p is None:
                    q.task_done()
                    break
                # Respect external stop: drop remaining work quickly
                if stop_event is not None and stop_event.is_set():
                    q.task_done()
                    continue

                proxy = p.strip()
                if not proxy:
                    q.task_done()
                    continue

                # Route by scheme: HTTP(S) via shared session+proxy param; SOCKS via per-proxy ProxyConnector
                sch = proxy.split("://", 1)[0].lower() if "://" in proxy else "http"
                if sch in ("socks4", "socks5"):
                    t0 = time.monotonic()
                    status: Optional[int] = None
                    final_url: Optional[str] = None
                    err: Optional[str] = None
                    ok = False
                    try:
                        connector2 = ProxyConnector.from_url(proxy, rdns=True)
                        timeout_cfg2 = aiohttp.ClientTimeout(total=float(max(0.1, timeout)), connect=float(min(timeout, 5.0)))
                        async with aiohttp.ClientSession(headers=headers, timeout=timeout_cfg2, connector=connector2, trust_env=False) as session2:
                            async with session2.get(url, allow_redirects=True) as resp:
                                status = resp.status
                                final_url = str(resp.url)
                                if not (200 <= resp.status < 400):
                                    prx = proxy
                                    elapsed = time.monotonic() - t0
                                    ok = False
                                    err = f"http_status_{resp.status}"
                                else:
                                    read_total = 0
                                    seen_first = False
                                    start_read = time.monotonic()
                                    async for chunk in resp.content.iter_chunked(max(1, _CHUNK_SIZE)):
                                        now2 = time.monotonic()
                                        if not seen_first and (now2 - start_read) >= _TTFB_SECONDS:
                                            err = "ttfb_timeout"
                                            break
                                        if not chunk:
                                            if (now2 - start_read) >= _READ_WINDOW_SECONDS:
                                                break
                                            continue
                                        seen_first = True
                                        read_total += len(chunk)
                                        if read_total >= max(1, _MIN_BYTES) or (now2 - start_read) >= _READ_WINDOW_SECONDS:
                                            break
                                    ok = seen_first and read_total >= max(1, _MIN_BYTES)
                                    if not ok and err is None:
                                        err = f"bytes={read_total}"
                        prx = proxy
                        elapsed = time.monotonic() - t0
                    except asyncio.TimeoutError:
                        prx = proxy
                        elapsed = time.monotonic() - t0
                        err = "timeout"
                        ok = False
                    except Exception as e:
                        prx = proxy
                        elapsed = time.monotonic() - t0
                        err = str(e)
                        ok = False
                else:
                    prx, ok, status, err, elapsed, final_url = await _validate_one(
                        session, proxy, url, _TTFB_SECONDS, _READ_WINDOW_SECONDS
                    )

                completed += 1
                details = {
                    "proxy": prx,
                    "ok": ok,
                    "status": status,
                    "error": err,
                    "elapsed": elapsed,
                    "final_url": final_url,
                }
                if ok:
                    try:
                        on_live(prx, details)
                    except Exception:
                        pass
                    live_list.append(prx)
                    if store_results:
                        results.append({"proxy": prx, "status": status, "elapsed": elapsed, "final_url": final_url})
                else:
                    if on_result is not None:
                        if store_results:
                            results.append({
                                "proxy": prx,
                                "status": status,
                                "elapsed": elapsed,
                                "final_url": final_url,
                                "error": err,
                            })
                        try:
                            on_result(details)
                        except Exception:
                            pass

                now = time.monotonic()
                if now - last_log >= 1.0 or (total and completed and completed % 100 == 0):
                    elapsed_total = max(1e-6, time.time() - start)
                    rate = completed / elapsed_total
                    pct = (completed / total * 100.0) if total else None
                    if pct is not None:
                        logger.debug(
                            "progress: {}/{} ({:.1f}%) done | live={} | rate={:.1f}/s | inflight~{}",
                            completed,
                            total or 0,
                            pct,
                            len(live_list),
                            rate,
                            int(workers),
                        )
                    else:
                        logger.debug(
                            "progress: {} done | live={} | rate={:.1f}/s | inflight~{}",
                            completed,
                            len(live_list),
                            rate,
                            int(workers),
                        )
                    last_log = now
                q.task_done()

        consumers = [asyncio.create_task(consume()) for _ in range(workers)]

        # Producer inline: enqueue unique, non-empty proxies
        for p in proxies:
            if stop_event is not None and stop_event.is_set():
                break
            s = (p or "").strip()
            if not s:
                continue
            if s in seen:
                continue
            seen.add(s)
            await q.put(s)

        # Signal completion
        for _ in range(len(consumers)):
            await q.put(None)

        # Wait for queue to drain and consumers to exit
        try:
            await q.join()
        except Exception:
            pass
        try:
            await asyncio.gather(*consumers, return_exceptions=True)
        except Exception:
            pass

    # Keep API: sort results by elapsed (if collected)
    if results:
        results.sort(key=lambda r: (float("inf") if r.get("elapsed") is None else r["elapsed"]))

    elapsed_total = time.time() - start
    logger.success(
        "done(stream): checked~{} live={} elapsed={:.1f}s peak_workers={}",
        len(seen),
        len(live_list),
        elapsed_total,
        int(workers),
    )
    return list(live_list), (results if store_results else [])


def check_proxies(
    proxies: Iterable[str],
    url: str,
    workers: int,
    timeout: float,
    verify_ssl: bool = True,  # kept for compatibility; aiohttp verifies by default
    user_agent: Optional[str] = None,
    total: Optional[int] = None,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    # Always use aiohttp against the provided URL (default Netflix)
    target = url or _DEFAULT_TARGET

    def _noop_live(_p: str, _d: Dict[str, Any]) -> None:
        return

    live, results = asyncio.run(
        _run_stream_async(
            proxies=proxies,
            url=target,
            workers=workers,
            timeout=timeout,
            on_live=_noop_live,
            on_result=None,
            user_agent=user_agent,
            total=total,
            stop_event=None,
            store_results=True,  # collect results for non-streaming API
        )
    )
    return live, results


def check_proxies_stream(
    proxies: Iterable[str],
    url: str,
    workers: int,
    timeout: float,
    on_live: OnLiveFn,
    on_result: Optional[OnResultFn] = None,
    verify_ssl: bool = True,  # kept for API compatibility
    user_agent: Optional[str] = None,
    total: Optional[int] = None,
    stop_event: Optional[threading.Event] = None,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    target = url or _DEFAULT_TARGET
    return asyncio.run(
        _run_stream_async(
            proxies=proxies,
            url=target,
            workers=workers,
            timeout=timeout,
            on_live=on_live,
            on_result=on_result,
            user_agent=user_agent,
            total=total,
            stop_event=stop_event,
            store_results=False,  # avoid O(n) accumulation in streaming mode
        )
    )