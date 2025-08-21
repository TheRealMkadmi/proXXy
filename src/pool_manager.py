from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Dict, Tuple
from collections import OrderedDict

import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector  # type: ignore[import-not-found]

logger = logging.getLogger("proXXy.poolmgr")
if not logger.handlers:
    logging.basicConfig(
        level=os.environ.get("PROXXY_LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(processName)s(%(process)d)/%(threadName)s: %(message)s",
    )


def _normalize_proxy(s: str) -> Optional[str]:
    s = (s or "").strip()
    if not s or s.startswith("#"):
        return None
    if "://" not in s:
        s = "http://" + s
    scheme = s.split("://", 1)[0].lower()
    if scheme not in ("http", "https", "socks4", "socks5"):
        return None
    return s


class LivePool:
    """
    Thread-safe in-memory pool of upstream proxies in canonical scheme://host:port form.
    Maintains insertion order and de-duplicates entries.
    Exposes oldest()/latest() for rechecks. TTL-based eviction has been removed.
    """
    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Maintain proxies in insertion/recency order with O(1) move-to-end
        # Mapping: proxy -> last_seen_ts
        self._ord: "OrderedDict[str, float]" = OrderedDict()

    def add(self, proxy: str, now: Optional[float] = None) -> bool:
        p = _normalize_proxy(proxy)
        if not p:
            return False
        ts = time.time() if now is None else float(now)
        with self._lock:
            if p in self._ord:
                # Refresh timestamp and recency
                self._ord[p] = ts
                self._ord.move_to_end(p, last=True)
                return False
            self._ord[p] = ts
            return True

    def add_many(self, proxies: Iterable[str], now: Optional[float] = None) -> int:
        n = 0
        ts = time.time() if now is None else float(now)
        with self._lock:
            for proxy in proxies:
                p = _normalize_proxy(proxy)
                if not p:
                    continue
                if p in self._ord:
                    self._ord[p] = ts
                    self._ord.move_to_end(p, last=True)
                    continue
                self._ord[p] = ts
                n += 1
        return n

    def remove(self, proxy: str) -> bool:
        p = _normalize_proxy(proxy)
        if not p:
            return False
        with self._lock:
            if p not in self._ord:
                return False
            try:
                self._ord.pop(p, None)
            except Exception:
                return False
            return True

    def clear(self) -> None:
        with self._lock:
            self._ord.clear()

    def snapshot(self) -> List[str]:
        with self._lock:
            return list(self._ord.keys())

    def size(self) -> int:
        with self._lock:
            return len(self._ord)

    def oldest(self, n: int) -> List[str]:
        """
        Return up to n proxies from the front of the list (oldest by recency).
        """
        n = max(0, int(n))
        with self._lock:
            if n == 0 or not self._ord:
                return []
            k = min(n, len(self._ord))
            out: List[str] = []
            i = 0
            for key in self._ord.keys():
                out.append(key)
                i += 1
                if i >= k:
                    break
            return out

    def latest(self, n: int) -> List[str]:
        """
        Return up to n proxies from the end of the list (newest by recency).
        """
        n = max(0, int(n))
        with self._lock:
            if n == 0 or not self._ord:
                return []
            k = min(n, len(self._ord))
            # Efficient tail slice via reversed iterator
            res = []
            for idx, key in enumerate(reversed(self._ord.keys())):
                if idx >= k:
                    break
                res.append(key)
            res.reverse()
            return res

    # TTL-based prune method removed.


class FileSyncWriter:
    """
    Debounced, atomic file writer for the proxy list.

    Guarantees:
    - Writes complete snapshots only (no partial lines).
    - Uses os.replace() to atomically swap temp file into place.
    - Debounces frequent updates to reduce I/O churn during bursts.
    """
    def __init__(self, pool: LivePool, path: str, debounce_ms: int = 150) -> None:
        self.pool = pool
        self.path = os.path.abspath(path)
        self.tmp_path = self.path + ".tmp"
        self.debounce_s = max(0.0, int(debounce_ms) / 1000.0)
        self._lock = threading.RLock()
        self._pending = False
        self._stop = threading.Event()
        self._timer: Optional[threading.Timer] = None
        # Ensure directory exists
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)

    def stop(self) -> None:
        with self._lock:
            self._stop.set()
            t = self._timer
            self._timer = None
        if t:
            try:
                t.cancel()
            except Exception:
                pass
        # Best-effort final flush
        try:
            self._write_once()
        except Exception:
            pass

    def schedule(self) -> None:
        with self._lock:
            if self._stop.is_set():
                return
            # Coalesce requests within debounce window
            if self._timer is not None:
                try:
                    self._timer.cancel()
                except Exception:
                    pass
                self._timer = None
            delay = self.debounce_s
            if delay <= 0:
                # immediate write in a detached thread to avoid caller blocking
                threading.Thread(target=self._write_once, name="pool-file-write", daemon=True).start()
            else:
                self._timer = threading.Timer(delay, self._write_once)
                self._timer.daemon = True
                self._timer.start()

    def _write_once(self) -> None:
        # Take snapshot outside lock to minimize contention
        items = self.pool.snapshot()
        data = ("\n".join(items) + ("\n" if items else "")).encode("utf-8", errors="replace")
        # Atomic replace pattern
        try:
            with open(self.tmp_path, "wb") as f:
                f.write(data)
                try:
                    f.flush()
                    os.fsync(f.fileno())
                except Exception:
                    # fsync may not be available or necessary on some platforms
                    pass
            # Replace atomically
            os.replace(self.tmp_path, self.path)
        except Exception as e:
            logger.warning("pool-file: write failed path=%s err=%s", self.path, e)


@dataclass
class PoolManagerConfig:
    file_path: str
    debounce_ms: int
    prune_interval_seconds: int
    health_check_url: Optional[str]
    # Recheck controls (centralized; no env lookups at runtime)
    enable_recheck: bool = True
    recheck_interval_seconds: float | int | None = None  # default to prune interval when None
    recheck_order: str = "newest"  # "newest" | "oldest"
    recheck_per_interval: int = 25
    recheck_workers: int = 8
    recheck_timeout: float = 3.0
    recheck_connect_timeout: float = 1.8
    recheck_min_bytes: int = 1024
    recheck_read_seconds: float = 2.5
    recheck_ttfb_seconds: float = 2.0
    recheck_chunk_size: int = 8192
    recheck_strikes_threshold: int = 2


class PoolManager:
    """
    In-process pool manager:
    - Maintains a LivePool of proxies (dedup, ordering, refresh-by-recheck).
    - Actively re-checks entries; TTL pruning removed.
    - Optionally re-checks a sample to remove dead proxies.
    - Mirrors the pool to a text file via atomic, debounced writes for consumption by the proxy server.
    """
    def __init__(self, cfg: PoolManagerConfig, pool: Optional[LivePool] = None) -> None:
        self.pool = pool or LivePool()
        self.cfg = cfg
        self.file_sync = FileSyncWriter(self.pool, cfg.file_path, cfg.debounce_ms)

        self._stop_ev = threading.Event()
        self._prune_thread = threading.Thread(target=self._prune_loop, name="pool-prune", daemon=True)
        self._recheck_thread: Optional[threading.Thread] = None
        # Recheck strike tracking to avoid removing on single transient failure
        self._recheck_strikes: Dict[str, int] = {}

    # Lifecycle
    def start(self) -> None:
        logger.info(
            "pool: start (prune=%ss recheck=%s url=%s file=%s debounce=%sms size=%s)",
            self.cfg.prune_interval_seconds,
            "on" if (self.cfg.enable_recheck and self.cfg.health_check_url) else "off",
            self.cfg.health_check_url or "-",
            self.cfg.file_path,
            self.cfg.debounce_ms,
            self.pool.size(),
        )
    # Initial write so the proxy server sees an empty file immediately
        try:
            self.file_sync.schedule()
        except Exception:
            pass
    # No TTL-based prune loop; reserved for future housekeeping if needed
        if self.cfg.enable_recheck and self.cfg.health_check_url:
            self._recheck_thread = threading.Thread(target=self._recheck_loop, name="pool-recheck", daemon=True)
            self._recheck_thread.start()

    def stop(self) -> None:
        try:
            self._stop_ev.set()
            self.file_sync.stop()
        except Exception:
            pass

    # Mutations
    def add(self, proxy: str) -> bool:
        added = self.pool.add(proxy)
        if added:
            self.file_sync.schedule()
        return added

    def add_many(self, proxies: Iterable[str]) -> int:
        n = self.pool.add_many(proxies)
        if n > 0:
            self.file_sync.schedule()
        return n

    def remove(self, proxy: str) -> bool:
        ok = self.pool.remove(proxy)
        if ok:
            self.file_sync.schedule()
        return ok

    def clear(self) -> None:
        self.pool.clear()
        self.file_sync.schedule()

    # Introspection
    def snapshot(self) -> List[str]:
        return self.pool.snapshot()

    def size(self) -> int:
        return self.pool.size()

    # Background loops
    def _prune_loop(self) -> None:
        # TTL pruning removed; keep method placeholder for potential future housekeeping
        while not self._stop_ev.wait(max(1, int(self.cfg.prune_interval_seconds))):
            try:
                pass
            except Exception:
                pass

    async def _recheck_one_async(self, session: aiohttp.ClientSession, pxy: str, health_url: str) -> Tuple[str, bool]:
        """
        Re-check a single proxy against health_url.
        - HTTP/HTTPS: reuse provided session with per-request proxy param.
        - SOCKS4/5: create a short-lived session using ProxyConnector for this proxy.
        """
        # Tunables (from config)
        min_bytes = int(self.cfg.recheck_min_bytes)
        read_window = float(self.cfg.recheck_read_seconds)
        ttfb = float(self.cfg.recheck_ttfb_seconds)
        chunk_size = int(self.cfg.recheck_chunk_size)
        # Choose path based on scheme
        sch = (pxy.split("://", 1)[0].lower() if "://" in pxy else "http")
        try:
            if sch in ("socks4", "socks5"):
                # Build a dedicated session for this SOCKS proxy
                timeout_total = float(self.cfg.recheck_timeout)
                connect_to = float(self.cfg.recheck_connect_timeout)
                tmo = aiohttp.ClientTimeout(total=max(0.1, timeout_total), connect=min(connect_to, timeout_total))
                connector2 = ProxyConnector.from_url(pxy, rdns=True)
                async with aiohttp.ClientSession(timeout=tmo, connector=connector2, trust_env=False) as sess2:
                    async with sess2.get(health_url, allow_redirects=True) as resp:
                        if not (200 <= resp.status < 400):
                            return pxy, False
                        total = 0
                        seen = False
                        t_start = time.monotonic()
                        async for chunk in resp.content.iter_chunked(max(1, int(chunk_size))):
                            now = time.monotonic()
                            if not seen and (now - t_start) >= ttfb:
                                return pxy, False
                            if not chunk:
                                if (now - t_start) >= read_window:
                                    break
                                continue
                            seen = True
                            total += len(chunk)
                            if total >= max(1, min_bytes) or (now - t_start) >= read_window:
                                break
                        return pxy, (seen and total >= max(1, min_bytes))
            else:
                async with session.get(health_url, proxy=pxy, allow_redirects=True) as resp:
                    if not (200 <= resp.status < 400):
                        return pxy, False
                    total = 0
                    seen = False
                    t_start = time.monotonic()
                    async for chunk in resp.content.iter_chunked(max(1, int(chunk_size))):
                        now = time.monotonic()
                        if not seen and (now - t_start) >= ttfb:
                            return pxy, False
                        if not chunk:
                            if (now - t_start) >= read_window:
                                break
                            continue
                        seen = True
                        total += len(chunk)
                        if total >= max(1, min_bytes) or (now - t_start) >= read_window:
                            break
                    return pxy, (seen and total >= max(1, min_bytes))
        except Exception:
            return pxy, False

    def _recheck_loop(self) -> None:
        # Resolve and validate health URL locally
        health_url = self.cfg.health_check_url
        if not isinstance(health_url, str) or not health_url:
            return
        interval_cfg = self.cfg.recheck_interval_seconds
        interval = float(self.cfg.prune_interval_seconds if (interval_cfg is None) else interval_cfg)
        # Persistent event loop and HTTP session to improve throughput
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
        except Exception:
            pass
        timeout_total = float(self.cfg.recheck_timeout)
        connect_to = float(self.cfg.recheck_connect_timeout)
        tmo = aiohttp.ClientTimeout(total=max(0.1, timeout_total), connect=min(connect_to, timeout_total))
        headers = {
            "Accept": "*/*",
            "Connection": "keep-alive",
        }

        async def _make_session():
            return aiohttp.ClientSession(timeout=tmo, headers=headers, trust_env=False)

        session = loop.run_until_complete(_make_session())
        try:
            while not self._stop_ev.wait(max(0.2, interval)):
                try:
                    order = (self.cfg.recheck_order or "newest").strip().lower()
                    count = int(self.cfg.recheck_per_interval)
                    sample = self.pool.latest(count) if order == "newest" else self.pool.oldest(count)
                    if not sample:
                        continue

                    async def _run_batch(sess: aiohttp.ClientSession, items: List[str]) -> Dict[str, bool]:
                        sem = asyncio.Semaphore(max(1, int(self.cfg.recheck_workers)))
                        results: Dict[str, bool] = {}

                        async def one(p: str):
                            async with sem:
                                px, ok = await self._recheck_one_async(sess, p, health_url)
                                results[px] = ok

                        tasks = [asyncio.create_task(one(p)) for p in items]
                        if tasks:
                            await asyncio.gather(*tasks, return_exceptions=True)
                        return results

                    outcome = loop.run_until_complete(_run_batch(session, sample))
                    removed = 0
                    ok_count = 0
                    for pxy, ok in outcome.items():
                        if ok:
                            ok_count += 1
                            try:
                                self._recheck_strikes.pop(pxy, None)
                            except Exception:
                                pass
                        else:
                            cnt = int(self._recheck_strikes.get(pxy, 0)) + 1
                            self._recheck_strikes[pxy] = cnt
                            if cnt >= int(self.cfg.recheck_strikes_threshold):
                                if self.pool.remove(pxy):
                                    removed += 1
                                try:
                                    self._recheck_strikes.pop(pxy, None)
                                except Exception:
                                    pass
                    if removed:
                        self.file_sync.schedule()
                    if removed or ok_count:
                        logger.info("pool: recheck url=%s ok=%s removed=%s size=%s", health_url, ok_count, removed, self.pool.size())
                except Exception:
                    # Never crash recheck thread
                    pass
        finally:
            try:
                loop.run_until_complete(session.close())
            except Exception:
                pass
            try:
                pending = asyncio.all_tasks(loop)
            except Exception:
                pending = set()
            for t in pending:
                try:
                    t.cancel()
                except Exception:
                    pass
            try:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            except Exception:
                pass
            try:
                loop.close()
            except Exception:
                pass


# Utility for ingesting producer updates from an mp.Queue of batches
def pool_ingest_loop(stop_evt: threading.Event, q, pool: PoolManager) -> None:
    """
    Consume batches from the producer process and add to the pool.
    Supported message shapes:
    - list[str]
    - dict with {"type": "add", "proxies": [...]}
    """
    try:
        while not stop_evt.is_set():
            try:
                msg = q.get(timeout=0.5)
            except Exception:
                continue
            try:
                if isinstance(msg, list):
                    pool.add_many(msg)
                elif isinstance(msg, dict):
                    mtyp = msg.get("type")
                    if mtyp == "add":
                        arr = msg.get("proxies") or []
                        if isinstance(arr, list):
                            pool.add_many([str(x) for x in arr])
                    elif mtyp == "remove":
                        p = msg.get("proxy")
                        if isinstance(p, str):
                            pool.remove(p)
                    elif mtyp == "clear":
                        pool.clear()
                # else ignore
            except Exception:
                # Do not crash the ingest loop
                pass
    except Exception:
        pass