from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Dict, Tuple

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
    Supports TTL-based eviction via prune_expired(), and exposes oldest() for rechecks.
    """
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._list: List[str] = []
        self._set = set()
        # last_seen timestamps (epoch seconds)
        self._meta: Dict[str, float] = {}

    def add(self, proxy: str, now: Optional[float] = None) -> bool:
        p = _normalize_proxy(proxy)
        if not p:
            return False
        ts = time.time() if now is None else float(now)
        with self._lock:
            if p in self._set:
                # Update last_seen and move to end to refresh recency
                self._meta[p] = ts
                try:
                    self._list.remove(p)
                    self._list.append(p)
                except ValueError:
                    self._list.append(p)
                return False
            self._list.append(p)
            self._set.add(p)
            self._meta[p] = ts
            return True

    def add_many(self, proxies: Iterable[str], now: Optional[float] = None) -> int:
        n = 0
        ts = time.time() if now is None else float(now)
        with self._lock:
            for proxy in proxies:
                p = _normalize_proxy(proxy)
                if not p:
                    continue
                if p in self._set:
                    self._meta[p] = ts
                    try:
                        self._list.remove(p)
                        self._list.append(p)
                    except ValueError:
                        self._list.append(p)
                    continue
                self._list.append(p)
                self._set.add(p)
                self._meta[p] = ts
                n += 1
        return n

    def remove(self, proxy: str) -> bool:
        p = _normalize_proxy(proxy)
        if not p:
            return False
        with self._lock:
            if p not in self._set:
                return False
            self._set.remove(p)
            self._meta.pop(p, None)
            try:
                self._list.remove(p)
            except ValueError:
                pass
            return True

    def clear(self) -> None:
        with self._lock:
            self._list.clear()
            self._set.clear()
            self._meta.clear()

    def snapshot(self) -> List[str]:
        with self._lock:
            return list(self._list)

    def size(self) -> int:
        with self._lock:
            return len(self._list)

    def oldest(self, n: int) -> List[str]:
        """
        Return up to n proxies from the front of the list (oldest by recency).
        """
        n = max(0, int(n))
        with self._lock:
            if n == 0 or not self._list:
                return []
            return list(self._list[: min(n, len(self._list))])

    def latest(self, n: int) -> List[str]:
        """
        Return up to n proxies from the end of the list (newest by recency).
        """
        n = max(0, int(n))
        with self._lock:
            if n == 0 or not self._list:
                return []
            k = min(n, len(self._list))
            return list(self._list[-k:])

    def prune_expired(self, ttl_seconds: float, now: Optional[float] = None) -> int:
        """
        Remove entries whose last_seen is older than now - ttl_seconds.
        Returns the number of removed entries.
        """
        if ttl_seconds <= 0:
            return 0
        ts_now = time.time() if now is None else float(now)
        cutoff = ts_now - ttl_seconds
        removed = 0
        with self._lock:
            survivors: List[str] = []
            for p in self._list:
                last_seen = self._meta.get(p, 0.0)
                if last_seen >= cutoff:
                    survivors.append(p)
                else:
                    self._set.discard(p)
                    self._meta.pop(p, None)
                    removed += 1
            if removed:
                self._list = survivors
        return removed


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
    ttl_seconds: int
    prune_interval_seconds: int
    health_check_url: Optional[str]
    recheck_timeout: float = 3.0
    recheck_per_interval: int = 25
    recheck_workers: int = 8
    enable_recheck: bool = True


class PoolManager:
    """
    In-process pool manager:
    - Maintains a LivePool of proxies (dedup, ordering, TTL refresh).
    - Periodically prunes by TTL.
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
        self._recheck_strike_threshold = int(os.getenv("PROXXY_POOL_RECHECK_STRIKES", "2"))

    # Lifecycle
    def start(self) -> None:
        logger.info(
            "pool: start (ttl=%ss prune=%ss recheck=%s url=%s file=%s debounce=%sms size=%s)",
            self.cfg.ttl_seconds,
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
        self._prune_thread.start()
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
        last_log = time.monotonic()
        while not self._stop_ev.wait(max(1, int(self.cfg.prune_interval_seconds))):
            try:
                removed = self.pool.prune_expired(max(0, int(self.cfg.ttl_seconds)))
                size = self.pool.size()
                if removed > 0:
                    self.file_sync.schedule()
                now = time.monotonic()
                if removed > 0 or (now - last_log) >= 60.0:
                    logger.info("pool: pruned=%s size=%s ttl=%ss", removed, size, self.cfg.ttl_seconds)
                    last_log = now
            except Exception:
                # Never crash pruning thread
                pass

    async def _recheck_one_async(self, session: aiohttp.ClientSession, pxy: str, health_url: str) -> Tuple[str, bool]:
        """
        Re-check a single proxy against health_url.
        - HTTP/HTTPS: reuse provided session with per-request proxy param.
        - SOCKS4/5: create a short-lived session using ProxyConnector for this proxy.
        """
        # Tunables
        min_bytes = int(os.getenv("PROXXY_POOL_RECHECK_MIN_BYTES", os.getenv("PROXXY_VALIDATOR_MIN_BYTES", "1024")))
        read_window = float(os.getenv("PROXXY_POOL_RECHECK_READ_SECONDS", os.getenv("PROXXY_VALIDATOR_READ_SECONDS", "2.5")))
        ttfb = float(os.getenv("PROXXY_POOL_RECHECK_TTFB_SECONDS", os.getenv("PROXXY_VALIDATOR_TTFB_SECONDS", "2.0")))
        chunk_size = int(os.getenv("PROXXY_POOL_RECHECK_CHUNK_SIZE", os.getenv("PROXXY_VALIDATOR_CHUNK_SIZE", "8192")))
        # Choose path based on scheme
        sch = (pxy.split("://", 1)[0].lower() if "://" in pxy else "http")
        try:
            if sch in ("socks4", "socks5"):
                # Build a dedicated session for this SOCKS proxy
                timeout_total = float(os.getenv("PROXXY_POOL_RECHECK_TIMEOUT", "3.0"))
                connect_to = float(os.getenv("PROXXY_POOL_RECHECK_CONNECT_TIMEOUT", "1.8"))
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
        interval = float(os.getenv("PROXXY_POOL_RECHECK_INTERVAL_SECONDS", str(self.cfg.prune_interval_seconds)))
        while not self._stop_ev.wait(max(0.2, interval)):
            try:
                order = (os.getenv("PROXXY_POOL_RECHECK_ORDER", "newest") or "newest").strip().lower()
                count = int(self.cfg.recheck_per_interval)
                if order == "newest":
                    sample = self.pool.latest(count)
                else:
                    sample = self.pool.oldest(count)
                if not sample:
                    continue

                async def _run_batch() -> Dict[str, bool]:
                    timeout_total = float(os.getenv("PROXXY_POOL_RECHECK_TIMEOUT", str(self.cfg.recheck_timeout)))
                    connect_to = float(os.getenv("PROXXY_POOL_RECHECK_CONNECT_TIMEOUT", "1.8"))
                    tmo = aiohttp.ClientTimeout(total=max(0.1, timeout_total), connect=min(connect_to, timeout_total))
                    headers = {
                        "Accept": "*/*",
                        "Connection": "keep-alive",
                    }
                    sem = asyncio.Semaphore(max(1, int(self.cfg.recheck_workers)))
                    results: Dict[str, bool] = {}

                    async with aiohttp.ClientSession(timeout=tmo, headers=headers, trust_env=False) as session:
                        async def one(p: str):
                            async with sem:
                                px, ok = await self._recheck_one_async(session, p, health_url)
                                results[px] = ok

                        tasks = [asyncio.create_task(one(p)) for p in sample]
                        if tasks:
                            await asyncio.gather(*tasks, return_exceptions=True)
                    return results

                outcome = asyncio.run(_run_batch())
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
                        if cnt >= int(self._recheck_strike_threshold):
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