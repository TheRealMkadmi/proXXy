from __future__ import annotations

import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterable, List, Optional, Dict, Tuple
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

logger = logging.getLogger("proXXy.pool")
if not logger.handlers:
    logging.basicConfig(
        level="INFO",
        format="%(asctime)s [%(levelname)s] %(processName)s(%(process)d)/%(threadName)s: %(message)s",
    )


def _normalize_proxy(s: str) -> Optional[str]:
    s = (s or "").strip()
    if not s or s.startswith("#"):
        return None
    if "://" not in s:
        s = "http://" + s
    scheme = s.split("://", 1)[0].lower()
    if scheme not in ("http", "https"):
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


class _PoolHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, pool: LivePool, bind_and_activate=True):
        self.pool = pool
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        # Quick reuse to avoid TIME_WAIT bind issues during restarts
        self.daemon_threads = True
        self.allow_reuse_address = True


class PoolRequestHandler(BaseHTTPRequestHandler):
    server: _PoolHTTPServer  # type: ignore[assignment]

    def log_message(self, format: str, *args) -> None:  # reduce noise, match BaseHTTPRequestHandler signature
        logger.debug("pool-http: " + format, *args)

    def _read_body(self) -> bytes:
        length = 0
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except Exception:
            length = 0
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/pool":
            items = self.server.pool.snapshot()
            body = ("\n".join(items) + ("\n" if items else "")).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404, "Not Found")

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/add":
            # Enforce simple upload size cap (2 MiB) to avoid accidental large posts
            try:
                length = int(self.headers.get("Content-Length") or "0")
            except Exception:
                length = 0
            if length > 2 * 1024 * 1024:
                self.send_error(413, "Payload Too Large")
                return
            body = self._read_body()
            ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            added = 0
            try:
                if ctype == "application/json":
                    data = json.loads(body.decode("utf-8") or "[]")
                    if isinstance(data, list):
                        added = self.server.pool.add_many([str(x) for x in data])
                    else:
                        self.send_error(400, "JSON body must be a list of proxies")
                        return
                else:
                    text = body.decode("utf-8", errors="replace")
                    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
                    added = self.server.pool.add_many(lines)
            except Exception as e:
                logger.exception("pool /add failed: %s", e)
                self.send_error(500, "Internal Server Error")
                return
            resp = json.dumps({"added": added}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        if self.path == "/clear":
            self.server.pool.clear()
            self.send_response(200)
            self.end_headers()
            return

        self.send_error(404, "Not Found")


class PoolServer:
    """
    Owns the HTTP server thread, TTL pruner, and optional health re-checker.
    Health re-check samples a subset of the pool every prune interval and removes dead proxies.
    """
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9009,
        pool: Optional[LivePool] = None,
        ttl_seconds: int = 900,
        prune_interval_seconds: int = 30,
        health_check_url: Optional[str] = None,
        recheck_timeout: float = 3.0,
        recheck_per_interval: int = 25,
        recheck_workers: int = 8,
        enable_recheck: bool = True,
    ) -> None:
        self.pool = pool or LivePool()
        self._server = _PoolHTTPServer((host, port), PoolRequestHandler, self.pool)
        self._http_thread = threading.Thread(target=self._server.serve_forever, name="pool-http", daemon=True)

        self._stop_ev = threading.Event()
        self._prune_thread = threading.Thread(target=self._prune_loop, name="pool-prune", daemon=True)

        self._recheck_thread: Optional[threading.Thread] = None
        self.enable_recheck = bool(enable_recheck and health_check_url)
        self.health_check_url = health_check_url
        self.recheck_timeout = float(recheck_timeout)
        self.recheck_per_interval = int(recheck_per_interval)
        self.recheck_workers = max(1, int(recheck_workers))

        self.host = host
        self.port = port
        self.ttl_seconds = max(0, int(ttl_seconds))
        self.prune_interval_seconds = max(1, int(prune_interval_seconds))

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        logger.info(
            "pool: starting HTTP on %s:%s (ttl=%ss, prune_interval=%ss, recheck=%s url=%s)",
            self.host,
            self.port,
            self.ttl_seconds,
            self.prune_interval_seconds,
            "on" if self.enable_recheck else "off",
            self.health_check_url or "-",
        )
        self._http_thread.start()
        self._prune_thread.start()
        if self.enable_recheck:
            self._recheck_thread = threading.Thread(target=self._recheck_loop, name="pool-recheck", daemon=True)
            self._recheck_thread.start()

    def stop(self) -> None:
        try:
            logger.info("pool: stopping HTTP server")
            self._stop_ev.set()
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass

    def _prune_loop(self) -> None:
        # Periodic TTL eviction
        last_log = time.monotonic()
        while not self._stop_ev.wait(self.prune_interval_seconds):
            try:
                removed = self.pool.prune_expired(self.ttl_seconds)
                size = self.pool.size()
                # Log on change or every ~60s
                now = time.monotonic()
                if removed > 0 or (now - last_log) >= 60.0:
                    logger.info("pool: pruned=%s size=%s ttl=%ss", removed, size, self.ttl_seconds)
                    last_log = now
            except Exception:
                # Never crash pruning thread
                pass

    def _recheck_loop(self) -> None:
        """
        Sample a subset of the pool and validate quickly using requests via the proxy.
        Removes proxies that fail immediately. Runs every prune_interval_seconds.
        """
        # Resolve and validate health URL locally to satisfy type-checkers and ensure safety.
        health_url = self.health_check_url
        if not isinstance(health_url, str) or not health_url:
            return

        sess = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=max(32, self.recheck_workers * 2),
            pool_maxsize=max(64, self.recheck_workers * 4),
            max_retries=Retry(total=0, connect=0, read=0, redirect=0, backoff_factor=0),
        )
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        sess.headers.update(
            {
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Connection": "keep-alive",
            }
        )

        def _check_one(pxy: str) -> Tuple[str, bool]:
            try:
                proxies = {"http": pxy, "https": pxy}
                # Stream small content; follow redirects; tiny timeout
                resp = sess.get(
                    health_url, proxies=proxies, timeout=self.recheck_timeout, stream=True, allow_redirects=True
                )
                # Tunables (fallback to validator defaults)
                min_bytes = int(os.getenv("PROXXY_POOL_RECHECK_MIN_BYTES", os.getenv("PROXXY_VALIDATOR_MIN_BYTES", "2048")))
                read_window = float(os.getenv("PROXXY_POOL_RECHECK_READ_SECONDS", os.getenv("PROXXY_VALIDATOR_READ_SECONDS", "1.5")))
                total = 0
                t_start = time.monotonic()
                for chunk in resp.iter_content(chunk_size=2048):
                    if not chunk:
                        break
                    total += len(chunk)
                    if total >= min_bytes or (time.monotonic() - t_start) >= read_window:
                        break
                ok = (200 <= resp.status_code < 400) and (total >= max(1, min_bytes // 4))
                resp.close()
                return pxy, ok
            except Exception:
                return pxy, False

        while not self._stop_ev.wait(self.prune_interval_seconds):
            try:
                sample = self.pool.oldest(self.recheck_per_interval)
                if not sample:
                    continue
                removed = 0
                ok_count = 0
                with ThreadPoolExecutor(max_workers=self.recheck_workers, thread_name_prefix="poolchk") as ex:
                    futs = [ex.submit(_check_one, pxy) for pxy in sample]
                    for fut in as_completed(futs):
                        pxy, ok = fut.result()
                        if ok:
                            ok_count += 1
                        else:
                            if self.pool.remove(pxy):
                                removed += 1
                if removed or ok_count:
                    logger.info(
                        "pool: recheck url=%s ok=%s removed=%s size=%s",
                        health_url,
                        ok_count,
                        removed,
                        self.pool.size(),
                    )
            except Exception:
                # Never crash recheck thread
                pass

    # Convenience passthroughs
    def add(self, proxy: str) -> bool:
        return self.pool.add(proxy)

    def add_many(self, proxies: Iterable[str]) -> int:
        return self.pool.add_many(proxies)

    def clear(self) -> None:
        self.pool.clear()

    def snapshot(self) -> List[str]:
        return self.pool.snapshot()

    def size(self) -> int:
        return self.pool.size()


def start_server(
    host: str = "127.0.0.1",
    port: int = 9009,
    ttl_seconds: int = 900,
    prune_interval_seconds: int = 30,
    health_check_url: Optional[str] = None,
) -> PoolServer:
    srv = PoolServer(
        host=host,
        port=port,
        ttl_seconds=ttl_seconds,
        prune_interval_seconds=prune_interval_seconds,
        health_check_url=health_check_url,
    )
    srv.start()
    return srv