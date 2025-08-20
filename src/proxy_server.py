from __future__ import annotations

import asyncio
import base64
import logging
import os
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple, Set, cast
from urllib.parse import urlsplit

# Minimal, tunneling-only forward proxy with upstream selection via pool file.
# - Supports HTTPS via CONNECT without MITM (no TLS termination on inbound).
# - Supports plain HTTP proxying (absolute-form URIs preferred).
# - Chains through upstream HTTP/HTTPS proxies listed in a pool file.
# - No certificate re-signing, ever.

logger = logging.getLogger("proXXy.tunnel")
if not logger.handlers:
    logging.basicConfig(
        level=os.environ.get("PROXXY_LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(processName)s(%(process)d)/%(threadName)s: %(message)s",
    )

# Diagnostics controls
_DIAG_STR = os.getenv("PROXXY_TUNNEL_DIAG", "basic").strip().lower()
_DIAG_ON = _DIAG_STR not in ("0", "off", "false", "no")
_DIAG_VERBOSE = _DIAG_STR in ("verbose", "v", "debug")
_FAIL_LOG_EVERY = max(1, int(os.getenv("PROXXY_TUNNEL_FAIL_LOG_EVERY", "1")))
# Early-close classification thresholds (used to mark target-scoped backoff after short tunnels)
_EARLY_CLOSE_MAX_A2B = int(os.getenv("PROXXY_TUNNEL_EARLY_CLOSE_MAX_A2B", "4096"))
_EARLY_CLOSE_MAX_B2A = int(os.getenv("PROXXY_TUNNEL_EARLY_CLOSE_MAX_B2A", "8192"))
_EARLY_CLOSE_MAX_MS = float(os.getenv("PROXXY_TUNNEL_EARLY_CLOSE_MAX_MS", "3000"))

def _new_cid() -> str:
    try:
        n = (time.time_ns() ^ os.getpid() ^ threading.get_ident())
        return f"{n & 0xFFFFFFFFFFFF:012x}"
    except Exception:
        return f"{int(time.time()*1000) % 1000000000:09d}"


@dataclass(frozen=True)
class UpstreamProxy:
    scheme: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None

    def auth_header_value(self) -> Optional[str]:
        if self.username is None:
            return None
        creds = f"{self.username}:{self.password or ''}".encode("utf-8")
        token = base64.b64encode(creds).decode("ascii")
        return f"Basic {token}"


def _parse_upstream(uri: str) -> Optional[UpstreamProxy]:
    try:
        s = uri.strip()
        if not s:
            return None
        if "://" not in s:
            s = "http://" + s
        u = urlsplit(s)
        scheme = (u.scheme or "").lower()
        if scheme not in ("http", "https", "socks4", "socks5"):
            return None
        host = u.hostname or ""
        if not host:
            return None
        default_port = 443 if scheme == "https" else (1080 if scheme.startswith("socks") else 80)
        port = u.port or default_port
        return UpstreamProxy(
            scheme=scheme,
            host=host,
            port=int(port),
            username=u.username,
            password=u.password,
        )
    except Exception:
        return None


class PoolFileUpstreams:
    """
    Thread-safe, on-demand reloading view of the upstream pool file.
    - Lines are scheme://host:port or host:port (assumed http).
    - Comment lines ('#') and blank lines ignored.
    - Round-robin iteration across current snapshot.
    """

    def __init__(self, path: str, reload_interval: float = 1.0) -> None:
        self.path = os.path.abspath(path)
        self.reload_interval = max(0.2, float(reload_interval))
        self._lock = threading.RLock()
        self._mtime = 0.0
        self._last_check = 0.0
        self._proxies: List[UpstreamProxy] = []
        self._idx = 0

    def _reload_if_changed(self) -> None:
        now = time.monotonic()
        if (now - self._last_check) < self.reload_interval:
            return
        self._last_check = now
        try:
            mt = os.path.getmtime(self.path)
        except Exception:
            mt = 0.0
        if mt == self._mtime:
            return
        self._mtime = mt
        proxies: List[UpstreamProxy] = []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for ln in f:
                    s = (ln or "").strip()
                    if not s or s.lstrip().startswith("#"):
                        continue
                    up = _parse_upstream(s)
                    if up:
                        proxies.append(up)
        except FileNotFoundError:
            proxies = []
        except Exception as e:
            logger.warning("tunnel: failed to read pool file %s: %s", self.path, e)
        with self._lock:
            self._proxies = proxies
            if self._idx >= len(self._proxies):
                self._idx = 0

    def size(self) -> int:
        self._reload_if_changed()
        with self._lock:
            return len(self._proxies)

    def next(self) -> Optional[UpstreamProxy]:
        self._reload_if_changed()
        with self._lock:
            n = len(self._proxies)
            if n == 0:
                return None
            i = self._idx % n
            self._idx = (self._idx + 1) % (1_000_000_000)
            return self._proxies[i]

    def next_many(self, k: int) -> List[UpstreamProxy]:
        self._reload_if_changed()
        with self._lock:
            n = len(self._proxies)
            if n == 0:
                return []
            res: List[UpstreamProxy] = []
            start = self._idx
            self._idx = (self._idx + k) % (1_000_000_000)
            for j in range(min(k, n)):
                res.append(self._proxies[(start + j) % n])
            return res


class TunnelProxyServer:
    """
    Inbound TCP proxy server that forwards requests via an upstream HTTP/HTTPS proxy
    chosen from a dynamic pool.

    HTTPS: Tunnels via CONNECT without TLS interception.
    HTTP:  Proxies requests (absolute-form preferred). Minimal header rewriting.
    """

    def __init__(
        self,
        host: str,
        port: int,
        pool_file: str,
        emit: Optional[Callable[[dict], None]] = None,
        dial_timeout: float = 3.0,
        io_timeout: float = 30.0,
        max_header_bytes: int = 64 * 1024,
        max_line_bytes: int = 8192,
        max_retries: int = 2,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.emit = emit
        self.pool = PoolFileUpstreams(pool_file)
        self.dial_timeout = float(os.getenv("PROXXY_PROXY_DIAL_TIMEOUT", str(dial_timeout)))
        self.io_timeout = float(os.getenv("PROXXY_PROXY_READ_TIMEOUT", str(io_timeout)))
        self.max_header_bytes = int(max_header_bytes)
        self.max_line_bytes = int(max_line_bytes)
        self.max_retries = max(0, int(os.getenv("PROXXY_PROXY_UPSTREAM_RETRIES", str(max_retries))))
        self._server: Optional[asyncio.AbstractServer] = None
        # Failure backoff cache for upstream selection (skip recently failed endpoints)
        # Default disabled (0) to avoid any cross-request stickiness
        self.failure_ttl = float(os.getenv("PROXXY_PROXY_UPSTREAM_FAILURE_TTL", "0"))
        # Key: (scheme, host, port, username, password)
        self._failures: Dict[Tuple[str, str, int, str, str], float] = {}
        # Target-scoped failure TTL (default to upstream TTL)
        self.target_failure_ttl = float(os.getenv("PROXXY_PROXY_TARGET_FAILURE_TTL", os.getenv("PROXXY_PROXY_UPSTREAM_FAILURE_TTL", "0")))
        # Key: (target, scheme, host, port, username, password)
        self._failures_by_target: Dict[Tuple[str, str, str, int, str, str], float] = {}
        # Candidate scan controls per client request
        self.scan_max = int(os.getenv("PROXXY_PROXY_UPSTREAM_SCAN_MAX", "50"))
        self.scan_budget = float(os.getenv("PROXXY_PROXY_UPSTREAM_SCAN_BUDGET", "8.0"))
        # Dedicated idle timeout for CONNECT tunnels; 0 = no idle timeout (recommended for H2)
        self.tunnel_idle_timeout = float(os.getenv("PROXXY_PROXY_TUNNEL_IDLE_TIMEOUT", "0"))
        # Track active client handler tasks for graceful shutdown
        self._client_tasks: Set[asyncio.Task] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port, start_serving=True)
        addrs = ", ".join(str(s.getsockname()) for s in (self._server.sockets or []))
        logger.info("tunnel: listening on %s (pool=%s size=%d)", addrs, self.pool.path, self.pool.size())

    async def stop(self) -> None:
        srv = self._server
        if srv:
            srv.close()
            try:
                await srv.wait_closed()
            except Exception:
                pass
            self._server = None
        # Cancel and await active client tasks to avoid "Task was destroyed but it is pending!"
        try:
            tasks = list(getattr(self, "_client_tasks", []))
            for t in tasks:
                try:
                    t.cancel()
                except Exception:
                    pass
            if tasks:
                try:
                    await asyncio.gather(*tasks, return_exceptions=True)
                except Exception:
                    pass
        except Exception:
            pass

    async def serve_until(self, stop_evt: threading.Event) -> None:
        await self.start()
        # poll stop event
        while not stop_evt.is_set():
            await asyncio.sleep(0.2)
        await self.stop()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        cid = _new_cid()
        # Register this handler task for graceful shutdown
        try:
            cur = asyncio.current_task()
            if cur is not None:
                self._client_tasks.add(cur)
        except Exception:
            pass
        try:
            # Parse request line
            line = await asyncio.wait_for(reader.readline(), timeout=self.io_timeout)
            if not line:
                return
            if len(line) > self.max_line_bytes:
                if _DIAG_ON:
                    logger.info("tunnel[%s]: reject peer=%s reason=uri_too_long", cid, peer)
                await self._respond(writer, 414, "Request-URI Too Long")
                return
            req_line = line.decode("latin1", "replace").rstrip("\r\n")
            parts = req_line.split(" ")
            if len(parts) < 3:
                if _DIAG_ON:
                    logger.info("tunnel[%s]: reject peer=%s reason=bad_request_line line=%r", cid, peer, req_line[:256])
                await self._respond(writer, 400, "Bad Request")
                return
            method, target, version = parts[0].upper(), parts[1], parts[2]
            if _DIAG_ON:
                try:
                    logger.info("tunnel[%s]: accept peer=%s %s %s %s pool=%d", cid, peer, method, target, version, self.pool.size())
                except Exception:
                    pass
    
            # Headers
            headers: List[str] = []
            total = len(line)
            while True:
                h = await asyncio.wait_for(reader.readline(), timeout=self.io_timeout)
                if not h:
                    break
                total += len(h)
                if total > self.max_header_bytes:
                    if _DIAG_ON:
                        logger.info("tunnel[%s]: reject peer=%s reason=header_too_large", cid, peer)
                    await self._respond(writer, 431, "Request Header Fields Too Large")
                    return
                if h in (b"\r\n", b"\n"):
                    break
                headers.append(h.decode("latin1", "replace").rstrip("\r\n"))
    
            hdr_map: Dict[str, str] = {}
            for h in headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    hdr_map[k.strip().lower()] = v.lstrip()
    
            # HTTP/2 (h2/h2c) detection and graceful refusal (we operate as HTTP/1.1 proxy)
            if method == "PRI" and target == "*" and version.upper().startswith("HTTP/2"):
                if _DIAG_ON:
                    logger.info("tunnel[%s]: reject peer=%s reason=http2_pri", cid, peer)
                await self._respond(writer, 505, "HTTP Version Not Supported")
                return
            if version.upper().startswith("HTTP/2"):
                if _DIAG_ON:
                    logger.info("tunnel[%s]: reject peer=%s reason=http2", cid, peer)
                await self._respond(writer, 505, "HTTP Version Not Supported")
                return
            upg = hdr_map.get("upgrade", "").lower()
            if "h2c" in upg or "http2-settings" in hdr_map:
                if _DIAG_ON:
                    logger.info("tunnel[%s]: reject peer=%s reason=h2c_upgrade", cid, peer)
                await self._respond(writer, 505, "HTTP Version Not Supported")
                return
    
            if self.pool.size() <= 0:
                if _DIAG_ON:
                    logger.warning("tunnel[%s]: no_upstreams_available", cid)
                await self._respond(writer, 503, "No Upstreams Available")
                return
    
            sticky_up = self.pool.next()
            if method == "CONNECT":
                await self._handle_connect(target, hdr_map, reader, writer, sticky_up, cid=cid)
            else:
                await self._handle_http(method, target, version, headers, hdr_map, reader, writer, sticky_up, cid=cid)
        except asyncio.TimeoutError:
            if _DIAG_ON:
                logger.info("tunnel[%s]: client_timeout peer=%s", cid, peer)
            await self._respond(writer, 408, "Request Timeout")
        except Exception as e:
            logger.debug("tunnel[%s]: client error peer=%s err=%s", cid, peer, e)
            try:
                await self._respond(writer, 400, "Bad Request")
            except Exception:
                pass
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                    except Exception:
                        pass
            except Exception:
                pass
            # Unregister this handler task
            try:
                cur = asyncio.current_task()
                if cur is not None:
                    self._client_tasks.discard(cur)
            except Exception:
                pass

    async def _handle_connect(
        self,
        target: str,
        _hdrs: Dict[str, str],
        client_r: asyncio.StreamReader,
        client_w: asyncio.StreamWriter,
        sticky: Optional[UpstreamProxy] = None,
        cid: Optional[str] = None,
    ) -> None:
        # Parse host:port
        host, port = self._split_host_port(target)
        if not host or port is None:
            if _DIAG_ON:
                logger.info("tunnel[%s]: reject reason=bad_connect_target target=%r", cid, target)
            await self._respond(client_w, 400, "Bad CONNECT Target")
            return
    
        attempts = self.max_retries + 1
        last_err: Optional[str] = None
        # Build candidate list: prefer sticky, then extras to honor retries
        _cand: List[UpstreamProxy] = [sticky] if sticky else []
        _extras = self.pool.next_many(max(attempts, min(self.pool.size(), int(getattr(self, "scan_max", 20)))))
        # Deduplicate by endpoint + credentials
        _seen_keys = set()
        candidates: List[UpstreamProxy] = []
        for up in (_cand + _extras):
            if up is None:
                continue
            _key = (up.scheme, up.host, up.port, up.username or "", up.password or "")
            if _key in _seen_keys:
                continue
            _seen_keys.add(_key)
            candidates.append(up)
        # Skip recently failed upstreams within TTL window (only if TTL > 0)
        skipped_ttl = 0
        if self.failure_ttl > 0:
            now_ts = time.monotonic()
            filtered: List[UpstreamProxy] = []
            for up in candidates:
                _key = (up.scheme, up.host, up.port, up.username or "", up.password or "")
                ts = self._failures.get(_key, 0.0)
                if ts and (now_ts - ts) < self.failure_ttl:
                    skipped_ttl += 1
                    continue
                filtered.append(up)
            if filtered:
                candidates = filtered
        # Target-scoped backoff
        skipped_target = 0
        target_label = f"{host}:{port}"
        if self.target_failure_ttl > 0:
            now_ts = time.monotonic()
            filtered2: List[UpstreamProxy] = []
            for up in candidates:
                _key_t = (target_label, up.scheme, up.host, up.port, up.username or "", up.password or "")
                ts = self._failures_by_target.get(_key_t, 0.0)
                if ts and (now_ts - ts) < self.target_failure_ttl:
                    skipped_target += 1
                    continue
                filtered2.append(up)
            if filtered2:
                candidates = filtered2
        budget = float(getattr(self, "scan_budget", 8.0))
        budget_deadline = time.monotonic() + max(0.0, budget)
        fanout = max(1, int(os.getenv("PROXXY_PROXY_UPSTREAM_FANOUT", "2")))
        idx = 0
    
        if _DIAG_ON:
            try:
                logger.info(
                    "tunnel[%s]: connect target=%s:%s candidates=%d skipped_ttl=%d skipped_target=%d fanout=%d budget_s=%.2f ttl=%.1f",
                    cid, host, port, len(candidates), skipped_ttl, skipped_target, fanout, budget, self.failure_ttl
                )
            except Exception:
                pass
    
        async def _try_connect(up: UpstreamProxy):
            # Return (ok, up_r, up_w, err, up). Supports HTTP(S) upstream proxies and SOCKS4/5.
            dial_ms = 0.0
            try:
                t0 = time.monotonic()
                if up.scheme in ("socks4", "socks5"):
                    # Establish tunnel to target via SOCKS immediately (no HTTP CONNECT handshake to upstream)
                    up_r, up_w = await asyncio.wait_for(self._open_socks_tunnel(up, host, int(port)), timeout=self.io_timeout)
                    dial_ms = (time.monotonic() - t0) * 1000.0
                    if _DIAG_ON:
                        logger.info(
                            "tunnel[%s]: socks tunnel ok upstream=%s://%s:%s dial_ms=%.0f",
                            cid, up.scheme, up.host, up.port, dial_ms
                        )
                    return True, up_r, up_w, "", up
                else:
                    up_r, up_w = await asyncio.wait_for(self._open_upstream(up), timeout=self.dial_timeout)
                    dial_ms = (time.monotonic() - t0) * 1000.0
            except Exception as e:
                if _DIAG_ON:
                    logger.info(
                        "tunnel[%s]: attempt fail phase=dial upstream=%s://%s:%s auth=%s err=%s",
                        cid, up.scheme, up.host, up.port, bool(up.username), e
                    )
                return False, None, None, f"connect-upstream-failed {e}", up

            # HTTP/HTTPS upstream: send CONNECT
            try:
                lines = [
                    f"CONNECT {host}:{port} HTTP/1.1",
                    f"Host: {host}:{port}",
                ]
                auth = up.auth_header_value()
                if auth:
                    lines.append(f"Proxy-Authorization: {auth}")
                data = ("\r\n".join(lines) + "\r\n\r\n").encode("latin1")
                up_w.write(data)
                await asyncio.wait_for(up_w.drain(), timeout=self.io_timeout)

                # Read upstream response
                t1 = time.monotonic()
                status_line = await asyncio.wait_for(up_r.readline(), timeout=self.io_timeout)
                if not status_line:
                    try:
                        up_w.close()
                        try:
                            await up_w.wait_closed()
                        except Exception:
                            pass
                    except Exception:
                        pass
                    if _DIAG_ON:
                        logger.info(
                            "tunnel[%s]: attempt fail phase=handshake upstream=%s://%s:%s auth=%s err=empty-response dial_ms=%.0f",
                            cid, up.scheme, up.host, up.port, bool(up.username), dial_ms
                        )
                    return False, None, None, "empty-response", up
                status = status_line.decode("latin1", "replace").strip()
                code = self._parse_status_code(status)
                # Drain headers
                while True:
                    line = await asyncio.wait_for(up_r.readline(), timeout=self.io_timeout)
                    if not line or line in (b"\r\n", b"\n"):
                        break
                hs_ms = (time.monotonic() - t1) * 1000.0
                if code == 200:
                    if _DIAG_ON:
                        logger.info(
                            "tunnel[%s]: connect ok upstream=%s://%s:%s auth=%s dial_ms=%.0f hs_ms=%.0f",
                            cid, up.scheme, up.host, up.port, bool(up.username), dial_ms, hs_ms
                        )
                    return True, up_r, up_w, "", up
                else:
                    try:
                        up_w.close()
                        try:
                            await up_w.wait_closed()
                        except Exception:
                            pass
                    except Exception:
                        pass
                    if _DIAG_ON:
                        logger.info(
                            "tunnel[%s]: attempt fail phase=handshake upstream=%s://%s:%s auth=%s status=%d dial_ms=%.0f hs_ms=%.0f",
                            cid, up.scheme, up.host, up.port, bool(up.username), code, dial_ms, hs_ms
                        )
                    return False, None, None, f"upstream-status-{code}", up
            except Exception as e:
                try:
                    up_w.close()
                    try:
                        await up_w.wait_closed()
                    except Exception:
                        pass
                except Exception:
                    pass
                if _DIAG_ON:
                    logger.info(
                        "tunnel[%s]: attempt fail phase=handshake upstream=%s://%s:%s auth=%s err=%s dial_ms=%.0f",
                        cid, up.scheme, up.host, up.port, bool(up.username), e, dial_ms
                    )
                return False, None, None, f"upstream-error {e}", up
    
        while idx < len(candidates):
            if time.monotonic() > budget_deadline:
                break
            batch = candidates[idx: idx + fanout]
            idx += fanout
            if not batch:
                break
            tasks = [asyncio.create_task(_try_connect(up)) for up in batch]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    
            # Check if any succeeded
            success_tuple = None
            for fut in done:
                ok, up_r, up_w, err, up = fut.result()
                if ok:
                    success_tuple = (up_r, up_w, up)
                    break
                else:
                    last_err = err
                    self._mark_fail(up)
                    self._mark_fail_for_target(target_label, up)
    
            if success_tuple is not None:
                # Cancel remaining attempts
                for t in pending:
                    try:
                        t.cancel()
                    except Exception:
                        pass
                if pending:
                    try:
                        await asyncio.gather(*pending, return_exceptions=True)
                    except Exception:
                        pass
                # Inform client and start piping
                up_r, up_w, up = success_tuple
                if up_r is None or up_w is None:
                    # Defensive: should not happen since success_tuple implies non-None
                    last_err = "internal-error: upstream streams absent"
                    try:
                        if up_w is not None:
                            up_w.close()
                            try:
                                await up_w.wait_closed()
                            except Exception:
                                pass
                    except Exception:
                        pass
                    continue
                self._clear_fail(up)
                self._clear_fail_for_target(target_label, up)
                await self._respond_raw(client_w, b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if _DIAG_ON:
                    logger.info(
                        "tunnel[%s]: CONNECT established target=%s:%s via=%s://%s:%s",
                        cid, host, port, up.scheme, up.host, up.port
                    )
                up_r_cast = cast(asyncio.StreamReader, up_r)
                up_w_cast = cast(asyncio.StreamWriter, up_w)
                t_pipe0 = time.monotonic()
                a2b, b2a, end_a, end_b = await self._pipe_bidirectional(
                    client_r,
                    client_w,
                    up_r_cast,
                    up_w_cast,
                    bufsize=65536,
                    idle_timeout=self.tunnel_idle_timeout,
                    cid=cid,
                    label=f"CONNECT {host}:{port} via {up.scheme}://{up.host}:{up.port}",
                )
                dur_ms = (time.monotonic() - t_pipe0) * 1000.0
                early_close = (dur_ms <= _EARLY_CLOSE_MAX_MS and a2b <= _EARLY_CLOSE_MAX_A2B and b2a <= _EARLY_CLOSE_MAX_B2A) and (end_a != "timeout" and end_b != "timeout")
                if early_close:
                    self._mark_fail_for_target(target_label, up)
                    if _DIAG_ON:
                        logger.info(
                            "tunnel[%s]: early_close target=%s via=%s://%s:%s a2b=%d b2a=%d dur_ms=%.0f",
                            cid, target_label, up.scheme, up.host, up.port, a2b, b2a, dur_ms
                        )
                if _DIAG_ON:
                    logger.info(
                        "tunnel[%s]: CONNECT closed target=%s:%s via=%s://%s:%s dur_ms=%.0f",
                        cid, host, port, up.scheme, up.host, up.port, dur_ms
                    )
                return
    
            # No success in this batch; cancel any still-pending and continue
            for t in pending:
                try:
                    t.cancel()
                except Exception:
                    pass
            if pending:
                try:
                    await asyncio.gather(*pending, return_exceptions=True)
                except Exception:
                    pass
            # continue to next batch
    
        # No upstream succeeded
        logger.warning("tunnel[%s]: CONNECT failed target=%s:%s err=%s", cid, host, port, last_err)
        await self._respond(client_w, 502, "Bad Gateway")

    async def _handle_http(
        self,
        method: str,
        target: str,
        version: str,
        raw_headers: List[str],
        hdr_map: Dict[str, str],
        client_r: asyncio.StreamReader,
        client_w: asyncio.StreamWriter,
        sticky: Optional[UpstreamProxy] = None,
        cid: Optional[str] = None,
    ) -> None:
        # Ensure absolute-form URI for upstream HTTP proxy
        if target.startswith("http://") or target.startswith("https://"):
            abs_uri = target
        else:
            host = hdr_map.get("host", "")
            if not host:
                if _DIAG_ON:
                    logger.info("tunnel[%s]: reject reason=missing_host", cid)
                await self._respond(client_w, 400, "Missing Host")
                return
            # Default to http schema for origin-form
            abs_uri = f"http://{host}{target}"

        # For diagnostics: extract authority/scheme (path redacted implicitly)
        try:
            u = urlsplit(abs_uri)
            authority = u.netloc
            scheme = (u.scheme or "").lower()
        except Exception:
            authority = "-"
            scheme = "-"
        if _DIAG_ON:
            logger.info("tunnel[%s]: http_forward %s://%s method=%s ver=%s", cid, scheme, authority, method, version)

        attempts = self.max_retries + 1
        last_err: Optional[str] = None
        # Build candidate list: prefer sticky, then extras to honor retries
        _cand: List[UpstreamProxy] = [sticky] if sticky else []
        _extras = self.pool.next_many(max(attempts, min(self.pool.size(), int(getattr(self, "scan_max", 20)))))
        # Deduplicate by endpoint + credentials
        _seen_keys = set()
        candidates: List[UpstreamProxy] = []
        for up in (_cand + _extras):
            if up is None:
                continue
            _key = (up.scheme, up.host, up.port, up.username or "", up.password or "")
            if _key in _seen_keys:
                continue
            _seen_keys.add(_key)
            candidates.append(up)
        # Skip recently failed upstreams within TTL window (only if TTL > 0)
        budget = float(getattr(self, "scan_budget", 8.0))
        budget_deadline = time.monotonic() + max(0.0, budget)
        skipped_ttl = 0
        if self.failure_ttl > 0:
            now_ts = time.monotonic()
            filtered: List[UpstreamProxy] = []
            for up in candidates:
                _key = (up.scheme, up.host, up.port, up.username or "", up.password or "")
                ts = self._failures.get(_key, 0.0)
                if ts and (now_ts - ts) < self.failure_ttl:
                    skipped_ttl += 1
                    continue
                filtered.append(up)
            if filtered:
                candidates = filtered
        # Target-scoped backoff for HTTP
        skipped_target = 0
        target_label = authority
        if self.target_failure_ttl > 0:
            now_ts = time.monotonic()
            filtered2: List[UpstreamProxy] = []
            for up in candidates:
                _key_t = (target_label, up.scheme, up.host, up.port, up.username or "", up.password or "")
                ts = self._failures_by_target.get(_key_t, 0.0)
                if ts and (now_ts - ts) < self.target_failure_ttl:
                    skipped_target += 1
                    continue
                filtered2.append(up)
            if filtered2:
                candidates = filtered2
        if _DIAG_ON:
            logger.info(
                "tunnel[%s]: http candidates=%d skipped_ttl=%d skipped_target=%d budget_s=%.2f",
                cid, len(candidates), skipped_ttl, skipped_target, budget
            )
        for up in candidates:
            if time.monotonic() > budget_deadline:
                break
            if up.scheme in ("http", "https"):
                try:
                    t0 = time.monotonic()
                    up_r, up_w = await self._open_upstream(up)
                    dial_ms = (time.monotonic() - t0) * 1000.0
                except Exception as e:
                    last_err = f"connect-upstream-failed {e}"
                    self._mark_fail(up)
                    self._mark_fail_for_target(target_label, up)
                    if _DIAG_ON:
                        logger.info(
                            "tunnel[%s]: http attempt fail phase=dial upstream=%s://%s:%s auth=%s err=%s",
                            cid, up.scheme, up.host, up.port, bool(up.username), e
                        )
                    continue
                try:
                    # Build request to upstream (speak HTTP/1.1 to upstream proxy)
                    out_lines: List[str] = [f"{method} {abs_uri} HTTP/1.1"]
                    # Rewrite headers: drop client Proxy-* headers and Connection, add our Proxy-Authorization if needed
                    for h in raw_headers:
                        if not h or ":" not in h:
                            continue
                        k, v = h.split(":", 1)
                        kn = k.strip()
                        kln = kn.lower()
                        if kln.startswith("proxy-") or kln == "connection":
                            continue
                        out_lines.append(f"{kn}:{v}")
                    auth = up.auth_header_value()
                    if auth:
                        out_lines.append(f"Proxy-Authorization: {auth}")
                    data = ("\r\n".join(out_lines) + "\r\n\r\n").encode("latin1")
                    up_w.write(data)
                    await asyncio.wait_for(up_w.drain(), timeout=self.io_timeout)

                    if _DIAG_ON:
                        logger.info(
                            "tunnel[%s]: http forward start upstream=%s://%s:%s auth=%s dial_ms=%.0f",
                            cid, up.scheme, up.host, up.port, bool(up.username), dial_ms
                        )
                    # After sending headers, relay bidirectionally (this supports bodies and simple keep-alive)
                    self._clear_fail(up)
                    self._clear_fail_for_target(target_label, up)
                    t_pipe0 = time.monotonic()
                    await self._pipe_bidirectional(
                        client_r,
                        client_w,
                        up_r,
                        up_w,
                        cid=cid,
                        label=f"HTTP {scheme}://{authority} via {up.scheme}://{up.host}:{up.port}",
                    )
                    dur_ms = (time.monotonic() - t_pipe0) * 1000.0
                    if _DIAG_ON:
                        logger.info(
                            "tunnel[%s]: http forward closed upstream=%s://%s:%s dur_ms=%.0f",
                            cid, up.scheme, up.host, up.port, dur_ms
                        )
                    return
                except Exception as e:
                    last_err = f"upstream-error {e}"
                    self._mark_fail(up)
                    try:
                        up_w.close()
                        try:
                            await up_w.wait_closed()
                        except Exception:
                            pass
                    except Exception:
                        pass
                    if _DIAG_ON:
                        logger.info(
                            "tunnel[%s]: http attempt fail phase=forward upstream=%s://%s:%s auth=%s err=%s",
                            cid, up.scheme, up.host, up.port, bool(up.username), e
                        )
                    continue
            else:
                # SOCKS upstream: connect to origin via SOCKS and forward origin-form request (HTTP only)
                try:
                    try:
                        u2 = urlsplit(abs_uri)
                        dst_host = u2.hostname or authority
                        dst_port = u2.port or 80
                        path = u2.path or "/"
                        if u2.query:
                            path = f"{path}?{u2.query}"
                    except Exception:
                        dst_host = authority.split(":")[0]
                        dst_port = 80
                        path = "/"
                    if scheme == "https":
                        # For HTTPS targets use CONNECT; non-CONNECT HTTPS is not supported over SOCKS forward
                        last_err = "https-over-socks-forward-unsupported"
                        if _DIAG_ON:
                            logger.info("tunnel[%s]: reject http-forward over socks to https authority=%s", cid, authority)
                        continue
                    t0 = time.monotonic()
                    up_r, up_w = await self._open_socks_tunnel(up, dst_host, int(dst_port))
                    dial_ms = (time.monotonic() - t0) * 1000.0
                    out_lines: List[str] = [f"{method} {path} HTTP/1.1"]
                    for h in raw_headers:
                        if not h or ":" not in h:
                            continue
                        k, v = h.split(":", 1)
                        kn = k.strip()
                        kln = kn.lower()
                        if kln.startswith("proxy-") or kln == "connection":
                            continue
                        out_lines.append(f"{kn}:{v}")
                    data = ("\r\n".join(out_lines) + "\r\n\r\n").encode("latin1")
                    up_w.write(data)
                    await asyncio.wait_for(up_w.drain(), timeout=self.io_timeout)

                    if _DIAG_ON:
                        logger.info(
                            "tunnel[%s]: http forward start via socks upstream=%s://%s:%s dial_ms=%.0f",
                            cid, up.scheme, up.host, up.port, dial_ms
                        )
                    self._clear_fail(up)
                    self._clear_fail_for_target(target_label, up)
                    t_pipe0 = time.monotonic()
                    await self._pipe_bidirectional(
                        client_r,
                        client_w,
                        up_r,
                        up_w,
                        cid=cid,
                        label=f"HTTP {scheme}://{authority} via {up.scheme}://{up.host}:{up.port}",
                    )
                    dur_ms = (time.monotonic() - t_pipe0) * 1000.0
                    if _DIAG_ON:
                        logger.info(
                            "tunnel[%s]: http forward closed via socks upstream=%s://%s:%s dur_ms=%.0f",
                            cid, up.scheme, up.host, up.port, dur_ms
                        )
                    return
                except Exception as e:
                    last_err = f"socks-forward-error {e}"
                    self._mark_fail(up)
                    if _DIAG_ON:
                        logger.info(
                            "tunnel[%s]: http attempt fail via socks upstream=%s://%s:%s err=%s",
                            cid, up.scheme, up.host, up.port, e
                        )
                    continue

        logger.warning("tunnel[%s]: HTTP forward failed authority=%s err=%s", cid, authority, last_err)
        await self._respond(client_w, 502, "Bad Gateway")

    async def _pipe_bidirectional(
        self,
        a_r: asyncio.StreamReader,
        a_w: asyncio.StreamWriter,
        b_r: asyncio.StreamReader,
        b_w: asyncio.StreamWriter,
        bufsize: int = 65536,
        idle_timeout: Optional[float] = None,
        cid: Optional[str] = None,
        label: str = "",
    ) -> Tuple[int, int, str, str]:
        """
        Relay data in both directions until EOF/idle/cancel.
        When diagnostics enabled and cid provided, logs a summary with byte counts and end reasons.
        """
        bytes_a2b = 0
        bytes_b2a = 0
        end_a = "-"
        end_b = "-"

        async def pump(name: str, src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> Tuple[str, int, str]:
            # If idle_timeout <= 0, do not enforce a read timeout (prevents H2 CANCEL due to proxy idle close)
            tmo_val = self.io_timeout if idle_timeout is None else float(idle_timeout)
            use_timeout = tmo_val is not None and tmo_val > 0
            total = 0
            reason = "eof"
            try:
                while True:
                    if use_timeout:
                        chunk = await asyncio.wait_for(src.read(bufsize), timeout=tmo_val)
                    else:
                        chunk = await src.read(bufsize)
                    if not chunk:
                        break
                    total += len(chunk)
                    dst.write(chunk)
                    if use_timeout:
                        await asyncio.wait_for(dst.drain(), timeout=tmo_val)
                    else:
                        await dst.drain()
            except asyncio.TimeoutError:
                # Idle timeout; simply unwind; no half-close on tunnel
                reason = "timeout"
            except Exception:
                reason = "error"
            finally:
                # Do not write_eof() on tunnels; it can break TLS/H2 streams
                return name, total, reason

        t1 = asyncio.create_task(pump("a->b", a_r, b_w))
        t2 = asyncio.create_task(pump("b->a", b_r, a_w))
        try:
            # When one direction finishes (EOF/idle), cancel the peer pump to avoid lingering pending tasks
            done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
            results: List[Tuple[str, int, str]] = []
            for fut in done:
                try:
                    results.append(await fut)
                except Exception:
                    pass
            for t in pending:
                try:
                    t.cancel()
                except Exception:
                    pass
            if pending:
                try:
                    pending_results = await asyncio.gather(*pending, return_exceptions=True)
                    for r in pending_results:
                        if isinstance(r, tuple) and len(r) == 3:
                            results.append(r)  # type: ignore[arg-type]
                except Exception:
                    pass
            for name, total, reason in results:
                if name == "a->b":
                    bytes_a2b = total
                    end_a = reason
                elif name == "b->a":
                    bytes_b2a = total
                    end_b = reason
        except asyncio.CancelledError:
            # If the handler is cancelled, ensure both pump tasks are cancelled and awaited
            try:
                t1.cancel()
            except Exception:
                pass
            try:
                t2.cancel()
            except Exception:
                pass
            try:
                await asyncio.gather(t1, t2, return_exceptions=True)
            except Exception:
                pass
            raise
        finally:
            # Close both writers
            for w in (a_w, b_w):
                try:
                    if not w.is_closing():
                        w.close()
                except Exception:
                    pass
            # Best-effort wait
            for w in (a_w, b_w):
                try:
                    await asyncio.wait_for(w.wait_closed(), timeout=1.0)
                except Exception:
                    pass
            # Summary logging
            if _DIAG_ON and cid is not None:
                try:
                    logger.info(
                        "tunnel[%s]: pipe_summary label=%s a2b=%d b2a=%d end=%s|%s",
                        cid, (label or "-"), bytes_a2b, bytes_b2a, end_a, end_b
                    )
                except Exception:
                    pass
            return bytes_a2b, bytes_b2a, end_a, end_b

    async def _respond(self, w: asyncio.StreamWriter, code: int, text: str) -> None:
        await self._respond_raw(w, f"HTTP/1.1 {code} {text}\r\nProxy-Agent: proXXy-tunnel\r\n\r\n".encode("latin1"))

    async def _respond_raw(self, w: asyncio.StreamWriter, data: bytes) -> None:
        try:
            w.write(data)
            await asyncio.wait_for(w.drain(), timeout=self.io_timeout)
        except Exception:
            pass

    async def _open_upstream(self, up: UpstreamProxy) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        ssl_ctx: Optional[ssl.SSLContext] = None
        if up.scheme == "https":
            ssl_ctx = ssl.create_default_context()
            # Optional TLS verification against upstream proxies (default off)
            try:
                verify_up = os.getenv("PROXXY_PROXY_UPSTREAM_SSL_VERIFY", "0").strip().lower() not in ("0", "false", "no", "off")
                if not verify_up:
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
            except Exception:
                pass
            # Force HTTP/1.1 to upstream proxies to avoid ALPN negotiating HTTP/2,
            # since we emit HTTP/1.1 proxy semantics on this connection.
            try:
                ssl_ctx.set_alpn_protocols(["http/1.1"])
            except Exception:
                pass
            try:
                # Best-effort for older implementations
                if hasattr(ssl_ctx, "set_npn_protocols"):
                    ssl_ctx.set_npn_protocols(["http/1.1"])  # type: ignore[attr-defined]
            except Exception:
                pass
        r, w = await asyncio.wait_for(asyncio.open_connection(host=up.host, port=up.port, ssl=ssl_ctx), timeout=self.dial_timeout)
        return r, w

    async def _open_socks_tunnel(self, up: UpstreamProxy, host: str, port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Connect to SOCKS4/5 proxy and establish a tunnel to (host, port).
        Returns the reader/writer streams for the established tunnel.
        """
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host=up.host, port=up.port, ssl=None), timeout=self.dial_timeout)
        except Exception as e:
            raise RuntimeError(f"dial-socks-failed {e}") from e
        try:
            if up.scheme == "socks5":
                await asyncio.wait_for(self._socks5_handshake(r, w, up, host, port), timeout=self.io_timeout)
            else:
                await asyncio.wait_for(self._socks4a_handshake(r, w, up, host, port), timeout=self.io_timeout)
            return r, w
        except Exception as e:
            try:
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
            except Exception:
                pass
            raise

    async def _socks5_handshake(self, r: asyncio.StreamReader, w: asyncio.StreamWriter, up: UpstreamProxy, host: str, port: int) -> None:
        # Greeting
        methods = [0x00]
        if up.username is not None:
            methods = [0x00, 0x02]
        w.write(bytes([0x05, len(methods), *methods]))
        await w.drain()
        data = await r.readexactly(2)
        if len(data) != 2 or data[0] != 0x05:
            raise RuntimeError("socks5-bad-greeting")
        method = data[1]
        if method == 0x02:
            # Username/Password auth
            uname = (up.username or "").encode("utf-8")
            pwd = (up.password or "").encode("utf-8")
            if len(uname) > 255 or len(pwd) > 255:
                raise RuntimeError("socks5-cred-too-long")
            w.write(bytes([0x01, len(uname)]) + uname + bytes([len(pwd)]) + pwd)
            await w.drain()
            a = await r.readexactly(2)
            if len(a) != 2 or a[1] != 0x00:
                raise RuntimeError("socks5-auth-failed")
        elif method == 0x00:
            pass
        else:
            raise RuntimeError("socks5-no-supported-auth")

        # CONNECT request with domain name
        host_b = host.encode("idna")
        if len(host_b) > 255:
            raise RuntimeError("socks5-hostname-too-long")
        req = bytearray()
        req += b"\x05\x01\x00"  # VER=5, CMD=CONNECT, RSV=0
        req += b"\x03" + bytes([len(host_b)]) + host_b  # ATYP=DOMAIN
        req += bytes([(port >> 8) & 0xFF, port & 0xFF])
        w.write(req)
        await w.drain()
        # Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
        hdr = await r.readexactly(4)
        if hdr[1] != 0x00:
            raise RuntimeError(f"socks5-connect-failed-rep={hdr[1]}")
        atyp = hdr[3]
        if atyp == 0x01:
            await r.readexactly(4)
        elif atyp == 0x03:
            l = await r.readexactly(1)
            await r.readexactly(l[0])
        elif atyp == 0x04:
            await r.readexactly(16)
        await r.readexactly(2)  # port

    async def _socks4a_handshake(self, r: asyncio.StreamReader, w: asyncio.StreamWriter, up: UpstreamProxy, host: str, port: int) -> None:
        # SOCKS4a: use 0.0.0.1 and append hostname
        uname = (up.username or "").encode("utf-8")
        host_b = host.encode("idna")
        req = bytearray()
        req += b"\x04\x01"  # VN=4, CD=1 CONNECT
        req += bytes([(port >> 8) & 0xFF, port & 0xFF])
        req += b"\x00\x00\x00\x01"
        req += uname + b"\x00"
        req += host_b + b"\x00"
        w.write(req)
        await w.drain()
        # Reply: VN(0x00), CD(0x5a success)
        rep = await r.readexactly(8)
        if len(rep) != 8 or rep[1] != 0x5A:
            raise RuntimeError("socks4-connect-failed")

    def _split_host_port(self, hp: str) -> Tuple[str, Optional[int]]:
        s = (hp or "").strip()
        if not s:
            return "", None
        if ":" in s:
            host, port_s = s.rsplit(":", 1)
            try:
                return host.strip(), int(port_s.strip())
            except Exception:
                return host.strip(), None
        return s, None

    def _parse_status_code(self, status_line: str) -> int:
        try:
            parts = status_line.split(" ", 2)
            if len(parts) >= 2:
                return int(parts[1])
        except Exception:
            pass
        return 0

    def _mark_fail(self, up: UpstreamProxy) -> None:
        if self.failure_ttl <= 0:
            return
        try:
            key = (up.scheme, up.host, up.port, up.username or "", up.password or "")
            self._failures[key] = time.monotonic()
        except Exception:
            pass

    def _clear_fail(self, up: UpstreamProxy) -> None:
        if self.failure_ttl <= 0:
            return
        try:
            key = (up.scheme, up.host, up.port, up.username or "", up.password or "")
            self._failures.pop(key, None)
        except Exception:
            pass

    def _mark_fail_for_target(self, target_label: str, up: UpstreamProxy) -> None:
        """
        Record a failure for a specific target (host:port or authority) and upstream endpoint.
        Used to temporarily back off this upstream when contacting the same target again.
        """
        if self.target_failure_ttl <= 0:
            return
        try:
            key_t = (target_label, up.scheme, up.host, up.port, up.username or "", up.password or "")
            self._failures_by_target[key_t] = time.monotonic()
        except Exception:
            pass

    def _clear_fail_for_target(self, target_label: str, up: UpstreamProxy) -> None:
        """
        Clear a previously recorded target-scoped failure for this upstream endpoint.
        """
        if self.target_failure_ttl <= 0:
            return
        try:
            key_t = (target_label, up.scheme, up.host, up.port, up.username or "", up.password or "")
            self._failures_by_target.pop(key_t, None)
        except Exception:
            pass



def run_tunnel_proxy(
    stop_event: threading.Event,
    host: str,
    port: int,
    pool_file: str,
    emit: Optional[Callable[[dict], None]] = None,
) -> None:
    """
    Blocking entry-point: runs an asyncio server until stop_event is set.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    server = TunnelProxyServer(host=host, port=port, pool_file=pool_file, emit=emit)

    async def _main():
        await server.serve_until(stop_event)

    try:
        loop.run_until_complete(_main())
    finally:
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