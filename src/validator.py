import concurrent.futures as futures
import os
import sys
import threading
import time
import socket
import ssl
import importlib
from urllib.parse import urlparse
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
_MIN_BYTES = int(os.getenv("PROXXY_VALIDATOR_MIN_BYTES", "4096"))


# Enforced per-request timeout (seconds) applied to all proxy validations
_ENFORCED_TIMEOUT_SECONDS = 25.0

# Aggressive streaming reader tunables
_READ_WINDOW_SECONDS = float(os.getenv("PROXXY_VALIDATOR_READ_SECONDS", "1.0"))
_CHUNK_SIZE = int(os.getenv("PROXXY_VALIDATOR_CHUNK_SIZE", "2048"))
_TTFB_SECONDS = float(os.getenv("PROXXY_VALIDATOR_TTFB_SECONDS", "0.8"))
_DEFAULT_UA = os.getenv("PROXXY_VALIDATOR_USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
_TCP_PREFLIGHT = os.getenv("PROXXY_VALIDATOR_TCP_PREFLIGHT", "1")
# Optional second URL to improve stability testing (falls back to primary when unset)
_SECOND_URL = os.getenv("PROXXY_VALIDATOR_SECOND_URL", "").strip()
# Connection phase timeout (connect), kept <= enforced overall timeout
_CONNECT_TIMEOUT_SECONDS = float(os.getenv("PROXXY_VALIDATOR_CONNECT_TIMEOUT", "3.0"))
# Re-check (2nd pass) read window
_RECHECK_READ_SECONDS = float(os.getenv("PROXXY_VALIDATOR_RECHECK_READ_SECONDS", "0.8"))
# Minimum sustained throughput after first byte (bytes/sec)
_MIN_BPS = int(os.getenv("PROXXY_VALIDATOR_MIN_BPS", "16384"))
# Require HTTP/1.1 response on validated fetch (some HTTP/1.0 paths are flaky)
_REQUIRE_HTTP11 = os.getenv("PROXXY_VALIDATOR_REQUIRE_HTTP11", "1")
# OS trust TLS preflight via system CA store (replicates Schannel/curl behavior)
_OS_TRUST_PREFLIGHT = os.getenv("PROXXY_VALIDATOR_OS_TRUST_PREFLIGHT", "1")
# HTTP/2 validation toggles (strict by default; HTTPS targets only)
_HTTP2_ENABLE = os.getenv("PROXXY_VALIDATOR_HTTP2_ENABLE", "1")
_HTTP2_REQUIRED = os.getenv("PROXXY_VALIDATOR_HTTP2_REQUIRED", "1")

def _os_trust_tls_preflight(proxy: str, url: str) -> Tuple[bool, str]:
    """
    Perform an OS-trust TLS preflight through the proxy using CONNECT to the target host.
    - Uses Windows/macOS OS trust via ssl.create_default_context + load_default_certs.
    - Fails when certificate chain is not trusted by OS (e.g., MITM or bad chain), mirroring curl/Schannel behavior.
    - When PROXXY_VALIDATOR_HTTP2_REQUIRED=1 and target is HTTPS, negotiate ALPN and require 'h2'.
    Returns (ok, error_string)
    """
    try:
        u = urlparse(url)
        target_host = u.hostname or ""
        target_port = u.port or 443
        target_scheme = (u.scheme or "").lower()
        pu = urlparse(proxy)
        proxy_host = pu.hostname or ""
        proxy_port = pu.port or (443 if (pu.scheme or "").lower() == "https" else 80)
        if not target_host or not proxy_host or not proxy_port:
            return False, "bad_host"

        with socket.create_connection((proxy_host, int(proxy_port)), timeout=min(_CONNECT_TIMEOUT_SECONDS, _ENFORCED_TIMEOUT_SECONDS, 5.0)) as sock:
            sock.settimeout(min(_ENFORCED_TIMEOUT_SECONDS, 5.0))
            # Issue CONNECT
            req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
            sock.sendall(req.encode("ascii", "strict"))
            # Read headers
            buff = b""
            while b"\r\n\r\n" not in buff and len(buff) < 8192:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                buff += chunk
            line = buff.split(b"\r\n", 1)[0] if buff else b""
            if not line.startswith(b"HTTP/1.1 200") and not line.startswith(b"HTTP/1.0 200"):
                return False, f"connect_resp:{line.decode('latin1', 'ignore')[:128]}"

            # TLS handshake with OS trust (Windows Schannel equivalent)
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            except Exception:
                pass
            try:
                # Ensure OS roots loaded (on Windows loads from Windows cert store)
                ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
            except Exception:
                pass
            # If HTTP/2 is required for HTTPS targets, advertise ALPN h2 and enforce selection.
            try:
                http2_required = str(_HTTP2_REQUIRED).strip().lower() not in ("0", "false", "no", "off")
                if http2_required and target_scheme == "https" and hasattr(ctx, "set_alpn_protocols"):
                    ctx.set_alpn_protocols(["h2", "http/1.1"])
            except Exception:
                # Ignore ALPN configuration errors; handshake will still validate trust.
                pass

            with ctx.wrap_socket(sock, server_hostname=target_host) as tls:
                # Force handshake; will raise on untrusted roots/SAN mismatch
                _ = tls.version()
                try:
                    # Enforce ALPN result when required
                    http2_required = str(_HTTP2_REQUIRED).strip().lower() not in ("0", "false", "no", "off")
                    if http2_required and target_scheme == "https":
                        sel = ""
                        try:
                            sel = tls.selected_alpn_protocol() or ""
                        except Exception:
                            sel = ""
                        if sel.lower() != "h2":
                            return False, f"alpn:{sel or 'none'}"
                except Exception:
                    # If ALPN introspection fails, treat as failure only when strictly required
                    return False, "alpn:introspect"
            return True, ""
    except ssl.SSLCertVerificationError as e:
        # Mirror useful details when available
        msg = getattr(e, "verify_message", str(e)) or str(e)
        code = getattr(e, "verify_code", "")
        code_s = f"{code}:" if code else ""
        return False, f"tls_verify:{code_s}{msg}"
    except Exception as e:
        return False, f"tls_preflight:{str(e)[:256]}"

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
            "Accept-Language": os.getenv("PROXXY_VALIDATOR_ACCEPT_LANGUAGE", "en-US,en;q=0.9"),
        }
    )
    if user_agent:
        sess.headers["User-Agent"] = user_agent
    else:
        ua = os.getenv("PROXXY_VALIDATOR_USER_AGENT", _DEFAULT_UA)
        if ua:
            sess.headers["User-Agent"] = ua
    # Store enforced per-request timeout (connect, read) on the session
    sess.request_timeout = (min(_CONNECT_TIMEOUT_SECONDS, _ENFORCED_TIMEOUT_SECONDS), _ENFORCED_TIMEOUT_SECONDS)  # type: ignore[attr-defined]
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
    # Optional TCP preflight to weed out proxies with closed or unresponsive ports quickly
    try:
        if (_TCP_PREFLIGHT or "1") and str(_TCP_PREFLIGHT).strip().lower() not in ("0", "false", "no", "off"):
            u = urlparse(proxies.get("http") or proxy)
            host = u.hostname
            port = u.port or (443 if (u.scheme or "").lower() == "https" else 80)
            if host and port:
                s = socket.create_connection((host, int(port)), timeout=min(_CONNECT_TIMEOUT_SECONDS, _ENFORCED_TIMEOUT_SECONDS, 3.0))
                try:
                    s.close()
                except Exception:
                    pass
    except Exception as e:
        return proxy, False, None, f"tcp_preflight:{e}", None, None

    # OS trust TLS preflight (detect untrusted cert chains akin to curl/Schannel)
    if (_OS_TRUST_PREFLIGHT or "1") and str(_OS_TRUST_PREFLIGHT).strip().lower() not in ("0", "false", "no", "off"):
        ok_tls, tls_err = _os_trust_tls_preflight(proxies.get("http") or proxy, url)
        if not ok_tls:
            return proxy, False, None, f"os_trust:{tls_err}", None, None

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
        first_byte_at: Optional[float] = None
        seen_first = False
        read_error = False
        # Capture a sample of response bytes for content signature checks
        sample_buf = bytearray()
        min_bytes = max(1, _MIN_BYTES)
        try:
            for chunk in resp.iter_content(chunk_size=max(1, _CHUNK_SIZE)):
                now = time.monotonic()
                # TTFB guard: if no data within threshold, treat as failure
                if not seen_first and (now - start_read) >= float(_TTFB_SECONDS):
                    read_error = True
                    break
                if not chunk:
                    if (now - start_read) >= float(_READ_WINDOW_SECONDS):
                        break
                    continue
                if not seen_first:
                    seen_first = True
                    first_byte_at = now
                total += len(chunk)
                # keep up to ~16KB sample for token checks
                if len(sample_buf) < 16384:
                    take = min(len(chunk), 16384 - len(sample_buf))
                    sample_buf.extend(chunk[:take])
                if total >= min_bytes or (now - start_read) >= float(_READ_WINDOW_SECONDS):
                    break
        except Exception:
            # treat read errors as failure
            read_error = True

        # Status and header sanity
        status_ok = 200 <= resp.status_code < 400
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        if 300 <= resp.status_code < 400 and "location" not in headers:
            status_ok = False

        # HTTP version check (when available)
        version_ok = True
        if (_REQUIRE_HTTP11 or "1") and str(_REQUIRE_HTTP11).strip().lower() not in ("0", "false", "no", "off"):
            try:
                ver = getattr(getattr(resp, "raw", None), "version", None)
                # http.client uses 11 for HTTP/1.1 and 10 for HTTP/1.0
                if isinstance(ver, int) and ver != 11:
                    version_ok = False
            except Exception:
                # if unknown, don't fail solely on this
                pass

        # Throughput after first byte
        speed_ok = True
        if seen_first and first_byte_at is not None:
            dur = max(1e-6, (time.monotonic() - first_byte_at))
            bps = total / dur
            if bps < max(1, _MIN_BPS):
                speed_ok = False
        else:
            speed_ok = False

        # Optional content signature checks
        tokens_ok = True
        try:
            want = [t.strip().lower() for t in (os.getenv("PROXXY_VALIDATOR_BODY_CONTAINS", "") or "").split(",") if t.strip()]
            if not want:
                uhost = (url or "").lower()
                if "netflix.com" in uhost:
                    want = ["netflix"]
            if want:
                text = bytes(sample_buf).decode("utf-8", errors="ignore").lower()
                tokens_ok = all(tok in text for tok in want)
        except Exception:
            tokens_ok = True  # don't fail solely on token parsing

        ok = status_ok and (total >= min_bytes) and (not read_error) and speed_ok and version_ok and tokens_ok
        try:
            elapsed = float(resp.elapsed.total_seconds()) if resp.elapsed is not None else None
        except Exception:
            elapsed = None
        if elapsed is None:
            elapsed = time.monotonic() - t0
        final_url = resp.url
        status = resp.status_code
        resp.close()

        # Optional double-check to reduce false positives that die immediately after first success
        if ok and (os.getenv("PROXXY_VALIDATOR_DOUBLE_CHECK", "1").strip().lower() not in ("0", "false", "no", "off")):
            target2 = _SECOND_URL or url
            try:
                # fresh session to ensure a new TCP connection path (avoid pooled reuse)
                sess2 = requests.Session()
                adapter2 = HTTPAdapter(pool_connections=8, pool_maxsize=8, max_retries=Retry(total=0, connect=0, read=0, redirect=0, backoff_factor=0))
                sess2.mount("http://", adapter2)
                sess2.mount("https://", adapter2)
                sess2.verify = sess.verify
                sess2.headers.update(dict(sess.headers))
                # propagate enforced timeout
                sess2.request_timeout = getattr(sess, "request_timeout", (_ENFORCED_TIMEOUT_SECONDS, _ENFORCED_TIMEOUT_SECONDS))  # type: ignore[attr-defined]
                resp2 = sess2.get(
                    target2,
                    proxies=proxies,
                    timeout=getattr(sess2, "request_timeout", (_ENFORCED_TIMEOUT_SECONDS, _ENFORCED_TIMEOUT_SECONDS)),
                    stream=True,
                    allow_redirects=True,
                    headers={"Connection": "close"},
                )
                total2 = 0
                start2 = time.monotonic()
                first2: Optional[float] = None
                seen_first2 = False
                read_error2 = False
                sample2 = bytearray()
                min_bytes2 = max(1, _MIN_BYTES)
                for chunk in resp2.iter_content(chunk_size=max(1, _CHUNK_SIZE)):
                    now2 = time.monotonic()
                    # TTFB guard for second pass
                    if not seen_first2 and (now2 - start2) >= float(_TTFB_SECONDS):
                        read_error2 = True
                        break
                    if not chunk:
                        if (now2 - start2) >= float(_RECHECK_READ_SECONDS):
                            break
                        continue
                    if not seen_first2:
                        seen_first2 = True
                        first2 = now2
                    total2 += len(chunk)
                    if len(sample2) < 16384:
                        t2 = min(len(chunk), 16384 - len(sample2))
                        sample2.extend(chunk[:t2])
                    if total2 >= min_bytes2 or (now2 - start2) >= float(_RECHECK_READ_SECONDS):
                        break

                # Status and header sanity for second pass
                status2_ok = 200 <= resp2.status_code < 400
                h2 = {k.lower(): v for k, v in (resp2.headers or {}).items()}
                if 300 <= resp2.status_code < 400 and "location" not in h2:
                    status2_ok = False

                # HTTP version check (when available)
                version2_ok = True
                if (_REQUIRE_HTTP11 or "1") and str(_REQUIRE_HTTP11).strip().lower() not in ("0", "false", "no", "off"):
                    try:
                        ver2 = getattr(getattr(resp2, "raw", None), "version", None)
                        if isinstance(ver2, int) and ver2 != 11:
                            version2_ok = False
                    except Exception:
                        pass

                # Throughput after first byte
                speed2_ok = True
                if seen_first2 and first2 is not None:
                    dur2 = max(1e-6, (time.monotonic() - first2))
                    bps2 = total2 / dur2
                    if bps2 < max(1, _MIN_BPS):
                        speed2_ok = False
                else:
                    speed2_ok = False

                # Optional content signature checks (second pass)
                tokens2_ok = True
                try:
                    want2 = [t.strip().lower() for t in (os.getenv("PROXXY_VALIDATOR_BODY_CONTAINS", "") or "").split(",") if t.strip()]
                    if not want2:
                        uhost2 = (target2 or "").lower()
                        if "netflix.com" in uhost2:
                            want2 = ["netflix"]
                    if want2:
                        text2 = bytes(sample2).decode("utf-8", errors="ignore").lower()
                        tokens2_ok = all(tok in text2 for tok in want2)
                except Exception:
                    tokens2_ok = True

                if not (status2_ok and total2 >= min_bytes2 and (not read_error2) and speed2_ok and version2_ok and tokens2_ok):
                    ok = False
                resp2.close()
                try:
                    sess2.close()
                except Exception:
                    pass
            except Exception:
                ok = False

        return proxy, ok, status, None if ok else f"http={status} bytes={total}", elapsed, final_url
    except Exception as e:
        return proxy, False, None, str(e), None, None


def _check_one(
    proxy: str, url: str, timeout: float, verify_ssl: bool, user_agent: Optional[str]
) -> Tuple[str, bool, Optional[int], Optional[str], Optional[float], Optional[str]]:
    """
    Route to HTTP/2 validation first (strict), then optionally fall back to HTTP/1.1.
    - When PROXXY_VALIDATOR_HTTP2_REQUIRED=1 and target is HTTPS, only H2 success is accepted.
    """
    try:
        sch = (urlparse(url).scheme or "").lower()
    except Exception:
        sch = "https"
    http2_enable = str(_HTTP2_ENABLE).strip().lower() not in ("0", "false", "no", "off")
    http2_required = str(_HTTP2_REQUIRED).strip().lower() not in ("0", "false", "no", "off")

    # Try HTTP/2 first for HTTPS targets when enabled
    if http2_enable and sch == "https":
        p, ok, status, err, elapsed, final_url = _check_one_http2(proxy, url, timeout, verify_ssl, user_agent)
        # In strict mode, return immediately (no fallback on H2 failure)
        if http2_required or ok:
            return p, ok, status, err, elapsed, final_url
        # else fall through to HTTP/1.1 requests path as a best-effort

    # Fallback to requests (HTTP/1.1)
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
# --- HTTP/2 validation path (httpx-based, strict) ---
def _check_one_http2(
    proxy: str, url: str, timeout: float, verify_ssl: bool, user_agent: Optional[str]
) -> Tuple[str, bool, Optional[int], Optional[str], Optional[float], Optional[str]]:
    """
    Validate a proxy using a real HTTP/2 GET to the target URL with streaming thresholds.
    - Requires ALPN 'h2' (enforced in TLS preflight when enabled) and response.http_version == 'HTTP/2'
    - Applies TTFB, minimal bytes, and sustained throughput checks
    Returns: (proxy, ok, status_code|None, error_reason|None, elapsed|None, final_url|None)
    Error reasons use 'h2_*' prefixes to distinguish from HTTP/1.1 path.
    """
    try:
        httpx_mod = importlib.import_module("httpx")
    except Exception:
        return proxy, False, None, "h2_dep:httpx", None, None

    # Optional TCP preflight to quickly reject closed/unreachable proxies
    try:
        if (_TCP_PREFLIGHT or "1") and str(_TCP_PREFLIGHT).strip().lower() not in ("0", "false", "no", "off"):
            pu = urlparse(proxy)
            h = pu.hostname
            p = pu.port or (443 if (pu.scheme or "").lower() == "https" else 80)
            if h and p:
                s = socket.create_connection((h, int(p)), timeout=min(_CONNECT_TIMEOUT_SECONDS, _ENFORCED_TIMEOUT_SECONDS, 3.0))
                try:
                    s.close()
                except Exception:
                    pass
    except Exception as e:
        return proxy, False, None, f"h2_tcp_preflight:{e}", None, None

    # OS trust TLS preflight (with ALPN enforcement when required)
    if (_OS_TRUST_PREFLIGHT or "1") and str(_OS_TRUST_PREFLIGHT).strip().lower() not in ("0", "false", "no", "off"):
        ok_tls, tls_err = _os_trust_tls_preflight(proxy, url)
        if not ok_tls:
            return proxy, False, None, f"os_trust:{tls_err}", None, None

    # Build httpx client with HTTP/2 enabled
    try:
        connect_t = min(_CONNECT_TIMEOUT_SECONDS, _ENFORCED_TIMEOUT_SECONDS)
        to = httpx_mod.Timeout(connect=connect_t, read=_ENFORCED_TIMEOUT_SECONDS, write=_ENFORCED_TIMEOUT_SECONDS, pool=_ENFORCED_TIMEOUT_SECONDS)
        proxies = {"http://": proxy, "https://": proxy}

        # HTTP/2 does not allow 'Connection' header; avoid setting it.
        headers: Dict[str, str] = {
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Accept-Language": os.getenv("PROXXY_VALIDATOR_ACCEPT_LANGUAGE", "en-US,en;q=0.9"),
        }
        ua = user_agent or os.getenv("PROXXY_VALIDATOR_USER_AGENT", _DEFAULT_UA)
        if ua:
            headers["User-Agent"] = ua

        t0 = time.monotonic()
        status = None
        final_url = None

        def _stream_once(client: Any, target: str, ttfb_s: float, read_window_s: float, min_bytes_req: int) -> Tuple[bool, int, bool, float, bytearray, Dict[str, str], Optional[str], str, int]:
            nonlocal status, final_url
            total = 0
            start_read = time.monotonic()
            first_byte_at: Optional[float] = None
            seen_first = False
            read_error = False
            sample_buf = bytearray()

            with client.stream("GET", target, headers=headers, follow_redirects=True) as resp:
                status = resp.status_code
                final_url = str(resp.url)
                # Normalize headers to lower keys
                hdrs = {str(k).lower(): str(v) for k, v in (resp.headers or {}).items()}

                # HTTP/2 protocol check at response level
                hv = ""
                try:
                    hv = str(getattr(resp, "http_version", "") or "").upper()
                except Exception:
                    # Fallback to httpx internal extension (best-effort)
                    try:
                        hv = str(resp.extensions.get("http_version") or "").upper()  # type: ignore[attr-defined]
                    except Exception:
                        hv = ""
                if not hv.startswith("HTTP/2"):
                    return False, total, read_error, start_read, sample_buf, hdrs, f"h2_httpver:{hv or 'none'}", final_url or target, status or 0

                # Read streaming body with TTFB/throughput guards
                try:
                    for chunk in resp.iter_bytes(chunk_size=max(1, _CHUNK_SIZE)):
                        now = time.monotonic()
                        if not seen_first and (now - start_read) >= float(ttfb_s):
                            read_error = True
                            break
                        if not chunk:
                            if (now - start_read) >= float(read_window_s):
                                break
                            continue
                        if not seen_first:
                            seen_first = True
                            first_byte_at = now
                        total += len(chunk)
                        if len(sample_buf) < 16384:
                            take = min(len(chunk), 16384 - len(sample_buf))
                            sample_buf.extend(chunk[:take])
                        if total >= max(1, min_bytes_req) or (now - start_read) >= float(read_window_s):
                            break
                except Exception as e:
                    return False, total, True, start_read, sample_buf, hdrs, f"h2_read:{str(e)[:128]}", final_url or target, status or 0

            # Status and header sanity
            status_ok = (status is not None) and (200 <= int(status) < 400)
            if status and 300 <= int(status) < 400 and "location" not in hdrs:
                status_ok = False

            # Throughput after first byte
            speed_ok = True
            if seen_first and first_byte_at is not None:
                dur = max(1e-6, (time.monotonic() - first_byte_at))
                bps = total / dur
                if bps < max(1, _MIN_BPS):
                    speed_ok = False
            else:
                speed_ok = False

            # Optional content signature checks
            tokens_ok = True
            try:
                want = [t.strip().lower() for t in (os.getenv("PROXXY_VALIDATOR_BODY_CONTAINS", "") or "").split(",") if t.strip()]
                if not want:
                    uhost = (target or "").lower()
                    if "netflix.com" in uhost:
                        want = ["netflix"]
                if want:
                    text = bytes(sample_buf).decode("utf-8", errors="ignore").lower()
                    tokens_ok = all(tok in text for tok in want)
            except Exception:
                tokens_ok = True

            ok = status_ok and (total >= max(1, min_bytes_req)) and (not read_error) and speed_ok and tokens_ok
            if not ok:
                reasons: List[str] = []
                if not status_ok:
                    reasons.append(f"http={status}")
                if read_error:
                    reasons.append("ttfb" if not seen_first else "read")
                if total < max(1, min_bytes_req):
                    reasons.append(f"bytes={total}")
                if not speed_ok:
                    reasons.append("speed")
                if not tokens_ok:
                    reasons.append("tokens")
                return False, total, read_error, start_read, sample_buf, hdrs, "h2:" + " ".join(reasons), final_url or target, status or 0
            return True, total, read_error, start_read, sample_buf, hdrs, None, final_url or target, status or 0

        # First pass
        with httpx_mod.Client(http2=True, verify=verify_ssl, proxies=proxies, timeout=to) as client:
            ok1, total1, read_err1, start1, sample1, hdrs1, err1, final1, status1 = _stream_once(
                client, url, _TTFB_SECONDS, _READ_WINDOW_SECONDS, max(1, _MIN_BYTES)
            )
            ok = ok1
            err = err1
            final_url = final1
            status = status1

        # Optional second pass (double-check) to reduce flakiness
        if ok and (os.getenv("PROXXY_VALIDATOR_DOUBLE_CHECK", "1").strip().lower() not in ("0", "false", "no", "off")):
            target2 = _SECOND_URL or url
            try:
                with httpx_mod.Client(http2=True, verify=verify_ssl, proxies=proxies, timeout=to) as client2:
                    ok2, total2, read_err2, start2, sample2, hdrs2, err2, final2, status2 = _stream_once(
                        client2, target2, _TTFB_SECONDS, _RECHECK_READ_SECONDS, max(1, _MIN_BYTES)
                    )
                    if not ok2:
                        ok = False
                        err = err2 or "h2:recheck"
                        final_url = final2
                        status = status2
            except Exception as e:
                ok = False
                err = f"h2_recheck:{str(e)[:128]}"

        elapsed = time.monotonic() - t0
        if ok:
            return proxy, True, status, None, elapsed, final_url
        else:
            # Normalize status in error reporting
            st = status if isinstance(status, int) else (None if status is None else int(status))
            if err:
                return proxy, False, st, err, elapsed, final_url
            return proxy, False, st, f"h2_fail:http={st} url={final_url or url}", elapsed, final_url
    except Exception as e:
        return proxy, False, None, f"h2:{str(e)[:256]}", None, None