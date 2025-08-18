import concurrent.futures as futures
import os
import sys
import threading
import time
import socket
import ssl
from urllib.parse import urlparse
from typing import Iterable, List, Optional, Set, Tuple, Dict, Any, Callable

import requests
import random
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from loguru import logger

# Configure loguru level from env (defaults to INFO)
_LOG_LEVEL = os.getenv("PROXXY_VALIDATOR_LOG_LEVEL", os.getenv("PROXXY_LOG_LEVEL", "INFO"))
try:
    logger.remove()
except Exception:
    pass
# Allow switching off queueing for lower overhead
_LOG_ENQUEUE = os.getenv("PROXXY_VALIDATOR_LOG_ENQUEUE", os.getenv("PROXXY_LOG_ENQUEUE", "0")).strip()
_ENQUEUE_BOOL = _LOG_ENQUEUE.lower() not in ("0", "false", "no", "off")
logger.add(sys.stderr, level=_LOG_LEVEL, backtrace=False, diagnose=False, enqueue=_ENQUEUE_BOOL)

# Thread-local session for connection pooling without cross-thread sharing
_thread_local = threading.local()

OnLiveFn = Callable[[str, Dict[str, Any]], None]
OnResultFn = Callable[[Dict[str, Any]], None]

# Minimal downloaded bytes to consider success (default 1; tune via env)
_MIN_BYTES = int(os.getenv("PROXXY_VALIDATOR_MIN_BYTES", "1024"))


# Enforced per-request timeout (seconds) applied to all proxy validations
_ENFORCED_TIMEOUT_SECONDS = 25.0

# Aggressive streaming reader tunables
_READ_WINDOW_SECONDS = float(os.getenv("PROXXY_VALIDATOR_READ_SECONDS", "2.5"))
_CHUNK_SIZE = int(os.getenv("PROXXY_VALIDATOR_CHUNK_SIZE", "8192"))
_TTFB_SECONDS = float(os.getenv("PROXXY_VALIDATOR_TTFB_SECONDS", "2.0"))
_DEFAULT_UA = os.getenv("PROXXY_VALIDATOR_USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
_TCP_PREFLIGHT = os.getenv("PROXXY_VALIDATOR_TCP_PREFLIGHT", "0")
# Optional second URL to improve stability testing (falls back to primary when unset)
_SECOND_URL = os.getenv("PROXXY_VALIDATOR_SECOND_URL", "").strip()
# Connection phase timeout (connect), kept <= enforced overall timeout
_CONNECT_TIMEOUT_SECONDS = float(os.getenv("PROXXY_VALIDATOR_CONNECT_TIMEOUT", "5.0"))
# Re-check (2nd pass) read window
_RECHECK_READ_SECONDS = float(os.getenv("PROXXY_VALIDATOR_RECHECK_READ_SECONDS", "1.5"))
# Minimum sustained throughput after first byte (bytes/sec)
_MIN_BPS = int(os.getenv("PROXXY_VALIDATOR_MIN_BPS", "4096"))
# Require HTTP/1.1 response on validated fetch (some HTTP/1.0 paths are flaky)
_REQUIRE_HTTP11 = os.getenv("PROXXY_VALIDATOR_REQUIRE_HTTP11", "0")
# OS trust TLS preflight via system CA store (replicates Schannel/curl behavior)
_OS_TRUST_PREFLIGHT = os.getenv("PROXXY_VALIDATOR_OS_TRUST_PREFLIGHT", "0")

# Global pool size (tuned per workers unless explicitly set via env)
_POOL_SIZE = int(os.getenv("PROXXY_VALIDATOR_POOL_SIZE", "256"))

# Cache tokens from env once
WANT_TOKENS = [
    t.strip().lower()
    for t in (os.getenv("PROXXY_VALIDATOR_BODY_CONTAINS", "") or "").split(",")
    if t.strip()
]

# TLS preflight success cache (avoid repeating CONNECT+TLS when not needed)
_TLS_PREFLIGHT_CACHE: Dict[Tuple[str, int, str, int], float] = {}
_TLS_PREFLIGHT_TTL_SECONDS = float(os.getenv("PROXXY_VALIDATOR_TLS_PREFLIGHT_TTL", "600"))

# Failure log sampling
_FAIL_LOG_EVERY = max(1, int(os.getenv("PROXXY_VALIDATOR_FAIL_LOG_EVERY", "1")))
_fail_log_counter = 0

# Double-check sampling
_DOUBLE_CHECK_RATIO = float(os.getenv("PROXXY_VALIDATOR_DOUBLE_CHECK_RATIO", "0.1"))

def _os_trust_tls_preflight(proxy: str, url: str) -> Tuple[bool, str]:
    """
    Perform an OS-trust TLS preflight through the proxy using CONNECT to the target host.
    - Uses Windows/macOS OS trust via ssl.create_default_context + load_default_certs.
    - Fails when certificate chain is not trusted by OS (e.g., MITM or bad chain), mirroring curl/Schannel behavior.
    Returns (ok, error_string)
    """
    try:
        u = urlparse(url)
        target_host = u.hostname or ""
        target_port = u.port or 443
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

            with ctx.wrap_socket(sock, server_hostname=target_host) as tls:
                # Force handshake; will raise on untrusted roots/SAN mismatch
                _ = tls.version()
            return True, ""
    except ssl.SSLCertVerificationError as e:
        # Mirror useful details when available
        msg = getattr(e, "verify_message", str(e)) or str(e)
        code = getattr(e, "verify_code", "")
        code_s = f"{code}:" if code else ""
        return False, f"tls_verify:{code_s}{msg}"
    except Exception as e:
        return False, f"tls_preflight:{str(e)[:256]}"

def _tls_preflight_cache_key(proxy: str, url: str) -> Optional[Tuple[str, int, str, int]]:
    try:
        u = urlparse(url)
        target_host = u.hostname or ""
        target_port = u.port or (443 if (u.scheme or "").lower() == "https" else 80)
        pu = urlparse(proxy)
        proxy_host = pu.hostname or ""
        proxy_port = pu.port or (443 if (pu.scheme or "").lower() == "https" else 80)
        if not target_host or not proxy_host or not proxy_port:
            return None
        return (proxy_host, int(proxy_port), target_host, int(target_port))
    except Exception:
        return None

def _get_session(timeout: float, verify_ssl: bool, user_agent: Optional[str] = None) -> requests.Session:
    sess: Optional[requests.Session] = getattr(_thread_local, "session", None)
    if sess is not None:
        return sess

    sess = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=_POOL_SIZE,
        pool_maxsize=_POOL_SIZE,
        max_retries=Retry(total=0, connect=0, read=0, redirect=0, backoff_factor=0),
    )
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    # Honor verify flag to enforce TLS verification
    sess.verify = verify_ssl
    # Disable env proxy pickup; we pass proxies explicitly
    sess.trust_env = False
    sess.headers.update(
        {
            "Accept": "*/*",
            # Let requests negotiate gzip/deflate/br to save bandwidth
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
    # Strict recheck profile (env toggle) adjusts effective windows and throughput threshold without mutating globals
    strict_recheck = os.getenv("PROXXY_VALIDATOR_RECHECK_STRICT", "0").strip().lower() not in ("0", "false", "no", "off")
    eff_TTFB = float(os.getenv("PROXXY_VALIDATOR_TTFB_SECONDS", str(_TTFB_SECONDS)))
    eff_READ = float(os.getenv("PROXXY_VALIDATOR_READ_SECONDS", str(_READ_WINDOW_SECONDS)))
    eff_MIN_BPS = int(os.getenv("PROXXY_VALIDATOR_MIN_BPS", str(_MIN_BPS)))
    if strict_recheck:
        eff_TTFB = min(eff_TTFB, float(os.getenv("PROXXY_VALIDATOR_STRICT_TTFB_SECONDS", "1.5")))
        eff_READ = min(eff_READ, float(os.getenv("PROXXY_VALIDATOR_STRICT_READ_SECONDS", "1.5")))
        try:
            mul = float(os.getenv("PROXXY_VALIDATOR_STRICT_BPS_MULTIPLIER", "1.5"))
        except Exception:
            mul = 1.5
        eff_MIN_BPS = max(eff_MIN_BPS, int(eff_MIN_BPS * mul))
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
    if (
        (_OS_TRUST_PREFLIGHT or "1")
        and str(_OS_TRUST_PREFLIGHT).strip().lower() not in ("0", "false", "no", "off")
        and verify_ssl
        and (urlparse(url).scheme or "https").lower() == "https"
    ):
        cache_key = _tls_preflight_cache_key(proxies.get("http") or proxy, url)
        now_ts = time.time()
        if cache_key is not None:
            ts = _TLS_PREFLIGHT_CACHE.get(cache_key)
            if ts is not None and (now_ts - ts) <= _TLS_PREFLIGHT_TTL_SECONDS:
                pass  # cached success; skip preflight
            else:
                ok_tls, tls_err = _os_trust_tls_preflight(proxies.get("http") or proxy, url)
                if not ok_tls:
                    return proxy, False, None, f"os_trust:{tls_err}", None, None
                _TLS_PREFLIGHT_CACHE[cache_key] = now_ts
        else:
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
        # Content-Length early exit
        try:
            # Do not early-fail on small Content-Length; compressed bodies can inflate after decoding.
            # Proceed to read and validate based on actual bytes read.
            _ = resp.headers.get("Content-Length")
        except Exception:
            pass
        total = 0
        start_read = time.monotonic()
        first_byte_at: Optional[float] = None
        seen_first = False
        read_error = False
        reason_code: Optional[str] = None
        # Capture a sample of response bytes for content signature checks
        sample_buf = bytearray()
        min_bytes = max(1, _MIN_BYTES)
        try:
            for chunk in resp.iter_content(chunk_size=max(1, _CHUNK_SIZE)):
                now = time.monotonic()
                # TTFB guard: if no data within threshold, treat as failure
                if not seen_first and (now - start_read) >= float(eff_TTFB):
                    read_error = True
                    if reason_code is None:
                        reason_code = "ttfb_timeout"
                    break
                if not chunk:
                    if (now - start_read) >= float(eff_READ):
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
        if 300 <= resp.status_code < 400 and "Location" not in resp.headers:
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
        if not version_ok and reason_code is None:
            reason_code = "version_mismatch"

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
            want = WANT_TOKENS[:] if WANT_TOKENS else []
            if want:
                text = bytes(sample_buf).decode("utf-8", errors="ignore").lower()
                tokens_ok = all(tok in text for tok in want)
        except Exception:
            tokens_ok = True  # don't fail solely on token parsing
        if not tokens_ok and reason_code is None:
            reason_code = "token_mismatch"

        if not status_ok and reason_code is None:
            try:
                reason_code = f"http_status_{int(resp.status_code)}"
            except Exception:
                reason_code = "http_status"
        ok = status_ok and (total >= min_bytes) and (not read_error) and version_ok and tokens_ok
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
        double_check_enabled = os.getenv("PROXXY_VALIDATOR_DOUBLE_CHECK", "1").strip().lower() not in ("0", "false", "no", "off")
        if ok and (double_check_enabled or strict_recheck):
            # Decide whether to double-check: always in strict mode; else sample or borderline results
            borderline = (total < max(min_bytes * 2, min_bytes + 2048))
            try:
                if seen_first and first_byte_at is not None:
                    dur_tmp = max(1e-6, (time.monotonic() - first_byte_at))
                    bps_tmp = total / dur_tmp
                    if bps_tmp < (eff_MIN_BPS * 1.25):
                        borderline = True
            except Exception:
                pass
            if not strict_recheck:
                if not borderline and random.random() >= max(0.0, min(1.0, _DOUBLE_CHECK_RATIO)):
                    return proxy, ok, status, None if ok else f"http={status} bytes={total}", elapsed, final_url
            target2 = _SECOND_URL or url
            try:
                # fresh session to ensure a new TCP connection path (avoid pooled reuse)
                sess2 = requests.Session()
                adapter2 = HTTPAdapter(pool_connections=min(16, _POOL_SIZE), pool_maxsize=min(16, _POOL_SIZE), max_retries=Retry(total=0, connect=0, read=0, redirect=0, backoff_factor=0))
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
                if 300 <= resp2.status_code < 400 and "Location" not in resp2.headers:
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
                    want2 = WANT_TOKENS[:] if WANT_TOKENS else []
                    if want2:
                        text2 = bytes(sample2).decode("utf-8", errors="ignore").lower()
                        tokens2_ok = all(tok in text2 for tok in want2)
                except Exception:
                    tokens2_ok = True

                if not (status2_ok and total2 >= min_bytes2 and (not read_error2) and version2_ok and tokens2_ok):
                    ok = False
                resp2.close()
                try:
                    sess2.close()
                except Exception:
                    pass
            except Exception:
                ok = False

        # Prefer structured error code when available
        err_out = None if ok else (reason_code or f"http={status} bytes={total}")
        return proxy, ok, status, err_out, elapsed, final_url
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
    # Tie pool size to workers unless overridden by env
    global _POOL_SIZE
    if os.getenv("PROXXY_VALIDATOR_POOL_SIZE") is None:
        _POOL_SIZE = max(32, max_workers * 2)
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
                    # sample failure logs to reduce overhead
                    if _FAIL_LOG_EVERY <= 1 or (completed % _FAIL_LOG_EVERY) == 0:
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
    # Tie pool size to workers unless overridden by env
    global _POOL_SIZE
    if os.getenv("PROXXY_VALIDATOR_POOL_SIZE") is None:
        _POOL_SIZE = max(32, max_workers * 2)
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
