from __future__ import annotations

import logging
import os
import sys
import threading
import time
from typing import List, Optional

# Orchestrator operates as a library; config import is package-relative
from .config import OrchestratorConfig, load_config_from_env
from .proxy_server import run_tunnel_proxy
from .validator import check_proxies_stream
from .scrapers import StaticUrlTextScraper, ProxyDBScraper

logger = logging.getLogger("proXXy.orchestrator")


def produce_process_loop(stop, config: Optional[OrchestratorConfig] = None, status_queue=None, pool_queue=None) -> None:
    """
    Throughput-first producer loop:
    - Scrape HTTP/HTTPS sources
    - Read, normalize, dedupe by endpoint
    - Validate candidates (streaming)
    - Publish live proxies to pool
    - Emit basic cycle metrics
    """
    cfg = config or load_config_from_env()

    # Ensure sibling imports when spawned on Windows (spawn)
    try:
        base = os.path.abspath(os.path.dirname(__file__))
        if base not in sys.path:
            sys.path.insert(0, base)
    except Exception:
        pass

    def emit(evt):
        if status_queue is None:
            return
        try:
            status_queue.put(evt)
        except Exception:
            pass

    os.makedirs(cfg.output_dir, exist_ok=True)

    cycle = 0

    while not stop.is_set():
        cycle += 1
        scrape_total = 0
        candidates_count = 0
        live_count = 0
        published = False
        publish_size = 0
        combined_size = 0
        scrape_dt = 0.0
        validate_dt = 0.0
        published_count = 0

        # 1) Scrape using pluggable scrapers (in-memory aggregation)
        proxies_all: List[str] = []
        try:
            logger.info("scrape: starting (in-process, pluggable)")
            t0 = time.perf_counter()
            # Scraper runtime config from env (allows toggling SSL verification)
            verify_ssl_env = os.environ.get("PROXXY_SCRAPER_VERIFY_SSL", "1").lower() not in ("0", "false", "no")
            ua_env = os.environ.get("PROXXY_SCRAPER_UA", None)
            try:
                logger.info("scrape.config: verify_ssl=%s ua=%s", verify_ssl_env, bool(ua_env))
            except Exception:
                pass
            scrapers = [
                StaticUrlTextScraper(protocols=("HTTP", "HTTPS"), verify_ssl=verify_ssl_env),
                ProxyDBScraper(protocol="http", anon_levels=(2, 4), country="", pages=1, user_agent=ua_env, verify_ssl=verify_ssl_env),
            ]
            seen = set()
            for s in scrapers:
                try:
                    sname = getattr(s, "name", s.__class__.__name__)
                    logger.debug("scrape.%s: starting", sname)
                    t_s0 = time.perf_counter()
                    items = s.scrape()
                    dt_s = time.perf_counter() - t_s0
                    added = 0
                    for p in items:
                        if p not in seen:
                            seen.add(p)
                            proxies_all.append(p)
                            added += 1
                    logger.debug("scrape.%s: got=%d added=%d dupes=%d in %.2fs", sname, len(items), added, len(items) - added, dt_s)
                except Exception:
                    logger.exception("scrape.%s: failed", getattr(s, "name", s.__class__.__name__))
            scrape_dt = time.perf_counter() - t0
            scrape_total = len(proxies_all)
            logger.info("scrape: done in %.2fs total=%d", scrape_dt, scrape_total)
        except Exception as e:
            logger.exception("scrape: failed: %s", e)

        # 2) Normalize to HTTP/HTTPS URL forms for validator
        candidates: List[str] = []
        try:
            for item in proxies_all:
                s = str(item).strip()
                if not s:
                    continue
                # Choose http:// by default; validator handles both schemes
                if "://" not in s:
                    s = f"http://{s}"
                else:
                    sch = s.split("://", 1)[0]
                    if sch not in ("http", "https"):
                        continue
                candidates.append(s)
            # Deduplicate by endpoint, prefer http:// when both exist
            by_endpoint: dict[str, str] = {}
            order: list[str] = []
            from urllib.parse import urlparse
            for p in candidates:
                try:
                    u = urlparse(p)
                    endpoint = u.netloc
                    if not endpoint:
                        continue
                    prev = by_endpoint.get(endpoint)
                    if prev is None:
                        by_endpoint[endpoint] = p
                        order.append(endpoint)
                    else:
                        if p.startswith("http://") and not prev.startswith("http://"):
                            by_endpoint[endpoint] = p
                except Exception:
                    continue
            candidates = [by_endpoint[e] for e in order]
            scrape_total = max(scrape_total, len(candidates))
        except Exception:
            candidates = []

        # Validate candidates and publish only live ones
        candidates_count = len(candidates)
        if candidates_count > 0:
            try:
                emit({
                    "type": "validate_start",
                    "total": candidates_count,
                    "workers": int(getattr(cfg, "validator_workers", 0) or 0),
                    "ts": time.time(),
                })
            except Exception:
                pass

            t_val0 = time.perf_counter()
            published_count = 0
            validated_count = 0
            completed_count = 0
            last_progress_emit = time.monotonic()
            batch: List[str] = []
            published_seen: set[str] = set()
            # Flush to pool early so proxy can start once min_upstreams are available
            flush_threshold = max(1, int(getattr(cfg, "min_upstreams", 10)))
            last_flush_ts = time.monotonic()

            def _flush_batch():
                nonlocal batch, publish_size, published, last_flush_ts
                if not batch:
                    return
                to_send = list(batch)
                if pool_queue is not None:
                    try:
                        pool_queue.put({"type": "add", "proxies": to_send}, timeout=0.1)
                    except Exception:
                        try:
                            for i in range(0, len(to_send), 2000):
                                pool_queue.put({"type": "add", "proxies": to_send[i:i+2000]}, timeout=0.1)
                        except Exception:
                            pass
                body_bytes = len(("\n".join(to_send) + "\n").encode("utf-8"))
                publish_size += body_bytes
                published = True
                # Emit publish flush event for status display
                try:
                    emit({"type": "publish_flush", "bytes": int(body_bytes), "count": int(len(to_send)), "ts": time.time()})
                except Exception:
                    pass
                batch.clear()
                last_flush_ts = time.monotonic()

            def _on_live(pxy: str, details: dict) -> None:
                nonlocal published_count, last_flush_ts, published_seen
                # publish unique only
                if pxy in published_seen:
                    return
                published_seen.add(pxy)
                published_count += 1
                batch.append(pxy)
                if len(batch) >= flush_threshold:
                    _flush_batch()
                else:
                    # time-based flush to keep pool warm
                    now = time.monotonic()
                    if (now - last_flush_ts) >= 1.0:
                        _flush_batch()

            def _on_result(details: dict) -> None:
                nonlocal completed_count, last_progress_emit
                completed_count += 1
                now = time.monotonic()
                if (completed_count % 500 == 0) or (now - last_progress_emit >= 1.0) or (completed_count >= candidates_count):
                    last_progress_emit = now
                    try:
                        emit({
                            "type": "validate_progress",
                            "completed": completed_count,
                            "live": published_count,
                            "total": candidates_count,
                            "workers": int(getattr(cfg, "validator_workers", 0) or 0),
                            "ts": time.time(),
                        })
                    except Exception:
                        pass
                return

            try:
                live_list, _ = check_proxies_stream(
                    proxies=candidates,
                    url=str(getattr(cfg, "validation_url", "https://www.netflix.com/")),
                    workers=int(getattr(cfg, "validator_workers", 256)),
                    timeout=float(getattr(cfg, "validator_timeout", 5.0)),
                    on_live=_on_live,
                    on_result=_on_result,
                    verify_ssl=True,
                    user_agent=None,
                    total=candidates_count,
                    stop_event=stop,
                )
                try:
                    validated_count = len(live_list or [])
                except Exception:
                    validated_count = 0
            except Exception as e:
                logger.exception("validate: failed: %s", e)
            finally:
                _flush_batch()
                validate_dt = time.perf_counter() - t_val0
                logger.info("validate: validated=%d published=%d in %.2fs", validated_count, published_count, validate_dt)
        else:
            logger.warning("produce: no scraped proxies found; skipping validation")

        emit({
            "type": "cycle_end",
            "cycle": cycle,
            "scrape_total": scrape_total,
            "candidates": candidates_count,
            "validate_live": published_count,
            "published": published,
            "publish_size": publish_size,
            "scrape_dt": scrape_dt,
            "validate_dt": validate_dt,
            "combined_input_size": max(0, combined_size),
            "workers": 0,
            "ts": time.time(),
        })

        if stop.is_set():
            break

def tunnel_proxy_server_loop(stop: threading.Event, config: Optional[OrchestratorConfig] = None, status_queue=None) -> None:
    """
    Start an in-process, tunneling-only forward proxy (no TLS interception).
    - Listens on cfg.proxy_host:cfg.proxy_port
    - Reads upstream proxies from cfg.pool_file_path (file-backed pool)
    - Emits lifecycle events to status_queue: proxy_starting, proxy_started, proxy_ready, proxy_exit
    """
    cfg = config or load_config_from_env()

    def emit(evt):
        if status_queue is None:
            return
        try:
            status_queue.put(evt)
        except Exception:
            pass

    host = cfg.proxy_host
    port = cfg.proxy_port
    pool_file = cfg.pool_file_path
    min_upstreams = max(0, int(getattr(cfg, "min_upstreams", 1)))

    def _count_upstreams() -> int:
        try:
            with open(pool_file, "r", encoding="utf-8") as f:
                count = 0
                for ln in f:
                    s = (ln or "").strip()
                    if s and not s.lstrip().startswith("#"):
                        count += 1
                return count
        except Exception:
            return 0


    # Non-simulated: wait for enough upstreams before starting server
    if min_upstreams > 0:
        while not stop.is_set():
            have = _count_upstreams()
            if have >= min_upstreams:
                border = "=" * 72
                try:
                    logger.info(border)
                    logger.info("= PROXY READY: upstreams >= %d (have %d) =", min_upstreams, have)
                    logger.info("= Starting tunnel on %s:%d =", host, port)
                    logger.info(border)
                except Exception:
                    pass
                break
            try:
                emit({"type": "proxy_waiting", "have": int(have), "need": int(min_upstreams)})
            except Exception:
                pass
            stop.wait(1.0)
        if stop.is_set():
            return

    # Announce readiness (since min_upstreams satisfied at this point)
    try:
        cnt = _count_upstreams()
        if cnt >= min_upstreams:
            logger.info("proxy: ready (tunnel %s:%d; upstreams>=%d)", host, port, min_upstreams)
            emit({"type": "proxy_ready", "upstreams": int(cnt)})
    except Exception:
        pass

    # Supervisor loop: restart the tunnel server if it exits unexpectedly
    attempt = 0
    backoff = 1.5
    max_backoff = 30.0
    while not stop.is_set():
        attempt += 1
        code = 1
        try:
            # lifecycle: starting/started per attempt
            try:
                emit({"type": "proxy_starting", "attempt": int(attempt)})
            except Exception:
                pass
            try:
                emit({"type": "proxy_started", "pid": int(os.getpid()), "attempt": int(attempt)})
            except Exception:
                emit({"type": "proxy_started", "attempt": int(attempt)})

            # Run the asyncio-based tunnel server in this thread until stop is set
            run_tunnel_proxy(stop, host, port, pool_file, emit=emit)
            code = 0 if stop.is_set() else 1
        except Exception as e:
            logger.exception("proxy: tunnel server error (attempt %d): %s", attempt, e)
            code = 1
        finally:
            try:
                emit({"type": "proxy_exit", "code": int(code), "attempt": int(attempt)})
            except Exception:
                pass
            logger.info("proxy: stopped (attempt %d, code %d)", attempt, code)

        if stop.is_set():
            break

        # Backoff and restart
        delay = min(max_backoff, backoff)
        logger.warning("proxy: restarting in %.1fs (attempt %d)", delay, attempt + 1)
        stop.wait(delay)
        backoff = min(max_backoff, backoff * 2)