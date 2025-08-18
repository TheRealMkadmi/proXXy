from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import time
from typing import List, Optional

# Orchestrator operates as a library; config import is package-relative
from .config import OrchestratorConfig, load_config_from_env
from .proxy_server import run_tunnel_proxy
from .validator import check_proxies_stream

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

        # 1) Scrape via subprocess; writes HTTP/HTTPS files
        try:
            logger.info("scrape: starting (subprocess)")
            t0 = time.perf_counter()
            scraper_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "scraper.py")
            scr_cmd = [
                sys.executable, scraper_path,
                "--protocols", "HTTP,HTTPS",
                "--output-dir", cfg.output_dir,
                "--timeout", "5",
                "--retry-times", "1",
                "--log-level", os.environ.get("PROXXY_SCRAPER_LOG_LEVEL", "WARNING"),
            ]
            cp = subprocess.run(scr_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            scrape_dt = time.perf_counter() - t0
            if cp.returncode != 0:
                logger.error("scrape: subprocess failed rc=%s stderr=%s", cp.returncode, (cp.stderr or "").strip())
            else:
                try:
                    import json as _json
                    data = _json.loads((cp.stdout or "").strip() or "{}")
                    scrape_total = int(data.get("total") or 0)
                except Exception:
                    scrape_total = 0
                logger.info("scrape: done rc=%s in %.2fs", cp.returncode, scrape_dt)
        except Exception as e:
            logger.exception("scrape: failed: %s", e)

        # 2) Collect proxies from output files (HTTP/HTTPS), prefix scheme
        candidates: List[str] = []
        try:
            def _read_lines(path: str) -> List[str]:
                out: List[str] = []
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        for ln in f:
                            s = ln.strip()
                            if s and not s.startswith("#"):
                                out.append(s)
                except Exception:
                    pass
                return out

            http_path = os.path.join(cfg.output_dir, "HTTP.txt")
            https_path = os.path.join(cfg.output_dir, "HTTPS.txt")
            for raw, scheme in ((http_path, "http"), (https_path, "https")):
                for item in _read_lines(raw):
                    s = str(item).strip()
                    if not s:
                        continue
                    if "://" not in s:
                        s = f"{scheme}://{s}"
                    else:
                        sch = s.split("://", 1)[0]
                        if sch not in ("http", "https"):
                            continue
                    candidates.append(s)

            # Deduplicate by endpoint (host:port), prefer http:// when both exist.
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
            live_count = 0
            batch: List[str] = []

            def _flush_batch():
                nonlocal batch, publish_size, published
                if not batch:
                    return
                if pool_queue is not None:
                    try:
                        pool_queue.put({"type": "add", "proxies": list(batch)}, timeout=0.1)
                    except Exception:
                        try:
                            for i in range(0, len(batch), 2000):
                                pool_queue.put({"type": "add", "proxies": batch[i:i+2000]}, timeout=0.1)
                        except Exception:
                            pass
                body_bytes = len(("\n".join(batch) + "\n").encode("utf-8"))
                publish_size += body_bytes
                published = True
                batch.clear()

            def _on_live(pxy: str, details: dict) -> None:
                nonlocal live_count
                live_count += 1
                batch.append(pxy)
                if len(batch) >= 200:
                    _flush_batch()

            def _on_result(_details: dict) -> None:
                # Optional: could emit validate_progress here if desired
                return

            try:
                check_proxies_stream(
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
            except Exception as e:
                logger.exception("validate: failed: %s", e)
            finally:
                _flush_batch()
                validate_dt = time.perf_counter() - t_val0
                logger.info("validate: live=%d in %.2fs", live_count, validate_dt)
        else:
            logger.warning("produce: no scraped proxies found; skipping validation")

        emit({
            "type": "cycle_end",
            "cycle": cycle,
            "scrape_total": scrape_total,
            "candidates": candidates_count,
            "validate_live": live_count,
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
    simulate = os.environ.get("PROXXY_PROXY_SIMULATE", "0").lower() not in ("0", "false", "no")

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

    if simulate:
        # Simulated mode: announce and monitor file; do not start server
        if min_upstreams > 0:
            while not stop.is_set():
                have = _count_upstreams()
                if have >= min_upstreams:
                    border = "=" * 72
                    try:
                        logger.info(border)
                        logger.info("= PROXY READY: upstreams >= %d (have %d) =", min_upstreams, have)
                        logger.info("= Simulated start on %s:%d =", host, port)
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
        emit({"type": "proxy_starting"})
        try:
            emit({"type": "proxy_started", "pid": int(os.getpid())})
        except Exception:
            emit({"type": "proxy_started"})
        # Announce readiness once file has required entries
        def _ready_watch_sim():
            while not stop.is_set():
                try:
                    count = _count_upstreams()
                    if count >= min_upstreams:
                        logger.info("proxy: ready (simulated %s:%d; upstreams>=%d)", host, port, min_upstreams)
                        try:
                            emit({"type": "proxy_ready", "upstreams": int(count)})
                        except Exception:
                            pass
                        return
                except Exception:
                    pass
                stop.wait(0.5)
        threading.Thread(target=_ready_watch_sim, name="proxy-ready-sim", daemon=True).start()

        # Stream simple counters to console
        def _sim_stream():
            last = -1
            while not stop.is_set():
                cnt = _count_upstreams()
                if cnt != last:
                    logger.info("sim-tunnel: upstreams=%d file=%s", cnt, pool_file)
                    last = cnt
                stop.wait(1.0)
        threading.Thread(target=_sim_stream, name="proxy-sim-stream", daemon=True).start()

        # Hold until stop
        while not stop.is_set():
            stop.wait(0.5)
        logger.info("proxy: stopped (simulated tunnel)")
        return

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

    # Start server
    emit({"type": "proxy_starting"})
    try:
        emit({"type": "proxy_started", "pid": int(os.getpid())})
    except Exception:
        emit({"type": "proxy_started"})

    # Announce readiness (since min_upstreams satisfied at this point)
    try:
        cnt = _count_upstreams()
        if cnt >= min_upstreams:
            logger.info("proxy: ready (tunnel %s:%d; upstreams>=%d)", host, port, min_upstreams)
            emit({"type": "proxy_ready", "upstreams": int(cnt)})
    except Exception:
        pass

    try:
        # Run the asyncio-based tunnel server in this thread until stop is set
        run_tunnel_proxy(stop, host, port, pool_file, emit=emit)
    except Exception as e:
        logger.exception("proxy: tunnel server error: %s", e)
    finally:
        try:
            emit({"type": "proxy_exit", "code": 0})
        except Exception:
            pass
        logger.info("proxy: stopped")