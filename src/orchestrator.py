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
from .bloom import TimeWindowBloom
from .proxy_server import run_tunnel_proxy

logger = logging.getLogger("proXXy.orchestrator")


def produce_process_loop(stop, config: Optional[OrchestratorConfig] = None, status_queue=None, pool_queue=None) -> None:
    """
    Child process continuous loop: scrape -> validate -> publish (to pool), then immediately repeat.
    Runs entirely via native Python imports (no CLI), in a single persistent process.
    Emits end-of-cycle metrics to a status_queue for live health reporting.
    """
    cfg = config or load_config_from_env()

    # Ensure imports for sibling modules (scraper/validator/utils) when spawned on Windows (spawn)
    try:
        base = os.path.abspath(os.path.dirname(__file__))
        if base not in sys.path:
            sys.path.insert(0, base)
    except Exception:
        pass

    try:
        import validator as validator_mod  # type: ignore
    except Exception as e:
        logger.exception("produce: failed importing validator: %s", e)
        return

    def emit(evt):
        if status_queue is None:
            return
        try:
            status_queue.put(evt)
        except Exception:
            pass

    os.makedirs(cfg.output_dir, exist_ok=True)

    # publishing via pool_queue (IPC), no HTTP pool

    cycle = 0
    # Dead-proxy Bloom: skip proxies that failed within the recent window
    dead_bf_enabled = (os.getenv("PROXXY_DEAD_BF_ENABLED", "1").strip().lower() not in ("0", "false", "no", "off"))
    dead_bf_window = float(os.getenv("PROXXY_DEAD_BF_WINDOW_SECONDS", "3600"))
    dead_bf_slices = int(os.getenv("PROXXY_DEAD_BF_SLICES", "4"))
    dead_bf_capacity = int(os.getenv("PROXXY_DEAD_BF_CAPACITY_PER_SLICE", "100000"))
    dead_bf_fpr = float(os.getenv("PROXXY_DEAD_BF_FPR", "0.01"))
    dead_bf_retest_pct = float(os.getenv("PROXXY_DEAD_BF_RETEST_PCT", "0.02"))
    dead_bf = TimeWindowBloom(window_seconds=dead_bf_window, slices=dead_bf_slices, capacity_per_slice=dead_bf_capacity, error_rate=dead_bf_fpr) if dead_bf_enabled else None
    while not stop.is_set():
        cycle += 1
        scrape_total = 0
        candidates_count = 0
        live_count = 0
        published = False
        publish_size = 0
        combined_size = 0  # legacy metric kept for logs
        scrape_dt = 0.0
        validate_dt = 0.0

        res = None
        # 1) Scrape via subprocess to avoid Twisted reactor reuse; writes HTTP/HTTPS files
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
                # best-effort parse of JSON summary
                try:
                    import json as _json
                    data = _json.loads((cp.stdout or "").strip() or "{}")
                    scrape_total = int(data.get("total") or 0)
                except Exception:
                    scrape_total = 0
                logger.info("scrape: done rc=%s in %.2fs", cp.returncode, scrape_dt)
        except Exception as e:
            logger.exception("scrape: failed: %s", e)

        # 2) Collect proxies from output files (HTTP/HTTPS), prefix scheme, dedupe
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
            candidates = list(dict.fromkeys(candidates))
            scrape_total = max(scrape_total, len(candidates))
        except Exception:
            candidates = []

        # Optional pre-filter using dead Bloom
        if dead_bf is not None and candidates:
            import random as _rnd
            _rnd.seed(os.getpid() + int(time.time()))
            filtered: List[str] = []
            skipped = 0
            explored = 0
            for p in candidates:
                hit = dead_bf.contains(p)
                if not hit:
                    filtered.append(p)
                    continue
                # exploration: re-test a small fraction of known-dead to discover resurrections
                if _rnd.random() < max(0.0, min(1.0, dead_bf_retest_pct)):
                    filtered.append(p)
                    explored += 1
                else:
                    skipped += 1
            candidates = filtered
            try:
                emit({"type": "deadbf_prefilter", "skipped": int(skipped), "explored": int(explored)})
            except Exception:
                pass

        candidates_count = len(candidates)
        if candidates_count == 0:
            logger.warning("produce: no scraped proxies found; keeping previous pool content")
        else:
            workers = max(1, min(cfg.validator_workers, candidates_count))
            logger.info(
                "validate: start total=%d workers=%d url='%s' timeout=%.1f",
                candidates_count,
                workers,
                cfg.validation_url,
                cfg.validator_timeout,
            )
            if logger.isEnabledFor(logging.DEBUG):
                sample = ", ".join(candidates[:3])
                logger.debug("produce: sample candidates: %s%s", sample, " ..." if len(candidates) > 3 else "")
            # Emit validate_start for in-progress visibility
            emit({
                "type": "validate_start",
                "cycle": cycle,
                "total": candidates_count,
                "workers": workers,
                "ts": time.time(),
            })

            # Streaming validation: push to pool in near real-time (tiny batching) via IPC queue
            batch: List[str] = []
            last_flush = time.perf_counter()

            def _flush_batch():
                nonlocal batch, last_flush, publish_size
                if not batch:
                    return
                count = len(batch)
                try:
                    # send a single message to reduce overhead
                    if pool_queue is not None:
                        try:
                            pool_queue.put({"type": "add", "proxies": list(batch)}, timeout=0.1)
                        except Exception:
                            # best-effort fallback: split if oversized
                            try:
                                for i in range(0, len(batch), 2000):
                                    pool_queue.put({"type": "add", "proxies": batch[i:i+2000]}, timeout=0.1)
                            except Exception:
                                pass
                    # estimate bytes similar to previous HTTP body size
                    body_bytes = len(("\n".join(batch) + "\n").encode("utf-8"))
                    publish_size += body_bytes
                    try:
                        emit({"type": "publish_flush", "count": int(count), "bytes": int(body_bytes), "ts": time.time()})
                    except Exception:
                        pass
                finally:
                    batch.clear()
                    last_flush = time.perf_counter()

            t1 = time.perf_counter()
            # In-progress counters for status ticker
            progress_completed = 0
            last_prog_emit = t1

            def on_live(proxy: str, details):
                nonlocal live_count, last_flush
                live_count += 1
                batch.append(proxy)
                now = time.perf_counter()
                # flush on small batch or short timer
                if len(batch) >= 50 or (now - last_flush) >= 0.2:
                    _flush_batch()

            def on_result(details):
                nonlocal progress_completed, last_prog_emit
                progress_completed += 1
                try:
                    if dead_bf is not None and not details.get("ok", False):
                        p = details.get("proxy")
                        if isinstance(p, str) and p:
                            dead_bf.add(p)
                except Exception:
                    pass
                now2 = time.perf_counter()
                if (now2 - last_prog_emit) >= 1.0:
                    try:
                        emit({
                            "type": "validate_progress",
                            "cycle": cycle,
                            "completed": progress_completed,
                            "live": live_count,
                            "total": candidates_count,
                            "workers": workers,
                            "ts": time.time(),
                        })
                    except Exception:
                        pass
                    last_prog_emit = now2

            try:
                _live_sorted, _details = validator_mod.check_proxies_stream(
                    candidates,
                    cfg.validation_url,
                    workers,
                    float(cfg.validator_timeout),
                    on_live=on_live,
                    on_result=on_result,
                    verify_ssl=True,
                    user_agent=None,
                    total=candidates_count,
                    stop_event=stop,
                )
                # final flush
                _flush_batch()
                # final progress emit
                try:
                    emit({
                        "type": "validate_progress",
                        "cycle": cycle,
                        "completed": progress_completed,
                        "live": live_count,
                        "total": candidates_count,
                        "workers": workers,
                        "ts": time.time(),
                    })
                except Exception:
                    pass
                validate_dt = time.perf_counter() - t1
                published = live_count > 0
                logger.info("produce: streamed to pool live=%d (validator %.2fs)", live_count, validate_dt)
            except Exception as e:
                logger.exception("produce: validator step failed: %s", e)

        # Emit end-of-cycle metrics
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
            "workers": min(cfg.validator_workers, max(1, candidates_count)),
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