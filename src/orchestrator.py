from __future__ import annotations

import logging
import os
import shlex
import subprocess
import sys
import threading
import time
from typing import List, Optional

# Orchestrator operates as a library; config import is package-relative
from .config import OrchestratorConfig, load_config_from_env

logger = logging.getLogger("proXXy.orchestrator")


def produce_process_loop(stop, config: Optional[OrchestratorConfig] = None, status_queue=None) -> None:
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

    pool_url = f"http://{cfg.pool_host}:{cfg.pool_port}"

    cycle = 0
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

            # Streaming validation: push to pool in near real-time (tiny batching)
            from urllib.request import Request, urlopen as _urlopen
            from urllib.error import URLError, HTTPError

            add_endpoint = f"{pool_url.rstrip('/')}/add"
            batch: List[str] = []
            last_flush = time.perf_counter()

            def _flush_batch():
                nonlocal batch, last_flush, publish_size
                if not batch:
                    return
                count = len(batch)
                body = ("\n".join(batch) + "\n").encode("utf-8")
                try:
                    req = Request(add_endpoint, data=body, headers={"Content-Type": "text/plain; charset=utf-8"}, method="POST")
                    with _urlopen(req, timeout=2.0) as resp:
                        code = getattr(resp, "status", None)
                        if code is None:
                            try:
                                code = resp.getcode()
                            except Exception:
                                code = 200
                    if 200 <= int(code) < 300:
                        publish_size += len(body)
                        try:
                            emit({"type": "publish_flush", "count": int(count), "bytes": int(len(body)), "ts": time.time()})
                        except Exception:
                            pass
                        batch.clear()
                        last_flush = time.perf_counter()
                    else:
                        logger.warning("publish: non-2xx status code=%s (will retry on next flush)", code)
                except (HTTPError, URLError, TimeoutError, OSError) as e:
                    logger.warning("publish: transient error: %s (will retry on next flush)", e)
                except Exception as e:
                    logger.exception("publish: error: %s", e)

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


def proxy_server_loop(stop: threading.Event, config: Optional[OrchestratorConfig] = None, status_queue=None) -> None:
    """
    Starts proxy.py as a subprocess with a rotating-upstream plugin that fetches pool state
    via HTTP and assigns one upstream per TCP connection (sticky).
    Emits lifecycle events to a status_queue for live health reporting.
    """
    cfg = config or load_config_from_env()

    def emit(evt):
        if status_queue is None:
            return
        try:
            status_queue.put(evt)
        except Exception:
            pass

    env = os.environ.copy()
    # Ensure plugin module is importable
    src_dir = os.path.abspath(os.path.dirname(__file__))
    existing_pp = env.get("PYTHONPATH", "")
    if src_dir not in (existing_pp.split(os.pathsep) if existing_pp else []):
        env["PYTHONPATH"] = src_dir + (os.pathsep + existing_pp if existing_pp else "")

    # Expose pool endpoint to plugin
    env["PROXXY_POOL_HOST"] = cfg.pool_host
    env["PROXXY_POOL_PORT"] = str(cfg.pool_port)
    env["PROXXY_POOL_URL"] = f"http://{cfg.pool_host}:{cfg.pool_port}"
    env["PROXXY_POOL_REFRESH_MS"] = str(cfg.pool_refresh_ms)

    host = cfg.proxy_host
    port = cfg.proxy_port
    log_level = cfg.proxy_log_level

    logger.info("proxy: starting with pool endpoint %s", env["PROXXY_POOL_URL"])

    cmd = [
        sys.executable, "-m", "proxy",
        "--hostname", host,
        "--port", str(port),
        "--plugins", "rotating_upstream_plugin.RotatingUpstreamPlugin",
        "--log-level", log_level,
    ]

    proc = None
    try:
        while not stop.is_set():
            try:
                # Decide whether to capture proxy.py subprocess output
                capture = os.environ.get("PROXXY_PROXY_CAPTURE_OUTPUT", "0").lower() not in ("0", "false", "no")
                stdout_target = subprocess.PIPE if capture else subprocess.DEVNULL
                stderr_target = subprocess.PIPE if capture else subprocess.DEVNULL
                text_mode = True if capture else False
                encoding = "utf-8" if capture else None
                errors = "replace" if capture else None
                bufsize = 1 if capture else 0

                logger.debug("proxy: starting cmd=%s", " ".join(shlex.quote(x) for x in cmd))
                emit({"type": "proxy_starting"})
                proc = subprocess.Popen(
                    cmd,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_target,
                    stderr=stderr_target,
                    text=text_mode,
                    encoding=encoding,
                    errors=errors,
                    bufsize=bufsize,
                )
                logger.info("proxy: listening on %s:%d (pid=%s)", host, port, getattr(proc, "pid", "?"))
                try:
                    emit({"type": "proxy_started", "pid": int(getattr(proc, "pid", 0) or 0)})
                except Exception:
                    emit({"type": "proxy_started"})

                # If capturing, stream subprocess output into our logger
                reader_threads = []
                if capture:
                    def _reader(stream, name, level):
                        try:
                            for line in iter(stream.readline, ""):
                                if not line:
                                    break
                                logger.log(level, "proxy-subproc %s: %s", name, line.rstrip())
                        except Exception:
                            pass
                    if proc.stdout:
                        t_out = threading.Thread(target=_reader, args=(proc.stdout, "stdout", logging.DEBUG), name="proxy-stdout", daemon=True)
                        t_out.start()
                        reader_threads.append(t_out)
                    if proc.stderr:
                        t_err = threading.Thread(target=_reader, args=(proc.stderr, "stderr", logging.WARNING), name="proxy-stderr", daemon=True)
                        t_err.start()
                        reader_threads.append(t_err)

                while not stop.is_set():
                    ret = proc.poll()
                    if ret is not None:
                        logger.error("proxy: exited code=%s; restarting in 5s", ret)
                        emit({"type": "proxy_exit", "code": int(ret)})
                        if stop.wait(5.0):
                            return
                        break
                    stop.wait(0.5)
            except FileNotFoundError:
                logger.error("proxy: module not found. Install dependency 'proxy.py'.")
                stop.wait(5.0)
                return
            except Exception as e:
                logger.exception("proxy: error: %s", e)
                if stop.wait(5.0):
                    return
            finally:
                if proc and proc.poll() is None:
                    try:
                        proc.terminate()
                        try:
                            proc.wait(timeout=3.0)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                    except Exception:
                        pass
    finally:
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except Exception:
                pass
        logger.info("proxy: stopped")