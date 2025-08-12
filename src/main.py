from __future__ import annotations

import os
import sys
import time
import signal
import logging
import argparse
import threading
from typing import List, Optional
import subprocess
import shlex
import multiprocessing as mp
from dataclasses import dataclass, field

# Child processes are used for scraper/validator isolation (no CLI invocations).

logger = logging.getLogger("proXXy.main")
if not logger.handlers:
    logging.basicConfig(
        level=os.environ.get("PROXXY_LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(processName)s(%(process)d)/%(threadName)s: %(message)s",
    )

@dataclass(frozen=True)
class OrchestratorConfig:
    output_dir: str
    validation_url: str
    validator_workers: int
    validator_timeout: float
    proxy_host: str
    proxy_port: int
    proxy_log_level: str
    work_with_scheme_path: str
    status_interval: int


def load_config_from_env() -> OrchestratorConfig:
    output_dir = os.environ.get("PROXXY_OUTPUT_DIR", "output")
    validation_url = os.environ.get("PROXXY_VALIDATION_URL", "https://www.netflix.com")
    validator_workers = int(os.environ.get("PROXXY_VALIDATOR_WORKERS", "512"))
    validator_timeout = float(os.environ.get("PROXXY_VALIDATOR_TIMEOUT", "5.0"))
    proxy_host = os.environ.get("PROXXY_PROXY_HOST", "127.0.0.1")
    proxy_port = int(os.environ.get("PROXXY_PROXY_PORT", "8899"))
    proxy_log_level = os.environ.get("PROXXY_PROXY_LOG_LEVEL", "WARNING")
    work_with_scheme_path = os.environ.get(
        "PROXXY_WORK_WITH_SCHEME_PATH",
        os.path.join(output_dir, "work_with_scheme.txt"),
    )
    status_interval = int(os.environ.get("PROXXY_STATUS_INTERVAL_SECONDS", "5"))
    return OrchestratorConfig(
        output_dir=output_dir,
        validation_url=validation_url,
        validator_workers=validator_workers,
        validator_timeout=validator_timeout,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        proxy_log_level=proxy_log_level,
        work_with_scheme_path=work_with_scheme_path,
        status_interval=status_interval,
    )


def atomic_write(path: str, data: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(data)
    os.replace(tmp, path)


def gather_http_https_proxies(output_dir: str) -> List[str]:
    """Read HTTP.txt and HTTPS.txt, prefix with correct scheme, de-duplicate, preserve order."""
    res: List[str] = []
    for proto, scheme in (("HTTP", "http"), ("HTTPS", "https")):
        p = os.path.join(output_dir, f"{proto}.txt")
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        s = line.strip()
                        if not s or s.startswith("#"):
                            continue
                        if "://" not in s:
                            s = f"{scheme}://{s}"
                        res.append(s)
            except OSError as e:
                logger.warning("Failed reading %s: %s", p, e)
    seen = set()
    uniq: List[str] = []
    for s in res:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def count_non_comment_lines(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip() and not line.lstrip().startswith("#"))
    except OSError:
        return 0


def wait_for_first_snapshot(
    stop: threading.Event,
    path: str,
    min_lines: int = 1,
    poll: float = 1.0,
    timeout: Optional[float] = None,
) -> bool:
    """
    Block until 'path' exists and has at least 'min_lines' non-comment lines.
    Returns False if 'stop' is set or timeout (if provided) expires.
    """
    start = time.monotonic()
    while not stop.is_set():
        try:
            if os.path.isfile(path) and count_non_comment_lines(path) >= min_lines:
                return True
        except Exception:
            pass
        if stop.wait(poll):
            return False
        if timeout is not None and (time.monotonic() - start) >= timeout:
            return False
    return False


# ---- Health and status helpers ----

def humanize_bytes(n: int) -> str:
    try:
        n = int(n)
    except Exception:
        return "0B"
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    u = 0
    while f >= 1024.0 and u < len(units) - 1:
        f /= 1024.0
        u += 1
    if u == 0:
        return f"{int(f)}{units[u]}"
    return f"{f:.1f}{units[u]}"

def humanize_duration(seconds: float) -> str:
    try:
        s = float(seconds)
    except Exception:
        s = 0.0
    s = max(0.0, s)
    m, s = divmod(int(round(s)), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h{m}m{s}s"
    if m:
        return f"{m}m{s}s"
    return f"{s}s"

@dataclass
class Health:
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    cycles: int = 0
    last_scrape_total: int = 0
    last_candidates: int = 0
    last_validate_live: int = 0
    last_publish_size: int = 0
    last_publish_time: float = 0.0
    last_scrape_dt: float = 0.0
    last_validate_dt: float = 0.0
    validator_workers: int = 0
    proxy_pid: Optional[int] = None
    proxy_restarts: int = 0
    proxy_running: bool = False
    snapshot_path: str = ""
    output_dir: str = ""
    combined_input_size: int = 0

def status_consumer(status_q, health: "Health", stop_evt: threading.Event) -> None:
    while not stop_evt.is_set():
        try:
            evt = status_q.get(timeout=1.0)
        except Exception:
            continue
        if not isinstance(evt, dict):
            continue
        typ = evt.get("type")
        with health.lock:
            if typ == "cycle_end":
                health.cycles = int(evt.get("cycle", health.cycles) or health.cycles)
                health.last_scrape_total = int(evt.get("scrape_total") or 0)
                health.last_candidates = int(evt.get("candidates") or 0)
                health.last_validate_live = int(evt.get("validate_live") or 0)
                health.last_publish_size = int(evt.get("publish_size") or 0)
                if evt.get("published"):
                    health.last_publish_time = float(evt.get("ts") or time.time())
                health.last_scrape_dt = float(evt.get("scrape_dt") or 0.0)
                health.last_validate_dt = float(evt.get("validate_dt") or 0.0)
                health.validator_workers = int(evt.get("workers") or 0)
                health.combined_input_size = int(evt.get("combined_input_size") or 0)
            elif typ == "proxy_started":
                try:
                    pid_val = evt.get("pid")
                    health.proxy_pid = int(pid_val) if pid_val is not None else None
                except Exception:
                    health.proxy_pid = None
                health.proxy_running = True
            elif typ == "proxy_exit":
                health.proxy_running = False
                health.proxy_restarts += 1
            elif typ == "config":
                if evt.get("snapshot_path"):
                    health.snapshot_path = str(evt.get("snapshot_path"))
                if evt.get("output_dir"):
                    health.output_dir = str(evt.get("output_dir"))
            # Other event types are informational

def status_ticker(health: "Health", stop_evt: threading.Event, interval_s: float) -> None:
    if interval_s <= 0:
        return
    while not stop_evt.wait(interval_s):
        with health.lock:
            cycles = health.cycles
            live = health.last_validate_live
            candidates = health.last_candidates
            workers = health.validator_workers
            scrape_dt = health.last_scrape_dt
            validate_dt = health.last_validate_dt
            pub_size = health.last_publish_size
            last_pub = health.last_publish_time
            pid = health.proxy_pid
            running = health.proxy_running
            restarts = health.proxy_restarts
        since_pub = humanize_duration(time.time() - last_pub) if last_pub else "never"
        size_str = humanize_bytes(pub_size) if pub_size else "0B"
        proxy_str = f"up pid={pid}" if running and pid else "down"
        logger.info(
            "status: cycles=%s | live=%s | candidates=%s | last_pub=%s | file=%s | scrape=%ss | validate=%ss | workers=%s | proxy=%s | restarts=%s",
            cycles, live, candidates, since_pub, size_str, f"{scrape_dt:.2f}", f"{validate_dt:.2f}", workers, proxy_str, restarts
        )

def scraper_worker(output_dir: str, log_level: str, result_queue) -> None:
    """
    Child-process entrypoint: run scraper.run_proxy_scrape for HTTP/HTTPS only.
    Emits protocol files into output_dir. Puts a small dict on result_queue.
    """
    try:
        # Ensure we can import peer modules when launched from project root
        import sys as _sys, os as _os
        _base = _os.path.abspath(_os.path.dirname(__file__))
        if _base not in _sys.path:
            _sys.path.insert(0, _base)
        import scraper as scraper_mod  # type: ignore
        import utils as utils_mod      # type: ignore

        try:
            srcs = utils_mod.proxy_sources()
            sources = {k.upper(): v for k, v in srcs.items() if k.upper() in ("HTTP", "HTTPS")}
        except Exception:
            sources = {}

        res = scraper_mod.run_proxy_scrape(
            sources=sources,
            output_dir=output_dir,
            write_files=True,
            merge_existing=True,
            user_agent=None,
            request_timeout=5,
            retry_times=1,
            log_level=log_level,
        )
        try:
            result_queue.put({"total": res.total, "wrote_to_files": res.wrote_to_files})
        except Exception:
            pass
    except Exception as e:
        try:
            result_queue.put({"error": str(e)})
        except Exception:
            pass


def validator_worker(
    input_path: str,
    out_temp_path: str,
    url: str,
    workers: int,
    timeout: float,
    result_queue,
) -> None:
    """
    Child-process entrypoint: run validator.check_proxies on proxies read from input_path
    and write live proxies (with scheme) to out_temp_path.
    """
    try:
        # Ensure we can import peer modules when launched from project root
        import sys as _sys, os as _os
        _base = _os.path.abspath(_os.path.dirname(__file__))
        if _base not in _sys.path:
            _sys.path.insert(0, _base)
        import validator as validator_mod  # type: ignore

        def _normalize(line: str):
            s = line.strip()
            if not s or s.startswith("#"):
                return None
            if "://" not in s:
                s = "http://" + s
            scheme = s.split("://", 1)[0]
            if scheme not in ("http", "https"):
                return None
            return s

        proxies = []
        try:
            with open(input_path, "r", encoding="utf-8") as f:
                for line in f:
                    p = _normalize(line)
                    if p:
                        proxies.append(p)
        except OSError:
            proxies = []

        # Deduplicate while preserving order
        unique = list(dict.fromkeys(proxies))
        w = max(1, min(int(workers), len(unique))) if unique else 1

        live, _details = validator_mod.check_proxies(
            unique, url, w, float(timeout), verify_ssl=True, user_agent=None, total=len(unique) or None
        )

        # Write temp output (with scheme)
        try:
            with open(out_temp_path, "w", encoding="utf-8") as f:
                for p in live:
                    f.write(p + "\n")
        except Exception:
            pass

        try:
            result_queue.put({"live": len(live), "total": len(unique)})
        except Exception:
            pass
    except Exception as e:
        try:
            result_queue.put({"error": str(e)})
        except Exception:
            pass


# Removed CLI-based validator invocation; using validator_worker() in a child process instead.


def produce_process_loop(stop, config: Optional[OrchestratorConfig] = None, status_queue=None) -> None:
    """
    Child process continuous loop: scrape -> validate -> publish, then immediately repeat.
    Runs entirely via native Python imports (no CLI), in a single persistent process.
    Emits end-of-cycle metrics to a status_queue for live health reporting.
    """
    cfg = config or load_config_from_env()

    # Ensure imports work when spawned on Windows (spawn)
    try:
        base = os.path.abspath(os.path.dirname(__file__))
        if base not in sys.path:
            sys.path.insert(0, base)
    except Exception:
        pass

    try:
        import scraper as scraper_mod  # type: ignore
        import validator as validator_mod  # type: ignore
        import utils as utils_mod  # type: ignore
    except Exception as e:
        logger.exception("produce: failed importing modules: %s", e)
        return

    def emit(evt):
        if status_queue is None:
            return
        try:
            status_queue.put(evt)
        except Exception:
            pass

    os.makedirs(cfg.output_dir, exist_ok=True)
    combined_input = os.path.join(cfg.output_dir, "__combined_http_https.txt")
    tmp_output = os.path.join(cfg.output_dir, "__work_with_scheme.tmp")
    final_output = cfg.work_with_scheme_path

    cycle = 0
    while not stop.is_set():
        cycle += 1
        scrape_total = 0
        candidates_count = 0
        live_count = 0
        published = False
        publish_size = 0
        combined_size = -1
        scrape_dt = 0.0
        validate_dt = 0.0

        # 1) Scrape (native import usage)
        try:
            try:
                srcs = utils_mod.proxy_sources()
                sources = {k.upper(): v for k, v in srcs.items() if k.upper() in ("HTTP", "HTTPS")}
            except Exception:
                sources = {}

            logger.info("scrape: starting (native)")
            t0 = time.perf_counter()
            res = scraper_mod.run_proxy_scrape(
                sources=sources,
                output_dir=cfg.output_dir,
                write_files=True,
                merge_existing=True,
                user_agent=None,
                request_timeout=5,
                retry_times=1,
                log_level=os.environ.get("PROXXY_SCRAPER_LOG_LEVEL", "WARNING"),
            )
            scrape_dt = time.perf_counter() - t0
            scrape_total = int(getattr(res, "total", 0) or 0)
            logger.info(
                "scrape: done total=%s wrote_files=%s in %.2fs",
                getattr(res, "total", None),
                getattr(res, "wrote_to_files", None),
                scrape_dt,
            )
        except Exception as e:
            logger.exception("scrape: failed: %s", e)

        # 2) Collect raw proxies emitted by scraper (HTTP/HTTPS only)
        candidates = gather_http_https_proxies(cfg.output_dir)
        candidates_count = len(candidates)
        if candidates_count == 0:
            logger.warning("produce: no scraped proxies found; keeping previous snapshot")
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

            try:
                # Persist combined input for diagnostics
                atomic_write(combined_input, "\n".join(candidates) + "\n")
                try:
                    combined_size = os.path.getsize(combined_input)
                except OSError:
                    combined_size = -1
                logger.info("validate: wrote combined input '%s' (%d bytes)", combined_input, combined_size)

                t1 = time.perf_counter()
                live, _details = validator_mod.check_proxies(
                    candidates,
                    cfg.validation_url,
                    workers,
                    float(cfg.validator_timeout),
                    verify_ssl=True,
                    user_agent=None,
                    total=candidates_count,
                )
                validate_dt = time.perf_counter() - t1

                # Write temp output (with scheme)
                try:
                    with open(tmp_output, "w", encoding="utf-8") as f:
                        for p in live:
                            f.write(p + "\n")
                except Exception as e:
                    logger.exception("produce: failed writing temp output: %s", e)

                live_count = len(live)
                if live_count > 0:
                    try:
                        with open(tmp_output, "r", encoding="utf-8") as f:
                            data = f.read()
                        atomic_write(final_output, data)
                        try:
                            publish_size = os.path.getsize(final_output)
                        except OSError:
                            publish_size = 0
                        published = True
                        logger.info(
                            "produce: published file='%s' size=%dB live=%d (validator %.2fs)",
                            final_output,
                            publish_size,
                            live_count,
                            validate_dt,
                        )
                    except Exception as e:
                        logger.exception("produce: failed publishing: %s", e)
                else:
                    logger.warning(
                        "produce: validator produced no live proxies; expected '%s' (elapsed %.2fs)",
                        tmp_output,
                        validate_dt,
                    )
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
    Starts proxy.py as a subprocess with a rotating-upstream plugin that reads
    output/work_with_scheme.txt and assigns one upstream per TCP connection (sticky).
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

    # Wait until a first non-empty upstream snapshot exists to avoid startup crash loops
    logger.info("proxy: waiting for upstream snapshot at '%s'", cfg.work_with_scheme_path)
    emit({"type": "proxy_waiting", "path": cfg.work_with_scheme_path})
    if not wait_for_first_snapshot(stop, cfg.work_with_scheme_path, min_lines=1, poll=1.0):
        logger.info("proxy: stop signalled before snapshot ready; exiting")
        return
    try:
        lines = count_non_comment_lines(cfg.work_with_scheme_path)
        logger.info("proxy: initial upstream snapshot ready (lines=%d)", lines)
        emit({"type": "first_snapshot_ready", "lines": int(lines)})
    except Exception:
        pass

    env = os.environ.copy()
    # Ensure plugin module is importable
    src_dir = os.path.abspath(os.path.dirname(__file__))
    existing_pp = env.get("PYTHONPATH", "")
    if src_dir not in (existing_pp.split(os.pathsep) if existing_pp else []):
        env["PYTHONPATH"] = src_dir + (os.pathsep + existing_pp if existing_pp else "")

    host = cfg.proxy_host
    port = cfg.proxy_port
    log_level = cfg.proxy_log_level

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
                capture = os.environ.get("PROXXY_PROXY_CAPTURE_OUTPUT", "1").lower() not in ("0", "false", "no")
                stdout_target = subprocess.PIPE if capture else subprocess.DEVNULL
                stderr_target = subprocess.PIPE if capture else subprocess.DEVNULL
                text_mode = True if capture else False
                encoding = "utf-8" if capture else None
                errors = "replace" if capture else None
                bufsize = 1 if capture else 0

                logger.info("proxy: starting cmd=%s", " ".join(shlex.quote(x) for x in cmd))
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
                        t_out = threading.Thread(target=_reader, args=(proc.stdout, "stdout", logging.INFO), name="proxy-stdout", daemon=True)
                        t_out.start()
                        reader_threads.append(t_out)
                    if proc.stderr:
                        t_err = threading.Thread(target=_reader, args=(proc.stderr, "stderr", logging.WARNING), name="proxy-stderr", daemon=True)
                        t_err.start()
                        reader_threads.append(t_err)

                while not stop.is_set():
                    ret = proc.poll()
                    if ret is not None:
                        logger.error("proxy: exited code=%s; restarting in 2s", ret)
                        emit({"type": "proxy_exit", "code": int(ret)})
                        if stop.wait(2.0):
                            return
                        break
                    stop.wait(0.5)
            except FileNotFoundError:
                logger.error("proxy: module not found. Install dependency 'proxy.py'.")
                stop.wait(5.0)
                return
            except Exception as e:
                logger.exception("proxy: error: %s", e)
                if stop.wait(2.0):
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


def start(config: Optional[OrchestratorConfig] = None) -> threading.Event:
    """Deprecated: This tool is CLI-only. Use `python -m src.main`."""
    raise RuntimeError("Programmatic start is not supported; run this module as a CLI: python -m src.main")


def _parse_cli_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """
    CLI to override environment variables. Precedence: CLI > env > defaults.
    Note: No interval flag; pipeline is continuous.
    """
    ap = argparse.ArgumentParser(
        prog="proXXy",
        description="Continuous proxy pipeline: scrape -> validate -> publish, with proxy.py upstream rotation.",
    )
    # Only set values when flags are provided (no default), so env/defaults remain if omitted.
    ap.add_argument("--output-dir", dest="output_dir", help="Override PROXXY_OUTPUT_DIR")
    ap.add_argument("--url", dest="validation_url", help="Override PROXXY_VALIDATION_URL")
    ap.add_argument("--workers", dest="validator_workers", type=int, help="Override PROXXY_VALIDATOR_WORKERS")
    ap.add_argument("--timeout", dest="validator_timeout", type=float, help="Override PROXXY_VALIDATOR_TIMEOUT (seconds)")
    ap.add_argument("--host", dest="proxy_host", help="Override PROXXY_PROXY_HOST")
    ap.add_argument("--port", dest="proxy_port", type=int, help="Override PROXXY_PROXY_PORT")
    ap.add_argument("--proxy-log-level", dest="proxy_log_level", help="Override PROXXY_PROXY_LOG_LEVEL (e.g., WARNING, INFO)")
    ap.add_argument("--status-interval", dest="status_interval", type=int, help="Override PROXXY_STATUS_INTERVAL_SECONDS")
    ap.add_argument("--snapshot-path", dest="work_with_scheme_path", help="Override PROXXY_WORK_WITH_SCHEME_PATH")
    # Optional convenience flags: pass-through to env for dependent components
    ap.add_argument("--scraper-log-level", dest="scraper_log_level", help="Set PROXXY_SCRAPER_LOG_LEVEL for Scrapy logs")
    ap.add_argument(
        "--proxy-capture-output",
        dest="proxy_capture_output",
        choices=["0", "1"],
        help="Set PROXXY_PROXY_CAPTURE_OUTPUT (1 to capture proxy.py stdout/stderr into main logs, 0 to suppress)",
    )
    return ap.parse_args(argv)


def main() -> int:
    # Parse CLI and map provided flags to environment variables before loading config.
    args = _parse_cli_args()
    cli_to_env = {
        "output_dir": "PROXXY_OUTPUT_DIR",
        "validation_url": "PROXXY_VALIDATION_URL",
        "validator_workers": "PROXXY_VALIDATOR_WORKERS",
        "validator_timeout": "PROXXY_VALIDATOR_TIMEOUT",
        "proxy_host": "PROXXY_PROXY_HOST",
        "proxy_port": "PROXXY_PROXY_PORT",
        "proxy_log_level": "PROXXY_PROXY_LOG_LEVEL",
        "status_interval": "PROXXY_STATUS_INTERVAL_SECONDS",
        "work_with_scheme_path": "PROXXY_WORK_WITH_SCHEME_PATH",
        "scraper_log_level": "PROXXY_SCRAPER_LOG_LEVEL",
        "proxy_capture_output": "PROXXY_PROXY_CAPTURE_OUTPUT",
    }
    for attr, env_key in cli_to_env.items():
        if hasattr(args, attr) and getattr(args, attr) is not None:
            os.environ[env_key] = str(getattr(args, attr))
    cfg = load_config_from_env()
    os.makedirs(cfg.output_dir, exist_ok=True)

    stop_thread = threading.Event()
    stop_proc = mp.Event()

    def handle_signal(signum, frame):
        logger.info("signal %s received, shutting down", signum)
        stop_thread.set()
        stop_proc.set()

    for sig in ("SIGINT", "SIGTERM"):
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), handle_signal)

    # Log config summary for at-a-glance visibility
    logger.info(
        "config: output_dir='%s' snapshot='%s' validate_url='%s' validator_workers=%d timeout=%.1fs proxy=%s:%d status_interval=%ss",
        cfg.output_dir,
        cfg.work_with_scheme_path,
        cfg.validation_url,
        cfg.validator_workers,
        cfg.validator_timeout,
        cfg.proxy_host,
        cfg.proxy_port,
        getattr(cfg, "status_interval", 5),
    )

    status_q = mp.Queue()
    # Seed status with config paths
    try:
        status_q.put({"type": "config", "snapshot_path": cfg.work_with_scheme_path, "output_dir": cfg.output_dir})
    except Exception:
        pass

    # Health reporting threads
    health = Health(snapshot_path=cfg.work_with_scheme_path, output_dir=cfg.output_dir)
    consumer_t = threading.Thread(target=status_consumer, name="status-consumer", args=(status_q, health, stop_thread), daemon=True)
    ticker_interval = float(getattr(cfg, "status_interval", 5))
    ticker_t = threading.Thread(target=status_ticker, name="status-ticker", args=(health, stop_thread, ticker_interval), daemon=True)

    # Spawn a single producer child process (scrape+validate loop)
    producer = mp.Process(
        target=produce_process_loop,
        args=(stop_proc, cfg, status_q),
        name="producer-proc",
        daemon=True,
    )
    # Start proxy supervisor in a thread (which launches proxy.py subprocess)
    proxy_t = threading.Thread(
        target=proxy_server_loop,
        name="proxy",
        args=(stop_thread, cfg, status_q),
        daemon=True,
    )

    consumer_t.start()
    if ticker_interval > 0:
        ticker_t.start()
    producer.start()
    proxy_t.start()

    try:
        while not stop_thread.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_thread.set()
        stop_proc.set()

    # Shutdown
    try:
        proxy_t.join(timeout=5.0)
    except Exception:
        pass
    try:
        producer.join(timeout=5.0)
        if producer.is_alive():
            producer.terminate()
    except Exception:
        pass
    try:
        stop_thread.set()
        # give consumer a moment to drain
        time.sleep(0.1)
        if hasattr(status_q, "close"):
            status_q.close()
        if hasattr(status_q, "join_thread"):
            status_q.join_thread()
    except Exception:
        pass

    logger.info("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())