from __future__ import annotations

import argparse
import logging
import multiprocessing as mp
import os
import signal
import threading
import time

# Keep main minimal: wire-up config, pool, producer, proxy, status
from .config import OrchestratorConfig, load_config_from_env
from .status import Health, status_consumer, status_ticker
from .pool_manager import PoolManager, PoolManagerConfig, pool_ingest_loop
from .orchestrator import produce_process_loop, rota_server_loop

logger = logging.getLogger("proXXy.main")
if not logger.handlers:
    logging.basicConfig(
        level=os.environ.get("PROXXY_LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(processName)s(%(process)d)/%(threadName)s: %(message)s",
    )


def _parse_cli_args(argv: list[str] | None = None) -> argparse.Namespace:
    """
    CLI to override environment variables. Precedence: CLI > env > defaults.
    The pipeline is continuous; there is no interval flag.
    """
    ap = argparse.ArgumentParser(
        prog="proXXy",
        description="Continuous proxy pipeline: scrape -> validate (stream) -> pool -> rota upstream rotation via file.",
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

    # File-backed pool and rota overrides
    ap.add_argument("--pool-file", dest="pool_file", help="Override PROXXY_POOL_FILE (default ./proxies.txt)")
    ap.add_argument("--pool-debounce-ms", dest="pool_debounce_ms", type=int, help="Override PROXXY_POOL_DEBOUNCE_MS (default 150)")
    ap.add_argument("--pool-ttl-seconds", dest="pool_ttl_seconds", type=int, help="Override PROXXY_POOL_TTL_SECONDS (default 900)")
    ap.add_argument("--pool-prune-interval-seconds", dest="pool_prune_interval_seconds", type=int, help="Override PROXXY_POOL_PRUNE_INTERVAL_SECONDS (default 30)")
    # Pool recheck aggressiveness
    ap.add_argument("--pool-recheck-per-interval", dest="pool_recheck_per_interval", type=int, help="Override PROXXY_POOL_RECHECK_PER_INTERVAL (default 200)")
    ap.add_argument("--pool-recheck-workers", dest="pool_recheck_workers", type=int, help="Override PROXXY_POOL_RECHECK_WORKERS (default 32)")
    ap.add_argument("--pool-recheck-timeout", dest="pool_recheck_timeout", type=float, help="Override PROXXY_POOL_RECHECK_TIMEOUT (seconds, default 2.5)")
    
    ap.add_argument("--rota-extra", dest="rota_extra", help="Override PROXXY_ROTA_EXTRA (extra flags)")
    ap.add_argument("--min-upstreams", "--min-proxies", dest="min_upstreams", type=int, help="Override PROXXY_MIN_UPSTREAMS (minimum upstream proxies required before starting rota)")
    
    # Optional convenience flags
    ap.add_argument("--scraper-log-level", dest="scraper_log_level", help="Set PROXXY_SCRAPER_LOG_LEVEL for Scrapy logs")
    ap.add_argument(
        "--proxy-capture-output",
        dest="proxy_capture_output",
        choices=["0", "1"],
        help="Set PROXXY_PROXY_CAPTURE_OUTPUT (1 to capture proxy.py stdout/stderr into main logs, 0 to suppress)",
    )
    ap.add_argument(
        "--proxy-simulate",
        dest="proxy_simulate",
        choices=["0", "1"],
        help="Set PROXXY_PROXY_SIMULATE (1 to simulate rota; no binary needed)",
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
        # File-backed pool + rota
        "pool_file": "PROXXY_POOL_FILE",
        "pool_debounce_ms": "PROXXY_POOL_DEBOUNCE_MS",
        "pool_ttl_seconds": "PROXXY_POOL_TTL_SECONDS",
        "pool_prune_interval_seconds": "PROXXY_POOL_PRUNE_INTERVAL_SECONDS",
        "pool_health_url": "PROXXY_POOL_HEALTH_URL",
        "pool_recheck_per_interval": "PROXXY_POOL_RECHECK_PER_INTERVAL",
        "pool_recheck_workers": "PROXXY_POOL_RECHECK_WORKERS",
        "pool_recheck_timeout": "PROXXY_POOL_RECHECK_TIMEOUT",
        "min_upstreams": "PROXXY_MIN_UPSTREAMS",
        "rota_extra": "PROXXY_ROTA_EXTRA",
        # Pass-through for dependent components
        "scraper_log_level": "PROXXY_SCRAPER_LOG_LEVEL",
        "proxy_capture_output": "PROXXY_PROXY_CAPTURE_OUTPUT",
        "proxy_simulate": "PROXXY_PROXY_SIMULATE",
    }
    for attr, env_key in cli_to_env.items():
        if hasattr(args, attr) and getattr(args, attr) is not None:
            os.environ[env_key] = str(getattr(args, attr))

    # Unify URLs: if pool-health not provided, use validation URL
    if not os.environ.get("PROXXY_POOL_HEALTH_URL") and os.environ.get("PROXXY_VALIDATION_URL"):
        os.environ["PROXXY_POOL_HEALTH_URL"] = os.environ["PROXXY_VALIDATION_URL"]
    cfg = load_config_from_env()
    os.makedirs(cfg.output_dir, exist_ok=True)

    stop_thread = threading.Event()
    stop_proc = mp.Event()

    def handle_signal(signum, _frame):
        logger.info("signal %s received, shutting down", signum)
        stop_thread.set()
        stop_proc.set()

    for sig in ("SIGINT", "SIGTERM"):
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), handle_signal)

    # Log config summary for at-a-glance visibility
    logger.info(
        "config: output_dir='%s' validate_url='%s' workers=%d timeout=%.1fs proxy=%s:%d "
        "pool_file='%s' ttl=%ss prune_interval=%ss status_interval=%ss",
        cfg.output_dir,
        cfg.validation_url,
        cfg.validator_workers,
        cfg.validator_timeout,
        cfg.proxy_host,
        cfg.proxy_port,
        cfg.pool_file_path,
        getattr(cfg, "pool_ttl_seconds", 900),
        getattr(cfg, "pool_prune_interval_seconds", 30),
        getattr(cfg, "status_interval", 5),
    )

    status_q = mp.Queue()
    try:
        status_q.put({
            "type": "config",
            "output_dir": cfg.output_dir,
            "pool_file": cfg.pool_file_path,
        })
    except Exception:
        pass

    # Health reporting threads (console metrics)
    health = Health(snapshot_path="", output_dir=cfg.output_dir)
    consumer_t = threading.Thread(target=status_consumer, name="status-consumer", args=(status_q, health, stop_thread), daemon=True)
    ticker_interval = float(getattr(cfg, "status_interval", 5))
    ticker_t = threading.Thread(target=status_ticker, name="status-ticker", args=(health, stop_thread, ticker_interval), daemon=True)

    # Start in-process PoolManager (TTL prune + optional recheck) and ingest thread
    pool_mgr = None
    pool_q = mp.Queue()
    try:
        pool_mgr = PoolManager(
            PoolManagerConfig(
                file_path=cfg.pool_file_path,
                debounce_ms=cfg.pool_debounce_ms,
                ttl_seconds=getattr(cfg, "pool_ttl_seconds", 900),
                prune_interval_seconds=getattr(cfg, "pool_prune_interval_seconds", 30),
                health_check_url=getattr(cfg, "pool_health_url", cfg.validation_url),
                recheck_timeout=float(os.getenv("PROXXY_POOL_RECHECK_TIMEOUT", "2.5")),
                recheck_per_interval=int(os.getenv("PROXXY_POOL_RECHECK_PER_INTERVAL", "200")),
                recheck_workers=int(os.getenv("PROXXY_POOL_RECHECK_WORKERS", "32")),
                enable_recheck=True,
            )
        )
        pool_mgr.start()
        ingest_t = threading.Thread(target=pool_ingest_loop, name="pool-ingest", args=(stop_thread, pool_q, pool_mgr), daemon=True)
        ingest_t.start()
    except Exception as e:
        logger.exception("pool: failed to start PoolManager: %s", e)
        return 1

    # Spawn a single producer child process (scrape+validate loop)
    producer = mp.Process(
        target=produce_process_loop,
        args=(stop_proc, cfg, status_q, pool_q),
        name="producer-proc",
        daemon=True,
    )
    # Start proxy supervisor in a thread (launches rota subprocess)
    proxy_t = threading.Thread(
        target=rota_server_loop,
        name="proxy",
        args=(stop_thread, cfg, status_q),
        daemon=True,
    )

    consumer_t.start()
    if ticker_interval > 0:
        ticker_t.start()
    producer.start()

    # Wait for enough upstream proxies before starting rota (gate launch)
    min_required = max(0, int(getattr(cfg, "min_upstreams", 1)))
    if min_required > 0:
        logger.info("proxy: waiting for at least %d upstream proxies before starting rota...", min_required)
    last_log = time.monotonic()
    while not stop_thread.is_set():
        if min_required <= 0:
            break
        try:
            ready = int(pool_mgr.size() if pool_mgr is not None else 0)
        except Exception:
            ready = 0
        if ready >= min_required:
            border = "=" * 72
            try:
                logger.info(border)
                logger.info("= PROXY READY: upstreams >= %d (have %d) =", min_required, ready)
                logger.info("= Starting %s on %s:%d =", getattr(cfg, "rota_bin", "proxy"), cfg.proxy_host, cfg.proxy_port)
                logger.info(border)
            except Exception:
                pass
            break
        if (time.monotonic() - last_log) >= 2.0:
            logger.info("proxy: upstreams %d/%d ready", ready, min_required)
            last_log = time.monotonic()
        time.sleep(0.5)

    if not stop_thread.is_set():
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
    try:
        if 'pool_mgr' in locals() and pool_mgr is not None:
            pool_mgr.stop()
    except Exception:
        pass

    logger.info("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())