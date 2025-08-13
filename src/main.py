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
from .pool_server import PoolServer
from .orchestrator import produce_process_loop, proxy_server_loop

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
        description="Continuous proxy pipeline: scrape -> validate (stream) -> pool -> proxy.py upstream rotation.",
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

    # Pool service overrides
    ap.add_argument("--pool-host", dest="pool_host", help="Override PROXXY_POOL_HOST (default 127.0.0.1)")
    ap.add_argument("--pool-port", dest="pool_port", type=int, help="Override PROXXY_POOL_PORT (default 9009)")
    ap.add_argument("--pool-refresh-ms", dest="pool_refresh_ms", type=int, help="Override PROXXY_POOL_REFRESH_MS (default 500)")
    ap.add_argument("--pool-ttl-seconds", dest="pool_ttl_seconds", type=int, help="Override PROXXY_POOL_TTL_SECONDS (default 900)")
    ap.add_argument("--pool-prune-interval-seconds", dest="pool_prune_interval_seconds", type=int, help="Override PROXXY_POOL_PRUNE_INTERVAL_SECONDS (default 30)")
    ap.add_argument("--pool-health-url", dest="pool_health_url", help="Override PROXXY_POOL_HEALTH_URL (default = validation URL)")

    # Optional convenience flags
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
        # Pool service
        "pool_host": "PROXXY_POOL_HOST",
        "pool_port": "PROXXY_POOL_PORT",
        "pool_refresh_ms": "PROXXY_POOL_REFRESH_MS",
        "pool_ttl_seconds": "PROXXY_POOL_TTL_SECONDS",
        "pool_prune_interval_seconds": "PROXXY_POOL_PRUNE_INTERVAL_SECONDS",
        "pool_health_url": "PROXXY_POOL_HEALTH_URL",
        # Pass-through for dependent components
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
        "pool=%s:%d refresh_ms=%s ttl=%ss prune_interval=%ss status_interval=%ss",
        cfg.output_dir,
        cfg.validation_url,
        cfg.validator_workers,
        cfg.validator_timeout,
        cfg.proxy_host,
        cfg.proxy_port,
        cfg.pool_host,
        cfg.pool_port,
        cfg.pool_refresh_ms,
        getattr(cfg, "pool_ttl_seconds", 900),
        getattr(cfg, "pool_prune_interval_seconds", 30),
        getattr(cfg, "status_interval", 5),
    )

    status_q = mp.Queue()
    try:
        status_q.put({
            "type": "config",
            "output_dir": cfg.output_dir,
            "pool_url": f"http://{cfg.pool_host}:{cfg.pool_port}",
        })
    except Exception:
        pass

    # Health reporting threads (console metrics)
    health = Health(snapshot_path="", output_dir=cfg.output_dir)
    consumer_t = threading.Thread(target=status_consumer, name="status-consumer", args=(status_q, health, stop_thread), daemon=True)
    ticker_interval = float(getattr(cfg, "status_interval", 5))
    ticker_t = threading.Thread(target=status_ticker, name="status-ticker", args=(health, stop_thread, ticker_interval), daemon=True)

    # Start pool HTTP server (with TTL and health re-check)
    pool_server = None
    try:
        pool_server = PoolServer(
            host=cfg.pool_host,
            port=cfg.pool_port,
            ttl_seconds=getattr(cfg, "pool_ttl_seconds", 900),
            prune_interval_seconds=getattr(cfg, "pool_prune_interval_seconds", 30),
            health_check_url=getattr(cfg, "pool_health_url", cfg.validation_url),
        )
        pool_server.start()
    except OSError as e:
        logger.error("pool: failed to start on %s:%s (%s). Is the port in use?", cfg.pool_host, cfg.pool_port, e)
        return 1
    except Exception as e:
        logger.exception("pool: failed to start: %s", e)
        return 1

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
    try:
        if pool_server is not None:
            pool_server.stop()
    except Exception:
        pass

    logger.info("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())