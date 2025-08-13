from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

logger = logging.getLogger("proXXy.status")

__all__ = [
    "Health",
    "humanize_bytes",
    "humanize_duration",
    "status_consumer",
    "status_ticker",
]


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
    proxy_pid: int | None = None
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