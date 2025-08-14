from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)
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
    # In-progress metrics
    validating: bool = False
    candidates_total: int = 0
    completed: int = 0
    live_so_far: int = 0
    last_progress_time: float = 0.0
    publish_bytes_total: int = 0
    publish_flush_count: int = 0
    last_publish_count: int = 0
    pool_url: str = ""
    pool_file: str = ""


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
                # End-of-cycle: mark validation complete
                health.validating = False
            elif typ == "validate_start":
                health.validating = True
                health.candidates_total = int(evt.get("total") or 0)
                health.completed = 0
                health.live_so_far = 0
                health.validator_workers = int(evt.get("workers") or health.validator_workers)
                health.last_progress_time = float(evt.get("ts") or time.time())
            elif typ == "validate_progress":
                # Throttled progress updates
                health.completed = int(evt.get("completed") or health.completed)
                health.live_so_far = int(evt.get("live") or health.live_so_far)
                if evt.get("total") is not None:
                    health.candidates_total = int(evt.get("total") or health.candidates_total)
                if evt.get("workers") is not None:
                    health.validator_workers = int(evt.get("workers") or health.validator_workers)
                health.last_progress_time = float(evt.get("ts") or time.time())
            elif typ == "publish_flush":
                # Accumulate published bytes and remember last flush
                try:
                    b = int(evt.get("bytes") or 0)
                except Exception:
                    b = 0
                try:
                    cnt = int(evt.get("count") or 0)
                except Exception:
                    cnt = 0
                health.publish_bytes_total += max(0, b)
                health.publish_flush_count += 1
                health.last_publish_count = cnt
                health.last_publish_time = float(evt.get("ts") or time.time())
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
                if evt.get("pool_url"):
                    health.pool_url = str(evt.get("pool_url"))
                if evt.get("pool_file"):
                    health.pool_file = str(evt.get("pool_file"))
            # Other event types are informational


def status_ticker(health: "Health", stop_evt: threading.Event, interval_s: float) -> None:
    if interval_s <= 0:
        return

    def _get_pool_file_size(path: str) -> int:
        if not path:
            return -1
        try:
            with open(path, "r", encoding="utf-8") as f:
                count = 0
                for ln in f:
                    s = ln.strip()
                    if s and not s.lstrip().startswith("#"):
                        count += 1
                return count
        except Exception:
            return -1

    while not stop_evt.wait(interval_s):
        with health.lock:
            cycles = health.cycles
            # Finalized metrics from last completed cycle
            last_live = health.last_validate_live
            last_candidates = health.last_candidates
            scrape_dt = health.last_scrape_dt
            validate_dt = health.last_validate_dt
            pub_file_size = health.last_publish_size
            last_pub_ts = health.last_publish_time
            # In-progress metrics
            validating = health.validating
            total = health.candidates_total
            completed = health.completed
            live_so_far = health.live_so_far
            publish_bytes_total = health.publish_bytes_total
            publish_flush_count = health.publish_flush_count
            workers = health.validator_workers
            # Proxy / pool
            pid = health.proxy_pid
            running = health.proxy_running
            restarts = health.proxy_restarts
            pool_file = health.pool_file

        pool_size = _get_pool_file_size(pool_file) if pool_file else -1
        since_pub = humanize_duration(time.time() - last_pub_ts) if last_pub_ts else "never"
        last_file_size_str = humanize_bytes(pub_file_size) if pub_file_size else "0B"
        total_pub_str = humanize_bytes(publish_bytes_total) if publish_bytes_total else "0B"
        proxy_state = (Fore.GREEN + f"UP pid={pid}" + Style.RESET_ALL) if (running and pid) else (Fore.RED + "DOWN" + Style.RESET_ALL)

        if validating and total > 0:
            pct = (completed / max(1, total)) * 100.0
            msg = (
                f"{Fore.CYAN}cycle{Style.RESET_ALL}={cycles} "
                f"| {Fore.YELLOW}validate{Style.RESET_ALL}={completed}/{total} ({pct:.1f}%) "
                f"live={live_so_far} w={workers} "
                f"| {Fore.MAGENTA}publish{Style.RESET_ALL}=flushes={publish_flush_count} total={total_pub_str} last={since_pub} "
                f"| {Fore.BLUE}pool{Style.RESET_ALL}={(pool_size if pool_size >= 0 else '?')} "
                f"| {proxy_state} restarts={restarts}"
            )
        else:
            msg = (
                f"{Fore.CYAN}cycle{Style.RESET_ALL}={cycles} "
                f"| {Fore.YELLOW}validate{Style.RESET_ALL}=idle live={last_live} cand={last_candidates} "
                f"dur={scrape_dt:.2f}s/{validate_dt:.2f}s w={workers} "
                f"| {Fore.MAGENTA}publish{Style.RESET_ALL}=file={last_file_size_str} last={since_pub} "
                f"| {Fore.BLUE}pool{Style.RESET_ALL}={(pool_size if pool_size >= 0 else '?')} "
                f"| {proxy_state} restarts={restarts}"
            )
        logger.info(msg)