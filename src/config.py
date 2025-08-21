from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class OrchestratorConfig:
    # Scrape / validate config
    output_dir: str
    validation_url: str
    validator_workers: int
    validator_timeout: float
    validator_min_bytes: int
    validator_read_seconds: float
    validator_ttfb_seconds: float
    validator_chunk_size: int
    validator_progress_every: float
    validator_user_agent: str | None
    validator_accept_language: str
    # Proxy listen config
    proxy_host: str
    proxy_port: int
    proxy_log_level: str
    # Proxy server settings (tunnel)
    proxy_dial_timeout: float
    proxy_read_timeout: float
    proxy_upstream_retries: int
    proxy_upstream_scan_max: int
    proxy_upstream_scan_budget: float
    proxy_tunnel_idle_timeout: float
    proxy_upstream_ssl_verify: bool
    proxy_upstream_fanout: int
    # Proxy diagnostics + early-close thresholds
    proxy_tunnel_diag_on: bool
    proxy_tunnel_diag_verbose: bool
    proxy_tunnel_fail_log_every: int
    proxy_tunnel_early_close_max_a2b: int
    proxy_tunnel_early_close_max_b2a: int
    proxy_tunnel_early_close_max_ms: float
    # status ticker
    status_interval: int
    # Orchestrator runtime
    progress_every: float
    # Scraper toggles
    scraper_verify_ssl: bool
    scraper_user_agent: str | None
    enable_socks: bool
    # File-backed pool
    pool_file_path: str
    pool_debounce_ms: int
    # Pool maintenance (TTL removed)
    pool_prune_interval_seconds: int
    # Pool health re-check
    pool_health_url: str | None
    # Minimum upstream proxies required before starting server
    min_upstreams: int
    # (No proxy implementation choice; tunnel only)


def load_config_from_env() -> OrchestratorConfig:
    output_dir = os.environ.get("PROXXY_OUTPUT_DIR", "output")
    validation_url = os.environ.get("PROXXY_VALIDATION_URL", "https://www.netflix.com/")
    validator_workers = int(os.environ.get("PROXXY_VALIDATOR_WORKERS", "256"))
    validator_timeout = float(os.environ.get("PROXXY_VALIDATOR_TIMEOUT", "5.0"))
    validator_min_bytes = int(os.environ.get("PROXXY_VALIDATOR_MIN_BYTES", "1024"))
    validator_read_seconds = float(os.environ.get("PROXXY_VALIDATOR_READ_SECONDS", "2.5"))
    validator_ttfb_seconds = float(os.environ.get("PROXXY_VALIDATOR_TTFB_SECONDS", "2.0"))
    validator_chunk_size = int(os.environ.get("PROXXY_VALIDATOR_CHUNK_SIZE", "8192"))
    validator_progress_every = float(os.environ.get("PROXXY_VALIDATOR_PROGRESS_EVERY", os.environ.get("PROXXY_PROGRESS_EVERY", "3")))
    validator_user_agent = os.environ.get("PROXXY_VALIDATOR_USER_AGENT")
    validator_accept_language = os.environ.get("PROXXY_VALIDATOR_ACCEPT_LANGUAGE", "en-US,en;q=0.9")

    proxy_host = os.environ.get("PROXXY_PROXY_HOST", "127.0.0.1")
    proxy_port = int(os.environ.get("PROXXY_PROXY_PORT", "8899"))
    proxy_log_level = os.environ.get("PROXXY_PROXY_LOG_LEVEL", "WARNING")
    # Proxy server centralized tuning
    proxy_dial_timeout = float(os.environ.get("PROXXY_PROXY_DIAL_TIMEOUT", "1.8"))
    proxy_read_timeout = float(os.environ.get("PROXXY_PROXY_READ_TIMEOUT", "30.0"))
    proxy_upstream_retries = int(os.environ.get("PROXXY_PROXY_UPSTREAM_RETRIES", "6"))
    proxy_upstream_scan_max = int(os.environ.get("PROXXY_PROXY_UPSTREAM_SCAN_MAX", "50"))
    proxy_upstream_scan_budget = float(os.environ.get("PROXXY_PROXY_UPSTREAM_SCAN_BUDGET", "8.0"))
    proxy_tunnel_idle_timeout = float(os.environ.get("PROXXY_PROXY_TUNNEL_IDLE_TIMEOUT", "0"))
    proxy_upstream_ssl_verify = os.environ.get("PROXXY_PROXY_UPSTREAM_SSL_VERIFY", "0").strip().lower() not in ("0", "false", "no", "off")
    proxy_upstream_fanout = int(os.environ.get("PROXXY_PROXY_UPSTREAM_FANOUT", "3"))

    # Proxy diagnostics centralization
    _diag_str = os.environ.get("PROXXY_TUNNEL_DIAG", "off").strip().lower()
    proxy_tunnel_diag_on = _diag_str not in ("0", "off", "false", "no")
    proxy_tunnel_diag_verbose = _diag_str in ("verbose", "v", "debug")
    proxy_tunnel_fail_log_every = max(1, int(os.environ.get("PROXXY_TUNNEL_FAIL_LOG_EVERY", "1")))
    proxy_tunnel_early_close_max_a2b = int(os.environ.get("PROXXY_TUNNEL_EARLY_CLOSE_MAX_A2B", "4096"))
    proxy_tunnel_early_close_max_b2a = int(os.environ.get("PROXXY_TUNNEL_EARLY_CLOSE_MAX_B2A", "8192"))
    proxy_tunnel_early_close_max_ms = float(os.environ.get("PROXXY_TUNNEL_EARLY_CLOSE_MAX_MS", "3000"))

    status_interval = int(os.environ.get("PROXXY_STATUS_INTERVAL_SECONDS", "5"))
    progress_every = float(os.environ.get("PROXXY_PROGRESS_EVERY", "3"))

    # Scraper + orchestrator toggles
    scraper_verify_ssl = os.environ.get("PROXXY_SCRAPER_VERIFY_SSL", "1").strip().lower() not in ("0", "false", "no")
    scraper_user_agent = os.environ.get("PROXXY_SCRAPER_UA")
    enable_socks = os.environ.get("PROXXY_ENABLE_SOCKS", "1").strip().lower() not in ("0", "false", "no")

    # File-backed pool defaults
    pool_file_path = os.environ.get("PROXXY_POOL_FILE", "./proxies.txt")
    pool_debounce_ms = int(os.environ.get("PROXXY_POOL_DEBOUNCE_MS", "150"))

    # Pool maintenance + recheck (TTL fully removed)
    pool_prune_interval_seconds = int(os.environ.get("PROXXY_POOL_PRUNE_INTERVAL_SECONDS", "30"))
    # Health check URL mirrors validation URL; no separate flag
    pool_health_url = validation_url
    
    # Minimum upstream proxies required before starting server
    min_upstreams = int(os.environ.get("PROXXY_MIN_UPSTREAMS", "10"))

    return OrchestratorConfig(
        output_dir=output_dir,
    validation_url=validation_url,
    validator_workers=validator_workers,
    validator_timeout=validator_timeout,
    validator_min_bytes=validator_min_bytes,
    validator_read_seconds=validator_read_seconds,
    validator_ttfb_seconds=validator_ttfb_seconds,
    validator_chunk_size=validator_chunk_size,
    validator_progress_every=validator_progress_every,
    validator_user_agent=validator_user_agent,
    validator_accept_language=validator_accept_language,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        proxy_log_level=proxy_log_level,
    proxy_dial_timeout=proxy_dial_timeout,
    proxy_read_timeout=proxy_read_timeout,
    proxy_upstream_retries=proxy_upstream_retries,
    proxy_upstream_scan_max=proxy_upstream_scan_max,
    proxy_upstream_scan_budget=proxy_upstream_scan_budget,
    proxy_tunnel_idle_timeout=proxy_tunnel_idle_timeout,
    proxy_upstream_ssl_verify=proxy_upstream_ssl_verify,
    proxy_upstream_fanout=proxy_upstream_fanout,
    proxy_tunnel_diag_on=proxy_tunnel_diag_on,
    proxy_tunnel_diag_verbose=proxy_tunnel_diag_verbose,
    proxy_tunnel_fail_log_every=proxy_tunnel_fail_log_every,
    proxy_tunnel_early_close_max_a2b=proxy_tunnel_early_close_max_a2b,
    proxy_tunnel_early_close_max_b2a=proxy_tunnel_early_close_max_b2a,
    proxy_tunnel_early_close_max_ms=proxy_tunnel_early_close_max_ms,
        status_interval=status_interval,
    progress_every=progress_every,
    scraper_verify_ssl=scraper_verify_ssl,
    scraper_user_agent=scraper_user_agent,
    enable_socks=enable_socks,
    pool_file_path=pool_file_path,
    pool_debounce_ms=pool_debounce_ms,
    pool_prune_interval_seconds=pool_prune_interval_seconds,
    pool_health_url=pool_health_url,
    min_upstreams=min_upstreams,
    )