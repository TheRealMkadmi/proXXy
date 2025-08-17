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
    # Proxy listen config
    proxy_host: str
    proxy_port: int
    proxy_log_level: str
    # legacy file snapshot path (unused in realtime mode; kept for compatibility)
    work_with_scheme_path: str
    # status ticker
    status_interval: int
    # File-backed pool
    pool_file_path: str
    pool_debounce_ms: int
    # Pool maintenance
    pool_ttl_seconds: int
    pool_prune_interval_seconds: int
    # Pool health re-check
    pool_health_url: str | None
    # Minimum upstream proxies required before starting server
    min_upstreams: int
    # (No proxy implementation choice; tunnel only)


def load_config_from_env() -> OrchestratorConfig:
    output_dir = os.environ.get("PROXXY_OUTPUT_DIR", "output")
    validation_url = os.environ.get("PROXXY_VALIDATION_URL", "https://www.netflix.com/")
    validator_workers = int(os.environ.get("PROXXY_VALIDATOR_WORKERS", "1024"))
    validator_timeout = float(os.environ.get("PROXXY_VALIDATOR_TIMEOUT", "5.0"))

    proxy_host = os.environ.get("PROXXY_PROXY_HOST", "127.0.0.1")
    proxy_port = int(os.environ.get("PROXXY_PROXY_PORT", "8899"))
    proxy_log_level = os.environ.get("PROXXY_PROXY_LOG_LEVEL", "WARNING")

    work_with_scheme_path = os.environ.get(
        "PROXXY_WORK_WITH_SCHEME_PATH",
        os.path.join(output_dir, "work_with_scheme.txt"),
    )
    status_interval = int(os.environ.get("PROXXY_STATUS_INTERVAL_SECONDS", "5"))

    # File-backed pool defaults
    pool_file_path = os.environ.get("PROXXY_POOL_FILE", "./proxies.txt")
    pool_debounce_ms = int(os.environ.get("PROXXY_POOL_DEBOUNCE_MS", "150"))

    # Pool maintenance + recheck
    pool_ttl_seconds = int(os.environ.get("PROXXY_POOL_TTL_SECONDS", "900"))  # 15 minutes
    pool_prune_interval_seconds = int(os.environ.get("PROXXY_POOL_PRUNE_INTERVAL_SECONDS", "30"))
    pool_health_url = os.environ.get("PROXXY_POOL_HEALTH_URL", validation_url)
    
    # Minimum upstream proxies required before starting server
    min_upstreams = int(os.environ.get("PROXXY_MIN_UPSTREAMS", "10"))

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
        pool_file_path=pool_file_path,
        pool_debounce_ms=pool_debounce_ms,
        pool_ttl_seconds=pool_ttl_seconds,
        pool_prune_interval_seconds=pool_prune_interval_seconds,
        pool_health_url=pool_health_url,
    min_upstreams=min_upstreams,
    )