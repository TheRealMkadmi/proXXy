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
    # proxy.py config
    proxy_host: str
    proxy_port: int
    proxy_log_level: str
    # legacy file snapshot path (unused in realtime mode; kept for compatibility)
    work_with_scheme_path: str
    # status ticker
    status_interval: int
    # Realtime pool service for plugin
    pool_host: str
    pool_port: int
    pool_refresh_ms: int
    # Pool maintenance
    pool_ttl_seconds: int
    pool_prune_interval_seconds: int
    # Pool health re-check
    pool_health_url: str | None


def load_config_from_env() -> OrchestratorConfig:
    output_dir = os.environ.get("PROXXY_OUTPUT_DIR", "output")
    validation_url = os.environ.get("PROXXY_VALIDATION_URL", "https://example.com")
    validator_workers = int(os.environ.get("PROXXY_VALIDATOR_WORKERS", "32"))
    validator_timeout = float(os.environ.get("PROXXY_VALIDATOR_TIMEOUT", "5.0"))
    proxy_host = os.environ.get("PROXXY_PROXY_HOST", "127.0.0.1")
    proxy_port = int(os.environ.get("PROXXY_PROXY_PORT", "8899"))
    proxy_log_level = os.environ.get("PROXXY_PROXY_LOG_LEVEL", "WARNING")
    work_with_scheme_path = os.environ.get(
        "PROXXY_WORK_WITH_SCHEME_PATH",
        os.path.join(output_dir, "work_with_scheme.txt"),
    )
    status_interval = int(os.environ.get("PROXXY_STATUS_INTERVAL_SECONDS", "5"))
    pool_host = os.environ.get("PROXXY_POOL_HOST", "127.0.0.1")
    pool_port = int(os.environ.get("PROXXY_POOL_PORT", "9009"))
    pool_refresh_ms = int(os.environ.get("PROXXY_POOL_REFRESH_MS", "500"))
    pool_ttl_seconds = int(os.environ.get("PROXXY_POOL_TTL_SECONDS", "900"))  # 15 minutes
    pool_prune_interval_seconds = int(os.environ.get("PROXXY_POOL_PRUNE_INTERVAL_SECONDS", "30"))
    pool_health_url = os.environ.get("PROXXY_POOL_HEALTH_URL", validation_url)

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
        pool_host=pool_host,
        pool_port=pool_port,
        pool_refresh_ms=pool_refresh_ms,
        pool_ttl_seconds=pool_ttl_seconds,
        pool_prune_interval_seconds=pool_prune_interval_seconds,
        pool_health_url=pool_health_url,
    )