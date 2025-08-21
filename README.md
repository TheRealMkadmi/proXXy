# proXXy — continuous proxy pipeline (scrape → validate → pool → tunnel)

proXXy continuously scrapes public proxy sources, validates candidates against a real target, maintains a live pool mirrored to a file, and serves a tunneling-only forward proxy that chains through those upstreams.

Quick links: [main()](src/main.py:59) · [produce_process_loop()](src/orchestrator.py:19) · [PoolManager](src/pool_manager.py:255) · [TunnelProxyServer](src/proxy_server.py:164)

---

## Features
- Continuous pipeline: scrape → validate (stream) → pool → forward proxy
- Async validators with bounded worker pool and backpressure
- File-backed pool with atomic, debounced writes for the proxy server
- Tunneling-only HTTP proxy (CONNECT and HTTP), no TLS interception
- Failure-aware upstream selection (retry, fanout, parallel scan budget)
- Simple, colorized status ticker

---

## Quickstart

Prerequisites:
- Python 3.13+
- uv package manager (https://docs.astral.sh/uv/)

Install dependencies:
```bash
uv sync
```

Run the pipeline with sensible defaults:
```bash
uv run python -m src.main --url https://www.netflix.com/ --workers 256 --timeout 5 --port 8899 --pool-file ./proxies.txt --min-upstreams 10
```

Then point your tooling at the local proxy: 127.0.0.1:8899.

---

## CLI flags and env mapping

The CLI only sets environment variables; precedence is CLI > env > defaults. All flags are optional.

- --output-dir → PROXXY_OUTPUT_DIR (default: output)
- --url → PROXXY_VALIDATION_URL (default: https://www.netflix.com/)
- --workers → PROXXY_VALIDATOR_WORKERS (default: 256)
- --timeout → PROXXY_VALIDATOR_TIMEOUT (seconds; default: 5.0)
- --host → PROXXY_PROXY_HOST (default: 127.0.0.1)
- --port → PROXXY_PROXY_PORT (default: 8899)
- --proxy-log-level → PROXXY_PROXY_LOG_LEVEL (default: WARNING)
- --status-interval → PROXXY_STATUS_INTERVAL_SECONDS (default: 5)
- --pool-file → PROXXY_POOL_FILE (default: ./proxies.txt)
- --pool-debounce-ms → PROXXY_POOL_DEBOUNCE_MS (default: 150)
  (pool TTL removed; pool entries persist as long as they keep passing checks)
- --pool-prune-interval-seconds → PROXXY_POOL_PRUNE_INTERVAL_SECONDS (default: 30)
- --min-upstreams → PROXXY_MIN_UPSTREAMS (default: 10)
- --scraper-log-level → PROXXY_SCRAPER_LOG_LEVEL (for scraper logging)

See flag definitions in [main._parse_cli_args()](src/main.py:25).

---

## Environment variables (selected)

Pipeline:
- PROXXY_OUTPUT_DIR="output"
- PROXXY_VALIDATION_URL="https://www.netflix.com/"
- PROXXY_VALIDATOR_WORKERS=256
- PROXXY_VALIDATOR_TIMEOUT=5.0

Proxy server (defaults set in [main()](src/main.py:85)):
- PROXXY_PROXY_UPSTREAM_RETRIES=6
- PROXXY_PROXY_DIAL_TIMEOUT=1.8
  (failure TTL/backoff removed; upstream selection uses retries + fanout)
- PROXXY_PROXY_UPSTREAM_FANOUT=3

Listener:
- PROXXY_PROXY_HOST="127.0.0.1"
- PROXXY_PROXY_PORT=8899
- PROXXY_PROXY_LOG_LEVEL="WARNING"

Status:
- PROXXY_STATUS_INTERVAL_SECONDS=5

Pool (file-backed) and maintenance:
- PROXXY_POOL_FILE="./proxies.txt"
- PROXXY_POOL_DEBOUNCE_MS=150
  (pool TTL removed)
- PROXXY_POOL_PRUNE_INTERVAL_SECONDS=30
 - Recheck loop is centrally configured in code (no env toggles). See `PoolManagerConfig` in `src/pool_manager.py` for defaults.

Scrapers:
- PROXXY_SCRAPER_VERIFY_SSL=1
- PROXXY_SCRAPER_UA=<string or empty>

Validator (see defaults in [validator.py](src/validator.py)):
- PROXXY_VALIDATOR_MIN_BYTES=1024
- PROXXY_VALIDATOR_READ_SECONDS=2.5
- PROXXY_VALIDATOR_TTFB_SECONDS=2.0
- PROXXY_VALIDATOR_CHUNK_SIZE=8192
- PROXXY_VALIDATOR_LOG_LEVEL, PROXXY_VALIDATOR_LOG_ENQUEUE

Proxy server tuning (see [TunnelProxyServer.__init__](src/proxy_server.py:173)):
- PROXXY_TUNNEL_DIAG=("basic"|"verbose"|off)
- PROXXY_TUNNEL_EARLY_CLOSE_MAX_A2B, PROXXY_TUNNEL_EARLY_CLOSE_MAX_B2A, PROXXY_TUNNEL_EARLY_CLOSE_MAX_MS
- PROXXY_PROXY_READ_TIMEOUT
- PROXXY_PROXY_UPSTREAM_SCAN_MAX, PROXXY_PROXY_UPSTREAM_SCAN_BUDGET
- PROXXY_PROXY_TUNNEL_IDLE_TIMEOUT (0 disables idle timeout; recommended for H2 targets)
- PROXXY_PROXY_UPSTREAM_SSL_VERIFY (0 to skip TLS verify to upstream proxies)

---

## Architecture

- Entry: [main()](src/main.py:59)  
  - Wires config, status threads, pool manager, producer process, proxy server thread.
- Producer: [produce_process_loop()](src/orchestrator.py:19)  
  - Scrapes via [StaticUrlTextScraper.scrape()](src/scrapers/static_url_text.py:22) and [ProxyDBScraper.scrape()](src/scrapers/proxydb.py:108)
  - Normalizes to http/https, dedupes by endpoint, streams to validator:
    - Validator: [check_proxies_stream()](src/validator.py:292) → per-proxy [_validate_one()](src/validator.py:36)
  - Publishes live proxies to pool queue (flushes by size/time for fast proxy startup).
- Pool manager: [PoolManager](src/pool_manager.py:255)  
  - In-memory pool: [LivePool](src/pool_manager.py:33) with recency metadata
  - File mirror: [FileSyncWriter](src/pool_manager.py:163) (atomic, debounced)
  - Pool maintenance: active rechecks, no TTL pruning
  - Optional health recheck: [PoolManager._recheck_loop()](src/pool_manager.py:380)
  - Ingest mp.Queue: [pool_ingest_loop()](src/pool_manager.py:448)
- Proxy server (tunnel only): [TunnelProxyServer](src/proxy_server.py:164) via [run_tunnel_proxy()](src/proxy_server.py:1026)  
  - CONNECT path: [_handle_connect()](src/proxy_server.py) with retry/fanout/budget
  - HTTP path: [_handle_http()](src/proxy_server.py:633) with minimal header rewrite
  - Bidirectional pipe: [_pipe_bidirectional()](src/proxy_server.py:803)
  - Upstream pool reader: [PoolFileUpstreams](src/proxy_server.py:87)
- Status and metrics: [status_consumer()](src/status.py:83), [status_ticker()](src/status.py:159)

Source configuration:
- Static URLs live in [proxy_sources.json](proxy_sources.json) loaded by [utils.proxy_sources()](src/utils.py:4)
- For site-specific HTML scraping, implement the [DynamicHtmlScraper](src/scrapers/dynamic_html.py:5) protocol and call it directly in the producer.

---

## How it works (end-to-end)

1. Producer scrapes text/HTML sources concurrently.
2. Candidates are normalized (prefers http://) and deduped per endpoint.
3. Validator checks candidates against PROXXY_VALIDATION_URL with bounded workers; live proxies are streamed out.
4. Pool manager ingests live proxies, refreshes recency, mirrors to the pool file.
5. Proxy server reloads the pool file on change and forwards client traffic via selected upstreams.
6. Startup gate: proxy waits until at least PROXXY_MIN_UPSTREAMS live entries exist, then starts.

---

## Security notes

- No inbound authentication/ACL by default. Keep PROXXY_PROXY_HOST on 127.0.0.1 unless you understand the risks.
- Upstream TLS verification to third-party proxies is disabled by default (PROXXY_PROXY_UPSTREAM_SSL_VERIFY=0). Enable as needed.
- Do not trust scraped proxies for sensitive workloads.

---

## Troubleshooting

- Stuck “waiting for upstreams”: ensure scrapers reach sources (network/DNS), or lower PROXXY_MIN_UPSTREAMS.
- Slow proxying: increase pool size or adjust PROXXY_PROXY_UPSTREAM_FANOUT and PROXXY_PROXY_UPSTREAM_RETRIES.
- Frequent early closes: consider adjusting early-close thresholds in the proxy server configuration.
- Validator too aggressive: raise PROXXY_VALIDATOR_MIN_BYTES or READ_SECONDS, or increase timeout/workers.

---

## Development

- Code entry points: [main()](src/main.py:59), [produce_process_loop()](src/orchestrator.py:19), [TunnelProxyServer](src/proxy_server.py:164)
- Style: typed, asyncio + threads + one producer process.
- Python version: see [pyproject.toml](pyproject.toml)

Run from sources:
```bash
uv run python -m src.main --help
```

---

## License

GPL-3.0-only. See [LICENSE](LICENSE)

---

## Acknowledgements

This codebase includes ideas and components for robust proxy selection, streaming validation, and atomic file mirroring inspired by production patterns.