from __future__ import annotations

import os
import sys
import time
import json
import signal
import logging
import threading
from typing import List, Optional
import subprocess

# validator is invoked via subprocess to avoid cross-thread/process sharing

logger = logging.getLogger("proXXy.main")
if not logger.handlers:
    logging.basicConfig(
        level=os.environ.get("PROXXY_LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(threadName)s: %(message)s",
    )

OUTPUT_DIR = os.environ.get("PROXXY_OUTPUT_DIR", "output")
SCRAPE_INTERVAL = int(os.environ.get("PROXXY_SCRAPE_INTERVAL_SECONDS", "1800"))
VALIDATION_URL = os.environ.get("PROXXY_VALIDATION_URL", "https://www.netflix.com")
VALIDATOR_WORKERS = int(os.environ.get("PROXXY_VALIDATOR_WORKERS", "512"))
VALIDATOR_TIMEOUT = float(os.environ.get("PROXXY_VALIDATOR_TIMEOUT", "5.0"))


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


def run_scraper_in_subprocess(output_dir: str) -> Optional[dict]:
    """Invoke the scraper CLI to fetch only HTTP/HTTPS proxies and write protocol files."""
    cmd = [
        sys.executable, "-u", "src/scraper.py",
        "--protocols", "HTTP,HTTPS",
        "--output-dir", output_dir,
        "--timeout", "5",
        "--retry-times", "1",
        "--log-level", "WARNING",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        out = proc.stdout.strip()
        if out:
            last = out.splitlines()[-1]
            try:
                return json.loads(last)
            except Exception:
                logger.debug("scraper stdout tail (non-JSON): %s", last)
        return None
    except subprocess.CalledProcessError as e:
        logger.error("Scraper subprocess failed: rc=%s stderr=%s", e.returncode, e.stderr)
    except Exception as e:
        logger.exception("Error running scraper subprocess: %s", e)
    return None


def run_validator_in_subprocess(input_path: str, out_temp_path: str, url: str, workers: int, timeout: float) -> bool:
    """
    Invoke validator CLI to check proxies and write a temp output file.
    We then atomically publish to the final file to ensure readers never see partial data.
    """
    cmd = [
        sys.executable, "-u", "src/validator.py",
        "--input", input_path,
        "--url", url,
        "--workers", str(max(1, workers)),
        "--output", out_temp_path,
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        return os.path.isfile(out_temp_path)
    except subprocess.CalledProcessError as e:
        logger.error("Validator subprocess failed: rc=%s stderr=%s", e.returncode, e.stderr)
        return False
    except Exception as e:
        logger.exception("Error running validator subprocess: %s", e)
        return False


def produce_loop(stop: threading.Event) -> None:
    """
    Single loop that:
      1) Scrapes proxies (via src/scraper.py)
      2) Validates them (via src/validator.py)
      3) Atomically publishes a single snapshot file used by proxy.py plugin
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    combined_input = os.path.join(OUTPUT_DIR, "__combined_http_https.txt")
    tmp_output = os.path.join(OUTPUT_DIR, "__work_with_scheme.tmp")
    final_output = os.path.join(OUTPUT_DIR, "work_with_scheme.txt")

    while not stop.is_set():
        logger.info("scrape: starting scraper subprocess")
        meta = run_scraper_in_subprocess(OUTPUT_DIR)
        if meta:
            logger.info("scrape: done total=%s wrote_files=%s", meta.get("total"), meta.get("wrote_to_files"))

        # Load raw proxies from scraper output (HTTP/HTTPS only)
        candidates = gather_http_https_proxies(OUTPUT_DIR)
        if not candidates:
            logger.warning("produce: no scraped proxies found; keeping previous snapshot")
        else:
            workers = max(1, min(VALIDATOR_WORKERS, len(candidates)))
            logger.info("validate: start total=%d workers=%d url='%s' timeout=%.1f", len(candidates), workers, VALIDATION_URL, VALIDATOR_TIMEOUT)
            try:
                # Write combined input for validator (preserve per-protocol scheme)
                atomic_write(combined_input, "\n".join(candidates) + "\n")
                ok = run_validator_in_subprocess(combined_input, tmp_output, VALIDATION_URL, workers, VALIDATOR_TIMEOUT)
                if ok:
                    try:
                        with open(tmp_output, "r", encoding="utf-8") as f:
                            data = f.read()
                        atomic_write(final_output, data)
                        live_count = sum(1 for _ in data.splitlines() if _.strip())
                        logger.info("produce: published live=%d proxies", live_count)
                    except Exception as e:
                        logger.exception("produce: failed publishing: %s", e)
                else:
                    logger.warning("produce: validator did not produce output")
            except Exception as e:
                logger.exception("produce: validator step failed: %s", e)

        if stop.wait(SCRAPE_INTERVAL):
            break


def proxy_server_loop(stop: threading.Event) -> None:
    """
    Starts proxy.py as a subprocess with a rotating-upstream plugin that reads
    output/work_with_scheme.txt and assigns one upstream per TCP connection (sticky).
    """
    env = os.environ.copy()
    # Ensure plugin module is importable
    src_dir = os.path.abspath(os.path.dirname(__file__))
    existing_pp = env.get("PYTHONPATH", "")
    if src_dir not in (existing_pp.split(os.pathsep) if existing_pp else []):
        env["PYTHONPATH"] = src_dir + (os.pathsep + existing_pp if existing_pp else "")

    host = os.environ.get("PROXXY_PROXY_HOST", "127.0.0.1")
    port = int(os.environ.get("PROXXY_PROXY_PORT", "8899"))
    log_level = os.environ.get("PROXXY_PROXY_LOG_LEVEL", "WARNING")

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
                proc = subprocess.Popen(
                    cmd,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    text=False,
                )
                logger.info("proxy: listening on %s:%d (pid=%s)", host, port, getattr(proc, "pid", "?"))
                while not stop.is_set():
                    ret = proc.poll()
                    if ret is not None:
                        logger.error("proxy: exited code=%s; restarting in 2s", ret)
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


def main() -> int:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    stop = threading.Event()

    threads = [
        threading.Thread(target=produce_loop, name="produce", args=(stop,), daemon=True),
        threading.Thread(target=proxy_server_loop, name="proxy", args=(stop,), daemon=True),
    ]
    for t in threads:
        t.start()

    def handle_signal(signum, frame):
        logger.info("signal %s received, shutting down", signum)
        stop.set()

    for sig in ("SIGINT", "SIGTERM"):
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), handle_signal)

    try:
        while not stop.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()

    for t in threads:
        t.join(timeout=5.0)
    logger.info("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())