from __future__ import annotations

import os
import time
import threading
import logging
from typing import Deque, Optional, List
from collections import deque

# Use stdlib HTTP client to avoid extra deps in proxy.py process
from urllib.request import urlopen
from urllib.error import URLError, HTTPError

# proxy.py plugin API
try:
    from proxy.http.proxy import HttpProxyBasePlugin  # proxy.py >= 2.x
except Exception as e:  # pragma: no cover
    raise ImportError("proxy.py is required for RotatingUpstreamPlugin") from e


# Real-time pool source (HTTP), not disk
POOL_HOST = os.environ.get("PROXXY_POOL_HOST", "127.0.0.1")
try:
    POOL_PORT = int(os.environ.get("PROXXY_POOL_PORT", "9009"))
except Exception:
    POOL_PORT = 9009
POOL_URL = os.environ.get("PROXXY_POOL_URL", f"http://{POOL_HOST}:{POOL_PORT}")
# Poll interval in milliseconds (default: 500ms)
try:
    _ms = int(os.environ.get("PROXXY_POOL_REFRESH_MS", "500"))
except Exception:
    _ms = 500
REFRESH_INTERVAL = max(0.1, _ms / 1000.0)


class RotatingUpstreamPlugin(HttpProxyBasePlugin):
    """
    A proxy.py plugin that assigns a single upstream per client TCP connection (sticky).

    - Maintains a process-wide deque of upstreams fetched from an HTTP pool service.
    - Background refresher polls GET {POOL_URL}/pool every REFRESH_INTERVAL.
    - If no upstreams are available, this plugin fails fast by raising ValueError.
    """

    _lock = threading.RLock()
    _dq: Deque[bytes] = deque()
    _refresher_started: bool = False
    _had_upstreams: bool = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Cache the first selected upstream for the lifetime of this client connection
        self._assigned_upstream: Optional[bytes] = None
        self._ensure_refresher()

    @classmethod
    def _ensure_refresher(cls) -> None:
        # Guard refresher startup to avoid races and set the flag only after thread is running
        with cls._lock:
            if cls._refresher_started:
                return

            def _refresher():
                url = f"{POOL_URL.rstrip('/')}/pool"
                # Local logger for plugin readiness (inherits proxy.py log configuration)
                _logger = logging.getLogger("proXXy.plugin")
                while True:
                    try:
                        with urlopen(url, timeout=max(1.0, REFRESH_INTERVAL * 3)) as resp:
                            # Expect text/plain with one proxy per line (scheme://host:port)
                            data = resp.read().decode("utf-8", errors="replace")
                        items: List[bytes] = []
                        for line in data.splitlines():
                            s = line.strip()
                            if not s or s.startswith("#"):
                                continue
                            if "://" not in s:
                                s = "http://" + s
                            try:
                                items.append(s.encode("utf-8"))
                            except Exception:
                                # Skip malformed entries
                                continue
                        with cls._lock:
                            prev = len(cls._dq)
                            cls._dq = deque(items)
                            new = len(cls._dq)
                            # Log transitions into/out of "ready" state within the proxy subprocess
                            if (not cls._had_upstreams) and new > 0:
                                cls._had_upstreams = True
                                try:
                                    _logger.info("proxy.plugin: upstreams available count=%d pool=%s", new, POOL_URL)
                                except Exception:
                                    pass
                            elif cls._had_upstreams and new == 0:
                                cls._had_upstreams = False
                                try:
                                    _logger.warning("proxy.plugin: upstreams depleted; waiting for pool=%s", POOL_URL)
                                except Exception:
                                    pass
                    except (HTTPError, URLError, TimeoutError, OSError):
                        # Keep previous deque on transient errors
                        pass
                    except Exception:
                        # Avoid crashing refresher
                        pass
                    time.sleep(REFRESH_INTERVAL)

            t = threading.Thread(target=_refresher, name="pool-refresher", daemon=True)
            t.start()
            cls._refresher_started = True

    # Hook used by proxy.py to fetch upstream once per client connection (sticky)
    def get_upstream_proxy(self) -> Optional[bytes]:
        with self._lock:
            # If we've already assigned an upstream for this connection, reuse it
            if getattr(self, "_assigned_upstream", None):
                return self._assigned_upstream

            if not self._dq:
                # Fail fast when no upstreams are available
                raise ValueError("No upstream proxies available")

            p = self._dq.popleft()
            self._dq.append(p)
            # Persist selection for the lifetime of this client TCP connection
            self._assigned_upstream = p
            return p