from __future__ import annotations

import os
import time
import threading
from typing import Deque, Optional, List
from collections import deque

# proxy.py plugin API
# Docs pattern: subclass HttpProxyBasePlugin and implement get_upstream_proxy()
try:
    from proxy.http.proxy import HttpProxyBasePlugin  # proxy.py >= 2.x
except Exception as e:  # pragma: no cover
    raise ImportError("proxy.py is required for RotatingUpstreamPlugin") from e


# Path from which to read live proxies (one per line), each line scheme://host:port
OUTPUT_DIR = os.environ.get("PROXXY_OUTPUT_DIR", "output")
WORK_WITH_SCHEME = os.environ.get("PROXXY_WORK_WITH_SCHEME_PATH", os.path.join(OUTPUT_DIR, "work_with_scheme.txt"))
# Throttle reload frequency to avoid excessive I/O
RELOAD_INTERVAL = float(os.environ.get("PROXXY_PLUGIN_RELOAD_INTERVAL", "5.0"))


class RotatingUpstreamPlugin(HttpProxyBasePlugin):
    """
    A proxy.py plugin that assigns a single upstream per client TCP connection (sticky).

    - Picks next value from a process-wide deque loaded from WORK_WITH_SCHEME.
    - Auto-reloads the file when it changes (mtime-based) at most once per RELOAD_INTERVAL.
    - If no upstreams are available, this plugin fails fast by raising ValueError.
    """

    _lock = threading.RLock()
    _last_checked: float = 0.0
    _last_mtime: float = 0.0
    _dq: Deque[bytes] = deque()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Cache the first selected upstream for the lifetime of this client connection
        self._assigned_upstream: Optional[bytes] = None

    @classmethod
    def _reload_if_needed(cls) -> None:
        now = time.time()
        if now - cls._last_checked < RELOAD_INTERVAL:
            return
        cls._last_checked = now
        path = WORK_WITH_SCHEME
        try:
            st = os.stat(path)
            # Only reload on mtime change
            if st.st_mtime <= cls._last_mtime:
                return
            cls._last_mtime = st.st_mtime
            items: List[bytes] = []
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    # Ensure a scheme for proxy.py upstream string
                    if "://" not in s:
                        s = "http://" + s
                    try:
                        items.append(s.encode("utf-8"))
                    except Exception:
                        # Skip malformed lines
                        continue
            cls._dq = deque(items)
        except FileNotFoundError:
            cls._dq = deque()
            cls._last_mtime = 0.0
        except OSError:
            # Leave current deque untouched on transient I/O errors
            pass

    # Hook used by proxy.py to fetch upstream once per client connection (sticky)
    def get_upstream_proxy(self) -> Optional[bytes]:
        with self._lock:
            # If we've already assigned an upstream for this connection, reuse it
            if getattr(self, "_assigned_upstream", None):
                return self._assigned_upstream

            self._reload_if_needed()
            if not self._dq:
                # Fail fast when no upstreams are available
                raise ValueError("No upstream proxies available")

            p = self._dq.popleft()
            self._dq.append(p)
            # Persist selection for the lifetime of this client TCP connection
            self._assigned_upstream = p
            return p