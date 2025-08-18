from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Protocol
import re

# Shared proxy pattern: IPv4:port
PROXY_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d+\b")

@dataclass(frozen=True)
class ExtractContext:
    protocol: Optional[str] = None  # HTTP, HTTPS, SOCKS4, SOCKS5
    source_url: Optional[str] = None

@dataclass(frozen=True)
class ExtractResult:
    proxies: List[str]

class BaseExtractor(Protocol):
    def extract(self, content: str, *, context: Optional[ExtractContext] = None) -> ExtractResult:
        ...
