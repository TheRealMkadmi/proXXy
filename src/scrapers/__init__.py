from .base import BaseProxyScraper
from .static_url_text import StaticUrlTextScraper
from .proxydb import ProxyDBScraper
from .dynamic_html import DynamicHtmlScraper

__all__ = [
    "BaseProxyScraper",
    "StaticUrlTextScraper",
    "DynamicHtmlScraper",
    "ProxyDBScraper",
]
