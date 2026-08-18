"""Limit crawl/fetch to the authorised target host."""
from __future__ import annotations
from urllib.parse import urlparse


def normalise_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    return raw


def host_of(url: str) -> str:
    try:
        return (urlparse(normalise_url(url)).netloc or "").lower()
    except Exception:
        return ""


def same_host(url: str, root: str) -> bool:
    a, b = host_of(url), host_of(root)
    return bool(a and b and a == b)


def is_http_url(url: str) -> bool:
    try:
        p = urlparse(normalise_url(url))
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False
