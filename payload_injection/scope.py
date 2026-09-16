"""Keep Active Test / payload sends inside authorised host scope."""

from __future__ import annotations
from urllib.parse import urlparse


def host_of(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        return (urlparse(raw).netloc or "").lower()
    except Exception:
        return ""


def in_scope(target_url: str, allowed_url: str) -> bool:
    """
    Default rule: same host (netloc) as the scanned target.
    """
    t = host_of(target_url)
    a = host_of(allowed_url)
    if not t or not a:
        return False
    return t == a
