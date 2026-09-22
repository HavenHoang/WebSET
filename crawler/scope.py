"""Limit crawl/fetch to the authorised target host and start path."""
from __future__ import annotations
from urllib.parse import urlparse, urlunparse
_FILE_EXT = (
    ".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".cgi",
    ".do", ".action", ".py", ".rb", ".pl",
)
def _canonical_netloc(netloc: str, scheme: str = "") -> str:
    raw = (netloc or "").strip()
    if not raw:
        return raw
    host, sep, port = raw.partition(":")
    if host.lower() == "localhost":
        host = "127.0.0.1"
    scheme = (scheme or "").lower()
    if port == "80" and scheme == "http":
        return host
    if port == "443" and scheme == "https":
        return host
    return host + sep + port if port else host
def normalise_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        p = urlparse(raw)
        netloc = _canonical_netloc(p.netloc, p.scheme)
        return urlunparse((p.scheme, netloc, p.path or "/", p.params, p.query, ""))
    except Exception:
        return raw
def host_of(url: str) -> str:
    try:
        return (urlparse(normalise_url(url)).netloc or "").lower()
    except Exception:
        return ""
def path_of(url: str) -> str:
    try:
        path = urlparse(normalise_url(url)).path or "/"
    except Exception:
        return "/"
    if not path.startswith("/"):
        path = "/" + path
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return path
def _directory_prefix(path: str) -> str:
    """
    A concrete file (login.php, index.html) is a page, not a crawl fence.
    Use its parent directory so the rest of the same app stays in scope.
    A directory path such as /app stays a prefix.
    """
    raw = path or "/"
    if raw in ("", "/"):
        return "/"
    last = raw.rsplit("/", 1)[-1].lower()
    if "." in last and any(last.endswith(ext) for ext in _FILE_EXT):
        parent = raw[: raw.rfind("/")]
        return parent or "/"
    return raw
def same_host(url: str, root: str) -> bool:
    a, b = host_of(url), host_of(root)
    return bool(a and b and a == b)
def under_start_path(url: str, root: str) -> bool:
    """True when url is on the start path or a subpath.
    Root path / keeps the whole host.
    A start URL that points at a file uses that file's directory as the prefix.
    """
    start = _directory_prefix(path_of(root))
    if start in ("", "/"):
        return True
    path = path_of(url)
    return path == start or path.startswith(start + "/")
def in_scope(url: str, root: str) -> bool:
    """Authorised crawl target: same host, and start-path when root is not /."""
    return same_host(url, root) and under_start_path(url, root)
def is_http_url(url: str) -> bool:
    try:
        p = urlparse(normalise_url(url))
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False
