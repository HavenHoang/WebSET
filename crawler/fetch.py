"""Primary Start Scan (URL) fetch. Returns one plain artefact dict."""
from __future__ import annotations
import time
from crawler.scope import normalise_url, is_http_url
from crawler.headers_cookies import headers_to_dict, set_cookie_list

DEFAULT_TIMEOUT = 15
DEFAULT_HEADERS = {
    "User-Agent": "WebSET-Scanner/1.0 (+local research)",
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
}


def fetch_target(url: str, *, timeout: float = DEFAULT_TIMEOUT,
                 use_browser: bool = False) -> dict:
    url = normalise_url(url)
    if not is_http_url(url):
        return _fail(url, "invalid_url")
    if use_browser:
        try:
            from crawler.browser import fetch_with_selenium
            return fetch_with_selenium(url, timeout=timeout)
        except Exception as exc:
            return _fail(url, f"browser: {exc}")
    try:
        import requests
        t0 = time.time()
        resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout,
                            allow_redirects=True)
        return {
            "ok": True, "url": str(resp.url), "status": int(resp.status_code),
            "redirect_chain": [{"status": int(r.status_code), "url": str(r.url)}
                               for r in resp.history],
            "headers": headers_to_dict(resp.headers),
            "set_cookie": set_cookie_list(resp.headers),
            "body": resp.text, "elapsed_ms": int((time.time() - t0) * 1000),
            "error": None,
        }
    except Exception as exc:
        return _fail(url, _classify_error(exc))


def _classify_error(exc) -> str:
    n, t = type(exc).__name__.lower(), str(exc).lower()
    if "timeout" in n or "timeout" in t: return "timeout"
    if "ssl" in n or "ssl" in t or "certificate" in t: return "ssl"
    if "getaddrinfo" in t or "name or service" in t or "dns" in t: return "dns"
    if "refused" in t or "connection" in n: return "connection"
    return str(exc)


def _fail(url: str, error: str) -> dict:
    return {"ok": False, "url": url or "", "status": 0, "redirect_chain": [],
            "headers": {}, "set_cookie": [], "body": "", "elapsed_ms": 0, "error": error}
