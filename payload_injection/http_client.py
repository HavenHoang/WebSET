"""Send exactly one HTTP request."""
from __future__ import annotations
import time
from urllib.parse import urljoin, urlparse
_RETRY_MARKERS = (
    "remotedisconnected",
    "connection aborted",
    "connectionreset",
    "remotedisconnected",
    "connection reset by peer",
    "broken pipe",
)
def _session_cookies(explicit=None) -> dict:
    jar = {}
    try:
        from core.shared_state import SharedState
        stored = getattr(SharedState, "scan_cookies", None) or {}
        if hasattr(stored, "items"):
            jar.update({str(k): str(v) for k, v in stored.items() if k})
        elif stored:
            jar.update(dict(stored))
    except Exception:
        pass
    if explicit:
        if hasattr(explicit, "items"):
            jar.update({str(k): str(v) for k, v in explicit.items() if k})
        else:
            try:
                jar.update(dict(explicit))
            except Exception:
                pass
    return jar
def _cookie_header(jar: dict) -> str:
    parts = []
    seen = set()
    for name, value in (jar or {}).items():
        key = str(name or "").strip()
        if not key or key.lower() in seen:
            continue
        seen.add(key.lower())
        parts.append(f"{key}={value}")
    return "; ".join(parts)
def _publish_cookies(jar: dict) -> None:
    if not jar:
        return
    try:
        from core.shared_state import SharedState
        SharedState.set_scan_cookies(jar, merge=True)
    except Exception:
        pass
def _should_retry(exc: Exception) -> bool:
    blob = str(exc or "").lower()
    return any(mark in blob for mark in _RETRY_MARKERS)
def _same_host(left: str, right: str) -> bool:
    a = urlparse(left if "://" in (left or "") else "http://" + (left or ""))
    b = urlparse(right if "://" in (right or "") else "http://" + (right or ""))
    return bool(a.netloc) and a.netloc.lower() == (b.netloc or "").lower()
def _absorb_cookies(jar: dict, resp) -> None:
    try:
        for key, value in (resp.cookies or {}).items():
            jar[str(key)] = str(value)
    except Exception:
        pass
    try:
        raw = (resp.headers or {}).get("Set-Cookie") or ""
        for part in str(raw).split(","):
            first = part.split(";", 1)[0]
            if "=" in first:
                name, value = first.split("=", 1)
                name = name.strip()
                if name:
                    jar[name] = value.strip()
    except Exception:
        pass
def send_once(
    *,
    method: str,
    url: str,
    headers: dict | None = None,
    data: str | bytes | None = None,
    timeout: float = 12.0,
    cookies: dict | None = None,
    follow_redirects: bool = True,
    max_redirects: int = 5,
) -> dict:
    """
    Returns:
      {
        "ok": bool,
        "status": int,
        "headers": dict,
        "body": str,
        "error": str | None,
        "requests_sent": 1,
      }
    Redirects stay on the same host only.
    """
    method = (method or "GET").upper()
    headers = dict(headers or {})
    headers.setdefault("User-Agent", "WebSET-ActiveTest")
    headers.setdefault("Connection", "close")
    jar = _session_cookies(cookies)
    cookie_line = _cookie_header(jar)
    if cookie_line:
        headers["Cookie"] = cookie_line
    last_error = None
    try:
        import requests
    except Exception as exc:
        return {
            "ok": False,
            "status": 0,
            "headers": {},
            "body": "",
            "error": str(exc),
            "requests_sent": 1,
        }
    for attempt in (1, 2):
        session = None
        try:
            session = requests.Session()
            session.headers.update(headers)
            current_url = url
            current_method = method
            current_data = data
            hops = 0
            resp = None
            while True:
                req_headers = dict(headers)
                line = _cookie_header(jar)
                if line:
                    req_headers["Cookie"] = line
                resp = session.request(
                    method=current_method,
                    url=current_url,
                    headers=req_headers,
                    data=current_data,
                    timeout=timeout,
                    allow_redirects=False,
                )
                _absorb_cookies(jar, resp)
                code = int(resp.status_code)
                if not follow_redirects or code not in (301, 302, 303, 307, 308):
                    break
                location = (resp.headers or {}).get("Location") or ""
                if not location:
                    break
                nxt = urljoin(current_url, location)
                if not _same_host(url, nxt):
                    break
                hops += 1
                if hops > max_redirects:
                    break
                current_url = nxt
                if code in (301, 302, 303) and current_method != "GET":
                    current_method = "GET"
                    current_data = None
            _publish_cookies(jar)
            try:
                body = resp.text
            except Exception:
                body = resp.content.decode("utf-8", errors="replace")
            return {
                "ok": True,
                "status": int(resp.status_code),
                "headers": dict(resp.headers),
                "body": body,
                "error": None,
                "requests_sent": 1,
            }
        except Exception as exc:
            last_error = exc
            if attempt == 1 and _should_retry(exc):
                time.sleep(0.35)
                continue
            return {
                "ok": False,
                "status": 0,
                "headers": {},
                "body": "",
                "error": str(exc),
                "requests_sent": 1,
            }
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass
    return {
        "ok": False,
        "status": 0,
        "headers": {},
        "body": "",
        "error": str(last_error or "request failed"),
        "requests_sent": 1,
    }
def absolute_url(finding_url: str, path_and_query: str) -> str:
    raw = (finding_url or "").strip()
    if "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    base = f"{p.scheme}://{p.netloc}"
    if path_and_query.startswith("http://") or path_and_query.startswith("https://"):
        return path_and_query
    if not path_and_query.startswith("/"):
        path_and_query = "/" + path_and_query
    return base + path_and_query
