"""Send exactly one HTTP request."""

from __future__ import annotations
from urllib.parse import urlparse


def send_once(
    *,
    method: str,
    url: str,
    headers: dict | None = None,
    data: str | bytes | None = None,
    timeout: float = 12.0,
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
    """
    method = (method or "GET").upper()
    headers = dict(headers or {})
    headers.setdefault("User-Agent", "WebSET-ActiveTest")

    try:
        import requests

        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            timeout=timeout,
            allow_redirects=False,
        )

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
        return {
            "ok": False,
            "status": 0,
            "headers": {},
            "body": "",
            "error": str(exc),
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
