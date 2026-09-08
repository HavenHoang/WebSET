"""Build ONE HTTP request from finding context + test marker."""

from __future__ import annotations
from urllib.parse import urlparse, quote


def _parse(url: str) -> tuple[str, str]:
    raw = (url or "").strip()
    if not raw:
        return "example.com", "/"
    if "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    host = p.netloc or "example.com"
    path = p.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return host, path


def build_request_from_finding(finding: dict, marker: str) -> str:
    """
    Uses finding fields:
      url/endpoint/location, method, param, param_location
    Returns a raw HTTP/1.1 request text.
    """
    method = str(finding.get("method") or "GET").upper()
    url = str(
        finding.get("url")
        or finding.get("endpoint")
        or finding.get("location")
        or ""
    )
    param = str(
        finding.get("param")
        or finding.get("input")
        or finding.get("parameter")
        or "q"
    )
    loc = str(
        finding.get("param_location")
        or finding.get("input_location")
        or "query"
    ).lower()

    host, path = _parse(url)
    encoded = quote(marker, safe="")

    if loc in ("query", "url", "get") or method == "GET":
        line = f"{method} {path}?{param}={encoded} HTTP/1.1"
        return f"{line}\nHost: {host}\nUser-Agent: WebSET-ActiveTest\n\n"

    if loc in ("json", "body_json"):
        body = f'{{"{param}": "{marker}"}}'
        return (
            f"{method} {path} HTTP/1.1\n"
            f"Host: {host}\n"
            f"Content-Type: application/json\n"
            f"User-Agent: WebSET-ActiveTest\n"
            f"Content-Length: {len(body)}\n\n"
            f"{body}"
        )

    body = f"{param}={encoded}"
    return (
        f"{method} {path} HTTP/1.1\n"
        f"Host: {host}\n"
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"User-Agent: WebSET-ActiveTest\n"
        f"Content-Length: {len(body)}\n\n"
        f"{body}"
    )
