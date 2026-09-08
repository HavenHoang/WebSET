"""Manual Payload mode — user-edited raw request."""

from __future__ import annotations
from urllib.parse import urlparse, parse_qs

from payload_injection.scope import in_scope, host_of
from payload_injection.http_client import send_once
from payload_injection.detectors import analyse_for_vuln_type

_TYPE_MAP = {
    "XSS": "xss",
    "SQLI": "sqli",
    "SQL": "sqli",
    "CUSTOM": "custom",
}


def _parse_raw_http(
    request_text: str,
    fallback_host: str
) -> tuple[str, str, dict, str | None]:
    """Very small parser for the GUI request editor text."""
    text = (request_text or "").replace("\r\n", "\n")
    parts = text.split("\n\n", 1)
    head = parts[0]
    body = parts[1] if len(parts) > 1 else None

    lines = head.split("\n")
    first = lines[0].strip() if lines else "GET / HTTP/1.1"
    bits = first.split()
    method = bits[0].upper() if bits else "GET"
    path = bits[1] if len(bits) > 1 else "/"

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    host = headers.get("Host") or fallback_host

    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        scheme = "https" if str(fallback_host).startswith("https://") else "http"
        url = f"{scheme}://{host}{path if path.startswith('/') else '/' + path}"

    return method, url, headers, body


def _marker_from_request(abs_url: str, body: str | None) -> str:
    parsed = urlparse(abs_url or "")
    q = parse_qs(parsed.query, keep_blank_values=True)
    for values in q.values():
        if values and str(values[0]).strip():
            return str(values[0])
    if body and str(body).strip():
        return str(body).strip()[:200]
    segs = [s for s in (parsed.path or "").split("/") if s]
    if segs:
        return segs[-1]
    return ""


def send_payload(
    url: str,
    request_text: str,
    payload_type: str = "Custom",
    marker: str | None = None,
) -> str:
    """
    GUI manual mode entry.
    Exactly one request is sent.
    """
    url = (url or "").strip()
    if not url:
        return "[Error] No target URL. Run Get Stack or Start Scan first."

    if not (request_text or "").strip():
        return "[Error] Empty HTTP request."

    fallback_host = host_of(url) or "localhost"
    method, abs_url, headers, body = _parse_raw_http(request_text, fallback_host)

    if not (request_text.splitlines()[0].split()[1].startswith("http://") or
            request_text.splitlines()[0].split()[1].startswith("https://")):
        parsed_scan = urlparse(url if "://" in url else "http://" + url)
        path = urlparse(abs_url).path or "/"
        if urlparse(abs_url).query:
            path += "?" + urlparse(abs_url).query
        abs_url = f"{parsed_scan.scheme}://{fallback_host}{path}"

    if not in_scope(abs_url, url):
        return (
            "[Error] Request host is outside scan scope.\n"
            f"Request host: {host_of(abs_url)}\n"
            f"Scan host:    {host_of(url)}\n"
        )

    resp = send_once(method=method, url=abs_url, headers=headers, data=body)

    if not resp.get("ok"):
        return f"[Error] {resp.get('error')}\nRequests sent: 1"

    body_preview = (resp.get("body") or "")[:2000]
    probe = (marker or "").strip() or _marker_from_request(abs_url, body)
    vtype = _TYPE_MAP.get(str(payload_type or "").upper(), "custom")
    detection = analyse_for_vuln_type(
        vtype,
        probe,
        resp.get("body") or "",
        int(resp.get("status") or 0),
        context="",
    )
    yes_no = lambda b: "YES" if b else "NO"

    return (
        "[Payload] Request completed\n\n"
        f"Target       : {url}\n"
        f"Type         : {payload_type}\n"
        f"Sent to      : {abs_url}\n"
        f"Method       : {method}\n"
        f"Status       : {resp.get('status')}\n"
        f"Requests sent: {resp.get('requests_sent')}\n"
        f"Probe / marker: {probe or '—'}\n\n"
        "----- Detection -----\n"
        f"HTTP status     : {resp.get('status')}\n"
        f"Found in body   : {yes_no(detection.get('found_in_body'))}\n"
        f"Encoded         : {yes_no(detection.get('encoded'))}\n"
        f"DB error signal : {yes_no(detection.get('db_error_signal'))}\n"
        f"Confidence      : {detection.get('confidence')}\n"
        f"Conclusion      : {detection.get('conclusion')}\n"
        f"Detail          : {detection.get('detail') or '—'}\n\n"
        "----- Response body (truncated) -----\n"
        f"{body_preview}\n"
    )
