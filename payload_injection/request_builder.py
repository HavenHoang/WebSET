"""Build ONE HTTP request from finding context + test marker."""
from __future__ import annotations
import json
import re
from urllib.parse import parse_qsl, quote, urlencode, urlparse
def _parse(url: str) -> tuple[str, str, str, str]:
    raw = (url or "").strip()
    if not raw:
        return "example.com", "/", "", ""
    if "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    host = p.netloc or "example.com"
    path = p.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return host, path, p.query or "", p.fragment or ""
def _existing_value(finding: dict, param: str, existing_query: str) -> str:
    q = dict(parse_qsl(existing_query or "", keep_blank_values=True))
    if param and str(q.get(param) or "").strip():
        return str(q.get(param))
    for key in ("original_value", "sample_value", "param_value"):
        val = str((finding or {}).get(key) or "").strip()
        if val:
            return val
    return ""
def _inject_value(finding: dict, param: str, marker: str, existing_query: str) -> str:
    marker = str(marker or "")
    vtype = str((finding or {}).get("vuln_type") or "").lower()
    if vtype in ("command_injection", "cmdi", "cmd") and marker[:1] in ";|&":
        base = _existing_value(finding, param, existing_query) or "localhost"
        return base + marker
    return marker
_FIELD_NAME_RE = re.compile(
    r"""<(?:input|select|textarea|button)\b[^>]*\bname\s*=\s*['"]([^'"]+)['"]""",
    re.I,
)
_BUTTON_NAME_RE = re.compile(r"submit|sign|login|^go$", re.I)
_SUBMIT_KEY_RE = _BUTTON_NAME_RE


def ensure_form_companions(finding: dict) -> dict:
    """POST handlers often ignore a body that is missing the submit control."""
    finding = dict(finding or {})
    method = str(finding.get("method") or "GET").upper()
    if method not in ("POST", "PUT", "PATCH"):
        return finding
    existing = finding.get("companions")
    if isinstance(existing, dict) and existing:
        return finding
    url = str(finding.get("url") or finding.get("endpoint") or "").strip()
    param = str(finding.get("param") or finding.get("input") or "").strip()
    if not url:
        return finding
    try:
        from payload_injection.http_client import send_once
        resp = send_once(method="GET", url=url, timeout=8)
        html = resp.get("body") or ""
    except Exception:
        return finding
    companions = {}
    for name in _FIELD_NAME_RE.findall(html):
        key = str(name or "").strip()
        if not key or key == param:
            continue
        companions[key] = "Submit" if _BUTTON_NAME_RE.search(key) else ""
    if companions:
        finding["companions"] = companions
        finding["param_location"] = finding.get("param_location") or "body"
    return finding
_LOGIN_PARAM_RE = re.compile(r"^(user|username|email|login|password)$", re.I)
def with_form_controls(fields: dict, param: str) -> dict:
    """Many HTML handlers only run when a successful submit control is present.
    GET probes that send only the injected field never hit the sink.
    """
    out = {
        str(k): ("" if v is None else str(v))
        for k, v in (fields or {}).items()
        if str(k or "").strip()
    }
    companions_ok = any(_SUBMIT_KEY_RE.search(str(k) or "") for k in out)
    if not companions_ok:
        out.setdefault("Submit", "Submit")
        out.setdefault("submit", "Submit")
        if _LOGIN_PARAM_RE.match(param or ""):
            out.setdefault("Login", "Login")
            out.setdefault("login", "Login")
    if _LOGIN_PARAM_RE.match(param or "") and str(param or "").lower() != "password":
        out.setdefault("password", out.get("password") or "webset")
    return out
def build_request_from_finding(finding: dict, marker: str) -> str:
    finding = finding or {}
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
    host, path, existing_query, fragment = _parse(url)
    value = _inject_value(finding, param, marker, existing_query)
    vtype = str(finding.get("vuln_type") or "").lower()
    client_route = fragment.startswith("/") or fragment.startswith("!/")
    if client_route and (method == "GET" or loc in ("query", "url", "get")):
        frag_path, _, frag_query = fragment.partition("?")
        q = dict(parse_qsl(frag_query, keep_blank_values=True))
        q[param] = value
        line = f"{method} {path}#{frag_path}?{urlencode(q)} HTTP/1.1"
        return f"{line}\nHost: {host}\nUser-Agent: WebSET-ActiveTest\n\n"
    nosql_path = vtype in ("nosqli", "nosql") and method == "GET"
    if loc in ("path", "url_path") or nosql_path:
        segs = [s for s in path.split("/") if s]
        if segs and segs[-1].lower() == param.lower():
            segs[-1] = value
        elif nosql_path:
            segs.append(value)
        elif segs:
            segs[-1] = value
        else:
            segs = [value]
        encoded = []
        for seg in segs:
            if any(ch in str(seg) for ch in '{}"$ '):
                encoded.append(quote(str(seg), safe=""))
            else:
                encoded.append(str(seg))
        path = "/" + "/".join(encoded)
        suffix = f"?{existing_query}" if existing_query else ""
        line = f"{method} {path}{suffix} HTTP/1.1"
        return f"{line}\nHost: {host}\nUser-Agent: WebSET-ActiveTest\n\n"
    use_query = method == "GET" or (
        loc in ("query", "url", "get") and method not in ("POST", "PUT", "PATCH")
    )
    extra = {}
    companions = finding.get("companions")
    if isinstance(companions, dict):
        extra = {
            str(k): ("" if v is None else str(v))
            for k, v in companions.items()
            if str(k or "").strip()
        }
    if use_query:
        q = dict(parse_qsl(existing_query, keep_blank_values=True))
        for k, v in extra.items():
            q.setdefault(k, v)
        q[param] = value
        q = with_form_controls(q, param)
        line = f"{method} {path}?{urlencode(q)} HTTP/1.1"
        return f"{line}\nHost: {host}\nUser-Agent: WebSET-ActiveTest\n\n"
    vtype = str(finding.get("vuln_type") or "").lower()
    xmlish = (
        vtype == "xxe"
        or str(marker or "").lstrip().startswith("<?xml")
        or param.lower() in ("xml", "file")
        and "<!DOCTYPE" in str(marker or "").upper()
    )
    if xmlish and method in ("POST", "PUT", "PATCH"):
        xml_body = str(marker or "")
        if param.lower() in ("file", "upload", "xmlfile"):
            boundary = "WebSETXXE"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{param}"; filename="probe.xml"\r\n'
                "Content-Type: text/xml\r\n\r\n"
                f"{xml_body}\r\n"
                f"--{boundary}--\r\n"
            )
            ctype = f"multipart/form-data; boundary={boundary}"
        else:
            body = xml_body
            ctype = "application/xml"
        return (
            f"{method} {path} HTTP/1.1\n"
            f"Host: {host}\n"
            f"Content-Type: {ctype}\n"
            f"User-Agent: WebSET-ActiveTest\n"
            f"Content-Length: {len(body.encode('utf-8'))}\n\n"
            f"{body}"
        )
    if loc in ("json", "body_json"):
        parsed = value
        text = str(value or "").strip()
        if text.startswith("{") or text.startswith("["):
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = value
        payload = {param: parsed}
        if param.lower() in ("email", "username", "user", "login"):
            payload.setdefault("password", "webset")
        if param.lower() in ("id", "_id") and isinstance(parsed, dict):
            payload.setdefault("message", "webset-nosql")
        body = json.dumps(payload)
        return (
            f"{method} {path} HTTP/1.1\n"
            f"Host: {host}\n"
            f"Content-Type: application/json\n"
            f"User-Agent: WebSET-ActiveTest\n"
            f"Content-Length: {len(body.encode('utf-8'))}\n\n"
            f"{body}"
        )
    fields = dict(extra)
    fields[param] = value
    fields = with_form_controls(fields, param)
    body = urlencode(fields)
    suffix = f"?{existing_query}" if existing_query else ""
    return (
        f"{method} {path}{suffix} HTTP/1.1\n"
        f"Host: {host}\n"
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"User-Agent: WebSET-ActiveTest\n"
        f"Content-Length: {len(body.encode('utf-8'))}\n\n"
        f"{body}"
    )
