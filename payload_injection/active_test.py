"""Single-request Active Test engine for authorised lab targets."""

from __future__ import annotations
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from payload_injection.scope import host_of, in_scope
from payload_injection.request_builder import build_request_from_finding
from payload_injection.http_client import send_once
from payload_injection.detectors import analyse_for_vuln_type

ACTIVE_TYPES = frozenset({"xss", "sqli", "path_traversal", "command_injection"})


def _is_active_testable(finding: dict) -> bool:
    if not finding:
        return False

    if str(finding.get("scan_origin") or "") == "Platform":
        return False

    vtype = str(finding.get("vuln_type") or "").lower()
    if vtype not in ACTIVE_TYPES:
        return False

    url = str(
        finding.get("url")
        or finding.get("endpoint")
        or finding.get("location")
        or ""
    ).strip()

    if not url:
        return False

    if vtype in {"xss", "sqli"}:
        param = str(finding.get("param") or finding.get("input") or "").strip()
        if not param:
            return False

    return True


def _target_url_with_marker(
    finding: dict,
    marker: str
) -> tuple[str, str, str | None]:
    method = str(finding.get("method") or "GET").upper()

    base = str(
        finding.get("url")
        or finding.get("endpoint")
        or finding.get("location")
        or ""
    ).strip()

    param = str(finding.get("param") or finding.get("input") or "q")
    loc = str(finding.get("param_location") or "query").lower()

    if "://" not in base:
        base = "http://" + base

    p = urlparse(base)

    if loc in ("query", "url", "get") or method == "GET":
        q = parse_qs(p.query, keep_blank_values=True)
        q[param] = [marker]
        new_query = urlencode(q, doseq=True)
        url = urlunparse((p.scheme, p.netloc, p.path or "/", "", new_query, ""))
        return method, url, None

    if loc in ("json", "body_json"):
        url = urlunparse((p.scheme, p.netloc, p.path or "/", "", "", ""))
        body = f'{{"{param}": "{marker}"}}'
        return method, url, body

    url = urlunparse((p.scheme, p.netloc, p.path or "/", "", "", ""))
    body = f"{param}={marker}"
    return method, url, body


def _parse_editor_request(
    request_text: str,
    fallback_url: str,
) -> tuple[str, str, dict, str | None] | None:
    """Parse the GUI HTTP editor into method, absolute URL, headers, body."""
    text = (request_text or "").replace("\r\n", "\n").strip()
    if not text:
        return None

    parts = text.split("\n\n", 1)
    head = parts[0]
    body = parts[1] if len(parts) > 1 and parts[1] != "" else None

    lines = head.split("\n")
    first = lines[0].strip() if lines else ""
    bits = first.split()
    if len(bits) < 2:
        return None

    method = bits[0].upper()
    path = bits[1]

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    raw_fallback = (fallback_url or "").strip()
    if raw_fallback and "://" not in raw_fallback:
        raw_fallback = "http://" + raw_fallback
    parsed_scan = urlparse(raw_fallback) if raw_fallback else urlparse("http://localhost")
    scheme = parsed_scan.scheme or "http"
    fallback_host = (
        headers.get("Host")
        or parsed_scan.netloc
        or host_of(fallback_url)
        or "localhost"
    )

    if path.startswith("http://") or path.startswith("https://"):
        abs_url = path
    else:
        if not path.startswith("/"):
            path = "/" + path
        abs_url = f"{scheme}://{fallback_host}{path}"

    return method, abs_url, headers, body


def _probe_from_sent(finding: dict, abs_url: str, body: str | None, fallback: str) -> str:
    param = str(finding.get("param") or finding.get("input") or "").strip()
    parsed = urlparse(abs_url or "")
    q = parse_qs(parsed.query, keep_blank_values=True)
    if param and param in q and q[param] and str(q[param][0]).strip():
        return str(q[param][0])
    for values in q.values():
        if values and str(values[0]).strip():
            return str(values[0])
    if body and str(body).strip():
        return str(body).strip()[:200]
    segs = [s for s in (parsed.path or "").split("/") if s]
    if segs:
        return segs[-1]
    return fallback


def format_result(
    *,
    test: dict,
    finding: dict,
    marker: str,
    url: str,
    status: int,
    detection: dict,
    request_text: str,
    error: str | None = None,
) -> str:
    if error:
        lines = [
            "[Active Test] Failed",
            "",
            f"Error: {error}",
            "Requests sent: 1",
            "",
            "----- Request -----",
            request_text,
        ]
        return "\n".join(lines)

    yes_no = lambda b: "YES" if b else "NO"
    label = test.get("label") or test.get("id")
    param = finding.get("param") or finding.get("input") or "-"

    lines = [
        "[Active Test] Single-request verification",
        "",
        f"Test            : {label}",
        f"Test id         : {test.get('id')}",
        f"Marker / input  : {marker}",
        f"Target          : {url}",
        f"Method          : {finding.get('method') or 'GET'}",
        f"Parameter       : {param}",
        f"Param location  : {finding.get('param_location') or 'query'}",
        f"Context         : {finding.get('context') or '-'}",
        "Requests sent   : 1",
        "",
        "----- Detection -----",
        f"HTTP status     : {status}",
        f"Found in body   : {yes_no(detection.get('found_in_body'))}",
        f"Encoded         : {yes_no(detection.get('encoded'))}",
        f"DB error signal : {yes_no(detection.get('db_error_signal'))}",
        f"Confidence      : {detection.get('confidence')}",
        f"Conclusion      : {detection.get('conclusion')}",
        f"Detail          : {detection.get('detail') or '-'}",
        "",
        "----- Request sent -----",
        request_text,
    ]
    return "\n".join(lines)


def run_active_test(finding: dict, test: dict, request_text: str) -> str:
    """Main hook used by the GUI Active Test button path."""
    finding = dict(finding or {})
    test = dict(test or {})
    default_marker = str(test.get("marker") or "TEST_MARKER_123")
    request_text = (request_text or "").strip() or build_request_from_finding(
        finding, default_marker
    )

    if not _is_active_testable(finding):
        return (
            "[Error] Active Test is only for injection-style findings "
            "(xss / sqli / path_traversal / command_injection) with URL + param.\n"
            "Passive findings (headers, cookies, CSP) are verified by the scan itself."
        )

    try:
        from core.shared_state import SharedState
        allowed = getattr(SharedState, "current_url", None) or ""
    except Exception:
        allowed = ""

    target_for_scope = str(
        finding.get("url") or finding.get("endpoint") or finding.get("location") or ""
    )

    parsed = _parse_editor_request(request_text, allowed or target_for_scope)
    if parsed:
        method, abs_url, headers, body = parsed
        headers = dict(headers or {})
        headers.setdefault("User-Agent", "WebSET-ActiveTest")
    else:
        method, abs_url, body = _target_url_with_marker(finding, default_marker)
        headers = {"User-Agent": "WebSET-ActiveTest"}
        loc = str(finding.get("param_location") or "query").lower()
        if loc in ("json", "body_json"):
            headers["Content-Type"] = "application/json"
        elif body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"

    marker = _probe_from_sent(finding, abs_url, body, default_marker)

    scope_url = abs_url or target_for_scope
    if allowed and not in_scope(scope_url, allowed):
        return (
            "[Error] Target host is outside the current scan scope.\n"
            f"Request host: {host_of(scope_url)}\n"
            f"Scan host:    {host_of(allowed)}\n"
        )

    resp = send_once(method=method, url=abs_url, headers=headers, data=body)

    if not resp.get("ok"):
        return format_result(
            test=test,
            finding=finding,
            marker=marker,
            url=abs_url,
            status=0,
            detection={},
            request_text=request_text,
            error=resp.get("error") or "request failed",
        )

    vtype = str(finding.get("vuln_type") or "").lower()
    detection = analyse_for_vuln_type(
        vtype,
        marker,
        resp.get("body") or "",
        int(resp.get("status") or 0),
        context=str(finding.get("context") or ""),
    )

    return format_result(
        test=test,
        finding=finding,
        marker=marker,
        url=abs_url,
        status=int(resp.get("status") or 0),
        detection=detection,
        request_text=request_text,
    )
