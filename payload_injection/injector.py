"""Manual Payload mode — user-edited raw request."""
from __future__ import annotations
from urllib.parse import urlparse, parse_qs, parse_qsl
from payload_injection.scope import in_scope, host_of
from payload_injection.http_client import send_once
from payload_injection.detectors import analyse_for_vuln_type, _is_xss_poc
_TYPE_MAP = {
    "XSS": "xss",
    "SQLI": "sqli",
    "SQL": "sqli",
    "NOSQLI": "nosqli",
    "NOSQL": "nosqli",
    "XXE": "xxe",
    "PATH TRAVERSAL": "path_traversal",
    "PATH_TRAVERSAL": "path_traversal",
    "LFI": "path_traversal",
    "COMMAND INJECTION": "command_injection",
    "COMMAND_INJECTION": "command_injection",
    "CMD": "command_injection",
    "IDOR": "idor",
    "BOLA": "idor",
    "CUSTOM": "custom",
}
def _session_cookies(explicit: dict | None) -> dict | None:
    if explicit:
        return explicit
    try:
        from core.shared_state import SharedState
        jar = getattr(SharedState, "scan_cookies", None)
        if isinstance(jar, dict) and jar:
            return jar
    except Exception:
        pass
    return None
def _send(method, url, headers, data, cookies):
    kwargs = dict(method=method, url=url, headers=headers, data=data, cookies=cookies)
    try:
        return send_once(**kwargs, follow_redirects=True)
    except TypeError:
        return send_once(**kwargs)
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
    frag = parsed.fragment or ""
    if "?" in frag:
        for key, values in parse_qs(frag.split("?", 1)[1], keep_blank_values=True).items():
            q.setdefault(key, values)
    for values in q.values():
        if values and str(values[0]).strip():
            return str(values[0])
    if body and str(body).strip():
        return str(body).strip()[:200]
    segs = [s for s in (parsed.path or "").split("/") if s]
    if segs:
        return segs[-1]
    return ""
def _rebase_url(abs_url: str, fallback_url: str, request_text: str) -> str:
    """Keep a client-route fragment. Rebuilding from path+query used to drop #/search."""
    first_path = ""
    try:
        first_path = request_text.splitlines()[0].split()[1]
    except Exception:
        first_path = ""
    if first_path.startswith(("http://", "https://")):
        return abs_url
    parsed_scan = urlparse(fallback_url if "://" in (fallback_url or "") else "http://" + (fallback_url or ""))
    parsed_abs = urlparse(abs_url or "")
    path = parsed_abs.path or "/"
    if parsed_abs.query:
        path += "?" + parsed_abs.query
    if parsed_abs.fragment:
        path += "#" + parsed_abs.fragment
    host = parsed_abs.netloc or host_of(fallback_url) or "localhost"
    scheme = parsed_scan.scheme or "http"
    return f"{scheme}://{host}{path}"
_SCRIPT_CACHE: dict[str, str] = {}
def _client_param(url: str, marker: str) -> str:
    frag = urlparse(url or "").fragment or ""
    query = frag.split("?", 1)[1] if "?" in frag else ""
    pairs = parse_qsl(query, keep_blank_values=True)
    wanted = str(marker or "")
    for key, value in pairs:
        if value == wanted:
            return key
    return pairs[0][0] if pairs else ""
def _script_for_origin(url: str) -> str:
    from security_checks.injection_checks import _harvest_script_text, _origin, _send
    origin = _origin(url)
    if not origin:
        return ""
    cached = _SCRIPT_CACHE.get(origin)
    if cached is not None:
        return cached
    page = _send("GET", origin + "/", timeout=8.0)
    body = page.get("body") if page.get("ok") else ""
    text = _harvest_script_text(origin + "/", body or "")
    _SCRIPT_CACHE[origin] = text or ""
    return _SCRIPT_CACHE[origin]
def _client_sink(url: str, param: str) -> str:
    """Same data-flow as the scan: query param copied into an HTML sink."""
    if not param:
        return ""
    from security_checks.injection_checks import _dom_xss_from_script, _origin
    origin = _origin(url) or ""
    script = _script_for_origin(url)
    if not script:
        return ""
    for item in _dom_xss_from_script(origin + "/", script):
        if str(item.get("param") or "").lower() == param.lower():
            return str(item.get("evidence") or "HTML sink")
    return ""
def _client_route(url: str) -> bool:
    frag = urlparse(url or "").fragment or ""
    return frag.startswith("/") or frag.startswith("!/")
def _plain_meaning(
    vtype: str,
    detection: dict,
    status,
    body: str,
    marker: str = "",
) -> tuple[str, str]:
    """Easy-read Conclusion + Detail for the GUI. Detector still owns the flags."""
    detection = detection or {}
    conclusion = str(detection.get("conclusion") or "").strip()
    detail = str(detection.get("detail") or "").strip()
    found = bool(detection.get("found_in_body"))
    encoded = bool(detection.get("encoded"))
    db_err = bool(detection.get("db_error_signal"))
    confirm = str(detection.get("confirmation") or "").strip().upper()
    body_l = (body or "").lower()
    has_token = (
        bool(detection.get("auth_success"))
        or '"token"' in body_l
        or '"authentication"' in body_l
        or "session token" in body_l
    )
    status_s = str(status if status not in (None, "") else "—")
    try:
        status_n = int(status_s)
    except Exception:
        status_n = 0
    if vtype == "sqli":
        if has_token and not db_err:
            return (
                "Login succeeded with a crafted SQL value",
                f"The probe was sent in the targeted field and the server answered HTTP {status_s} "
                f"with a session or user object. The login check accepted the crafted value, so "
                f"someone else can sign in as that account and use what the account can do.",
            )
        if db_err:
            return (
                "The field broke the database query",
                f"The probe was sent in the targeted field. The server answered HTTP {status_s} "
                f"with a database / ORM error. The app copied that field into SQL, so an attacker "
                f"can change how the query runs and reach data or accounts the query is meant to protect.",
            )
        if status_n >= 500:
            return (
                "The server errored after this SQL probe",
                f"The probe was sent in the targeted field. The server answered HTTP {status_s} "
                f"without an explicit database / ORM error string. That is a weaker signal than "
                f"a SQL error — the field may have reached the query, but this step is not exploit proof.",
            )
        return (
            conclusion or "No SQL injection signal on this probe",
            detail
            or (
                f"The server answered HTTP {status_s}. There was no database error and no "
                f"successful login for this payload."
            ),
        )
    if vtype == "xss":
        poc = _is_xss_poc(marker)
        sink = str(detection.get("evidence") or detection.get("detail") or "").strip()
        if sink and sink[-1] not in ".!?":
            sink += "."
        client_sink = "html sink" in sink.lower() or "client script" in sink.lower()
        if client_sink and confirm == "CONFIRMED" and poc:
            return (
                "The value is written into an HTML sink without encoding",
                f"{sink} A browser treats that value as HTML, so a payload in this "
                f"parameter can run as script in the page. The HTTP response itself does not contain the payload.",
            )
        if client_sink and confirm == "LIKELY":
            return (
                "The value reaches an HTML sink without encoding",
                f"{sink} The parameter is copied into the page as HTML. A plain marker "
                f"only shows the sink is reachable. It is not proof that script would run.",
            )
        if found and not encoded and poc and confirm == "CONFIRMED":
            return (
                "The probe came back in the page unescaped",
                f"Proof-of-concept markup sent in the parameter appeared in the response "
                f"(HTTP {status_s}) without encoding. A browser would treat attacker-controlled "
                f"script as part of the site, so a signed-in user's session or actions in the "
                f"app can be taken over.",
            )
        if found and not encoded and poc:
            return (
                "Unencoded markup came back — page type needs review",
                f"Proof-of-concept markup appeared in the response (HTTP {status_s}) without "
                f"encoding. Confirm the client renders this as HTML before treating it as a "
                f"working XSS exploit.",
            )
        if found and not encoded:
            return (
                "The probe came back in the page unescaped",
                f"The same value sent in the parameter appeared in the response (HTTP {status_s}) "
                f"without encoding. That shows the field is reflected. It is not proof that "
                f"script would run — later steps must deliver markup.",
            )
        if found and encoded:
            return (
                "The probe came back encoded",
                f"The value appeared in the response (HTTP {status_s}) but it was encoded. "
                f"The page reflected the input; encoding reduced the chance of script running.",
            )
        return (
            conclusion or "The probe was not reflected as-is",
            detail
            or (
                f"The server answered HTTP {status_s} and the probe was not found unescaped "
                f"in the body."
            ),
        )
    if vtype in ("path_traversal", "lfi"):
        ev = str(detection.get("evidence") or detection.get("detail") or "").lower()
        included = any(s in ev for s in ("include(", "require(", "failed opening", "for inclusion"))
        if confirm == "CONFIRMED" and included and "root:x:" not in ev:
            return (
                "The parameter was passed to a file include",
                "The server tried to include the path from this parameter. "
                "The file was not found, but that include is the vulnerability. "
                "A successful file read is not required.",
            )
        if confirm == "CONFIRMED":
            return (
                "The response included a file outside the intended path",
                f"The server answered HTTP {status_s} with file contents after a path probe. "
                f"An attacker can read files the app should not expose, including configuration "
                f"or credentials if those files are reachable.",
            )
        if confirm == "LIKELY":
            return (
                conclusion or "Filesystem error after the path probe",
                detail
                or (
                    f"The server answered HTTP {status_s} with a filesystem-style error. "
                    f"That is not proof a foreign file was read."
                ),
            )
        if found:
            return (
                "Possible reflection — path probe is not distinctive",
                f"Input appears in the body (HTTP {status_s}) but is not unique enough to confirm "
                f"that a foreign file was read.",
            )
        return (
            conclusion or "No file-disclosure signal on this probe",
            detail or f"The server answered HTTP {status_s} without returning those file contents.",
        )
    if vtype in ("command_injection", "cmd"):
        if confirm == "CONFIRMED":
            return (
                "The server ran the probe as part of a command",
                f"The response (HTTP {status_s}) included command output. An attacker can run "
                f"commands in the application's environment and reach whatever that account can reach.",
            )
        if confirm == "LIKELY":
            return (
                conclusion or "Possible command-adjacent signal",
                detail
                or (
                    f"Input appears in the body (HTTP {status_s}) but command output was not confirmed."
                ),
            )
        if found:
            return (
                "Possible reflection — probe is not distinctive",
                f"Input appears in the body (HTTP {status_s}) but command output was not confirmed.",
            )
        return (
            conclusion or "No command-output signal on this probe",
            detail or f"The server answered HTTP {status_s} without command output.",
        )
    if conclusion or detail:
        return (conclusion or "Check finished", detail or f"The server answered HTTP {status_s}.")
    return ("Check finished", f"The server answered HTTP {status_s}.")
def send_payload(
    url: str,
    request_text: str,
    payload_type: str = "Custom",
    marker: str | None = None,
    cookies: dict | None = None,
    expect: str = "",
) -> str:
    """
    GUI manual mode entry.
    Exactly one request is sent.
    Reuses scan session cookies when provided (or SharedState.scan_cookies).
    """
    url = (url or "").strip()
    if not url:
        return "[Error] No target URL. Run Get Stack or Start Scan first."
    if not (request_text or "").strip():
        return "[Error] Empty HTTP request."
    cookies = _session_cookies(cookies)
    fallback_host = host_of(url) or "localhost"
    method, abs_url, headers, body = _parse_raw_http(request_text, fallback_host)
    headers = dict(headers or {})
    headers.setdefault("Connection", "close")
    headers.setdefault("User-Agent", "WebSET-ActiveTest")
    abs_url = _rebase_url(abs_url, url, request_text)
    if not in_scope(abs_url, url):
        return (
            "[Error] Request host is outside scan scope.\n"
            f"Request host: {host_of(abs_url)}\n"
            f"Scan host:    {host_of(url)}\n"
        )
    vtype = _TYPE_MAP.get(str(payload_type or "").upper(), "custom")
    probe = (marker or "").strip() or _marker_from_request(abs_url, body)
    xml_blob = (marker or body or "").strip()
    preset = None
    if _client_route(abs_url) and vtype == "xss":
        evidence = _client_sink(abs_url, _client_param(abs_url, probe))
        resp = {"ok": True, "status": 200, "body": "", "headers": {}, "error": None, "requests_sent": 1}
        if evidence:
            from payload_injection.detectors import _is_distinctive, _is_xss_poc
            if _is_xss_poc(probe):
                confirmation = "CONFIRMED"
                conclusion = "The value is written into an HTML sink without encoding"
            elif _is_distinctive(probe) or "<" in probe:
                confirmation = "LIKELY"
                conclusion = "The value reaches an HTML sink without encoding"
            else:
                confirmation = "NOT CONFIRMED"
                conclusion = "No clear reflection"
            preset = {
                "found_in_body": False,
                "encoded": False,
                "db_error_signal": False,
                "auth_success": False,
                "confirmation": confirmation,
                "conclusion": conclusion,
                "detail": evidence,
                "evidence": evidence,
            }
    elif vtype == "xxe" and xml_blob.lstrip().startswith("<?xml"):
        try:
            import requests
            hdrs = {
                k: v for k, v in headers.items()
                if str(k).lower() not in ("content-type", "content-length")
            }
            raw = requests.request(
                method=method or "POST",
                url=abs_url,
                headers=hdrs,
                files={"file": ("probe.xml", xml_blob.encode("utf-8"), "text/xml")},
                cookies=cookies or None,
                timeout=12,
                allow_redirects=True,
            )
            try:
                text = raw.text
            except Exception:
                text = raw.content.decode("utf-8", errors="replace")
            resp = {
                "ok": True,
                "status": int(raw.status_code),
                "body": text,
                "headers": {str(k).lower(): str(v) for k, v in raw.headers.items()},
                "requests_sent": 1,
            }
        except Exception as exc:
            resp = {"ok": False, "error": str(exc), "status": 0, "body": ""}
    else:
        resp = _send(
            method=method,
            url=abs_url,
            headers=headers,
            data=body,
            cookies=cookies,
        )
    if not resp.get("ok"):
        return f"[Error] {resp.get('error')}\nRequests sent: 1"
    body_preview = (resp.get("body") or "")[:2000]
    if preset is not None and not body_preview.strip():
        body_preview = (
            "(empty) Hash routes are not sent to the server. "
            "This HTTP body is only the app shell and does not contain the payload."
        )
    if preset is None:
        detection = analyse_for_vuln_type(
            vtype,
            probe,
            resp.get("body") or "",
            int(resp.get("status") or 0),
            context="",
            expect=str(expect or ""),
        )
    else:
        detection = preset
    yes_no = lambda b: "YES" if b else "NO"
    meaning_title, meaning_detail = _plain_meaning(
        vtype,
        detection,
        resp.get("status"),
        resp.get("body") or "",
        marker=probe,
    )
    evidence = str(detection.get("evidence") or "").strip()
    evidence_line = f"Evidence        : {evidence}\n" if evidence else ""
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
        f"Auth success    : {yes_no(detection.get('auth_success'))}\n"
        f"Confirmation    : {detection.get('confirmation') or '—'}\n"
        f"Conclusion      : {meaning_title}\n"
        f"Detail          : {meaning_detail}\n"
        f"{evidence_line}"
        "\n----- Response body (truncated) -----\n"
        f"{body_preview}\n"
    )
