from __future__ import annotations
import json
from urllib.parse import urlparse, parse_qs, parse_qsl, urlencode, urlunparse
from payload_injection.scope import host_of, in_scope
from payload_injection.request_builder import build_request_from_finding, with_form_controls
from payload_injection.http_client import send_once
from payload_injection.detectors import analyse_for_vuln_type, summarise_detections
from payload_injection.library import get_active_tests
from payload_injection.injector import _plain_meaning
ACTIVE_TYPES = frozenset({"xss", "sqli", "nosqli", "path_traversal", "command_injection", "idor", "xxe"})
_EXPLOIT_EXPECTS = frozenset({
    "raw_script",
    "raw_breakout",
    "raw_js_uri",
    "raw_angle_brackets",
    "auth_success",
    "foreign_file_or_error",
    "shell_error_or_canary",
    "idor_dump",
})
def _finding_vtype(finding: dict) -> str:
    v = str((finding or {}).get("vuln_type") or "").lower()
    name = str((finding or {}).get("vulnerability") or (finding or {}).get("name") or "").lower()
    plugin = str((finding or {}).get("plugin_id") or "").lower()
    if v in ("nosqli", "nosql") or plugin == "nosqli" or "nosql" in name:
        return "nosqli"
    if (
        v in ("idor", "bola")
        or plugin == "idor-bola"
        or "insecure direct" in name
        or "broken object" in name
    ):
        return "idor"
    return v


def _origin_of(url: str) -> str:
    raw = str(url or "")
    if raw and "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    if not p.scheme or not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}"


def _login_bearer(finding: dict) -> str:
    origin = _origin_of(
        finding.get("url") or finding.get("endpoint") or finding.get("location") or ""
    )
    if not origin:
        return ""
    paths = (
        "/rest/user/login",
        "/api/login",
        "/api/auth/login",
        "/login",
        "/auth/login",
        "/user/login",
    )
    taut = (
        "' OR true-- ",
        "' OR '1'='1'-- ",
        "' OR 1=1-- ",
        "' OR true--",
        "' OR '1'='1'--",
        "' OR 1=1--",
    )
    fields = ("email", "username", "user", "login")
    for path in paths:
        for field in fields:
            for payload in taut:
                body = json.dumps({field: payload, "password": "webset"})
                resp = send_once(
                    method="POST",
                    url=origin + path,
                    headers={"Content-Type": "application/json", "User-Agent": "WebSET-ActiveTest"},
                    data=body,
                )
                text = str((resp or {}).get("body") or "")
                try:
                    data = json.loads(text)
                except Exception:
                    continue
                if not isinstance(data, dict):
                    continue
                blob = data.get("authentication") if isinstance(data.get("authentication"), dict) else data
                if not isinstance(blob, dict):
                    continue
                for key in ("token", "access_token", "accessToken", "jwt"):
                    if blob.get(key):
                        return str(blob.get(key))
    nonce = str(abs(hash(origin)) % 10 ** 10)
    email = "webset" + nonce + "@example.com"
    password = "WebsetPass1!"
    register_body = json.dumps({
        "email": email,
        "password": password,
        "username": "webset" + nonce,
        "user": email,
    })
    for path in (
        "/api/users",
        "/api/Users",
        "/api/user",
        "/api/register",
        "/register",
        "/signup",
        "/api/signup",
        "/api/accounts",
        "/api/Accounts",
    ):
        resp = send_once(
            method="POST",
            url=origin + path,
            headers={"Content-Type": "application/json", "User-Agent": "WebSET-ActiveTest"},
            data=register_body,
        )
        if int((resp or {}).get("status") or 0) not in (200, 201):
            continue
        text = str((resp or {}).get("body") or "")
        try:
            data = json.loads(text)
        except Exception:
            data = None
        if isinstance(data, dict):
            blob = data.get("authentication") if isinstance(data.get("authentication"), dict) else data
            if isinstance(blob, dict):
                for key in ("token", "access_token", "accessToken", "jwt"):
                    if blob.get(key):
                        return str(blob.get(key))
        for field in ("email", "username"):
            body = json.dumps({field: email, "password": password})
            for login_path in paths:
                resp = send_once(
                    method="POST",
                    url=origin + login_path,
                    headers={"Content-Type": "application/json", "User-Agent": "WebSET-ActiveTest"},
                    data=body,
                )
                text = str((resp or {}).get("body") or "")
                try:
                    data = json.loads(text)
                except Exception:
                    continue
                if not isinstance(data, dict):
                    continue
                blob = data.get("authentication") if isinstance(data.get("authentication"), dict) else data
                if not isinstance(blob, dict):
                    continue
                for key in ("token", "access_token", "accessToken", "jwt"):
                    if blob.get(key):
                        return str(blob.get(key))
    return ""


def _is_active_testable(finding: dict) -> bool:
    if not finding:
        return False
    if str(finding.get("scan_origin") or "") == "Platform":
        return False
    vtype = _finding_vtype(finding)
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
    param = str(finding.get("param") or finding.get("input") or "").strip()
    if not param:
        return False
    return True
def _existing_param_value(finding: dict, param: str) -> str:
    raw = str(
        finding.get("url")
        or finding.get("endpoint")
        or finding.get("location")
        or ""
    ).strip()
    if raw and "://" not in raw:
        raw = "http://" + raw
    try:
        q = parse_qs(urlparse(raw).query, keep_blank_values=True)
        if param and q.get(param) and str(q[param][0]).strip():
            return str(q[param][0])
    except Exception:
        pass
    for key in ("original_value", "sample_value", "param_value"):
        val = str(finding.get(key) or "").strip()
        if val:
            return val
    return ""
def _inject_value(finding: dict, marker: str) -> str:
    marker = marker or ""
    param = str(finding.get("param") or finding.get("input") or "")
    vtype = str(finding.get("vuln_type") or "").lower()
    if vtype in ("command_injection", "cmdi", "cmd") and marker[:1] in ";|&":
        base = _existing_param_value(finding, param) or "localhost"
        return base + marker
    return marker
def _form_body(param: str, value: str, companions: dict | None = None) -> str:
    fields = {}
    if isinstance(companions, dict):
        for key, raw in companions.items():
            name = str(key or "").strip()
            if name:
                fields[name] = "" if raw is None else str(raw)
    fields[param] = value
    fields = with_form_controls(fields, param)
    return urlencode(fields)
def _target_url_with_marker(
    finding: dict,
    marker: str,
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
    value = _inject_value(finding, marker)
    if "://" not in base:
        base = "http://" + base
    p = urlparse(base)
    if loc in ("header", "headers") or str(finding.get("vuln_type") or "").lower() == "idor":
        url = urlunparse((p.scheme, p.netloc, p.path or "/", "", p.query, ""))
        return method, url, None
    if method == "GET" or loc in ("query", "url", "get") and method not in ("POST", "PUT", "PATCH"):
        frag = p.fragment or ""
        if frag.startswith("/") or frag.startswith("!/"):
            frag_path, _, frag_query = frag.partition("?")
            q = dict(parse_qsl(frag_query, keep_blank_values=True))
            q[param] = value
            url = urlunparse((p.scheme, p.netloc, p.path or "/", "", "", f"{frag_path}?{urlencode(q)}"))
            return method, url, None
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        companions = finding.get("companions")
        if isinstance(companions, dict):
            for k, v in companions.items():
                kn = str(k or "").strip()
                if kn and kn not in q:
                    q[kn] = "" if v is None else str(v)
        q[param] = value
        q = with_form_controls(q, param)
        url = urlunparse((p.scheme, p.netloc, p.path or "/", "", urlencode(q), ""))
        return method, url, None
    if loc in ("json", "body_json"):
        url = urlunparse((p.scheme, p.netloc, p.path or "/", "", p.query, ""))
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
        return method, url, json.dumps(payload)
    url = urlunparse((p.scheme, p.netloc, p.path or "/", "", p.query, ""))
    return method, url, _form_body(param, value, finding.get("companions"))
def _parse_editor_request(
    request_text: str,
    fallback_url: str,
) -> tuple[str, str, dict, str | None] | None:
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
    frag = parsed.fragment or ""
    if "?" in frag:
        q = dict(q)
        for key, values in parse_qs(frag.split("?", 1)[1], keep_blank_values=True).items():
            q.setdefault(key, values)
    if param and param in q and q[param] and str(q[param][0]).strip():
        return str(q[param][0])
    if body:
        try:
            data = json.loads(body)
            if isinstance(data, dict) and param and param in data:
                return str(data.get(param) or fallback)
        except Exception:
            form = parse_qs(str(body), keep_blank_values=True)
            if param and form.get(param) and str(form[param][0]).strip():
                return str(form[param][0])
        text = str(body).strip()
        if text:
            return text[:200]
    for values in q.values():
        if values and str(values[0]).strip():
            return str(values[0])
    segs = [s for s in (parsed.path or "").split("/") if s]
    if segs:
        return segs[-1]
    return fallback
def _client_route(url: str) -> bool:
    frag = urlparse(url or "").fragment or ""
    return frag.startswith("/") or frag.startswith("!/")
def _render_client_route(url: str, marker: str) -> dict:
    """Hash/client routes are not in the HTTP body. Render them once."""
    try:
        from crawler.browser import fetch_with_selenium
    except Exception as exc:
        return {"ok": False, "status": 0, "body": "", "headers": {}, "error": str(exc)}
    rendered = fetch_with_selenium(
        url,
        timeout=16.0,
        wait_text=marker,
        skip_login=True,
    )
    if not rendered.get("ok"):
        return {
            "ok": False,
            "status": 0,
            "body": "",
            "headers": {},
            "error": rendered.get("error") or "browser render failed",
        }
    return {
        "ok": True,
        "status": 200,
        "body": rendered.get("body") or "",
        "headers": {},
        "error": None,
    }
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
        return "\n".join([
            "[Active Test] Failed",
            "",
            f"Error: {error}",
            "Requests sent: 1",
            "",
            "----- Request -----",
            request_text,
        ])
    yes_no = lambda b: "YES" if b else "NO"
    label = test.get("label") or test.get("id")
    param = finding.get("param") or finding.get("input") or "-"
    confirm = detection.get("confirmation") or "-"
    step = test.get("step") or "-"
    vtype = str(finding.get("vuln_type") or "").lower()
    body_hint = '"authentication"' if detection.get("auth_success") else ""
    meaning_title, meaning_detail = _plain_meaning(
        vtype, detection or {}, status, body_hint, marker=marker
    )
    evidence = str((detection or {}).get("evidence") or "").strip()
    lines = [
        "[Active Test] Exploit-chain step",
        "",
        f"Step            : {step}",
        f"Test            : {label}",
        f"Test id         : {test.get('id')}",
        f"Expect          : {test.get('expect') or '-'}",
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
        f"Auth success    : {yes_no(detection.get('auth_success'))}",
        f"Confirmation    : {confirm}",
        f"Conclusion      : {meaning_title}",
        f"Detail          : {meaning_detail}",
    ]
    if evidence:
        lines.append(f"Evidence        : {evidence}")
    lines.extend([
        "",
        "----- Request sent -----",
        request_text,
    ])
    return "\n".join(lines)
def _has_signal(det: dict, vtype: str = "") -> bool:
    det = det or {}
    flag = str(det.get("confirmation") or "").upper()
    if flag == "NOT CONFIRMED":
        return False
    if det.get("db_error_signal") or det.get("auth_success"):
        return True
    if flag == "CONFIRMED":
        return True
    vtype = str(vtype or "").lower()
    if vtype == "xss":
        return bool(det.get("found_in_body")) and not det.get("encoded")
    if vtype in ("path_traversal", "command_injection"):
        return False
    if flag == "LIKELY":
        return True
    return False
def _is_exploit_hit(test: dict, det: dict, vtype: str = "") -> bool:
    det = det or {}
    expect = str((test or {}).get("expect") or "").lower()
    flag = str(det.get("confirmation") or "").upper()
    if det.get("auth_success"):
        return True
    if expect in ("raw_script", "raw_breakout", "raw_js_uri", "raw_angle_brackets"):
        return bool(det.get("found_in_body")) and not det.get("encoded")
    if expect in ("foreign_file_or_error", "shell_error_or_canary", "command_output"):
        return flag == "CONFIRMED"
    if expect == "auth_success":
        return bool(det.get("auth_success"))
    return False
def plain_suite_analysis(finding: dict, runs: list[dict]) -> str:
    """Short suite paragraph for the GUI Summary box. No model, no extra requests."""
    finding = finding or {}
    runs = runs or []
    vtype = str(finding.get("vuln_type") or "").lower() or "this"
    param = finding.get("param") or finding.get("input") or "the targeted field"
    n = len(runs)
    signal_runs = []
    exploit_runs = []
    for item in runs:
        if item.get("error"):
            continue
        det = item.get("detection") or {}
        test = item.get("test") or {}
        if _has_signal(det, vtype):
            signal_runs.append(item)
        if _is_exploit_hit(test, det, vtype):
            exploit_runs.append(item)
    lines = [
        f"WebSET sent {n} controlled request(s) into parameter `{param}`.",
        f"{len(signal_runs)} of {n} checks produced a detection signal.",
    ]
    if not signal_runs:
        lines.append(
            f"No useful {vtype.upper()} proof came back. The field may not be a sink, "
            "the probe may be filtered, or the app answered without a detectable error or reflection."
        )
        lines.append("This is not evidence of a working exploit.")
        return "\n\n".join(lines)
    labels = []
    for item in signal_runs:
        test = item.get("test") or {}
        labels.append(str(test.get("label") or test.get("id") or "check"))
    lines.append("Signal on: " + "; ".join(labels) + ".")
    if vtype == "sqli":
        if exploit_runs and any(
            (item.get("detection") or {}).get("auth_success") for item in exploit_runs
        ):
            lines.append(
                "A login probe returned a session or user object without a valid password. "
                "That is exploit-class proof that the parameter reached authentication logic."
            )
        elif any((item.get("detection") or {}).get("db_error_signal") for item in signal_runs):
            lines.append(
                "The value reached the database layer (SQL / ORM error or a changed query shape). "
                "That confirms injection into the query. It is not a table dump and no extra rows "
                "were requested."
            )
        else:
            lines.append(
                "A server error followed the SQL probe without an explicit database error string. "
                "That is a weaker signal than a SQL / ORM error and is not exploit proof."
            )
    elif vtype == "xss":
        if exploit_runs:
            lines.append(
                "Attacker-controlled markup came back unencoded. A browser could treat that as "
                "part of the page. This suite does not execute script in a real user session."
            )
        else:
            lines.append(
                "The probe was visible in the response, but this suite did not get unencoded "
                "markup through. Treat it as reachability, not a finished XSS exploit."
            )
    elif vtype == "path_traversal":
        if exploit_runs:
            lines.append(
                "A path probe returned unexpected file content or a filesystem error. "
                "That is exploit-class proof that the parameter influences file location."
            )
        else:
            lines.append(
                "A path probe was reflected or produced a filesystem-style error, without returning "
                "a foreign file body. That is not exploit proof."
            )
    elif vtype == "command_injection":
        if exploit_runs:
            lines.append(
                "Command output or a shell error came back after a separator probe. "
                "That is exploit-class proof. No destructive command was sent."
            )
        else:
            lines.append(
                "The canary reached a command-adjacent sink, but this suite did not get "
                "command output back."
            )
    elif vtype == "idor":
        if exploit_runs:
            lines.append(
                "An authenticated (or unauthenticated) collection GET returned records "
                "for more than one user identity. That is object-level access failure."
            )
        else:
            lines.append(
                "The collection GET did not return multiple user identities. "
                "No IDOR dump was proven by this suite."
            )
    else:
        lines.append("A detector flag fired. Open the per-check notes for the exact signal.")
    if not exploit_runs:
        lines.append(
            "No exploit-class step matched. Use the per-check cards if you need to confirm impact."
        )
    return "\n\n".join(lines)
def _execute_one(finding: dict, test: dict, request_text: str = "") -> dict:
    finding = dict(finding or {})
    test = dict(test or {})
    default_marker = str(test.get("marker") or "TEST_MARKER_123")
    request_text = (request_text or "").strip() or build_request_from_finding(
        finding, default_marker
    )
    out = {
        "test": test,
        "request": request_text,
        "ok": False,
        "status": 0,
        "url": "",
        "marker": default_marker,
        "detection": {},
        "error": None,
        "text": "",
    }
    if not _is_active_testable(finding):
        out["error"] = "finding is not Active-Testable"
        out["text"] = (
            "[Error] Active Test is only for injection-style findings "
            "(xss / sqli / nosqli / path_traversal / command_injection / idor) with URL + param."
        )
        return out
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
        headers.setdefault("Connection", "close")
    else:
        method, abs_url, body = _target_url_with_marker(finding, default_marker)
        headers = {"User-Agent": "WebSET-ActiveTest", "Connection": "close"}
        loc = str(finding.get("param_location") or "query").lower()
        if loc in ("json", "body_json"):
            headers["Content-Type"] = "application/json"
        elif body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
    marker = _probe_from_sent(finding, abs_url, body, default_marker)
    out["marker"] = marker
    out["url"] = abs_url
    scope_url = abs_url or target_for_scope
    if allowed and not in_scope(scope_url, allowed):
        out["error"] = "out of scope"
        out["text"] = (
            "[Error] Target host is outside the current scan scope.\n"
            f"Request host: {host_of(scope_url)}\n"
            f"Scan host:    {host_of(allowed)}\n"
        )
        return out
    if _finding_vtype(finding) in ("nosqli", "idor") and "authorization" not in {k.lower() for k in headers}:
        want_auth = _finding_vtype(finding) == "nosqli" or str(test.get("auth") or "").lower() in (
            "1", "true", "yes",
        ) or str(test.get("expect") or "").lower() == "idor_dump"
        if want_auth:
            token = _login_bearer(finding)
            if token:
                headers["Authorization"] = f"Bearer {token}"
                headers.setdefault("Accept", "application/json")
                if "\n\n" in request_text and "Authorization:" not in request_text:
                    head, rest = request_text.split("\n\n", 1)
                    request_text = head + f"\nAuthorization: Bearer {token}\n\n" + rest
                    out["request"] = request_text
    if _client_route(abs_url):
        resp = _render_client_route(abs_url, marker)
    else:
        resp = send_once(method=method, url=abs_url, headers=headers, data=body)
    if not resp.get("ok"):
        out["error"] = resp.get("error") or "request failed"
        out["text"] = format_result(
            test=test,
            finding=finding,
            marker=marker,
            url=abs_url,
            status=0,
            detection={},
            request_text=request_text,
            error=out["error"],
        )
        return out
    vtype = _finding_vtype(finding)
    detection = analyse_for_vuln_type(
        vtype,
        marker,
        resp.get("body") or "",
        int(resp.get("status") or 0),
        context=str(finding.get("context") or ""),
        expect=str(test.get("expect") or ""),
    )
    detection["step"] = test.get("step")
    detection["expect"] = test.get("expect") or ""
    status = int(resp.get("status") or 0)
    out["ok"] = True
    out["status"] = status
    out["detection"] = detection
    out["text"] = format_result(
        test=test,
        finding=finding,
        marker=marker,
        url=abs_url,
        status=status,
        detection=detection,
        request_text=request_text,
    )
    return out
def format_suite_summary(finding: dict, runs: list[dict]) -> str:
    name = finding.get("vulnerability") or finding.get("name") or "This finding"
    vtype = _finding_vtype(finding) or str(finding.get("vuln_type") or "").lower() or "unknown"
    method = finding.get("method") or "GET"
    param = finding.get("param") or finding.get("input") or "—"
    url = (
        finding.get("url")
        or finding.get("endpoint")
        or finding.get("location")
        or "—"
    )
    summary = summarise_detections(
        vtype,
        [item.get("detection") or {} for item in runs],
    )
    confirmation = summary.get("confirmation") or "NOT CONFIRMED"
    verdict = plain_suite_analysis(finding, runs)
    conclusion = summary.get("conclusion") or confirmation
    n = len(runs)
    lines = [
        "ACTIVE TEST SUMMARY",
        "===================",
        "",
        f"RESULT          : {confirmation}",
        f"Conclusion      : {conclusion}",
        "",
        "What this is",
        "------------",
        f"WebSET ran the {vtype.upper()} exploit chain for this finding.",
        "Each step is one controlled request on the same parameter.",
        "Later steps prove exploitation; earlier steps only prove reachability.",
        "Alerts severity is not changed by this result.",
        "",
        "Target",
        "------",
        f"Finding     : {name}",
        f"URL         : {url}",
        f"Method      : {method}",
        f"Parameter   : {param}",
        f"Steps run   : {n}",
        "",
        "In plain language",
        "-----------------",
        verdict,
        "",
        "What RESULT means",
        "-----------------",
        "CONFIRMED      = an exploit step matched",
        "                 (SQLi: auth token / SQL error; XSS: raw markup in HTML).",
        "LIKELY         = a chain step fired, final exploit condition not met.",
        "NOT CONFIRMED  = no useful proof from this suite.",
        "",
        "Per-step notes",
        "--------------",
    ]
    for i, item in enumerate(runs, start=1):
        test = item.get("test") or {}
        label = test.get("label") or test.get("id") or f"Step {i}"
        det = item.get("detection") or {}
        status = item.get("status") or "—"
        if item.get("error"):
            lines.append(f"{i}. {label}")
            lines.append(f"   Could not complete: {item.get('error')}")
        else:
            found = "YES" if det.get("found_in_body") else "NO"
            encoded = "YES" if det.get("encoded") else "NO"
            auth = "YES" if det.get("auth_success") else "NO"
            confirm = det.get("confirmation") or "—"
            lines.append(f"{i}. {label}")
            lines.append(
                f"   HTTP {status} · in body: {found} · encoded: {encoded} "
                f"· auth: {auth} · {confirm}"
            )
            if det.get("conclusion"):
                lines.append(f"   {det.get('conclusion')}")
        hint = str(test.get("hint") or "").strip()
        if hint:
            lines.append(f"   Why this step: {hint}")
        lines.append("")
    lines.extend([
        "Detail from each response",
        "-------------------------",
    ])
    for i, item in enumerate(runs, start=1):
        test = item.get("test") or {}
        label = test.get("label") or f"Step {i}"
        lines.append(f"[{i}] {label}")
        lines.append(item.get("text") or "(no output)")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
def run_active_test(finding: dict, test: dict, request_text: str) -> str:
    return _execute_one(finding, test, request_text).get("text") or ""
def run_active_test_suite(finding: dict, tests: list[dict] | None = None) -> str:
    finding = dict(finding or {})
    if not _is_active_testable(finding):
        return (
            "[Error] Active Test is only for injection-style findings "
            "(xss / sqli / nosqli / path_traversal / command_injection / idor) with URL + param.\n"
            "Passive findings (headers, cookies, CSP) are verified by the scan itself."
        )
    vtype = _finding_vtype(finding)
    suite = list(tests or get_active_tests(vtype, finding) or [])
    if not suite:
        return "[Error] No recommended Active Tests for this vulnerability type."
    runs = []
    for test in suite:
        marker = str(test.get("marker") or "TEST_MARKER_123")
        request_text = build_request_from_finding(finding, marker)
        runs.append(_execute_one(finding, test, request_text))
    return format_suite_summary(finding, runs)
