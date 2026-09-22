"""Primary Start Scan (URL) fetch. Returns one plain artefact dict."""
from __future__ import annotations
import re
import time
from urllib.parse import urljoin, urlparse, urlunparse
from crawler.scope import normalise_url, is_http_url, in_scope, same_host
from crawler.headers_cookies import headers_to_dict, set_cookie_list
DEFAULT_TIMEOUT = 15
DEFAULT_HEADERS = {
    "User-Agent": "WebSET-Scanner/1.0 (+local research)",
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Connection": "close",
}
_LAB_LOGINS = (
    ("admin", "password"),
    ("admin", ""),
    ("admin", "admin"),
    ("bee", "bug"),
)
_NAME_RE = re.compile(r"""name\s*=\s*(?:['"]([^'"]+)['"]|([^\s>]+))""", re.I)
_VALUE_RE = re.compile(r"""value\s*=\s*(?:['"]([^'"]*)['"]|([^\s>]+))""", re.I)
_ACTION_RE = re.compile(
    r"""<form[^>]*action\s*=\s*(?:['"]([^'"]*)['"]|([^\s>]+))""",
    re.I,
)
_TOKEN_RE = re.compile(
    r"""name\s*=\s*['"](?:user_token|csrf|_token|csrf_token)['"][^>]*value\s*=\s*['"]([^'"]+)['"]"""
    r"""|value\s*=\s*['"]([^'"]+)['"][^>]*name\s*=\s*['"](?:user_token|csrf|_token|csrf_token)['"]""",
    re.I,
)
_SECURITY_FIELD_RE = re.compile(
    r"""<(?:select|input)[^>]*name\s*=\s*['"]security['"][^>]*>""",
    re.I,
)
_HREF_RE = re.compile(r"""href\s*=\s*['"]([^'"]+)['"]""", re.I)
_HASH_ROUTE_RE = re.compile(
    r"""#(/[A-Za-z0-9][A-Za-z0-9_./\-]*(?:\?[A-Za-z0-9_\-.=&%]*)?)""",
)
_STATIC_EXT_RE = re.compile(
    r"\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp)(?:\?|$)",
    re.I,
)
def _prefer_ipv4(url: str) -> str:
    parsed = urlparse(url or "")
    host = (parsed.hostname or "").lower()
    if host != "localhost":
        return url
    netloc = "127.0.0.1"
    if parsed.port:
        netloc = f"127.0.0.1:{parsed.port}"
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )
def _hash_to_http(fragment: str, page_url: str) -> str:
    frag = str(fragment or "").strip()
    if frag.startswith("#"):
        frag = frag[1:]
    if not frag.startswith("/"):
        return ""
    if _STATIC_EXT_RE.search(frag):
        return ""
    parsed = urlparse(page_url or "")
    if not parsed.scheme or not parsed.netloc:
        return ""
    if "?" in frag:
        path, query = frag.split("?", 1)
    else:
        path, query = frag, ""
    return f"{parsed.scheme}://{parsed.netloc}{path or '/'}" + (f"?{query}" if query else "")
def discover_same_host_links(body: str, page_url: str, limit: int = 80) -> list[str]:
    """In-scope HTML / listing / hash-route links from one page."""
    out: list[str] = []
    seen = set()

    def _keep(abs_u: str) -> None:
        if not abs_u or abs_u in seen:
            return
        if not is_http_url(abs_u):
            return
        if not same_host(abs_u, page_url):
            return
        path = urlparse(abs_u).path or "/"
        if _STATIC_EXT_RE.search(path):
            return
        seen.add(abs_u)
        out.append(abs_u)

    for raw in _HREF_RE.findall(body or ""):
        text = str(raw or "").strip()
        if not text or text.startswith(("mailto:", "javascript:", "data:")):
            continue
        if text.startswith("#"):
            _keep(_hash_to_http(text, page_url))
            continue
        _keep(urljoin(page_url, text.split("#")[0]))
        if len(out) >= limit:
            return out
    for match in _HASH_ROUTE_RE.findall(body or ""):
        _keep(_hash_to_http(match if str(match).startswith("#") else "#" + str(match), page_url))
        if len(out) >= limit:
            break
    return out
def _cookie_name_value(item) -> tuple[str, str]:
    if not isinstance(item, dict):
        return "", ""
    name = str(item.get("name") or "").strip()
    value = str(item.get("value") or "")
    if not name:
        raw = str(item.get("raw") or "")
        if "=" in raw:
            name, value = raw.split("=", 1)
            name = name.strip()
    return name, value
def _shared_cookie_list() -> list:
    out = []
    try:
        from core.shared_state import SharedState
        jar = getattr(SharedState, "scan_cookies", None) or {}
        if hasattr(jar, "items"):
            for name, value in jar.items():
                if name:
                    out.append({"name": str(name), "value": str(value), "path": "/"})
    except Exception:
        pass
    return out
def _header_cookie_items(header_value: str) -> list:
    out = []
    for part in str(header_value or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if name:
            out.append({"name": name, "value": value.strip(), "path": "/", "raw": f"{name}={value.strip()}"})
    return out
def _publish_scan_cookies(artefact: dict | None) -> None:
    """Hand session cookies to GUI/Active Test. Merge, do not drop existing."""
    if not artefact or not artefact.get("ok"):
        return
    raw = list(artefact.get("cookies") or []) + list(artefact.get("set_cookie") or [])
    jar = {}
    try:
        from core.shared_state import SharedState
        existing = getattr(SharedState, "scan_cookies", None) or {}
        if hasattr(existing, "items"):
            jar.update({str(k): str(v) for k, v in existing.items() if k})
    except Exception:
        pass
    for item in raw:
        name, value = _cookie_name_value(item)
        if name:
            jar[name] = value
    if not jar:
        return
    try:
        from core.shared_state import SharedState
        SharedState.set_scan_cookies(jar)
    except Exception:
        pass
def _apply_session_cookies(sess, cookies: list | None) -> None:
    if not cookies:
        return
    for item in cookies:
        name, value = _cookie_name_value(item)
        if not name:
            continue
        path = "/"
        domain = None
        if isinstance(item, dict):
            path = str(item.get("path") or "/") or "/"
            domain = str(item.get("domain") or "").strip() or None
        try:
            if domain:
                sess.cookies.set(name, value, path=path, domain=domain)
            else:
                sess.cookies.set(name, value, path=path)
        except Exception:
            try:
                sess.cookies.set(name, value)
            except Exception:
                continue
def _sync_cookie_header(sess) -> None:
    """Force Cookie header. http.cookiejar often drops localhost cookies."""
    parts = []
    seen = set()
    try:
        for cookie in sess.cookies:
            key = str(cookie.name).lower()
            if not key or key in seen:
                continue
            seen.add(key)
            parts.append(f"{cookie.name}={cookie.value}")
    except Exception:
        pass
    try:
        existing = str(sess.headers.get("Cookie") or "")
        for item in _header_cookie_items(existing):
            key = str(item.get("name") or "").lower()
            if key and key not in seen:
                seen.add(key)
                parts.append(f"{item['name']}={item['value']}")
    except Exception:
        pass
    if parts:
        sess.headers["Cookie"] = "; ".join(parts)
def _cookies_from_session(sess, extra: list | None = None) -> list:
    collected = []
    seen = set()
    try:
        for cookie in sess.cookies:
            rec = {
                "name": cookie.name,
                "value": cookie.value,
                "path": cookie.path or "/",
                "raw": f"{cookie.name}={cookie.value}",
            }
            key = cookie.name.lower()
            if key in seen:
                continue
            seen.add(key)
            collected.append(rec)
    except Exception:
        pass
    try:
        for item in _header_cookie_items(str(sess.headers.get("Cookie") or "")):
            name, _value = _cookie_name_value(item)
            key = name.lower()
            if name and key not in seen:
                seen.add(key)
                collected.append(item)
    except Exception:
        pass
    for item in extra or []:
        name, _value = _cookie_name_value(item)
        if name and name.lower() not in seen:
            seen.add(name.lower())
            collected.append(item)
    return collected
def _attr(match) -> str:
    if not match:
        return ""
    return (match.group(1) or match.group(2) or "").strip()
def _login_path(url: str) -> bool:
    path = urlparse(url or "").path.lower().rstrip("/")
    last = path.rsplit("/", 1)[-1]
    return last in ("login", "login.php", "signin", "signin.php")
def _has_password_field(body: str) -> bool:
    low = (body or "").lower()
    return (
        'name="password"' in low
        or "name='password'" in low
        or 'type="password"' in low
        or "type='password'" in low
    )
def _looks_login_page(body: str, url: str) -> bool:
    low = (body or "").lower()
    if "logout" in low:
        return False
    if not _has_password_field(body):
        return False
    if _login_path(url):
        return True
    return "login" in low or "sign in" in low or "username" in low
def _logged_in(body: str, url: str = "") -> bool:
    low = (body or "").lower()
    if "logout" in low:
        return True
    if not url:
        return False
    if _login_path(url):
        return False
    if _looks_login_page(body, url):
        return False
    return True
def _form_action(body: str, page_url: str) -> str:
    action = _attr(_ACTION_RE.search(body or ""))
    return urljoin(page_url, action or "")
def _field_names(body: str) -> tuple[str, str, str]:
    user = "username"
    password = "password"
    submit = "Login"
    for match in re.finditer(r"<input[^>]*>", body or "", re.I):
        tag = match.group(0)
        name = _attr(_NAME_RE.search(tag))
        if not name:
            continue
        low_tag = tag.lower()
        low_name = name.lower()
        if "password" in low_tag or low_name in ("password", "pass", "pwd"):
            password = name
        elif "submit" in low_tag or low_name == "submit":
            submit = name
        elif low_name in ("username", "user", "email"):
            user = name
        elif low_name == "login" and "submit" not in low_tag:
            user = name
    return user, password, submit
def _form_fields(body: str) -> dict:
    fields = {}
    for match in re.finditer(r"<input[^>]*>", body or "", re.I):
        tag = match.group(0)
        name = _attr(_NAME_RE.search(tag))
        if not name:
            continue
        fields[name] = _attr(_VALUE_RE.search(tag))
    token = _TOKEN_RE.search(body or "")
    if token:
        token_val = token.group(1) or token.group(2)
        if "user_token" in (body or ""):
            fields["user_token"] = token_val
        elif "csrf_token" in (body or "").lower():
            fields["csrf_token"] = token_val
        else:
            fields["_token"] = token_val
    return fields
def _usable_login_html(status: int, body: str) -> bool:
    if int(status or 0) >= 400:
        return False
    low = (body or "").lower()
    return "<form" in low or "password" in low or "username" in low
def _artefact_from_response(resp, sess, t0: float, extra_cookies=None) -> dict:
    collected = _cookies_from_session(sess, extra_cookies or set_cookie_list(resp.headers))
    body = resp.text
    page_url = str(resp.url)
    return {
        "ok": True,
        "url": page_url,
        "status": int(resp.status_code),
        "redirect_chain": [
            {"status": int(r.status_code), "url": str(r.url)}
            for r in resp.history
        ],
        "headers": headers_to_dict(resp.headers),
        "set_cookie": collected,
        "cookies": collected,
        "body": body,
        "links": discover_same_host_links(body, page_url),
        "elapsed_ms": int((time.time() - t0) * 1000),
        "error": None,
    }
def _home_urls(page_url: str) -> list[str]:
    parsed = urlparse(page_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return [
        origin + "/",
        origin + "/index.php",
        origin + "/index.html",
        origin + "/home",
        origin + "/home.php",
        origin + "/about.php",
    ]
def _login_urls(page_url: str) -> list[str]:
    parsed = urlparse(page_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    out = []
    if _login_path(page_url):
        out.append(page_url)
    for extra in ("/login.php", "/login", "/signin"):
        out.append(origin + extra)
    seen = []
    for item in out:
        if item not in seen:
            seen.append(item)
    return seen
def _security_form_urls(page_url: str) -> list[str]:
    parsed = urlparse(page_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return [
        origin + "/security.php",
        origin + "/security",
        origin + "/settings",
        origin + "/settings.php",
        origin + "/config",
        origin + "/options",
    ]
def _soften_security(sess, page_url: str, timeout: float) -> None:
    """If the app exposes a security-level field, prefer the weakest option."""
    try:
        sess.cookies.set("security", "low", path="/")
        _sync_cookie_header(sess)
    except Exception:
        pass
    for target in _security_form_urls(page_url):
        try:
            page = sess.get(target, timeout=timeout, allow_redirects=True)
        except Exception:
            continue
        html = page.text or ""
        if not _SECURITY_FIELD_RE.search(html):
            continue
        data = _form_fields(html)
        data["security"] = "low"
        submitted = False
        for key in list(data):
            if "submit" in key.lower():
                data[key] = data.get(key) or "Submit"
                submitted = True
        if not submitted:
            data["seclev_submit"] = "Submit"
        try:
            sess.post(
                _form_action(html, str(page.url)) or target,
                data=data,
                timeout=timeout,
                allow_redirects=True,
                headers={"Referer": str(page.url)},
            )
            sess.cookies.set("security", "low", path="/")
            _sync_cookie_header(sess)
        except Exception:
            pass
        break
def _try_form_login(sess, page_url: str, body: str, timeout: float):
    candidates = _login_urls(page_url)
    post_to = _form_action(body, page_url) or page_url
    if post_to and post_to not in candidates:
        candidates.insert(0, post_to)
    for user, password in _LAB_LOGINS:
        for target in candidates:
            try:
                fresh = sess.get(target, timeout=timeout, allow_redirects=True)
            except Exception:
                continue
            if fresh is None or not _usable_login_html(fresh.status_code, fresh.text):
                continue
            html = fresh.text
            source = str(fresh.url)
            if not _looks_login_page(html, source) and not _has_password_field(html):
                continue
            user_f, pass_f, submit_f = _field_names(html)
            data = _form_fields(html)
            data[user_f] = user
            data[pass_f] = password
            data[submit_f] = "Login"
            try:
                resp = sess.post(
                    _form_action(html, source) or target,
                    data=data,
                    timeout=timeout,
                    allow_redirects=True,
                    headers={"Referer": source},
                )
            except Exception:
                continue
            if resp is None:
                continue
            if _logged_in(resp.text, str(resp.url)):
                try:
                    sess.cookies.set("security", "low", path="/")
                    _sync_cookie_header(sess)
                except Exception:
                    pass
                _soften_security(sess, str(resp.url) or page_url, timeout)
                return resp
    return None
def _http_get(url: str, timeout: float, cookies: list | None = None) -> dict:
    import requests
    t0 = time.time()
    sess = requests.Session()
    sess.headers.update(DEFAULT_HEADERS)
    merged = list(cookies or []) + _shared_cookie_list()
    _apply_session_cookies(sess, merged)
    _sync_cookie_header(sess)
    resp = sess.get(url, timeout=timeout, allow_redirects=True)
    extra = set_cookie_list(resp.headers)
    if merged:
        extra = list(merged) + extra
    if not _logged_in(resp.text, str(resp.url)):
        logged = _try_form_login(sess, str(resp.url), resp.text, timeout)
        if logged is not None:
            _soften_security(sess, str(logged.url) or url, timeout)
            chosen = None
            try:
                again = sess.get(url, timeout=timeout, allow_redirects=True)
                _sync_cookie_header(sess)
                if again is not None and _logged_in(again.text, str(again.url)):
                    chosen = again
            except Exception:
                chosen = None
            if chosen is None and _logged_in(logged.text, str(logged.url)):
                chosen = logged
            if chosen is None:
                for home_url in _home_urls(str(logged.url) or url):
                    try:
                        home = sess.get(home_url, timeout=timeout, allow_redirects=True)
                        _sync_cookie_header(sess)
                    except Exception:
                        continue
                    if home is not None and _logged_in(home.text, str(home.url)):
                        chosen = home
                        break
            if chosen is not None:
                resp = chosen
    extra = list(extra or []) + _header_cookie_items(str(sess.headers.get("Cookie") or ""))
    return _artefact_from_response(resp, sess, t0, extra)
def fetch_target(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    use_browser: bool = False,
    root: str | None = None,
    cookies: list | None = None,
) -> dict:
    url = _prefer_ipv4(normalise_url(url))
    scope_root = _prefer_ipv4(normalise_url(root or url))
    if not is_http_url(url):
        return _fail(url, "invalid_url")
    if scope_root and not in_scope(url, scope_root):
        return _fail(url, "out_of_scope")
    http_art = None
    try:
        http_art = _http_get(url, timeout, cookies=cookies)
    except Exception as exc:
        if not use_browser:
            return _fail(url, _classify_error(exc))
    if http_art and http_art.get("ok") and http_art.get("url"):
        if not same_host(http_art["url"], scope_root or url):
            return _fail(url, "out_of_scope")
    if use_browser:
        try:
            from crawler.browser import fetch_with_selenium
            browser_art = fetch_with_selenium(
                url,
                timeout=timeout,
                cookies=cookies or (http_art.get("set_cookie") if http_art else None),
            )
        except Exception as exc:
            return http_art or _fail(url, f"browser: {exc}")
        if not browser_art.get("ok"):
            return http_art or browser_art
        if browser_art.get("url") and not same_host(browser_art["url"], scope_root or url):
            return http_art or _fail(url, "out_of_scope")
        if http_art and http_art.get("ok"):
            headers = dict(http_art.get("headers") or {})
            headers.update(browser_art.get("headers") or {})
            browser_art["headers"] = headers
            if not browser_art.get("set_cookie"):
                browser_art["set_cookie"] = http_art.get("set_cookie") or []
            if http_art.get("redirect_chain") and not browser_art.get("redirect_chain"):
                browser_art["redirect_chain"] = http_art["redirect_chain"]
        browser_art["cookies"] = (
            browser_art.get("cookies")
            or browser_art.get("set_cookie")
            or []
        )
        browser_art["links"] = discover_same_host_links(
            browser_art.get("body") or "",
            str(browser_art.get("url") or url),
        )
        _publish_scan_cookies(browser_art)
        return browser_art
    if http_art:
        http_art["cookies"] = http_art.get("cookies") or http_art.get("set_cookie") or []
        _publish_scan_cookies(http_art)
    return http_art or _fail(url, "connection")
def _classify_error(exc) -> str:
    n, t = type(exc).__name__.lower(), str(exc).lower()
    if "timeout" in n or "timeout" in t:
        return "timeout"
    if "ssl" in n or "ssl" in t or "certificate" in t:
        return "ssl"
    if "getaddrinfo" in t or "name or service" in t or "dns" in t:
        return "dns"
    if "refused" in t or "connection" in n:
        return "connection"
    return str(exc)
def _fail(url: str, error: str) -> dict:
    return {
        "ok": False,
        "url": url or "",
        "status": 0,
        "redirect_chain": [],
        "headers": {},
        "set_cookie": [],
        "cookies": [],
        "body": "",
        "links": [],
        "elapsed_ms": 0,
        "error": error,
    }
