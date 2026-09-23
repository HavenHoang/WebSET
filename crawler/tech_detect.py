"""
Get Stack detection API + page-level tech names (for form artefacts).
Return list[dict] with keys: name, category, version, description.
Never attach CWE/OWASP. Never emit vulnerability findings here.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse
from crawler.scope import normalise_url, is_http_url
from crawler.signatures import (
    HEADER_RULES,
    BODY_RULES,
    FILE_RULES,
    stack_item,
    extract_version,
)
from crawler.fetch import fetch_target
_VERSION_PATTERNS = {
    "Apache": re.compile(r"apache[/\s]+(\d+(?:\.\d+){1,3})", re.I),
    "Nginx": re.compile(r"nginx[/\s]+(\d+(?:\.\d+){1,3})", re.I),
    "PHP": re.compile(r"php[/\s]+(\d+(?:\.\d+){1,3})", re.I),
    "Express": re.compile(r"express[/\s-]+(\d+(?:\.\d+){1,3})", re.I),
    "Angular": re.compile(r"ng-version\s*=\s*['\"](\d+(?:\.\d+){1,3})", re.I),
    "jQuery": re.compile(r"jquery[.-](\d+(?:\.\d+){1,3})", re.I),
    "WordPress": re.compile(r"(?:wordpress|generator[^>]*(?:wordpress))\s*[/:]?\s*(\d+(?:\.\d+){1,3})", re.I),
    "Node.js": re.compile(r"node(?:\.js)?[/\s-]+(\d+(?:\.\d+){1,3})", re.I),
    "Socket.IO": re.compile(r"(?:socket\.io|engine\.io)[/\s-]+(\d+(?:\.\d+){1,3})", re.I),
    "Bootstrap": re.compile(r"bootstrap[.-](\d+(?:\.\d+){1,3})", re.I),
    "Tomcat": re.compile(r"tomcat[/\s-]+(\d+(?:\.\d+){1,3})", re.I),
}
def _version_of(name: str, *blobs: str) -> str:
    text = "\n".join(str(b or "") for b in blobs)
    try:
        found = extract_version(name, text)
        if found:
            return str(found)
    except Exception:
        pass
    pat = _VERSION_PATTERNS.get(name)
    if not pat:
        return ""
    match = pat.search(text)
    return match.group(1) if match else ""
def _looks_spa(body: str) -> bool:
    text = (body or "").lower()
    if len(text) >= 8000:
        return False
    return any(
        token in text
        for token in (
            "<app-root",
            "ng-version",
            'id="root"',
            "id='root'",
            "__next",
            "data-reactroot",
        )
    )
def _body_thin(body: str) -> bool:
    return len((body or "").strip()) < 120
def _cookie_blob(page: dict) -> str:
    parts = []
    for item in page.get("set_cookie") or page.get("cookies") or []:
        if isinstance(item, dict):
            parts.append(str(item.get("name") or ""))
            parts.append(str(item.get("raw") or item.get("value") or ""))
        else:
            parts.append(str(item))
    return " ".join(parts).lower()
def _origin(url: str) -> str:
    raw = url if "://" in (url or "") else "http://" + (url or "")
    p = urlparse(raw)
    if not p.netloc:
        return ""
    return f"{p.scheme or 'http'}://{p.netloc}"
def _stack_names(found: list) -> set:
    return {str(item.get("name") or "").lower() for item in (found or [])}
def _should_probe_wordpress(found: list, body_lc: str) -> bool:
    blob = body_lc or ""
    return any(
        path in blob or path.rstrip("/") in blob
        for path in (
            "/wp-login.php",
            "/wp-includes/js/wp-embed.min.js",
            "/xmlrpc.php",
            "/wp-json/",
            "/readme.html",
        )
    )
def _should_probe_node(found: list, body_lc: str) -> bool:
    blob = body_lc or ""
    return "socket.io" in blob or "engine.io" in blob
def _scan(headers_lc: dict, body_lc: str, host: str, neutral: bool, cookies_lc: str = "") -> list:
    found, seen = [], set()
    def add(name, cat, version, desc):
        k = name.lower()
        if k in seen:
            return
        seen.add(k)
        found.append(stack_item(name, cat, version or "", desc))
    header_blob = " ".join(f"{k}: {v}" for k, v in headers_lc.items())
    blob = "\n".join((header_blob, body_lc, cookies_lc))
    for name, cat, _v, rule in HEADER_RULES:
        try:
            if rule(headers_lc):
                add(name, cat, _version_of(name, header_blob, body_lc),
                    f"Detected from HTTP headers on {host}.")
        except Exception:
            pass
    for name, cat, _v, rule in BODY_RULES:
        try:
            if rule(body_lc):
                add(name, cat, _version_of(name, body_lc, header_blob),
                    f"Detected from response body markers on {host}.")
        except Exception:
            pass
    powered = headers_lc.get("x-powered-by", "")
    server = headers_lc.get("server", "")
    if "php" in powered or "phpsessid" in cookies_lc:
        add("PHP", "Language", _version_of("PHP", powered, header_blob),
            f"PHP indicated by headers or session cookie on {host}.")
    if "express" in powered or "express" in server or "connect.sid" in cookies_lc:
        add("Express", "Backend", _version_of("Express", powered, server, body_lc),
            f"Express indicated by headers/cookies on {host}.")
        add("Node.js", "Runtime", _version_of("Node.js", powered, server, body_lc),
            "Inferred from Express / session cookie.")
    if "nginx" in server:
        add("Nginx", "Web Server", _version_of("Nginx", server),
            f"Server header indicates Nginx on {host}.")
    if "apache" in server:
        add("Apache", "Web Server", _version_of("Apache", server),
            f"Server header indicates Apache on {host}.")
    if "tomcat" in server or "coyote" in server:
        add("Apache Tomcat", "Web Server", _version_of("Tomcat", server),
            f"Servlet container indicated by Server header on {host}.")
        add("Java", "Language", "", "Inferred from Tomcat / servlet container.")
    if "jsessionid" in cookies_lc:
        add("Java", "Language", "", f"JSESSIONID cookie on {host}.")
    if "laravel_session" in cookies_lc:
        add("Laravel", "Framework", "", f"Laravel session cookie on {host}.")
        add("PHP", "Language", _version_of("PHP", powered, header_blob),
            "Inferred from Laravel session cookie.")
    if "csrftoken" in cookies_lc and "django" in body_lc:
        add("Django", "Framework", "", f"Django CSRF cookie on {host}.")
        add("Python", "Language", "", "Inferred from Django.")
    if "<app-root" in body_lc or "ng-version" in body_lc or "angular" in body_lc:
        add("Angular", "Frontend", _version_of("Angular", body_lc),
            f"Angular markers in the response body on {host}.")
    if "react" in body_lc or "data-reactroot" in body_lc:
        add("React", "Frontend", "", f"React markers in the response body on {host}.")
    if "__next" in body_lc:
        add("Next.js", "Frontend", "", f"Next.js markers in the response body on {host}.")
    if "vue" in body_lc and ("data-v-" in body_lc or "vue.js" in body_lc):
        add("Vue.js", "Frontend", "", f"Vue markers in the response body on {host}.")
    if "jquery" in body_lc:
        add("jQuery", "Library", _version_of("jQuery", body_lc),
            f"jQuery assets referenced on {host}.")
    if "bootstrap" in body_lc:
        add("Bootstrap", "Library", _version_of("Bootstrap", body_lc),
            f"Bootstrap assets referenced on {host}.")
    if (
        "wp-content" in body_lc
        or "wp-includes" in body_lc
        or "wordpress" in body_lc
        or "wp-json" in body_lc
        or "/wp-login.php" in body_lc
    ):
        add("WordPress", "CMS", _version_of("WordPress", body_lc, header_blob),
            f"WordPress markers in the response body or links on {host}.")
    if "socket.io" in body_lc:
        add("Socket.IO", "Library", _version_of("Socket.IO", body_lc),
            f"Socket.IO client assets on {host}.")
    return found
def _lc(page):
    headers = {
        str(k).lower(): str(v).lower()
        for k, v in (page.get("headers") or {}).items()
    }
    body = (page.get("body") or "").lower()
    return headers, body, _cookie_blob(page)
def _merge_pages(*pages: dict):
    headers: dict[str, str] = {}
    bodies: list[str] = []
    cookies: list[str] = []
    url = ""
    for page in pages:
        if not page:
            continue
        url = page.get("url") or url
        for k, v in (page.get("headers") or {}).items():
            headers[str(k).lower()] = str(v).lower()
        bodies.append((page.get("body") or "").lower())
        cookies.append(_cookie_blob(page))
    return headers, "\n".join(bodies), url, " ".join(cookies)
def _probe_node_stack(url: str, found: list, body_lc: str = "") -> list:
    blob = body_lc or ""
    if "socket.io" not in blob and "engine.io" not in blob:
        return found
    names = {str(item.get("name") or "").lower() for item in found}
    origin = _origin(url)
    if not origin:
        return found
    extra = fetch_target(origin + "/socket.io/socket.io.js")
    body = (extra.get("body") or "").lower()
    headers = {
        str(k).lower(): str(v).lower()
        for k, v in (extra.get("headers") or {}).items()
    }
    if extra.get("ok") and extra.get("status") == 200 and ("socket" in body or "engine.io" in body):
        if "socket.io" not in names:
            found.append(stack_item(
                "Socket.IO",
                "Library",
                _version_of("Socket.IO", body),
                f"Socket.IO script at {origin}/socket.io/socket.io.js.",
            ))
            names.add("socket.io")
    powered = headers.get("x-powered-by", "")
    if "express" in powered and "express" not in names:
        found.append(stack_item(
            "Express",
            "Backend",
            _version_of("Express", powered),
            f"X-Powered-By on {origin}/socket.io/socket.io.js.",
        ))
        names.add("express")
    if any(token in powered for token in ("node.js", "nodejs", "node/")) and "node.js" not in names:
        found.append(stack_item(
            "Node.js",
            "Runtime",
            _version_of("Node.js", powered),
            f"X-Powered-By on {origin}/socket.io/socket.io.js.",
        ))
    return found
def _probe_php_wordpress(url: str, found: list, body_lc: str = "") -> list:
    """Confirm a WordPress path only when that path is already referenced."""
    names = {str(item.get("name") or "").lower() for item in found}
    origin = _origin(url)
    if not origin:
        return found
    page_blob = body_lc or ""
    probes = (
        "/wp-login.php",
        "/wp-includes/js/wp-embed.min.js",
        "/xmlrpc.php",
        "/wp-json/",
        "/readme.html",
    )
    for path in probes:
        if path not in page_blob and path.rstrip("/") not in page_blob:
            continue
        extra = fetch_target(origin + path)
        if not extra.get("ok"):
            continue
        status = int(extra.get("status") or 0)
        body = (extra.get("body") or "")
        headers = {
            str(k).lower(): str(v).lower()
            for k, v in (extra.get("headers") or {}).items()
        }
        blob = "\n".join((body.lower(), " ".join(headers.values())))
        powered = headers.get("x-powered-by", "")
        if "php" in powered and "php" not in names:
            found.append(stack_item(
                "PHP",
                "Language",
                _version_of("PHP", powered),
                f"X-Powered-By on {origin}{path}.",
            ))
            names.add("php")
        if status in (200, 401, 403, 405):
            hit = any(
                tok in blob
                for tok in (
                    "wordpress", "wp-login", "wp-includes", "xmlrpc",
                    "wp-json", "wp-embed",
                )
            )
            if path.endswith("readme.html") and "wordpress" not in blob:
                hit = False
            if path.endswith("xmlrpc.php"):
                hit = hit and (
                    "xml-rpc" in blob or "methodresponse" in blob or "faultcode" in blob
                )
            if hit and "wordpress" not in names:
                ver = _version_of("WordPress", body)
                found.append(stack_item(
                    "WordPress",
                    "CMS",
                    ver,
                    f"WordPress surface at {origin}{path}.",
                ))
                names.add("wordpress")
    return found
def detect_tech_stack(url: str) -> list:
    url = normalise_url(url)
    if not is_http_url(url):
        return []
    page = fetch_target(url)
    body = page.get("body") or ""
    if page.get("ok") and (_body_thin(body) or _looks_spa(body)):
        try:
            browser_page = fetch_target(url, use_browser=True)
        except TypeError:
            browser_page = {}
        except Exception:
            browser_page = {}
        if browser_page.get("ok"):
            headers, body_lc, host, cookies = _merge_pages(page, browser_page)
            found = _scan(headers, body_lc, host or url, True, cookies)
            if _should_probe_wordpress(found, body_lc):
                found = _probe_php_wordpress(url, found, body_lc)
            if _should_probe_node(found, body_lc):
                found = _probe_node_stack(url, found, body_lc)
            return found
    headers, body_lc, cookies = _lc(page)
    found = _scan(headers, body_lc, url, bool(page.get("ok")), cookies)
    if _should_probe_wordpress(found, body_lc):
        found = _probe_php_wordpress(url, found, body_lc)
    if _should_probe_node(found, body_lc):
        found = _probe_node_stack(url, found, body_lc)
    return found
def detect_tech_from_page(page: dict) -> list:
    headers, body, cookies = _lc(page)
    return _scan(headers, body, page.get("url", ""), False, cookies)
def detect_tech_names(page: dict) -> list:
    return [t["name"] for t in detect_tech_from_page(page)]
def detect_tech_stack_from_path(project_root: str) -> list:
    from crawler.zip_reader import list_zip_paths
    paths = list_zip_paths(project_root)
    if not paths:
        return []
    found, seen = [], set()
    low = [p.replace("\\", "/").lower() for p in paths]
    def add(name, cat, ver, desc):
        k = name.lower()
        if k in seen:
            return
        seen.add(k)
        found.append(stack_item(name, cat, ver, desc))
    for name, cat, ver, rule in FILE_RULES:
        try:
            if rule(low):
                add(name, cat, ver, "Detected from project file layout / manifests.")
        except Exception:
            pass
    return found
