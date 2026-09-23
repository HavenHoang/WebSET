from __future__ import annotations
import re
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse
from crawler.scope import is_http_url, same_host
_HREF_RE = re.compile(
    r"""(?:href|src|action|formaction)\s*=\s*['"]([^'"]+)['"]""",
    re.I,
)
_API_PATH_RE = re.compile(
    r"""['"`]((?:https?:)?//[^'"`\s]+|/(?:api|rest|v\d+|graphql|search|find|query)[a-zA-Z0-9_./\-?]*)['"`]""",
    re.I,
)
_AUTH_PATH_RE = re.compile(
    r"""['"`]((?:https?:)?//[^'"`\s]+|/(?:api|rest|v\d+|auth|user|users|account)?/?[A-Za-z0-9_./-]*(?:login|signin|authenticate|session)[A-Za-z0-9_./-]*)['"`]""",
    re.I,
)
_SEARCH_PATH_RE = re.compile(r"/(?:search|find|query|products?/search)\b", re.I)
# Paths written in minified JS, quoted or concatenated — must appear in artefact text.
_LOOSE_API_PATH_RE = re.compile(
    r"(/(?:api|rest|v\d+)[A-Za-z0-9_./\-]*(?:search|find|query|login)[A-Za-z0-9_./\-]*)",
    re.I,
)
_AUTH_PATH_HINT = re.compile(r"(?:login|signin|authenticate|session)\b", re.I)
_INPUT_NAME_RE = re.compile(
    r"""<(?:input|select|textarea)\b[^>]*\bname\s*=\s*['"]([^'"]+)['"]""",
    re.I,
)
_QUOTED_URL_RE = re.compile(
    r"""['"`]((?:https?:)?//[^'"`\s]+|/[^'"`\s]+)['"`]""",
    re.I,
)
_HASH_ROUTE_RE = re.compile(
    r"""#(/[A-Za-z0-9][A-Za-z0-9_./\-]*(?:\?[A-Za-z0-9_\-.=&%]*)?)""",
)
_QUOTED_HASH_RE = re.compile(
    r"""['"`](#/[A-Za-z0-9][A-Za-z0-9_./\-]*(?:\?[A-Za-z0-9_\-.=&%]*)?)['"`]""",
)
_JS_ENDPOINT_RE = re.compile(
    r"""(?P<path>/(?:api|rest|graphql|v\d+)(?:/[A-Za-z0-9_.\-]+){1,10})"""
    r"""(?:\?(?P<name>[A-Za-z_][A-Za-z0-9_]{0,40})(?:=|&|['"`]|$))?""",
)
_JS_ROUTER_PATH_RE = re.compile(
    r"""\bpath\s*:\s*(['"`])([A-Za-z0-9][^'"`]{0,80})\1"""
)
_JS_HASH_MODE_RE = re.compile(
    r"useHash\s*:\s*(?:!0|true)|HashLocationStrategy",
    re.I,
)
_JS_HASH_LITERAL_RE = re.compile(r"""#/([A-Za-z0-9][A-Za-z0-9_\-./]{0,80})""")
_SINKISH_RE = re.compile(r"search|find|query|result", re.I)
_STATIC_EXT_RE = re.compile(
    r"\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp)(?:\?|$)",
    re.I,
)
def _canon_host(host: str) -> str:
    name = (host or "").lower()
    if name == "localhost":
        return "127.0.0.1"
    return name
def _same_site(a: str, b: str) -> bool:
    try:
        if same_host(a, b):
            return True
    except Exception:
        pass
    pa, pb = urlparse(a or ""), urlparse(b or "")
    ha, hb = _canon_host(pa.hostname or ""), _canon_host(pb.hostname or "")
    if not ha or ha != hb:
        return False
    return (pa.port or None) == (pb.port or None)
def _origin(url: str) -> str:
    raw = url if "://" in (url or "") else "http://" + (url or "")
    p = urlparse(raw)
    host = _canon_host(p.hostname or "")
    if not host:
        return ""
    netloc = f"{host}:{p.port}" if p.port else host
    return f"{p.scheme or 'http'}://{netloc}"
def _clean_url(url: str) -> str:
    p = urlparse(url)
    path = p.path or "/"
    return urlunparse((p.scheme, p.netloc, path, "", p.query, ""))
def _abs_url(raw: str, base: str) -> str:
    text = str(raw or "").strip()
    if not text or text.startswith(("mailto:", "javascript:", "data:")):
        return ""
    if text.startswith("#"):
        return _hash_to_http(text, base)
    if text.startswith("//"):
        scheme = urlparse(base).scheme or "http"
        text = f"{scheme}:{text}"
    return urljoin(base, text)
def _hash_to_http(fragment: str, base: str) -> str:
    """Turn #/path?a=b into origin/path?a=b so probes can use a real request URL."""
    frag = str(fragment or "").strip()
    if frag.startswith("#"):
        frag = frag[1:]
    if not frag.startswith("/"):
        return ""
    if _STATIC_EXT_RE.search(frag):
        return ""
    origin = _origin(base)
    if not origin:
        return ""
    if "?" in frag:
        path, query = frag.split("?", 1)
    else:
        path, query = frag, ""
    path = path or "/"
    return f"{origin}{path}" + (f"?{query}" if query else "")
def _ok_param_name(name: str) -> bool:
    n = str(name or "").strip()
    if not n:
        return False
    low = n.lower()
    if ";" in n or low.startswith("amp;") or n.startswith("&") or n.startswith("#"):
        return False
    if any(ch.isspace() for ch in n):
        return False
    return True


def _add_target(out: list, seen: set, url: str, method: str, name: str, location: str, value: str = ""):
    if not url or not _ok_param_name(name):
        return
    method = (method or "GET").upper()
    location = (location or "query").lower()
    key = (method, urlparse(url).path or "/", name.lower(), location)
    if key in seen:
        return
    seen.add(key)
    out.append({
        "url": _clean_url(url),
        "method": method,
        "parameters": [{
            "name": name,
            "value": value,
            "type": "text",
            "location": location,
        }],
    })
def _add_page(out: list, seen: set, url: str):
    if not url:
        return
    cleaned = _clean_url(url).split("?")[0]
    key = ("PAGE", urlparse(cleaned).path or "/")
    if key in seen:
        return
    seen.add(key)
    out.append({
        "url": cleaned,
        "method": "GET",
        "parameters": [],
    })
def _targets_from_url(url: str, root: str, out: list, seen: set):
    if not url or not is_http_url(url) or not _same_site(url, root):
        return
    p = urlparse(url)
    base = urlunparse((p.scheme, p.netloc, p.path or "/", "", "", ""))
    path = p.path or "/"
    if _STATIC_EXT_RE.search(path):
        return
    _add_page(out, seen, base)
    names = list(parse_qsl(p.query, keep_blank_values=True))
    if names:
        for name, value in names:
            if name:
                _add_target(out, seen, base, "GET", name, "query", value)
    if _SEARCH_PATH_RE.search(path):
        _add_target(out, seen, base, "GET", "q", "query")
    if _AUTH_PATH_HINT.search(path):
        for field in ("email", "username", "user", "login"):
            _add_target(out, seen, base, "POST", field, "json")
def _targets_from_hash_text(text: str, page_url: str, root: str, out: list, seen: set):
    blobs = [text or ""]
    for rx in (_HASH_ROUTE_RE, _QUOTED_HASH_RE):
        for match in rx.findall(text or ""):
            abs_url = _hash_to_http(match if str(match).startswith("#") else "#" + str(match), page_url)
            _targets_from_url(abs_url, root, out, seen)
    p = urlparse(page_url or "")
    if p.fragment:
        abs_url = _hash_to_http("#" + p.fragment, page_url)
        _targets_from_url(abs_url, root, out, seen)
def discover_request_targets(page: dict, base_url: str = "") -> list:
    """
    Same-host request targets for Start Scan probes.
    Does not submit forms or send payloads.
    """
    if isinstance(page, str):
        page = {"body": page, "url": base_url or ""}
    page = page or {}
    root = base_url or page.get("url") or ""
    if not root:
        return []
    if "://" not in root:
        root = "http://" + root
    out: list = []
    seen: set = set()
    body = page.get("body") or ""
    page_url = page.get("url") or root
    page_base = _clean_url(page_url)
    _targets_from_url(page_url, root, out, seen)
    _targets_from_url(root, root, out, seen)
    _targets_from_hash_text(body, page_url, root, out, seen)
    try:
        from crawler.forms import extract_forms
        for form in extract_forms(page, page_url):
            form_url = form.get("url") or page_url
            if not _same_site(form_url, root):
                continue
            method = form.get("method") or "GET"
            _add_page(out, seen, form_url)
            for field in form.get("parameters") or []:
                name = str(field.get("name") or "").strip()
                if not name:
                    continue
                loc = str(field.get("location") or ("body" if method == "POST" else "query"))
                _add_target(
                    out,
                    seen,
                    form_url,
                    method,
                    name,
                    loc,
                    str(field.get("value") or ""),
                )
    except Exception:
        pass
    for name in _INPUT_NAME_RE.findall(body):
        key = str(name or "").strip()
        if key:
            _add_target(out, seen, page_base, "GET", key, "query")
    for match in _HREF_RE.findall(body):
        abs_url = _abs_url(match, page_url)
        _targets_from_url(abs_url, root, out, seen)
    origin = _origin(page_url) or _origin(root)
    for raw in list(_API_PATH_RE.findall(body)) + list(_AUTH_PATH_RE.findall(body)):
        abs_url = _abs_url(raw, origin + "/")
        _targets_from_url(abs_url, root, out, seen)
    for raw in _LOOSE_API_PATH_RE.findall(body or ""):
        abs_url = _abs_url(raw, origin + "/")
        _targets_from_url(abs_url, root, out, seen)
    for raw in _QUOTED_URL_RE.findall(body):
        abs_url = _abs_url(raw, origin + "/")
        if abs_url:
            _targets_from_url(abs_url, root, out, seen)
    return out
def discover_script_sinks(text: str, base_url: str) -> dict:
    """
    Endpoints and hash routes copied out of script that was actually downloaded.
    Does not invent paths. Query names come from the same literal (?q=, &id=).
    """
    raw = (text or "").replace("\\/", "/")
    origin = _origin(base_url)
    if not origin:
        return {"params": [], "hash_paths": [], "hash_params": [], "hash_mode": False}
    params: list[dict] = []
    seen: set = set()
    hash_names: list[str] = []
    def _add_param(path: str, name: str):
        path = (path or "").split("?", 1)[0]
        if not path.startswith("/") or _STATIC_EXT_RE.search(path):
            return
        name = str(name or "").strip()
        if not _ok_param_name(name):
            return
        key = ("GET", path, name.lower())
        if key in seen:
            return
        seen.add(key)
        params.append({
            "name": name,
            "value": "",
            "location": "query",
            "method": "GET",
            "url": origin + path,
            "source": "url",
        })
        if name.lower() not in {n.lower() for n in hash_names}:
            if _SINKISH_RE.search(path) or name.lower() in ("q", "query", "search", "keyword", "term"):
                hash_names.append(name)
    for match in _JS_ENDPOINT_RE.finditer(raw):
        path = match.group("path") or ""
        name = match.group("name") or ""
        if name:
            _add_param(path, name)
    hash_paths: list[str] = []
    path_seen: set = set()
    def _add_hash(path: str):
        path = "/" + str(path or "").strip("/")
        path = path.split("?", 1)[0]
        if not path or path in ("/",) or "*" in path or ":" in path:
            return
        if not _SINKISH_RE.search(path):
            return
        if path in path_seen:
            return
        path_seen.add(path)
        hash_paths.append(path)
    for match in _JS_ROUTER_PATH_RE.finditer(raw):
        _add_hash(match.group(2))
    for match in _JS_HASH_LITERAL_RE.finditer(raw):
        _add_hash(match.group(1))
    if hash_paths and not hash_names and re.search(r"[?&]q=", raw):
        hash_names.append("q")
    params.sort(key=lambda p: (0 if _SINKISH_RE.search(str(p.get("url") or "")) else 1, str(p.get("url") or "")))
    hash_paths.sort(key=lambda p: (0 if "search" in p.lower() else 1, len(p)))
    return {
        "params": params[:60],
        "hash_paths": hash_paths[:4],
        "hash_params": hash_names[:4],
        "hash_mode": bool(_JS_HASH_MODE_RE.search(raw)),
    }
def discover_params(page: dict | None = None, base_url: str = "") -> list:
    return discover_request_targets(page or {}, base_url)
def extract_params(body: str, base_url: str = "") -> list:
    return discover_request_targets({"body": body or "", "url": base_url}, base_url)
