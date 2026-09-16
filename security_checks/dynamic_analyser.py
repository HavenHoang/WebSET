from __future__ import annotations

from urllib.parse import urljoin, urlparse, urlunparse

from security_checks.http_context import HttpContext, normalise_url
from security_checks.passive_checks import run_passive_checks
from security_checks.schema import sort_findings

try:
    from crawler.scope import in_scope as _in_scope
except Exception:
    _in_scope = None


_ERROR_CODES = {
    "invalid_url": "invalid_url",
    "timeout": "timeout",
    "dns": "unreachable",
    "connection": "unreachable",
    "ssl": "ssl_error",
}

_UNUSABLE_STATUSES = frozenset({0, 502, 503, 504})

_MAX_EXTRA_TARGETS = 80

_FS_PREFIXES = (
    "/users/",
    "/home/",
    "/documents/",
    "/windows/",
    "/tmp/",
)

_FILE_EXT = (
    ".php",
    ".html",
    ".htm",
    ".asp",
    ".aspx",
    ".jsp",
    ".cgi",
    ".do",
    ".action",
    ".py",
    ".rb",
    ".pl",
)

_SKIP_EXT = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
    ".pdf",
    ".zip",
)

_PRIORITY_HINTS = (
    "login",
    "signin",
    "auth",
    "session",
    "search",
    "ftp",
    "upload",
    "admin",
    "backup",
    "metrics",
    "swagger",
    "inject",
    "xss",
    "sql",
    "exec",
    "cmd",
    "include",
    "redirect",
    "captcha",
    "csrf",
    "brute",
    "api",
    "crypto",
    "ping",
    "command",
    "encryption",
    "package.json",
    "jwks",
    "track",
    "result",
)

_HOME_PATHS = (
    "/",
    "/index.php",
    "/index.html",
    "/home",
    "/home.php",
)


def _error(code: str) -> dict:
    return {"error": code}


def _map_error(raw: str | None) -> str:
    key = str(raw or "").strip().lower()
    return _ERROR_CODES.get(key, "unreachable")


def _canon_host(host: str) -> str:
    name = (host or "").lower()

    if name == "localhost":
        return "127.0.0.1"

    return name


def _origin(url: str) -> str:
    p = urlparse(
        url if "://" in (url or "") else "http://" + (url or "")
    )

    host = _canon_host(p.hostname or "")

    if not host:
        return ""

    netloc = host

    if p.port:
        netloc = f"{host}:{p.port}"

    return f"{p.scheme or 'http'}://{netloc}"


def _same_origin(candidate: str, origin: str) -> bool:
    if not candidate or not origin:
        return False

    return _origin(candidate) == origin


def _directory_prefix(path: str) -> str:
    raw = path or "/"

    if raw in ("", "/"):
        return "/"

    last = raw.rsplit("/", 1)[-1].lower()

    if "." in last and any(last.endswith(ext) for ext in _FILE_EXT):
        parent = raw[:raw.rfind("/")]
        return parent or "/"

    return raw


def _parent_prefix(path: str) -> str:
    prefix = _directory_prefix(path)

    if prefix in ("", "/"):
        return "/"

    parent = prefix.rsplit("/", 1)[0]

    return parent or "/"


def _allowed(candidate: str, start: str) -> bool:
    if not candidate or not start:
        return False

    if not _same_origin(candidate, _origin(start)):
        return False

    path = urlparse(
        candidate if "://" in candidate else "http://" + candidate
    ).path.lower()

    if any(path.endswith(ext) for ext in _SKIP_EXT):
        return False

    if _in_scope is not None:
        try:
            if bool(_in_scope(candidate, start)):
                return True
        except Exception:
            pass

    start_path = urlparse(
        start if "://" in start else "http://" + start
    ).path or "/"

    cand_path = urlparse(
        candidate if "://" in candidate else "http://" + candidate
    ).path or "/"

    prefix = _directory_prefix(start_path)
    parent = _parent_prefix(start_path)

    if not cand_path.startswith("/"):
        cand_path = "/" + cand_path

    if prefix in ("", "/"):
        return True

    return (
        cand_path == prefix
        or cand_path.startswith(prefix + "/")
        or cand_path == parent
        or cand_path.startswith(parent + "/")
    )


def _drop_fragment(url: str) -> str:
    p = urlparse(url or "")

    if not p.netloc:
        return url or ""

    return urlunparse(
        (
            p.scheme,
            p.netloc,
            p.path or "/",
            "",
            p.query,
            "",
        )
    )


def _looks_local_fs(url: str) -> bool:
    path = urlparse(url or "").path.lower()

    return any(path.startswith(prefix) for prefix in _FS_PREFIXES)


def _looks_spa(artefact: dict | None) -> bool:
    body = str((artefact or {}).get("body") or "").lower()

    if "<app-root" in body or "ng-version" in body:
        return True

    if 'id="root"' in body or "id='root'" in body:
        return True

    if "__next" in body or "data-reactroot" in body:
        return True

    return False


def _looks_login(artefact: dict | None) -> bool:
    body = str((artefact or {}).get("body") or "").lower()
    url = str((artefact or {}).get("url") or "").lower()

    if "password" not in body:
        return False

    if "logout" in body:
        return False

    return "login" in body or "login" in url or "signin" in url


def _body_thin(artefact: dict | None) -> bool:
    return len(
        str((artefact or {}).get("body") or "").strip()
    ) < 80


def _priority(url: str) -> int:
    low = (url or "").lower()

    return 0 if any(
        hint in low for hint in _PRIORITY_HINTS
    ) else 1


def _cookie_key(item: dict) -> tuple:
    name = str(
        item.get("name") or ""
    ).strip().lower()

    if not name:
        raw = str(item.get("raw") or "")

        name = (
            raw.split("=", 1)[0].strip().lower()
            if "=" in raw
            else raw.lower()
        )

    path = str(
        item.get("path") or "/"
    ).lower()

    return name, path


def _merge_cookies(
    base: list | None,
    extra: list | None,
) -> list:
    out = []
    seen = set()

    for item in list(extra or []) + list(base or []):
        if not isinstance(item, dict):
            continue

        key = _cookie_key(item)

        if not key[0] or key in seen:
            continue

        seen.add(key)
        out.append(item)

    return out


def _artefact_cookies(artefact: dict | None) -> list:
    art = artefact or {}

    return list(
        art.get("cookies")
        or art.get("set_cookie")
        or []
    )


def _publish_session_cookies(
    cookies: list | None,
) -> None:
    jar = {}

    for item in cookies or []:
        if not isinstance(item, dict):
            continue

        name = str(
            item.get("name") or ""
        ).strip()

        value = str(
            item.get("value") or ""
        )

        if not name and "=" in str(
            item.get("raw") or ""
        ):
            name, value = str(
                item.get("raw")
            ).split("=", 1)

            name = name.strip()

        if name:
            jar[name] = value

    if not jar:
        return

    try:
        from core.shared_state import SharedState

        SharedState.set_scan_cookies(jar)
    except Exception:
        pass


def _home_urls(start: str) -> list[str]:
    origin = _origin(start)

    if not origin:
        return []

    parsed = urlparse(
        start if "://" in start else "http://" + start
    )

    prefix = _directory_prefix(
        parsed.path or "/"
    )

    out = [
        origin + path
        for path in _HOME_PATHS
    ]

    if prefix not in ("", "/"):
        out.append(origin + prefix)
        out.append(
            origin
            + prefix.rstrip("/")
            + "/index.php"
        )
        out.append(
            origin
            + prefix.rstrip("/")
            + "/"
        )

    return out


def _dedupe(findings: list) -> list:
    seen = set()
    out = []

    for f in findings or []:
        key = (
            str(
                f.get("vulnerability")
                or f.get("name")
                or ""
            ).lower(),
            str(
                f.get("location")
                or f.get("url")
                or ""
            ).lower(),
            str(
                f.get("param")
                or f.get("input")
                or ""
            ).lower(),
            str(
                f.get("plugin_id")
                or ""
            ),
        )

        if key in seen:
            continue

        seen.add(key)
        out.append(f)

    return out


def _normalise_target(
    raw: str,
    origin: str,
) -> str:
    text = str(raw or "").strip()

    if not text or text.startswith(
        ("mailto:", "javascript:", "data:")
    ):
        return ""

    if text.startswith("#"):
        frag = text[1:]

        if not frag.startswith("/"):
            return ""

        if "?" in frag:
            path, query = frag.split("?", 1)
        else:
            path, query = frag, ""

        text = (
            origin
            + (path or "/")
            + (f"?{query}" if query else "")
        )

    if text.startswith("//"):
        text = (
            urlparse(origin).scheme
            + ":"
            + text
        )

    elif text.startswith("/"):
        text = urljoin(
            origin + "/",
            text.lstrip("/"),
        )

    elif "://" not in text:
        text = urljoin(
            origin + "/",
            text,
        )

    parsed = urlparse(text)

    if not parsed.netloc:
        return ""

    cleaned = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            "",
            parsed.query,
            "",
        )
    )

    if _looks_local_fs(cleaned):
        return ""

    return cleaned


def _html_links(
    body: str,
    origin: str,
) -> list[str]:
    import re

    urls = []

    for match in re.finditer(
        r"""(?:href|src|action|formaction)\s*=\s*['"]([^'"]+)['"]""",
        body or "",
        re.I,
    ):
        u = _normalise_target(
            match.group(1),
            origin,
        )

        if u and _same_origin(u, origin):
            urls.append(u)

    for match in re.finditer(
        r"""#(/[A-Za-z0-9][A-Za-z0-9_./\-]*(?:\?[A-Za-z0-9_\-.=&%]*)?)""",
        body or "",
    ):
        u = _normalise_target(
            "#" + match.group(1),
            origin,
        )

        if u and _same_origin(u, origin):
            urls.append(u)

    return urls


def _discover_urls(
    target: str,
    artefact: dict | None,
) -> list[str]:
    origin = _origin(
        str(
            (artefact or {}).get("url")
            or target
        )
        or target
    )

    if not origin:
        origin = _origin(target)

    if not origin:
        return []

    seen = {target.rstrip("/")}
    out: list[str] = []

    def add(raw: str):
        u = _normalise_target(
            raw,
            origin,
        )

        if not u or not _allowed(
            u,
            target,
        ):
            return

        key = u.rstrip("/")

        if key in seen:
            return

        seen.add(key)
        out.append(u)

    body = str(
        (artefact or {}).get("body")
        or ""
    )

    for u in _html_links(
        body,
        origin,
    ):
        add(u)

    for u in (
        artefact or {}
    ).get("links") or []:
        add(u)

    try:
        from crawler.forms import extract_forms

        forms = extract_forms(
            artefact or {},
            target,
        ) or []
    except Exception:
        forms = []

    for form in forms:
        if isinstance(form, dict):
            add(
                form.get("action")
                or form.get("url")
                or ""
            )

    try:
        from crawler.param_discover import discover_params

        found = discover_params(
            artefact or {},
            target,
        ) or []
    except Exception:
        found = []

    if not found:
        try:
            from crawler.param_discover import extract_params

            found = extract_params(
                body,
                target,
            ) or []
        except Exception:
            found = []

    for item in found:
        if isinstance(item, str):
            add(item)

        elif isinstance(item, dict):
            add(
                item.get("url")
                or item.get("endpoint")
                or item.get("action")
                or ""
            )

    out.sort(key=_priority)

    return out[:_MAX_EXTRA_TARGETS]


def _run_injection(
    ctx,
    artefact,
) -> list:
    try:
        from security_checks.injection_checks import (
            run_injection_checks,
        )

        return list(
            run_injection_checks(
                ctx,
                artefact,
            )
            or []
        )
    except Exception as exc:
        print(
            "injection_checks:",
            exc,
        )
        return []


def _run_surface(
    ctx,
    artefact,
) -> list:
    try:
        from security_checks.generic_surface_checks import (
            run_generic_surface_checks,
        )

        return list(
            run_generic_surface_checks(
                ctx,
                artefact,
            )
            or []
        )
    except Exception as exc:
        print(
            "generic_surface_checks:",
            exc,
        )
        return []


def analyse_dynamic(
    url: str,
    *,
    fetch_fn=None,
    use_browser: bool = False,
    timeout: float | None = None,
) -> list | dict:
    target = _drop_fragment(
        normalise_url(url)
    )

    if not target:
        return _error("invalid_url")

    try:
        from security_checks.injection_checks import (
            reset_origin_wide_probes as _reset_inj,
        )

        _reset_inj()
    except Exception:
        pass

    try:
        from security_checks.generic_surface_checks import (
            reset_origin_wide_probes as _reset_surf,
        )

        _reset_surf()
    except Exception:
        pass

    if fetch_fn is None:
        try:
            from crawler.fetch import fetch_target as fetch_fn
        except ImportError:
            return _error("crawler_unavailable")

    session_cookies: list = []

    def _fetch(
        u: str,
        browser: bool = False,
    ) -> dict:
        if (
            not _allowed(u, target)
            and u.rstrip("/")
            != target.rstrip("/")
        ):
            return {
                "ok": False,
                "error": "out_of_scope",
                "url": u,
            }

        kwargs = {
            "root": target,
        }

        if timeout is not None:
            kwargs["timeout"] = timeout

        if browser or use_browser:
            kwargs["use_browser"] = True

        if session_cookies:
            kwargs["cookies"] = list(
                session_cookies
            )

        try:
            return fetch_fn(
                u,
                **kwargs,
            ) or {}

        except TypeError:
            try:
                return fetch_fn(u) or {}
            except Exception:
                return {
                    "ok": False,
                    "error": "connection",
                    "url": u,
                }

        except Exception:
            return {
                "ok": False,
                "error": "connection",
                "url": u,
            }

    artefact = _fetch(
        target,
        browser=False,
    )

    session_cookies = _merge_cookies(
        session_cookies,
        _artefact_cookies(artefact),
    )

    ctx = HttpContext.from_fetch(
        artefact,
        requested_url=target,
    )

    need_browser = (
        not ctx.ok
        or _body_thin(artefact)
        or _looks_spa(artefact)
    )

    if need_browser and not use_browser:
        browser_art = _fetch(
            target,
            browser=True,
        )

        browser_ctx = HttpContext.from_fetch(
            browser_art,
            requested_url=target,
        )

        if (
            browser_ctx.ok
            and not _body_thin(browser_art)
        ):
            artefact = browser_art
            ctx = browser_ctx

            session_cookies = _merge_cookies(
                session_cookies,
                _artefact_cookies(
                    browser_art
                ),
            )

    if (
        _looks_login(artefact)
        and session_cookies
    ):
        for home in _home_urls(target):
            home_art = _fetch(
                home,
                browser=False,
            )

            session_cookies = _merge_cookies(
                session_cookies,
                _artefact_cookies(home_art),
            )

            home_ctx = HttpContext.from_fetch(
                home_art,
                requested_url=home,
            )

            if (
                home_ctx.ok
                and not _looks_login(home_art)
                and not _body_thin(home_art)
            ):
                artefact = home_art
                ctx = home_ctx
                break

    if not ctx.ok:
        return _error(
            _map_error(ctx.error)
        )

    if ctx.status in _UNUSABLE_STATUSES:
        return _error("bad_response")

    _publish_session_cookies(
        session_cookies
    )

    findings = list(
        run_passive_checks(ctx)
        or []
    )

    findings.extend(
        _run_injection(
            ctx,
            artefact,
        )
    )

    findings.extend(
        _run_surface(
            ctx,
            artefact,
        )
    )

    visited = {
        target.rstrip("/")
    }

    landed = str(
        artefact.get("url")
        or target
    )

    if (
        landed.rstrip("/")
        != target.rstrip("/")
    ):
        visited.add(
            landed.rstrip("/")
        )

    queue = _discover_urls(
        target,
        artefact,
    )

    for home in _home_urls(target):
        if home.rstrip("/") not in visited:
            queue.append(home)

    queue.sort(key=_priority)

    while (
        queue
        and len(visited)
        <= _MAX_EXTRA_TARGETS
    ):
        extra_url = queue.pop(0)

        key = extra_url.rstrip("/")

        if key in visited:
            continue

        if not _allowed(
            extra_url,
            target,
        ):
            continue

        visited.add(key)

        extra_art = _fetch(
            extra_url,
            browser=_looks_spa(
                artefact
            ),
        )

        session_cookies = _merge_cookies(
            session_cookies,
            _artefact_cookies(extra_art),
        )

        extra_ctx = HttpContext.from_fetch(
            extra_art,
            requested_url=extra_url,
        )

        if not extra_ctx.ok:
            continue

        findings.extend(
            run_passive_checks(extra_ctx)
            or []
        )

        findings.extend(
            _run_injection(
                extra_ctx,
                extra_art,
            )
        )

        findings.extend(
            _run_surface(
                extra_ctx,
                extra_art,
            )
        )

        for nxt in _discover_urls(
            target,
            extra_art,
        ):
            if nxt.rstrip("/") not in visited:
                queue.append(nxt)

        queue.sort(key=_priority)

    _publish_session_cookies(
        session_cookies
    )

    try:
        from security_checks.injection_checks import (
            run_origin_wide_checks,
        )

        findings.extend(
            list(
                run_origin_wide_checks(
                    ctx,
                    artefact,
                )
                or []
            )
        )
    except Exception as exc:
        print(
            "origin_wide_checks:",
            exc,
        )

    return sort_findings(
        _dedupe(findings)
    )


def scan_summary(
    findings: list,
) -> dict:
    summary = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "total": 0,
    }

    for f in findings or []:
        severity = str(
            f.get("severity") or ""
        )

        if severity == "Critical":
            severity = "High"

        if severity in summary:
            summary[severity] += 1

        summary["total"] += 1

    return summary


def run_scan(url: str):
    return analyse_dynamic(url)
