"""
Get Stack detection API + page-level tech names (for form artefacts).
Return list[dict] with keys: name, category, version, description.
Never attach CWE/OWASP. Never emit vulnerability findings here.
"""
from __future__ import annotations
from crawler.scope import normalise_url, is_http_url
from crawler.signatures import (HEADER_RULES, BODY_RULES, FILE_RULES,
                              stack_item, extract_version)
from crawler.fetch import fetch_target


def _scan(headers_lc: dict, body_lc: str, host: str, neutral: bool) -> list:
    found, seen = [], set()

    def add(name, cat, version, desc):
        k = name.lower()
        if k in seen:
            return
        seen.add(k)
        found.append(stack_item(name, cat, version, desc))

    header_blob = " ".join(f"{k}: {v}" for k, v in headers_lc.items())
    for name, cat, _v, rule in HEADER_RULES:
        try:
            if rule(headers_lc):
                add(name, cat, extract_version(name, header_blob),
                    f"Detected from HTTP headers on {host}.")
        except Exception:
            pass
    for name, cat, _v, rule in BODY_RULES:
        try:
            if rule(body_lc):
                add(name, cat, extract_version(name, body_lc),
                    f"Detected from response body markers on {host}.")
        except Exception:
            pass
    if neutral and not found:
        add("HTTP Service", "Web Server", "",
            f"Reachable HTTP endpoint at {host}; specific stack markers not identified.")
    return found


def _lc(page):
    headers = {str(k).lower(): str(v).lower()
               for k, v in (page.get("headers") or {}).items()}
    body = (page.get("body") or "").lower()
    return headers, body


def detect_tech_stack(url: str) -> list:
    url = normalise_url(url)
    if not is_http_url(url):
        return []
    page = fetch_target(url)
    headers, body = _lc(page)
    return _scan(headers, body, url, neutral=bool(page.get("ok")))


def detect_tech_from_page(page: dict) -> list:
    """Tech dicts from an already-fetched page artefact (no re-fetch, no neutral fallback)."""
    headers, body = _lc(page)
    return _scan(headers, body, page.get("url", ""), neutral=False)


def detect_tech_names(page: dict) -> list:
    """Just the technology names for the form/parameter artefact."""
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
