"""
Form & parameter extraction (Start Scan URL).
Produces the request-target shape Member 1 uses to know where inputs live:
    {
      "url": "https://host/login",
      "method": "POST",
      "parameters": [
        {"name": "username", "type": "text",     "location": "body"},
        {"name": "password", "type": "password", "location": "body"},
        {"name": "csrf_token", "type": "hidden", "location": "body"}
      ],
      "technologies": ["PHP", "Apache"]
    }
Uses the standard-library HTML parser (no extra dependency). Member 2 only
extracts inputs -- it does NOT submit forms or send payloads (that is Member 3).
"""
from __future__ import annotations
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse
from crawler.tech_detect import detect_tech_names
class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.links = []
        self._cur = None
    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""),
                         "method": (a.get("method") or "GET").upper(),
                         "fields": []}
        elif tag in ("input", "select", "textarea", "button") and self._cur is not None:
            name = (a.get("name") or a.get("id") or "").strip()
            if not name:
                return
            if tag == "input":
                ftype = a.get("type", "text") or "text"
            elif tag == "button":
                ftype = a.get("type") or "submit"
            else:
                ftype = tag
            self._cur["fields"].append({
                "name": name,
                "type": ftype,
                "value": a.get("value", ""),
            })
        elif tag == "a":
            href = a.get("href", "").strip()
            if href:
                self.links.append(href)
    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None
    def close(self):
        super().close()
        if self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None
def _canon_host(host: str) -> str:
    name = (host or "").lower()
    if name == "localhost":
        return "127.0.0.1"
    return name
def _same_host(a: str, b: str) -> bool:
    pa, pb = urlparse(a or ""), urlparse(b or "")
    ha, hb = _canon_host(pa.hostname or ""), _canon_host(pb.hostname or "")
    if not ha or not hb or ha != hb:
        return False
    return (pa.port or None) == (pb.port or None)
def _query_params(url: str) -> list:
    pairs = parse_qsl(urlparse(url or "").query, keep_blank_values=True)
    seen = set()
    out = []
    for name, _value in pairs:
        key = name.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append({"name": key, "type": "text", "location": "query"})
    return out
def _strip_query_fragment(url: str) -> str:
    p = urlparse(url or "")
    return urlunparse((p.scheme, p.netloc, p.path or "/", "", "", ""))
def extract_forms(page: dict, base_url: str | None = None) -> list:
    """Return one request-target dict per <form> found in the page body."""
    if isinstance(page, str):
        page = {"body": page, "url": base_url or ""}
    page = page or {}
    body = page.get("body") or ""
    page_url = base_url or page.get("url") or ""
    if not body and not page_url:
        return []
    parser = _FormParser()
    try:
        if body:
            parser.feed(body)
            parser.close()
    except Exception:
        pass
    techs = detect_tech_names(page) if isinstance(page, dict) else []
    targets = []
    seen = set()
    def _add(url, method, params):
        method = method if method in ("GET", "POST") else "GET"
        key = (method, url, tuple(sorted(p["name"] for p in params)))
        if key in seen:
            return
        seen.add(key)
        targets.append({
            "url": url,
            "method": method,
            "parameters": params,
            "technologies": techs,
        })
    page_params = _query_params(page_url)
    if page_params:
        _add(_strip_query_fragment(page_url) or page_url, "GET", page_params)
    for form in parser.forms:
        method = form["method"] if form["method"] in ("GET", "POST") else "GET"
        location = "body" if method == "POST" else "query"
        action = urljoin(page_url, form["action"]) if form["action"] else page_url
        params = [{"name": f["name"], "type": f["type"], "location": location}
                  for f in form["fields"]]
        extra = _query_params(action)
        if extra:
            names = {p["name"] for p in params}
            for item in extra:
                if item["name"] not in names:
                    params.append(item)
            action = _strip_query_fragment(action) or action
        _add(action, method, params)
    for href in parser.links:
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        abs_url = urljoin(page_url, href)
        if page_url and not _same_host(abs_url, page_url):
            continue
        params = _query_params(abs_url)
        page = _strip_query_fragment(abs_url) or abs_url
        if params:
            _add(page, "GET", params)
        else:
            _add(page, "GET", [])
    return targets
