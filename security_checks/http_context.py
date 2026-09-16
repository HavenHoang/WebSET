from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit
def normalise_url(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text
    parts = urlsplit(text)
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    if host == "localhost":
        host = "127.0.0.1"
    if not host:
        return text
    netloc = host
    port = parts.port
    if port and port != {"http": 80, "https": 443}.get(scheme):
        netloc = f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", "", ""))
def _scheme_of(url: str) -> str:
    return (urlsplit(str(url or "")).scheme or "").lower()
def _record_from_raw(raw: str) -> dict:
    text = str(raw or "").strip()
    name, sep, rest = text.partition("=")
    value = rest.split(";", 1)[0].strip() if sep else ""
    return {
        "name": name.strip(),
        "value": value,
        "raw": text,
    }
def _shared_cookie_records() -> list[dict]:
    out = []
    try:
        from core.shared_state import SharedState
        jar = getattr(SharedState, "scan_cookies", None) or {}
        if hasattr(jar, "items"):
            for name, value in jar.items():
                if not name:
                    continue
                out.append({
                    "name": str(name),
                    "value": str(value),
                    "path": "/",
                    "raw": f"{name}={value}",
                })
    except Exception:
        pass
    return out
def _cookies_from_artefact(data: dict) -> tuple[list[dict], list[str]]:
    records: list[dict] = []
    seen = set()
    def add(item):
        if isinstance(item, dict):
            rec = {
                "name": str(item.get("name") or "").strip(),
                "value": str(item.get("value") or ""),
                "path": str(item.get("path") or "/"),
                "raw": str(item.get("raw") or ""),
            }
            if not rec["raw"] and rec["name"]:
                rec["raw"] = f"{rec['name']}={rec['value']}"
        elif item:
            rec = _record_from_raw(str(item))
        else:
            return
        key = (rec.get("name") or rec.get("raw") or "").lower()
        if not key or key in seen:
            return
        seen.add(key)
        records.append(rec)
    for key in ("cookies", "set_cookie", "set_cookies"):
        for item in data.get(key) or []:
            add(item)
    headers = data.get("headers") or {}
    for key, value in headers.items():
        if str(key).lower() != "set-cookie" or not value:
            continue
        if isinstance(value, (list, tuple)):
            for part in value:
                add(part)
        else:
            for part in str(value).split("\n"):
                add(part.strip())
    for item in _shared_cookie_records():
        add(item)
    raw_lines = [str(r.get("raw") or "") for r in records if r.get("raw")]
    return records, raw_lines
@dataclass
class HttpContext:
    ok: bool = False
    error: str | None = None
    url: str = ""
    raw_url: str = ""
    requested_url: str = ""
    scheme: str = ""
    requested_scheme: str = ""
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    body: str = ""
    redirect_chain: list[dict] = field(default_factory=list)
    elapsed_ms: int = 0
    @classmethod
    def from_fetch(cls, artefact: dict, requested_url: str = "") -> "HttpContext":
        data = artefact if isinstance(artefact, dict) else {}
        raw_url = str(data.get("url") or "").strip()
        final_url = normalise_url(raw_url)
        chain = data.get("redirect_chain") or []
        origin = requested_url or ""
        if not origin and chain:
            first = chain[0]
            if isinstance(first, dict):
                origin = first.get("url") or ""
        origin_url = normalise_url(origin) or final_url
        headers = {
            str(k).strip().lower(): str(v)
            for k, v in (data.get("headers") or {}).items()
        }
        cookie_records, cookie_lines = _cookies_from_artefact(data)
        return cls(
            ok=bool(data.get("ok")),
            error=data.get("error"),
            url=final_url,
            raw_url=raw_url or final_url,
            requested_url=origin_url,
            scheme=_scheme_of(final_url),
            requested_scheme=_scheme_of(origin_url),
            status=int(data.get("status") or 0),
            headers=headers,
            set_cookies=cookie_lines,
            cookies=cookie_records,
            body=str(data.get("body") or ""),
            redirect_chain=list(chain),
            elapsed_ms=int(data.get("elapsed_ms") or 0),
        )
    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(str(name).strip().lower(), default)
    def has_header(self, name: str) -> bool:
        return bool(self.header(name).strip())
    @property
    def is_https(self) -> bool:
        return self.scheme == "https"
    @property
    def was_upgraded(self) -> bool:
        return self.requested_scheme == "http" and self.scheme == "https"
    def csp_directives(self) -> dict[str, str]:
        raw = self.header("content-security-policy")
        if not raw.strip():
            return {}
        directives: dict[str, str] = {}
        for chunk in raw.split(";"):
            chunk = chunk.strip()
            if not chunk:
                continue
            name, _, value = chunk.partition(" ")
            directives[name.strip().lower()] = value.strip()
        return directives
    def has_csp_directive(self, name: str) -> bool:
        return str(name).strip().lower() in self.csp_directives()
def context_from_url(url: str, fetch_fn=None, **fetch_kwargs) -> HttpContext:
    if fetch_fn is None:
        from crawler.fetch import fetch_target as fetch_fn
    return HttpContext.from_fetch(fetch_fn(url, **fetch_kwargs), requested_url=url)
