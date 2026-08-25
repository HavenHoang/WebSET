from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

#: Keys expected in a crawler fetch artefact. Anything missing degrades to a
#: safe empty value rather than raising.
_FETCH_KEYS = (
    "ok", "url", "status", "redirect_chain", "headers",
    "set_cookie", "body", "elapsed_ms", "error",
)


def normalise_url(raw: str) -> str:
    """Return a canonical form of ``raw`` for use as a finding location.

    Lowercases the scheme and host, drops a default port, and guarantees a
    path so that ``http://host`` and ``http://host/`` do not appear as two
    different locations in Alerts. Query and fragment are dropped: a finding
    describes a page, not one parameterised request to it.

    Safe to call on an already-normalised URL, so it does not matter whether
    the crawler's own ``normalise_url`` ran first.
    """
    text = str(raw or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text

    parts = urlsplit(text)
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    if not host:
        return text

    netloc = host
    port = parts.port
    default_port = {"http": 80, "https": 443}.get(scheme)
    if port and port != default_port:
        netloc = f"{host}:{port}"

    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def _scheme_of(url: str) -> str:
    """Scheme of ``url`` in lowercase, empty string if it has none."""
    return (urlsplit(str(url or "")).scheme or "").lower()


@dataclass
class HttpContext:
    """A fetched response, normalised for the detection checks.

    Attributes:
        ok: Whether the fetch succeeded. When False only ``error`` and
            ``requested_url`` are meaningful.
        error: Crawler error code - invalid_url, timeout, ssl, dns,
            connection, or a raw message.
        url: Final URL after redirects, normalised.
        requested_url: URL originally asked for, normalised. Differs from
            ``url`` when the server redirected.
        scheme: Scheme of the final URL - "http" or "https".
        requested_scheme: Scheme of the original request. The transport check
            compares the two to decide whether HTTP was upgraded.
        status: Final HTTP status code.
        headers: Response headers with keys lowercased.
        set_cookies: Every Set-Cookie value, unparsed.
        body: Response body text.
        redirect_chain: Hops the crawler followed, as given.
        elapsed_ms: Fetch duration.
    """

    ok: bool = False
    error: str | None = None
    url: str = ""
    requested_url: str = ""
    scheme: str = ""
    requested_scheme: str = ""
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    body: str = ""
    redirect_chain: list[dict] = field(default_factory=list)
    elapsed_ms: int = 0

    # -- construction ---------------------------------------------------

    @classmethod
    def from_fetch(cls, artefact: dict, requested_url: str = "") -> "HttpContext":
        """Build a context from ``crawler.fetch.fetch_target`` output.

        Args:
            artefact: The dict returned by the crawler.
            requested_url: The URL the user asked to scan. Pass it when
                available - after ``allow_redirects=True`` the artefact only
                reports the final URL, and the transport check needs to know
                whether the request started on HTTP.
        """
        data = artefact if isinstance(artefact, dict) else {}

        final_url = normalise_url(data.get("url") or "")
        chain = data.get("redirect_chain") or []

        # Prefer the caller's URL; fall back to the first redirect hop, which
        # is where the request actually started.
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

        return cls(
            ok=bool(data.get("ok")),
            error=data.get("error"),
            url=final_url,
            requested_url=origin_url,
            scheme=_scheme_of(final_url),
            requested_scheme=_scheme_of(origin_url),
            status=int(data.get("status") or 0),
            headers=headers,
            set_cookies=[str(c) for c in (data.get("set_cookie") or []) if c],
            body=str(data.get("body") or ""),
            redirect_chain=list(chain),
            elapsed_ms=int(data.get("elapsed_ms") or 0),
        )

    # -- header access --------------------------------------------------

    def header(self, name: str, default: str = "") -> str:
        """Value of a response header, matched without regard to case."""
        return self.headers.get(str(name).strip().lower(), default)

    def has_header(self, name: str) -> bool:
        """Whether a header is present with a non-empty value."""
        return bool(self.header(name).strip())

    # -- derived facts --------------------------------------------------

    @property
    def is_https(self) -> bool:
        """Whether the final response came over HTTPS."""
        return self.scheme == "https"

    @property
    def was_upgraded(self) -> bool:
        """Whether an HTTP request ended up on HTTPS via redirect."""
        return self.requested_scheme == "http" and self.scheme == "https"

    def csp_directives(self) -> dict[str, str]:
        """Content-Security-Policy parsed into ``{directive: value}``.

        Directive names are lowercased. Returns an empty dict when no policy
        is set, so callers can treat "no CSP" and "CSP without this
        directive" the same way.
        """
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
        """Whether the policy defines a directive, e.g. ``frame-ancestors``.

        The X-Frame-Options check uses this: a page with a frame-ancestors
        directive is protected against framing even without the header, so
        reporting it would be a false positive.
        """
        return str(name).strip().lower() in self.csp_directives()


def context_from_url(url: str, fetch_fn=None, **fetch_kwargs) -> HttpContext:
    """Fetch ``url`` and return a context in one step.

    Args:
        url: Target to scan.
        fetch_fn: Callable returning a crawler-shaped artefact. Defaults to
            ``crawler.fetch.fetch_target``. Injecting a stub here is what lets
            the checks be tested without network access.
        **fetch_kwargs: Forwarded to the fetch function.
    """
    if fetch_fn is None:
        from crawler.fetch import fetch_target as fetch_fn  # noqa: PLC0415

    return HttpContext.from_fetch(fetch_fn(url, **fetch_kwargs), requested_url=url)