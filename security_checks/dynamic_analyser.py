from __future__ import annotations

from security_checks.http_context import HttpContext, normalise_url
from security_checks.passive_checks import run_passive_checks
from security_checks.schema import sort_findings

#: Crawler error codes mapped to the short codes the GUI already handles.
#: Anything unrecognised collapses to "unreachable" so the interface never has
#: to render a raw exception string.
_ERROR_CODES = {
    "invalid_url": "invalid_url",
    "timeout": "timeout",
    "dns": "unreachable",
    "connection": "unreachable",
    "ssl": "ssl_error",
}

#: HTTP statuses that mean we never saw the application itself. Findings drawn
#: from an error page describe the error page, not the target.
_UNUSABLE_STATUSES = frozenset({0, 502, 503, 504})


def _error(code: str) -> dict:
    """Build the failure shape the GUI expects."""
    return {"error": code}


def _map_error(raw: str | None) -> str:
    """Translate a crawler error into a GUI-facing code."""
    key = str(raw or "").strip().lower()
    if key in _ERROR_CODES:
        return _ERROR_CODES[key]
    # Unclassified crawler messages (a raw exception string) become generic.
    return "unreachable"


def analyse_dynamic(
    url: str,
    *,
    fetch_fn=None,
    use_browser: bool = False,
    timeout: float | None = None,
) -> list | dict:
    """Run a dynamic Start Scan against an authorised target.

    Args:
        url: Target URL. Must be a laboratory target the team is authorised to
            test - DVWA or OWASP Juice Shop for this project.
        fetch_fn: Optional replacement for ``crawler.fetch.fetch_target``,
            used by the test suite to replay stored responses offline. It must
            accept a URL and return a crawler-shaped artefact dict.
        use_browser: Forwarded to the crawler for JavaScript-rendered pages.
        timeout: Forwarded to the crawler.

    Returns:
        On success, a list of findings sorted by severity. On failure, a dict
        with an ``error`` key holding one of: invalid_url, timeout,
        unreachable, ssl_error, bad_response.
    """
    target = normalise_url(url)
    if not target:
        return _error("invalid_url")

    if fetch_fn is None:
        try:
            from crawler.fetch import fetch_target as fetch_fn
        except ImportError:
            return _error("crawler_unavailable")

    kwargs = {}
    if timeout is not None:
        kwargs["timeout"] = timeout
    if use_browser:
        kwargs["use_browser"] = True

    try:
        artefact = fetch_fn(target, **kwargs)
    except Exception:
        # The crawler returns errors rather than raising, but a stub or a
        # future change might not. One scan must never take down the GUI.
        return _error("unreachable")

    ctx = HttpContext.from_fetch(artefact, requested_url=target)

    if not ctx.ok:
        return _error(_map_error(ctx.error))

    if ctx.status in _UNUSABLE_STATUSES:
        return _error("bad_response")

    findings = run_passive_checks(ctx)

    # Injection checks are added here once Member 2's form discovery output is
    # confirmed. They need parameters to probe, which passive checks do not.

    return sort_findings(findings)


def scan_summary(findings: list) -> dict:
    """Count findings by severity for the dashboard tiles.

    Returns zeros for an empty list so the caller can render the tiles without
    a special case.
    """
    summary = {"High": 0, "Medium": 0, "Low": 0, "total": 0}
    for f in findings or []:
        severity = str(f.get("severity") or "")
        if severity == "Critical":
            severity = "High"
        if severity in summary:
            summary[severity] += 1
        summary["total"] += 1
    return summary


# Alias kept for compatibility with the original code pack.
def run_scan(url: str):
    """Deprecated alias for :func:`analyse_dynamic`."""
    return analyse_dynamic(url)