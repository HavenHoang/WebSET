from __future__ import annotations

from security_checks.finding_builder import build_passive_rule_finding
from security_checks.http_context import HttpContext

# ---------------------------------------------------------------------------
# Tuning constants
# ---------------------------------------------------------------------------

#: Headers checked for a version banner, in reporting priority order.
VERSION_BANNER_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
)

#: Substrings that mark a cookie as session-bearing. Used to decide whether a
#: missing HttpOnly flag is worth reporting at full severity: a front-end
#: preference cookie legitimately needs to be readable by script, a session
#: token does not.
SESSION_COOKIE_HINTS = (
    "session",
    "sess",
    "sid",
    "auth",
    "token",
    "jwt",
    "login",
    "remember",
    "csrf",
    "xsrf",
)

#: Products whose banner is version-less by default and therefore not worth
#: reporting even though the header exists.
_BANNER_IGNORE = ("cloudflare", "cloudfront", "akamai")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _looks_versioned(value: str) -> bool:
    """Whether a banner value exposes something version-like.

    Requires a digit next to a separator or letter, so ``nginx/1.24.0`` and
    ``PHP/8.2`` are reported while a bare ``nginx`` or ``Apache`` is not.
    """
    text = (value or "").strip()
    if not text:
        return False
    if any(vendor in text.lower() for vendor in _BANNER_IGNORE):
        return False
    return any(ch.isdigit() for ch in text)


def parse_set_cookie(raw: str) -> dict:
    """Parse one Set-Cookie header value into name and attribute flags.

    Only the attributes the cookie rules need are extracted. Returns a dict
    with ``name``, ``secure``, ``httponly``, ``samesite`` (lowercased string
    or None) and ``raw``.

    A malformed header degrades to an empty name rather than raising, so one
    odd cookie cannot stop the scan.
    """
    text = str(raw or "").strip()
    result = {
        "name": "",
        "value": "",
        "secure": False,
        "httponly": False,
        "samesite": None,
        "raw": text,
    }
    if not text:
        return result

    parts = [p.strip() for p in text.split(";")]

    # First segment is name=value.
    name, sep, value = parts[0].partition("=")
    if sep:
        result["name"] = name.strip()
        result["value"] = value.strip()
    else:
        result["name"] = parts[0].strip()

    for attr in parts[1:]:
        low = attr.lower()
        if low == "secure":
            result["secure"] = True
        elif low == "httponly":
            result["httponly"] = True
        elif low.startswith("samesite"):
            _, _, sval = attr.partition("=")
            result["samesite"] = sval.strip().lower() or None

    return result


def _is_session_cookie(name: str) -> bool:
    """Whether a cookie name suggests it carries session or auth state."""
    low = (name or "").lower()
    return any(hint in low for hint in SESSION_COOKIE_HINTS)


# ---------------------------------------------------------------------------
# Header checks
# ---------------------------------------------------------------------------

def check_security_headers(ctx: HttpContext) -> list[dict]:
    """Check the response for missing or weak security headers.

    Covers five rules: X-Frame-Options, Content-Security-Policy,
    Strict-Transport-Security, X-Content-Type-Options and Referrer-Policy,
    plus version-banner disclosure.
    """
    findings: list[dict] = []
    location = ctx.url

    # -- X-Frame-Options -------------------------------------------------
    # CSP frame-ancestors supersedes this header, so a page carrying the
    # directive is protected even without it. Reporting anyway is a false
    # positive.
    if not ctx.has_header("x-frame-options"):
        if not ctx.has_csp_directive("frame-ancestors"):
            findings.append(
                build_passive_rule_finding(
                    "header-xfo",
                    location=location,
                    confidence="High",
                    scan_origin=ctx_origin(ctx),
                )
            )

    # -- Content-Security-Policy ----------------------------------------
    # Report-Only publishes violations without enforcing them, so it does not
    # count as a policy, but it does show the team is mid-rollout - lower the
    # confidence rather than suppressing the finding.
    if not ctx.has_header("content-security-policy"):
        report_only = ctx.has_header("content-security-policy-report-only")
        findings.append(
            build_passive_rule_finding(
                "header-csp",
                location=location,
                confidence="Medium" if report_only else "High",
                scan_origin=ctx_origin(ctx),
                evidence=(
                    "Content-Security-Policy-Report-Only is set instead"
                    if report_only else ""
                ),
            )
        )

    # -- Strict-Transport-Security ---------------------------------------
    # Only meaningful over HTTPS. Sending HSTS on a plain HTTP response has no
    # effect, so an HTTP target gets transport-plaintext instead.
    if ctx.is_https and not ctx.has_header("strict-transport-security"):
        findings.append(
            build_passive_rule_finding(
                "header-hsts",
                location=location,
                confidence="High",
                scan_origin=ctx_origin(ctx),
            )
        )

    # -- X-Content-Type-Options ------------------------------------------
    nosniff = ctx.header("x-content-type-options").strip().lower()
    if nosniff != "nosniff":
        findings.append(
            build_passive_rule_finding(
                "header-nosniff",
                location=location,
                confidence="High",
                scan_origin=ctx_origin(ctx),
                evidence=(
                    f"X-Content-Type-Options: {nosniff}" if nosniff else ""
                ),
            )
        )

    # -- Referrer-Policy --------------------------------------------------
    if not ctx.has_header("referrer-policy"):
        findings.append(
            build_passive_rule_finding(
                "header-referrer-policy",
                location=location,
                confidence="High",
                scan_origin=ctx_origin(ctx),
            )
        )

    # -- Version banners --------------------------------------------------
    findings.extend(check_version_disclosure(ctx))

    return findings


def check_version_disclosure(ctx: HttpContext) -> list[dict]:
    """Report headers that leak a product version.

    At most one finding is produced even when several headers leak, because
    the remediation is the same for all of them and separate rows would just
    inflate the Alerts count. Every leaking header is listed in the evidence.
    """
    leaks = [
        (name, ctx.header(name))
        for name in VERSION_BANNER_HEADERS
        if _looks_versioned(ctx.header(name))
    ]
    if not leaks:
        return []

    first_name, first_value = leaks[0]
    evidence = "; ".join(f"{n}: {v}" for n, v in leaks)

    return [
        build_passive_rule_finding(
            "info-disclosure-server",
            location=ctx.url,
            confidence="High",
            scan_origin=ctx_origin(ctx),
            evidence=evidence,
            header_name=first_name,
            header_value=first_value,
        )
    ]


# ---------------------------------------------------------------------------
# Cookie checks
# ---------------------------------------------------------------------------

def check_cookies(ctx: HttpContext) -> list[dict]:
    """Check every Set-Cookie header for missing security attributes.

    One cookie can trigger up to three rules, and several cookies each produce
    their own findings, so the cookie name is carried in the description to
    keep rows distinguishable in Alerts.
    """
    findings: list[dict] = []
    origin = ctx_origin(ctx)

    for raw in ctx.set_cookies:
        cookie = parse_set_cookie(raw)
        name = cookie["name"]
        if not name:
            continue

        is_session = _is_session_cookie(name)
        # Redacted so a session value never lands in a stored finding.
        evidence = _redact_cookie(cookie)

        # -- Secure -------------------------------------------------------
        # Only reportable over HTTPS: the attribute stops the cookie being
        # sent on plain HTTP, which is moot if the whole site is HTTP - that
        # case is covered by transport-plaintext.
        if ctx.is_https and not cookie["secure"]:
            findings.append(
                build_passive_rule_finding(
                    "cookie-secure",
                    location=ctx.url,
                    confidence="High",
                    scan_origin=origin,
                    evidence=evidence,
                    severity=None if is_session else "Medium",
                    cookie_name=name,
                )
            )

        # -- HttpOnly -----------------------------------------------------
        # A cookie the front end must read legitimately omits this, so
        # non-session cookies are reported at lower severity and confidence
        # rather than suppressed.
        if not cookie["httponly"]:
            findings.append(
                build_passive_rule_finding(
                    "cookie-httponly",
                    location=ctx.url,
                    confidence="High" if is_session else "Low",
                    scan_origin=origin,
                    evidence=evidence,
                    severity=None if is_session else "Low",
                    cookie_name=name,
                )
            )

        # -- SameSite -----------------------------------------------------
        samesite = cookie["samesite"]
        if samesite is None or samesite == "none":
            findings.append(
                build_passive_rule_finding(
                    "cookie-samesite",
                    location=ctx.url,
                    confidence="High" if is_session else "Medium",
                    scan_origin=origin,
                    evidence=evidence,
                    severity=None if is_session else "Low",
                    cookie_name=name,
                )
            )

    return findings


def _redact_cookie(cookie: dict) -> str:
    """Rebuild a Set-Cookie line with the value replaced.

    Findings are stored in the database and exported into reports, so the
    actual session value must not travel with them.
    """
    raw = cookie["raw"]
    value = cookie["value"]
    if value:
        raw = raw.replace(value, "<redacted>", 1)
    return raw


# ---------------------------------------------------------------------------
# Transport checks
# ---------------------------------------------------------------------------

def check_transport(ctx: HttpContext) -> list[dict]:
    """Report a target that stays on plain HTTP.

    The crawler follows redirects, so a final HTTP response means no upgrade
    to HTTPS happened anywhere in the chain. A request that started on HTTP
    and finished on HTTPS was upgraded correctly and is not reported.
    """
    if ctx.is_https or ctx.was_upgraded:
        return []
    if ctx.scheme != "http":
        return []

    hops = len(ctx.redirect_chain)
    evidence = (
        f"final scheme http after {hops} redirect(s)"
        if hops else "no redirect to HTTPS observed"
    )

    return [
        build_passive_rule_finding(
            "transport-plaintext",
            location=ctx.url,
            confidence="High",
            scan_origin=ctx_origin(ctx),
            evidence=evidence,
            param_location="",
        )
    ]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def ctx_origin(ctx: HttpContext) -> str:
    """Scan origin for findings from this context.

    Passive checks only ever run against a fetched URL, so this is always
    Dynamic. Kept as a function so a future static HTTP replay can override
    it in one place.
    """
    return "Dynamic"


def run_passive_checks(ctx: HttpContext) -> list[dict]:
    """Run every passive check against a fetched response.

    Args:
        ctx: A successful fetch. Callers should check ``ctx.ok`` first; an
            unsuccessful context yields no findings rather than an error,
            since there is no response to describe.

    Returns:
        Findings from all passive rules, unsorted. The caller decides
        ordering - see :func:`security_checks.schema.sort_findings`.
    """
    if not ctx or not ctx.ok:
        return []

    # Every finding needs a location. A context without one cannot be
    # attributed to anything, so there is nothing meaningful to report.
    if not ctx.url:
        return []

    findings: list[dict] = []
    findings.extend(check_security_headers(ctx))
    findings.extend(check_cookies(ctx))
    findings.extend(check_transport(ctx))
    return findings