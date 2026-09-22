from __future__ import annotations
import re
from security_checks.finding_builder import build_passive_rule_finding, build_passive_finding
from security_checks.http_context import HttpContext
VERSION_BANNER_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
)
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
_BANNER_IGNORE = ("cloudflare", "cloudfront", "akamai")
_DIR_LISTING_SIGNS = (
    "index of /",
    "directory listing for",
    "<title>directory listing",
    "parent directory</a>",
    "[to parent directory]",
)
_KEY_MATERIAL_SIGNS = (
    "-----begin rsa private key-----",
    "-----begin private key-----",
    "-----begin ec private key-----",
    "-----begin public key-----",
    "-----begin rsa public key-----",
    "-----begin certificate-----",
    '"kty":"rsa"',
    '"kty": "rsa"',
)
_VERBOSE_ERROR_SIGNS = (
    "traceback (most recent call last)",
    "stack trace",
    "referenceerror",
    "whitelabel error page",
    "sequelizedatabaseerror",
    "java.lang.",
    "system.nullreferenceexception",
)
_SENSITIVE_PATH_RE = re.compile(
    r"(?i)/(?:metrics|debug|console|trace|actuator(?:/[^/]+)?|"
    r"server-status|phpinfo\.php|\.git(?:/|$)|\.env|env\.js|"
    r"adminer|phpmyadmin|debug/default/view|"
    r"ftp/?|backup/?|backups/?|uploads/?|"
    r"package\.json|package-lock\.json|"
    r"encryptionkeys(?:/[^/]+)?|jwks\.json|jwt\.pub)$"
)
_PRIVILEGED_ROUTE_RE = re.compile(
    r"(?i)(?:/#/|/#!?/|path\s*:\s*['\"]/)(?:administration|admin|"
    r"debug|internal|console)\b"
)
_FORM_RE = re.compile(r"(?is)<form\b([^>]*)>(.*?)</form>")
_INPUT_NAME_RE = re.compile(r"(?is)<input\b[^>]*\bname\s*=\s*['\"]([^'\"]+)['\"]")
_METHOD_RE = re.compile(r"(?i)\bmethod\s*=\s*['\"]([^'\"]+)['\"]")
_TOKEN_NAME_RE = re.compile(r"(csrf|xsrf|_token|authenticity|anti[-_]?forgery)", re.I)
_UNSAFE_CSP_RE = re.compile(
    r"(unsafe-inline|unsafe-eval|script-src[^;]*\*)",
    re.I,
)
def _looks_versioned(value: str) -> bool:
    text = (value or "").strip()
    if not text:
        return False
    if any(vendor in text.lower() for vendor in _BANNER_IGNORE):
        return False
    return any(ch.isdigit() for ch in text)
def parse_set_cookie(raw: str) -> dict:
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
    low = (name or "").lower()
    return any(hint in low for hint in SESSION_COOKIE_HINTS)
def ctx_origin(ctx: HttpContext) -> str:
    return "Dynamic"
def check_security_headers(ctx: HttpContext) -> list[dict]:
    findings: list[dict] = []
    location = ctx.url
    if not ctx.has_header("x-frame-options"):
        if not ctx.has_csp_directive("frame-ancestors"):
            findings.append(
                build_passive_rule_finding(
                    "header-xfo",
                    location=location,
                    scan_origin=ctx_origin(ctx),
                )
            )
    if not ctx.has_header("content-security-policy"):
        report_only = ctx.has_header("content-security-policy-report-only")
        findings.append(
            build_passive_rule_finding(
                "header-csp",
                location=location,
                scan_origin=ctx_origin(ctx),
                evidence=(
                    "Content-Security-Policy-Report-Only is set instead"
                    if report_only else ""
                ),
            )
        )
    if ctx.is_https and not ctx.has_header("strict-transport-security"):
        findings.append(
            build_passive_rule_finding(
                "header-hsts",
                location=location,
                scan_origin=ctx_origin(ctx),
            )
        )
    nosniff = ctx.header("x-content-type-options").strip().lower()
    if nosniff != "nosniff":
        findings.append(
            build_passive_rule_finding(
                "header-nosniff",
                location=location,
                scan_origin=ctx_origin(ctx),
                evidence=(
                    f"X-Content-Type-Options: {nosniff}" if nosniff else ""
                ),
            )
        )
    if not ctx.has_header("referrer-policy"):
        findings.append(
            build_passive_rule_finding(
                "header-referrer-policy",
                location=location,
                scan_origin=ctx_origin(ctx),
            )
        )
    if not ctx.has_header("permissions-policy") and not ctx.has_header("feature-policy"):
        findings.append(
            build_passive_rule_finding(
                "header-permissions-policy",
                location=location,
                scan_origin=ctx_origin(ctx),
            )
        )
    findings.extend(check_version_disclosure(ctx))
    findings.extend(check_cors(ctx))
    findings.extend(check_weak_csp(ctx))
    return findings
def check_weak_csp(ctx: HttpContext) -> list[dict]:
    csp = ctx.header("content-security-policy").strip()
    if not csp:
        return []
    hit = _UNSAFE_CSP_RE.search(csp)
    if not hit:
        return []
    return [
        build_passive_finding(
            severity="Medium",
            vulnerability="Weak Content-Security-Policy",
            location=ctx.url,
            description=(
                "The Content-Security-Policy header allows unsafe script execution "
                f"({hit.group(1)}). Injected script can still run in the page."
            ),
            remediation=(
                "Remove unsafe-inline and unsafe-eval from script-src. "
                "Use nonces or hashes and avoid wildcard script sources."
            ),
            cwe_id="CWE-1021",
            wasc_id="WASC-15",
            owasp="A05:2025 Security Misconfiguration",
            nist="NIST SP 800-53 Rev. 5 SC-7",
            sans="Not in CWE Top 25 (2025)",
            scan_origin=ctx_origin(ctx),
            plugin_id="weak-csp",
            vuln_type="generic",
            evidence=f"CSP contains {hit.group(1)}",
        )
    ]
def check_cors(ctx: HttpContext) -> list[dict]:
    acao = ctx.header("access-control-allow-origin").strip()
    if acao != "*":
        return []
    acac = ctx.header("access-control-allow-credentials").strip().lower()
    creds = acac in ("true", "1")
    evidence = "Access-Control-Allow-Origin: *"
    if creds:
        evidence += "; Access-Control-Allow-Credentials: " + acac
    return [
        build_passive_rule_finding(
            "header-cors",
            location=ctx.url,
            scan_origin=ctx_origin(ctx),
            evidence=evidence,
            severity="High" if creds else "Medium",
        )
    ]
def check_version_disclosure(ctx: HttpContext) -> list[dict]:
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
            scan_origin=ctx_origin(ctx),
            evidence=evidence,
            header_name=first_name,
            header_value=first_value,
        )
    ]
def check_cookies(ctx: HttpContext) -> list[dict]:
    findings: list[dict] = []
    origin = ctx_origin(ctx)
    for raw in ctx.set_cookies:
        cookie = parse_set_cookie(raw)
        name = cookie["name"]
        if not name:
            continue
        is_session = _is_session_cookie(name)
        evidence = _redact_cookie(cookie)
        if ctx.is_https and not cookie["secure"]:
            findings.append(
                build_passive_rule_finding(
                    "cookie-secure",
                    location=ctx.url,
                    scan_origin=origin,
                    evidence=evidence,
                    severity=None if is_session else "Medium",
                    cookie_name=name,
                )
            )
        if not cookie["httponly"]:
            findings.append(
                build_passive_rule_finding(
                    "cookie-httponly",
                    location=ctx.url,
                    scan_origin=origin,
                    evidence=evidence,
                    severity=None if is_session else "Low",
                    cookie_name=name,
                )
            )
        samesite = cookie["samesite"]
        if samesite is None or samesite == "none":
            findings.append(
                build_passive_rule_finding(
                    "cookie-samesite",
                    location=ctx.url,
                    scan_origin=origin,
                    evidence=evidence,
                    severity=None if is_session else "Low",
                    cookie_name=name,
                )
            )
    return findings
def _redact_cookie(cookie: dict) -> str:
    raw = cookie["raw"]
    value = cookie["value"]
    if value:
        raw = raw.replace(value, "<redacted>", 1)
    return raw
def check_transport(ctx: HttpContext) -> list[dict]:
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
            scan_origin=ctx_origin(ctx),
            evidence=evidence,
            param_location="",
        )
    ]
def check_directory_listing(ctx: HttpContext) -> list[dict]:
    if int(getattr(ctx, "status", 0) or 0) not in (200, 203):
        return []
    low = (ctx.body or "").lower()
    hit = next((sig for sig in _DIR_LISTING_SIGNS if sig in low), None)
    if not hit:
        return []
    return [
        build_passive_rule_finding(
            "dir-listing",
            location=ctx.url,
            scan_origin=ctx_origin(ctx),
            evidence=f"listing signature: '{hit}'",
        )
    ]
def check_sensitive_path(ctx: HttpContext) -> list[dict]:
    if int(getattr(ctx, "status", 0) or 0) not in (200, 203):
        return []
    path = ""
    try:
        from urllib.parse import urlparse
        path = urlparse(ctx.url or "").path or ""
    except Exception:
        path = ctx.url or ""
    if not _SENSITIVE_PATH_RE.search(path):
        return []
    return [
        build_passive_rule_finding(
            "sensitive-path",
            location=ctx.url,
            scan_origin=ctx_origin(ctx),
            evidence=f"diagnostic or internal path returned HTTP {ctx.status}",
        )
    ]
def check_key_material(ctx: HttpContext) -> list[dict]:
    low = (ctx.body or "").lower()
    hit = next((sig for sig in _KEY_MATERIAL_SIGNS if sig in low), None)
    if not hit:
        return []
    return [
        build_passive_rule_finding(
            "exposed-key-material",
            location=ctx.url,
            scan_origin=ctx_origin(ctx),
            evidence=f"key material signature: '{hit}'",
        )
    ]
def check_verbose_error_body(ctx: HttpContext) -> list[dict]:
    if int(getattr(ctx, "status", 0) or 0) < 400:
        return []
    low = (ctx.body or "").lower()
    hit = next((sig for sig in _VERBOSE_ERROR_SIGNS if sig in low), None)
    if not hit:
        return []
    return [
        build_passive_rule_finding(
            "verbose-error",
            location=ctx.url,
            scan_origin=ctx_origin(ctx),
            evidence=f"error body contains '{hit}'",
        )
    ]
def check_client_privileged_routes(ctx: HttpContext) -> list[dict]:
    body = ctx.body or ""
    ctype = ""
    try:
        ctype = ctx.header("content-type").lower()
    except Exception:
        pass
    if "javascript" not in ctype and "html" not in ctype and "<script" not in body.lower():
        if not body.lstrip().startswith(("!", "(", "{")):
            return []
    match = _PRIVILEGED_ROUTE_RE.search(body)
    if not match:
        return []
    return [
        build_passive_rule_finding(
            "client-privileged-route",
            location=ctx.url,
            scan_origin=ctx_origin(ctx),
            evidence=f"client bundle names route '{match.group(0)}'",
        )
    ]
def check_csrf_forms(ctx: HttpContext) -> list[dict]:
    """POST forms that change state should carry an anti-CSRF field."""
    body = ctx.body or ""
    if "<form" not in body.lower():
        return []
    findings = []
    for attrs, inner in _FORM_RE.findall(body):
        method_m = _METHOD_RE.search(attrs or "")
        method = (method_m.group(1) if method_m else "GET").upper()
        if method != "POST":
            continue
        names = _INPUT_NAME_RE.findall(inner or "")
        if any(_TOKEN_NAME_RE.search(n or "") for n in names):
            continue
        findings.append(
            build_passive_finding(
                severity="Medium",
                vulnerability="State-changing form without CSRF token",
                location=ctx.url,
                description=(
                    f"A POST form on {ctx.url} has no hidden field whose name "
                    "looks like a CSRF / anti-forgery token. A third-party page "
                    "can submit that form using the victim's session."
                ),
                remediation=(
                    "Add a per-session anti-CSRF token as a hidden field and "
                    "reject POST requests that omit or mismatch the token. "
                    "Prefer SameSite=Lax or Strict cookies as defence in depth."
                ),
                cwe_id="CWE-352",
                wasc_id="WASC-9",
                owasp="A01:2025 Broken Access Control",
                nist="NIST SP 800-53 Rev. 5 SC-23",
                sans="CWE Top 25 (2025)",
                scan_origin=ctx_origin(ctx),
                plugin_id="csrf-form",
                param_location="body",
                evidence="POST form has no csrf/xsrf/token input name",
            )
        )
        break
    return findings
def check_weak_session_id(ctx: HttpContext) -> list[dict]:
    """Short or numeric-only session cookies are guessable."""
    findings = []
    for raw in ctx.set_cookies:
        cookie = parse_set_cookie(raw)
        name = cookie["name"]
        value = cookie["value"]
        if not name or not _is_session_cookie(name):
            continue
        if not value:
            continue
        weak = value.isdigit() and len(value) <= 8
        weak = weak or (len(value) <= 6)
        if not weak:
            continue
        findings.append(
            build_passive_finding(
                severity="Medium",
                vulnerability="Weak session identifier",
                location=ctx.url,
                description=(
                    f"Session cookie '{name}' on {ctx.url} has a short or "
                    "numeric-only value, so identifiers may be predictable."
                ),
                remediation=(
                    "Issue session identifiers from a CSPRNG with at least "
                    "128 bits of entropy. Do not use incrementing integers."
                ),
                cwe_id="CWE-330",
                wasc_id="WASC-18",
                owasp="A07:2025 Identification and Authentication Failures",
                nist="NIST SP 800-53 Rev. 5 IA-5",
                sans="CWE Top 25 (2025)",
                scan_origin=ctx_origin(ctx),
                plugin_id="weak-session-id",
                param_location="cookie",
                evidence=f"cookie {name} length={len(value)} numeric={value.isdigit()}",
            )
        )
    return findings
_PASSWORD_INPUT_RE = re.compile(
    r"""(?is)<input\b[^>]*\btype\s*=\s*['"]password['"][^>]*>"""
)
_AUTOCOMPLETE_RE = re.compile(r"""autocomplete\s*=\s*['"]([^'"]+)['"]""", re.I)


def check_password_autocomplete(ctx: HttpContext) -> list[dict]:
    """Hygiene: password fields that still allow the browser to store the value."""
    body = ctx.body or ""
    if "password" not in body.lower() or "<input" not in body.lower():
        return []
    for raw in _PASSWORD_INPUT_RE.findall(body):
        ac = _AUTOCOMPLETE_RE.search(raw or "")
        value = (ac.group(1) if ac else "").strip().lower()
        if value in ("off", "new-password", "one-time-code"):
            continue
        return [
            build_passive_rule_finding(
                "password-autocomplete",
                location=ctx.url,
                scan_origin=ctx_origin(ctx),
                evidence="password input without autocomplete=off/new-password",
            )
        ]
    return []


def run_passive_checks(ctx: HttpContext) -> list[dict]:
    if not ctx or not ctx.ok:
        return []
    if not ctx.url:
        return []
    findings: list[dict] = []
    findings.extend(check_security_headers(ctx))
    findings.extend(check_cookies(ctx))
    findings.extend(check_transport(ctx))
    findings.extend(check_directory_listing(ctx))
    findings.extend(check_sensitive_path(ctx))
    findings.extend(check_key_material(ctx))
    findings.extend(check_verbose_error_body(ctx))
    findings.extend(check_client_privileged_routes(ctx))
    findings.extend(check_csrf_forms(ctx))
    findings.extend(check_weak_session_id(ctx))
    findings.extend(check_password_autocomplete(ctx))
    return findings
