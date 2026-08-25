from __future__ import annotations

RULES: dict[str, dict] = {

    # ------------------------------------------------------------------
    # Security response headers
    # ------------------------------------------------------------------

    "header-xfo": {
        "vulnerability": "Missing X-Frame-Options Header",
        "severity": "Medium",
        "cwe_id": "CWE-1021",
        "wasc_id": "WASC-15",
        "owasp": "A05:2021 Security Misconfiguration",
        "nist": "NIST SP 800-53 SC-18",
        "sans": "Not in CWE Top 25 (2024)",
        "description_template": (
            "The X-Frame-Options response header is not set on {location}, and "
            "no Content-Security-Policy frame-ancestors directive was found. "
            "The page can therefore be embedded in a frame or iframe by another "
            "origin, which allows an attacker to overlay it with their own "
            "interface and trick a user into clicking controls they cannot see."
        ),
        "remediation": (
            "Set 'X-Frame-Options: DENY' on responses that should never be "
            "framed, or 'SAMEORIGIN' if your own pages need to frame them. For "
            "modern browsers prefer the Content-Security-Policy directive "
            "\"frame-ancestors 'none'\" (or an explicit origin list), which "
            "supersedes X-Frame-Options."
        ),
    },

    "header-csp": {
        "vulnerability": "Missing Content-Security-Policy Header",
        "severity": "Medium",
        "cwe_id": "CWE-693",
        "wasc_id": "WASC-15",
        "owasp": "A05:2021 Security Misconfiguration",
        "nist": "NIST SP 800-53 SC-18",
        "sans": "Not in CWE Top 25 (2024)",
        "description_template": (
            "No Content-Security-Policy header was returned by {location}. "
            "Without a policy the browser will execute script from any source "
            "the page references, so the application loses its main defence-in-"
            "depth control against cross-site scripting and injected content."
        ),
        "remediation": (
            "Define a Content-Security-Policy header starting from a restrictive "
            "baseline such as \"default-src 'self'\" and widen it only for "
            "origins the application genuinely needs. Avoid 'unsafe-inline' and "
            "'unsafe-eval'; deploy in Content-Security-Policy-Report-Only mode "
            "first to find breakage before enforcing."
        ),
    },

    "header-hsts": {
        "vulnerability": "Missing Strict-Transport-Security Header",
        "severity": "Medium",
        "cwe_id": "CWE-319",
        "wasc_id": "WASC-4",
        "owasp": "A02:2021 Cryptographic Failures",
        "nist": "NIST SP 800-53 SC-8",
        "sans": "Not in CWE Top 25 (2024)",
        "description_template": (
            "{location} is served over HTTPS but does not return a "
            "Strict-Transport-Security header. A browser that has not yet seen "
            "the header may be persuaded to make a first request over plain "
            "HTTP, giving a network attacker an opportunity to intercept or "
            "downgrade the connection before the redirect to HTTPS happens."
        ),
        "remediation": (
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
            "to HTTPS responses. Confirm every subdomain is reachable over HTTPS "
            "before enabling includeSubDomains, and consider preload submission "
            "once the policy has been stable in production."
        ),
    },

    "header-nosniff": {
        "vulnerability": "Missing X-Content-Type-Options Header",
        "severity": "Low",
        "cwe_id": "CWE-693",
        "wasc_id": "WASC-15",
        "owasp": "A05:2021 Security Misconfiguration",
        "nist": "NIST SP 800-53 SC-18",
        "sans": "Not in CWE Top 25 (2024)",
        "description_template": (
            "The X-Content-Type-Options header is missing or not set to "
            "'nosniff' on {location}. Browsers may then ignore the declared "
            "Content-Type and infer the type from the response body, so a file "
            "served as text or as an upload could be interpreted as script."
        ),
        "remediation": (
            "Return 'X-Content-Type-Options: nosniff' on all responses and make "
            "sure each response carries an accurate Content-Type header, "
            "including a charset for text types."
        ),
    },

    "header-referrer-policy": {
        "vulnerability": "Missing Referrer-Policy Header",
        "severity": "Low",
        "cwe_id": "CWE-200",
        "wasc_id": "WASC-13",
        "owasp": "A05:2021 Security Misconfiguration",
        "nist": "NIST SP 800-53 AC-4",
        "sans": "CWE Top 25 (2024) - #17",
        "description_template": (
            "No Referrer-Policy header was returned by {location}. The browser "
            "default may send the full URL, including path and query string, to "
            "third-party sites the user navigates to, which can leak identifiers "
            "or tokens embedded in the URL."
        ),
        "remediation": (
            "Set 'Referrer-Policy: strict-origin-when-cross-origin' (or "
            "'no-referrer' where no referrer information is needed). Separately, "
            "avoid placing session tokens or other sensitive values in URLs."
        ),
    },

    "info-disclosure-server": {
        "vulnerability": "Server or Framework Version Disclosure",
        "severity": "Low",
        "cwe_id": "CWE-200",
        "wasc_id": "WASC-13",
        "owasp": "A05:2021 Security Misconfiguration",
        "nist": "NIST SP 800-53 CM-6",
        "sans": "CWE Top 25 (2024) - #17",
        "description_template": (
            "A response header from {location} discloses software version "
            "information ({header_name}: {header_value}). Version banners let an "
            "attacker match the target against published vulnerabilities for "
            "that exact release without probing the application further."
        ),
        "remediation": (
            "Suppress or genericise version banners. Remove application-level "
            "headers such as X-Powered-By, X-AspNet-Version and X-Generator at "
            "the framework level, and configure the web server to emit a product "
            "name without a version (for example 'server_tokens off' in nginx or "
            "'ServerTokens Prod' in Apache)."
        ),
    },

    # ------------------------------------------------------------------
    # Cookie attributes
    # ------------------------------------------------------------------

    "cookie-secure": {
        "vulnerability": "Cookie Set Without Secure Flag",
        "severity": "High",
        "cwe_id": "CWE-614",
        "wasc_id": "WASC-4",
        "owasp": "A02:2021 Cryptographic Failures",
        "nist": "NIST SP 800-53 SC-8",
        "sans": "Not in CWE Top 25 (2024)",
        "description_template": (
            "The cookie '{cookie_name}' is set by {location} without the Secure "
            "attribute. The browser will attach it to plain HTTP requests to the "
            "same host, so any request that falls back to HTTP exposes the cookie "
            "value to anyone observing the network path."
        ),
        "remediation": (
            "Add the Secure attribute to every cookie set over HTTPS, especially "
            "session and authentication cookies, and serve the application over "
            "HTTPS only so no downgrade path remains."
        ),
    },

    "cookie-httponly": {
        "vulnerability": "Cookie Set Without HttpOnly Flag",
        "severity": "Medium",
        "cwe_id": "CWE-1004",
        "wasc_id": "WASC-15",
        "owasp": "A05:2021 Security Misconfiguration",
        "nist": "NIST SP 800-53 SC-23",
        "sans": "Not in CWE Top 25 (2024)",
        "description_template": (
            "The cookie '{cookie_name}' is set by {location} without the HttpOnly "
            "attribute, so client-side script can read it through "
            "document.cookie. If the application is ever affected by cross-site "
            "scripting, the session value can be read and exfiltrated directly."
        ),
        "remediation": (
            "Add the HttpOnly attribute to session and authentication cookies. "
            "Only omit it for cookies that front-end code genuinely has to read, "
            "and keep no sensitive value in those."
        ),
    },

    "cookie-samesite": {
        "vulnerability": "Cookie Missing or Weak SameSite Attribute",
        "severity": "Medium",
        "cwe_id": "CWE-1275",
        "wasc_id": "WASC-9",
        "owasp": "A01:2021 Broken Access Control",
        "nist": "NIST SP 800-53 SC-23",
        "sans": "Not in CWE Top 25 (2024)",
        "description_template": (
            "The cookie '{cookie_name}' set by {location} has no SameSite "
            "attribute or uses SameSite=None. The cookie is therefore sent on at "
            "least some cross-site requests, which weakens the browser's built-in "
            "protection against cross-site request forgery."
        ),
        "remediation": (
            "Set 'SameSite=Lax' as a baseline, or 'SameSite=Strict' for cookies "
            "that never need to survive a cross-site navigation. Use "
            "'SameSite=None' only where a genuine cross-site flow requires it, "
            "and always pair it with the Secure attribute. Keep anti-CSRF tokens "
            "in place regardless."
        ),
    },

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    "transport-plaintext": {
        "vulnerability": "Application Served Over Plain HTTP",
        "severity": "Medium",
        "cwe_id": "CWE-319",
        "wasc_id": "WASC-4",
        "owasp": "A02:2021 Cryptographic Failures",
        "nist": "NIST SP 800-53 SC-8",
        "sans": "Not in CWE Top 25 (2024)",
        "description_template": (
            "{location} was served over plain HTTP and no redirect to an HTTPS "
            "equivalent was observed. Request and response contents, including "
            "any credentials or session cookies, travel unencrypted and can be "
            "read or altered by anyone on the network path."
        ),
        "remediation": (
            "Serve the application over HTTPS and return a permanent redirect "
            "from the HTTP listener to the HTTPS URL. Once the redirect is in "
            "place, add Strict-Transport-Security so browsers stop attempting "
            "HTTP on later visits."
        ),
    },

    # ------------------------------------------------------------------
    # Injection (Active Test context supplied by injection_checks.py)
    # ------------------------------------------------------------------

    "xss-reflected": {
        "vulnerability": "Potential Reflected Cross-Site Scripting",
        "severity": "High",
        "cwe_id": "CWE-79",
        "wasc_id": "WASC-8",
        "owasp": "A03:2021 Injection",
        "nist": "NIST SP 800-53 SI-10",
        "sans": "CWE Top 25 (2024) - #1",
        "description_template": (
            "A value supplied in the '{param}' parameter was returned inside the "
            "HTML response from {location} without evidence of contextual "
            "encoding. If the reflection is genuinely unencoded, an attacker can "
            "craft a link that executes script in the victim's browser under this "
            "origin."
        ),
        "remediation": (
            "Encode all user-controlled data for the context it is rendered into "
            "(HTML body, attribute, JavaScript, URL) using the framework's "
            "built-in escaping rather than manual replacement. Validate input "
            "against an allow-list where the format is known, and deploy a strict "
            "Content-Security-Policy as defence in depth."
        ),
    },

    "sqli-error": {
        "vulnerability": "Potential SQL Injection",
        "severity": "High",
        "cwe_id": "CWE-89",
        "wasc_id": "WASC-19",
        "owasp": "A03:2021 Injection",
        "nist": "NIST SP 800-53 SI-10",
        "sans": "CWE Top 25 (2024) - #3",
        "description_template": (
            "The response from {location} contained database error indicators "
            "after the '{param}' parameter was varied. This suggests the value "
            "reaches a data-query path without adequate handling, though an "
            "unrelated application fault can produce the same signature."
        ),
        "remediation": (
            "Use parameterised queries or prepared statements and never build SQL "
            "by concatenating user input. Apply least-privilege database "
            "accounts, and return generic error pages so database messages are "
            "not exposed to the client."
        ),
    },

    # ------------------------------------------------------------------
    # Static analysis
    # ------------------------------------------------------------------

    "static-env-file": {
        "vulnerability": "Environment File Committed to Project",
        "severity": "High",
        "cwe_id": "CWE-540",
        "wasc_id": "WASC-13",
        "owasp": "A05:2021 Security Misconfiguration",
        "nist": "NIST SP 800-53 CM-6",
        "sans": "Not in CWE Top 25 (2024)",
        "description_template": (
            "An environment file was found in the project at {location}. These "
            "files usually hold database passwords, API keys and signing "
            "secrets. Anyone with repository access can read them, and if the "
            "file is inside the web root it may also be retrievable over HTTP."
        ),
        "remediation": (
            "Remove the file from version control and add its name to "
            ".gitignore. Rotate every credential it contained, since the values "
            "must be treated as exposed. Commit a .env.example holding key "
            "names with placeholder values so the required configuration is "
            "still documented, and confirm the web server refuses to serve "
            "dotfiles."
        ),
    },

    "static-debug-enabled": {
        "vulnerability": "Debug Mode Enabled in Configuration",
        "severity": "Medium",
        "cwe_id": "CWE-489",
        "wasc_id": "WASC-13",
        "owasp": "A05:2021 Security Misconfiguration",
        "nist": "NIST SP 800-53 CM-7",
        "sans": "Not in CWE Top 25 (2024)",
        "description_template": (
            "A debug setting appears to be enabled in {location} ({evidence_hint}). "
            "Debug modes return stack traces, configuration values and "
            "environment details in error responses, which hands an attacker a "
            "map of the application's internals."
        ),
        "remediation": (
            "Disable debug mode for any deployed environment and drive the "
            "setting from an environment variable rather than a committed "
            "value. Return generic error pages to users and send the detail to "
            "a server-side log instead."
        ),
    },

    "static-secret-pattern": {
        "vulnerability": "Hard-coded Credential Pattern",
        "severity": "Medium",
        "cwe_id": "CWE-798",
        "wasc_id": "WASC-15",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "nist": "NIST SP 800-53 IA-5",
        "sans": "CWE Top 25 (2024) - #22",
        "description_template": (
            "A pattern resembling a hard-coded credential or API key was found in "
            "{location}. Secrets committed to source are readable by anyone with "
            "repository access and remain in version-control history after they "
            "are removed from the working tree."
        ),
        "remediation": (
            "Move the value to an environment variable or secret manager and load "
            "it at runtime. Rotate any credential that has been committed, since "
            "it must be treated as exposed, and add a pre-commit secret scanner "
            "to prevent recurrence."
        ),
    },
}


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

#: Keys every catalogue entry must define.
RULE_KEYS = (
    "vulnerability",
    "severity",
    "cwe_id",
    "wasc_id",
    "owasp",
    "nist",
    "sans",
    "description_template",
    "remediation",
)


def get_rule(plugin_id: str) -> dict:
    """Return the catalogue entry for ``plugin_id``.

    Raises:
        KeyError: if the rule is not defined. Failing loudly is deliberate - a
            typo in a detection module should not silently produce a finding
            with blank standards metadata.
    """
    key = str(plugin_id or "").strip()
    if key not in RULES:
        known = ", ".join(sorted(RULES)) or "<none>"
        raise KeyError(f"Unknown rule id {key!r}. Defined rules: {known}")
    return RULES[key]


def list_rule_ids() -> list[str]:
    """All defined rule ids, sorted."""
    return sorted(RULES)


def validate_catalogue() -> list[str]:
    """Check every entry defines all required keys. Empty list means OK.

    Call this once from the test suite so a half-written rule is caught before
    it reaches a scan.
    """
    problems: list[str] = []
    for rid in sorted(RULES):
        rule = RULES[rid]
        for key in RULE_KEYS:
            if not str(rule.get(key) or "").strip():
                problems.append(f"{rid}: missing {key}")
    return problems


def coverage_rows() -> list[tuple[str, str, str, str, str]]:
    """Catalogue as rows of (id, name, severity, cwe, owasp).

    Convenience for the Detection section of the final report and for a quick
    'what do we actually cover?' check during team meetings.
    """
    return [
        (
            rid,
            RULES[rid]["vulnerability"],
            RULES[rid]["severity"],
            RULES[rid]["cwe_id"],
            RULES[rid]["owasp"],
        )
        for rid in list_rule_ids()
    ]