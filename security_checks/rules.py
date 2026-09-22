from __future__ import annotations

RULES: dict[str, dict] = {
    "header-xfo": {
        "vulnerability": "Missing X-Frame-Options Header",
        "severity": "Medium",
        "cwe_id": "CWE-1021",
        "wasc_id": "WASC-15",
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 SC-18",
        "sans": "Not in CWE Top 25 (2025)",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 SC-18",
        "sans": "Not in CWE Top 25 (2025)",
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
        "owasp": "A04:2025 Cryptographic Failures",
        "nist": "NIST SP 800-53 Rev. 5 SC-8",
        "sans": "Not in CWE Top 25 (2025)",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 SC-18",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "The X-Content-Type-Options header is missing or not set to "
            "'nosniff' on {location}. Browsers may then ignore the declared "
            "Content-Type and infer the type from the body, so a file "
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
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 AC-4",
        "sans": "In CWE Top 25 (2025)",
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
    "header-cors": {
        "vulnerability": "Permissive Cross-Origin Resource Sharing",
        "severity": "Medium",
        "cwe_id": "CWE-942",
        "wasc_id": "WASC-15",
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 AC-4",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "{location} returns Access-Control-Allow-Origin: *, so any site can "
            "read the response from a victim's browser. If credentials are also "
            "allowed, authenticated content can be retrieved across origins."
        ),
        "remediation": (
            "Reflect only trusted origins in Access-Control-Allow-Origin. Do not "
            "use '*' on responses that carry private data. Never combine '*' "
            "with Access-Control-Allow-Credentials: true."
        ),
    },
    "info-disclosure-server": {
        "vulnerability": "Server or Framework Version Disclosure",
        "severity": "Low",
        "cwe_id": "CWE-200",
        "wasc_id": "WASC-13",
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 CM-6",
        "sans": "In CWE Top 25 (2025)",
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
    "verbose-error": {
        "vulnerability": "Verbose Error or Stack Trace Disclosure",
        "severity": "Medium",
        "cwe_id": "CWE-209",
        "wasc_id": "WASC-13",
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 SI-11",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "A request to {location} returned an error body that includes "
            "implementation detail such as a stack trace, SQL fragment, "
            "framework path or exception class. That material maps internals "
            "for follow-on attacks and is not needed by an end user."
        ),
        "remediation": (
            "Return a generic client error page. Log the exception server-side "
            "only. Disable debug modes in deployed environments and ensure "
            "database and framework errors are never forwarded in HTTP bodies."
        ),
    },
    "dir-listing": {
        "vulnerability": "Directory Listing Enabled",
        "severity": "Medium",
        "cwe_id": "CWE-548",
        "wasc_id": "WASC-16",
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 CM-6",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "{location} returns an index of files and folders rather than a "
            "default document. Listing exposes names that are not linked from "
            "the application and often includes backups, documents or source "
            "archives that should not be public."
        ),
        "remediation": (
            "Disable autoindexing on the web server and application static "
            "handler. Serve only an explicit default document, and block "
            "direct listing of upload, backup and document directories."
        ),
    },
    "sensitive-path": {
        "vulnerability": "Sensitive Path Exposure",
        "severity": "Medium",
        "cwe_id": "CWE-538",
        "wasc_id": "WASC-16",
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 AC-3",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "{location} is reachable without an application-level control and "
            "exposes an operational or diagnostic surface (metrics, debug, "
            "console, dump or similar). The contents are useful for mapping "
            "the deployment even when they do not contain credentials."
        ),
        "remediation": (
            "Remove diagnostic endpoints from publicly reachable listeners, or "
            "bind them to an internal network and require authentication. "
            "Do not publish raw metrics or debug consoles on the same origin "
            "as the user application."
        ),
    },
    "sensitive-file": {
        "vulnerability": "Sensitive File Publicly Retrievable",
        "severity": "High",
        "cwe_id": "CWE-538",
        "wasc_id": "WASC-13",
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 AC-3",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "A file retrieved from {location} matches a sensitive-name pattern "
            "(backup, environment, key material, internal document or dump). "
            "The body was returned to an unauthenticated request, so anyone "
            "who can guess or list the path can read it."
        ),
        "remediation": (
            "Keep backups, keys and internal documents outside the web root. "
            "Deny by extension for .bak, .env, .pem, .key and similar names. "
            "Rotate any secret that was served."
        ),
    },
    "exposed-key-material": {
        "vulnerability": "Cryptographic Key Material Exposed",
        "severity": "High",
        "cwe_id": "CWE-321",
        "wasc_id": "WASC-13",
        "owasp": "A04:2025 Cryptographic Failures",
        "nist": "NIST SP 800-53 Rev. 5 SC-12",
        "sans": "CWE Top 25 (2025) - #8",
        "description_template": (
            "{location} returned content that matches published key material "
            "(PEM, JWK, or a clearly labelled public/private key file). Even a "
            "public verification key can enable algorithm-confusion or token "
            "forgery against a misconfigured verifier; a private key is a "
            "direct compromise."
        ),
        "remediation": (
            "Do not serve key files from the application origin. Store keys in "
            "a secrets manager or filesystem outside the web root. Restrict "
            "JWT libraries to an explicit algorithm allow-list so a published "
            "verification key cannot be reused as an HMAC secret."
        ),
    },
    "client-privileged-route": {
        "vulnerability": "Privileged Client Route Disclosed in Script",
        "severity": "Low",
        "cwe_id": "CWE-497",
        "wasc_id": "WASC-13",
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 CM-6",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "A client script loaded from {location} contains a route or "
            "endpoint name associated with administration, scoring, debug or "
            "internal tools. Hiding the link is not access control; the path "
            "is still present in the bundle."
        ),
        "remediation": (
            "Keep privileged UI out of the public bundle where practical. "
            "Regardless of routing, enforce authorisation on every matching "
            "server endpoint. Client-side route guards are not a security "
            "boundary."
        ),
    },
    "cookie-secure": {
        "vulnerability": "Cookie Set Without Secure Flag",
        "severity": "High",
        "cwe_id": "CWE-614",
        "wasc_id": "WASC-4",
        "owasp": "A04:2025 Cryptographic Failures",
        "nist": "NIST SP 800-53 Rev. 5 SC-8",
        "sans": "Not in CWE Top 25 (2025)",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 SC-23",
        "sans": "Not in CWE Top 25 (2025)",
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
        "owasp": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 SC-23",
        "sans": "Not in CWE Top 25 (2025)",
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
    "transport-plaintext": {
        "vulnerability": "Application Served Over Plain HTTP",
        "severity": "Medium",
        "cwe_id": "CWE-319",
        "wasc_id": "WASC-4",
        "owasp": "A04:2025 Cryptographic Failures",
        "nist": "NIST SP 800-53 Rev. 5 SC-8",
        "sans": "Not in CWE Top 25 (2025)",
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
    "xss-reflected": {
        "vulnerability": "Potential Reflected Cross-Site Scripting",
        "severity": "High",
        "cwe_id": "CWE-79",
        "wasc_id": "WASC-8",
        "owasp": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10",
        "sans": "CWE Top 25 (2025) - #1",
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
        "owasp": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10",
        "sans": "CWE Top 25 (2025) - #2",
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
    "sqli-auth": {
        "vulnerability": "Potential SQL Injection in Authentication",
        "severity": "High",
        "cwe_id": "CWE-89",
        "wasc_id": "WASC-19",
        "owasp": "A07:2025 Authentication Failures",
        "nist": "NIST SP 800-53 Rev. 5 SI-10",
        "sans": "CWE Top 25 (2025) - #2",
        "description_template": (
            "Submitting a controlled SQL metacharacter sequence in '{param}' at "
            "{location} produced an authentication success signal (session "
            "token, authenticated user object, or a post-login landing) without "
            "a valid password. That pattern is consistent with a concatenated "
            "login query whose predicate can be forced true."
        ),
        "remediation": (
            "Parameterise the login query. Compare passwords with a slow hash "
            "outside SQL. Do not treat a non-empty result set as proof of "
            "identity if the WHERE clause can be altered by input. Return the "
            "same error for unknown users and wrong passwords."
        ),
    },
    "nosqli": {
        "vulnerability": "Potential NoSQL Operator Injection",
        "severity": "High",
        "cwe_id": "CWE-943",
        "wasc_id": "WASC-19",
        "owasp": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "A query or body field '{param}' on {location} accepted a document-"
            "database operator form (for example $ne, $gt or $where) and the "
            "response differed from the baseline in a way that indicates the "
            "operator reached the query engine rather than being treated as "
            "plain text."
        ),
        "remediation": (
            "Do not pass raw request objects into database APIs. Cast each "
            "field to the expected type and reject keys that begin with '$'. "
            "Disable server-side JavaScript query operators unless they are "
            "strictly required."
        ),
    },
    "path-traversal": {
        "vulnerability": "Potential Path Traversal",
        "severity": "High",
        "cwe_id": "CWE-22",
        "wasc_id": "WASC-33",
        "owasp": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 AC-3",
        "sans": "CWE Top 25 (2025) - #8",
        "description_template": (
            "Varying '{param}' on {location} with a traversal sequence caused "
            "the server to return content whose type or marker is consistent "
            "with a file outside the intended directory. Encoded separators "
            "or null-byte wrappers that change the result are treated the "
            "same way."
        ),
        "remediation": (
            "Resolve the requested path, confirm it stays inside an allow-listed "
            "root, and open that canonical path only. Do not use client-supplied "
            "names as filesystem paths. Reject encoded separators and trailing "
            "extension wrappers rather than string-matching the suffix."
        ),
    },
    "xxe": {
        "vulnerability": "Potential XML External Entity Processing",
        "severity": "High",
        "cwe_id": "CWE-611",
        "wasc_id": "WASC-43",
        "owasp": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "An XML body or upload accepted at {location} appears to expand an "
            "external or file entity. The response included entity-derived "
            "content or an XML parser fault that names DTD or entity "
            "resolution. That behaviour can disclose local files or trigger "
            "server-side requests."
        ),
        "remediation": (
            "Disable DTD and external-entity resolution in the XML parser. "
            "Prefer a parser configuration that rejects DOCTYPE. Do not parse "
            "untrusted XML with a validating resolver that can reach the "
            "filesystem or the network."
        ),
    },
    "cmdi": {
        "vulnerability": "Potential OS Command Injection",
        "severity": "High",
        "cwe_id": "CWE-78",
        "wasc_id": "WASC-31",
        "owasp": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10",
        "sans": "CWE Top 25 (2025) - #7",
        "description_template": (
            "A marker placed in '{param}' at {location} came back in a form "
            "consistent with shell interpolation (timing aside, echoed command "
            "output or a shell error string). The value may be concatenated "
            "into an operating-system command."
        ),
        "remediation": (
            "Do not build shell strings from request data. If a process must "
            "run, pass arguments as a list to an API that does not invoke a "
            "shell. Allow-list verbs and operands."
        ),
    },
    "cmd-injection": {
        "vulnerability": "Potential OS Command Injection",
        "severity": "High",
        "cwe_id": "CWE-78",
        "wasc_id": "WASC-31",
        "owasp": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10",
        "sans": "CWE Top 25 (2025) - #7",
        "description_template": (
            "A marker placed in '{param}' at {location} came back in a form "
            "consistent with shell interpolation (timing aside, echoed command "
            "output or a shell error string). The value may be concatenated "
            "into an operating-system command."
        ),
        "remediation": (
            "Do not build shell strings from request data. If a process must "
            "run, pass arguments as a list to an API that does not invoke a "
            "shell. Allow-list verbs and operands."
        ),
    },
    "open-redirect": {
        "vulnerability": "Open Redirect",
        "severity": "Medium",
        "cwe_id": "CWE-601",
        "wasc_id": "WASC-38",
        "owasp": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 AC-4",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "A user-controlled parameter '{param}' at {location} was accepted "
            "as a redirect target and sent the client off-site. Phishing and "
            "token-theft flows can hide behind a trusted host this way."
        ),
        "remediation": (
            "Allow only an internal allow-list of redirect targets. Do not pass "
            "user-controlled URLs into Location headers or meta-refresh."
        ),
    },
    "csrf-form": {
        "vulnerability": "State-changing Form Without CSRF Token",
        "severity": "Medium",
        "cwe_id": "CWE-352",
        "wasc_id": "WASC-9",
        "owasp": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 SC-23",
        "sans": "CWE Top 25 (2025)",
        "description_template": (
            "A POST form on {location} has no hidden field whose name looks "
            "like a CSRF or anti-forgery token. A third-party page can submit "
            "that form using the victim's session cookie."
        ),
        "remediation": (
            "Add a per-session anti-CSRF token as a hidden field and reject "
            "POST requests that omit or mismatch the token. Prefer SameSite=Lax "
            "or Strict cookies as defence in depth."
        ),
    },
    "weak-session-id": {
        "vulnerability": "Weak Session Identifier",
        "severity": "Medium",
        "cwe_id": "CWE-330",
        "wasc_id": "WASC-18",
        "owasp": "A07:2025 Identification and Authentication Failures",
        "nist": "NIST SP 800-53 Rev. 5 IA-5",
        "sans": "CWE Top 25 (2025)",
        "description_template": (
            "A session cookie set by {location} has a short or numeric-only "
            "value, so identifiers may be predictable."
        ),
        "remediation": (
            "Issue session identifiers from a CSPRNG with at least 128 bits of "
            "entropy. Do not use incrementing integers."
        ),
    },
    "client-validation-bypass": {
        "vulnerability": "Client-Side Validation Bypass",
        "severity": "Medium",
        "cwe_id": "CWE-602",
        "wasc_id": "WASC-20",
        "owasp": "A04:2025 Insecure Design",
        "nist": "NIST SP 800-53 Rev. 5 SI-10",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "A field on {location} is constrained in the browser markup "
            "(min, max, maxlength or pattern) but the server accepted a value "
            "that those constraints would have blocked. Client checks are not "
            "a security boundary if the same rule is not enforced server-side."
        ),
        "remediation": (
            "Re-apply the same min, max, length and pattern rules on the "
            "server. Treat browser validation as a usability aid only."
        ),
    },
    "upload-surface": {
        "vulnerability": "File Upload Control Present",
        "severity": "Medium",
        "cwe_id": "CWE-434",
        "wasc_id": "WASC-20",
        "owasp": "A04:2025 Insecure Design",
        "nist": "NIST SP 800-53 Rev. 5 SI-10",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "{location} exposes a file-upload input. If the server does not "
            "validate type, size and storage path, uploaded content can be "
            "executed or overwrite application files."
        ),
        "remediation": (
            "Restrict extensions and MIME types, store uploads outside the web "
            "root, and serve them with a non-executable Content-Type."
        ),
    },
    "static-env-file": {
        "vulnerability": "Environment File Committed to Project",
        "severity": "High",
        "cwe_id": "CWE-540",
        "wasc_id": "WASC-13",
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 CM-6",
        "sans": "Not in CWE Top 25 (2025)",
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
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 CM-7",
        "sans": "Not in CWE Top 25 (2025)",
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
        "owasp": "A07:2025 Authentication Failures",
        "nist": "NIST SP 800-53 Rev. 5 IA-5",
        "sans": "Not in CWE Top 25 (2025)",
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
    "static-eval": {
        "vulnerability": "Dangerous Dynamic Code Execution",
        "severity": "High",
        "cwe_id": "CWE-95",
        "wasc_id": "WASC-31",
        "owasp": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10",
        "sans": "CWE Top 25 (2025) - #11",
        "description_template": (
            "A dynamic code-execution sink such as eval() or Function() was "
            "found in {location}. If user-controlled data reaches this sink, "
            "the application can execute attacker-supplied code."
        ),
        "remediation": (
            "Remove eval() and Function() constructors. Use parsed data "
            "structures or an allow-listed operation map instead of executing "
            "strings as code."
        ),
    },
    "static-html-sink": {
        "vulnerability": "Unencoded HTML Sink",
        "severity": "Medium",
        "cwe_id": "CWE-79",
        "wasc_id": "WASC-8",
        "owasp": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10",
        "sans": "CWE Top 25 (2025) - #1",
        "description_template": (
            "An HTML sink such as innerHTML, document.write or "
            "dangerouslySetInnerHTML was found in {location}. Unencoded data "
            "written here becomes a cross-site scripting path."
        ),
        "remediation": (
            "Use textContent or the framework's encoding helpers. Avoid raw "
            "HTML insertion unless the content is already sanitised."
        ),
    },
    "static-sql-concat": {
        "vulnerability": "SQL String Concatenation",
        "severity": "High",
        "cwe_id": "CWE-89",
        "wasc_id": "WASC-19",
        "owasp": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10",
        "sans": "CWE Top 25 (2025) - #2",
        "description_template": (
            "SQL appears to be built by string concatenation in {location}. "
            "User-controlled values in that string can change the query."
        ),
        "remediation": (
            "Use parameterised queries or an ORM. Do not concatenate untrusted "
            "input into SQL."
        ),
    },
    "static-command-exec": {
        "vulnerability": "OS Command Execution Sink",
        "severity": "High",
        "cwe_id": "CWE-78",
        "wasc_id": "WASC-31",
        "owasp": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10",
        "sans": "CWE Top 25 (2025) - #7",
        "description_template": (
            "An operating-system command execution API was found in {location}. "
            "If request data reaches this call, command injection is possible."
        ),
        "remediation": (
            "Avoid shelling out from web request handlers. If a process must "
            "run, pass arguments as a list and never interpolate untrusted "
            "strings into a shell command."
        ),
    },
    "static-weak-crypto": {
        "vulnerability": "Weak Cryptography",
        "severity": "Medium",
        "cwe_id": "CWE-327",
        "wasc_id": "WASC-04",
        "owasp": "A04:2025 Cryptographic Failures",
        "nist": "NIST SP 800-53 Rev. 5 SC-13",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "A weak digest or non-cryptographic random source (MD5, SHA-1, "
            "Math.random) was found in {location}. These primitives are not "
            "suitable for passwords, tokens or integrity checks."
        ),
        "remediation": (
            "Use SHA-256 or stronger for integrity, a password hash (Argon2, "
            "bcrypt, scrypt) for secrets, and a CSPRNG for tokens and session IDs."
        ),
    },
    "static-path-sink": {
        "vulnerability": "User-Controlled File Path",
        "severity": "High",
        "cwe_id": "CWE-22",
        "wasc_id": "WASC-33",
        "owasp": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 AC-3",
        "sans": "CWE Top 25 (2025) - #8",
        "description_template": (
            "A filesystem API in {location} appears to take a request parameter "
            "as part of the path. That pattern is a directory-traversal sink."
        ),
        "remediation": (
            "Resolve paths against a fixed root, reject .. segments, and map "
            "user input to an allow-list of filenames rather than concatenating it."
        ),
    },
    "static-jwt-hardcoded": {
        "vulnerability": "JWT Secret or Unverified Decode",
        "severity": "Medium",
        "cwe_id": "CWE-347",
        "wasc_id": "WASC-15",
        "owasp": "A07:2025 Authentication Failures",
        "nist": "NIST SP 800-53 Rev. 5 IA-5",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "JWT handling in {location} uses a hard-coded secret name or decode "
            "without an obvious verify step. Algorithm confusion and forged "
            "tokens follow from that pattern."
        ),
        "remediation": (
            "Load signing keys from a secret manager, pin the allowed algorithm "
            "explicitly, and reject tokens that are only decoded."
        ),
    },
    "static-empty-handler": {
        "vulnerability": "Empty Error Handler",
        "severity": "Low",
        "cwe_id": "CWE-390",
        "wasc_id": "WASC-13",
        "owasp": "A09:2025 Security Logging and Monitoring Failures",
        "nist": "NIST SP 800-53 Rev. 5 SI-11",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "An empty catch / except block was found in {location}. Failures "
            "are swallowed, so operators never see the fault and attackers can "
            "probe without leaving a log trail."
        ),
        "remediation": (
            "Log the exception server-side and return a generic client error. "
            "Do not use empty handlers around authentication, payment or file I/O."
        ),
    },
    "static-debug-residue": {
        "vulnerability": "Debug Residue in Source",
        "severity": "Low",
        "cwe_id": "CWE-489",
        "wasc_id": "WASC-13",
        "owasp": "A09:2025 Security Logging and Monitoring Failures",
        "nist": "NIST SP 800-53 Rev. 5 SI-11",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "Debug print or console logging remains in {location}. In a deployed "
            "build this leaks internal values to logs or the browser console."
        ),
        "remediation": (
            "Strip console.log / print debug from production builds and keep "
            "diagnostic output behind a server-side log level."
        ),
    },
    "static-todo-secret": {
        "vulnerability": "TODO Near Credential Handling",
        "severity": "Low",
        "cwe_id": "CWE-546",
        "wasc_id": "WASC-15",
        "owasp": "A04:2025 Insecure Design",
        "nist": "NIST SP 800-53 Rev. 5 SA-11",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "A TODO / FIXME comment sits next to credential or token handling "
            "in {location}. Unfinished auth work is a design and quality defect "
            "that often ships as a weak control."
        ),
        "remediation": (
            "Close or ticket the leftover work before release. Do not ship "
            "placeholder authentication or hard-coded test passwords."
        ),
    },
    "header-permissions-policy": {
        "vulnerability": "Missing Permissions-Policy Header",
        "severity": "Low",
        "cwe_id": "CWE-693",
        "wasc_id": "WASC-15",
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 CM-6",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "No Permissions-Policy (Feature-Policy) header was returned by "
            "{location}. Powerful browser features stay enabled for this origin "
            "and for embedded frames unless the page opts out."
        ),
        "remediation": (
            "Send a Permissions-Policy that disables unused powerful features "
            "(camera, microphone, geolocation, payment) for this origin and for "
            "embedded content."
        ),
    },
    "password-autocomplete": {
        "vulnerability": "Password Field Allows Autocomplete",
        "severity": "Low",
        "cwe_id": "CWE-522",
        "wasc_id": "WASC-15",
        "owasp": "A07:2025 Authentication Failures",
        "nist": "NIST SP 800-53 Rev. 5 IA-5",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "A password input on {location} does not set autocomplete=\"off\" or "
            "autocomplete=\"new-password\". Shared browsers may persist the value."
        ),
        "remediation": (
            "Set autocomplete=\"off\" or autocomplete=\"new-password\" on password "
            "fields where the threat model includes shared workstations. This is "
            "a hygiene control, not a substitute for hashing stored passwords."
        ),
    },
    "static-ssrf": {
        "vulnerability": "User-Controlled Outbound Request (SSRF)",
        "severity": "High",
        "cwe_id": "CWE-918",
        "wasc_id": "WASC-15",
        "owasp": "A10:2021 Server-Side Request Forgery",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / SC-7",
        "sans": "CWE Top 25 (2025) - #18",
        "description_template": (
            "An HTTP or URL-fetch API in {location} is reached by request data. "
            "If the destination is not constrained, an attacker can make the "
            "server request internal hosts, cloud metadata endpoints or third-"
            "party URLs on their behalf."
        ),
        "remediation": (
            "Do not pass request values into URL-fetch APIs. Resolve against an "
            "allow-list of hosts, block link-local and metadata ranges, and "
            "disable redirects to untrusted destinations."
        ),
    },
    "static-deser": {
        "vulnerability": "Insecure Deserialization Sink",
        "severity": "High",
        "cwe_id": "CWE-502",
        "wasc_id": "WASC-15",
        "owasp": "A08:2025 Software and Data Integrity Failures",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / SI-7",
        "sans": "CWE Top 25 (2025) - #16",
        "description_template": (
            "A native deserializer (unserialize, pickle, yaml.load, "
            "ObjectInputStream or similar) was found in {location}. Loading "
            "untrusted bytes through these APIs can instantiate attacker-"
            "chosen types and execute code."
        ),
        "remediation": (
            "Prefer JSON with an explicit schema. If native deserialization is "
            "required, sign the payload, restrict allowed types, and never "
            "pass request bodies into pickle.loads, yaml.load or unserialize."
        ),
    },
    "static-open-redirect": {
        "vulnerability": "User-Controlled Redirect Target",
        "severity": "Medium",
        "cwe_id": "CWE-601",
        "wasc_id": "WASC-38",
        "owasp": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 AC-4 / SI-10",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "A redirect API in {location} appears to take a request-controlled "
            "target. An attacker can send victims to a look-alike origin after "
            "an authenticated flow on this application."
        ),
        "remediation": (
            "Map request values to an allow-list of internal paths. Reject "
            "scheme-relative and absolute external URLs unless they match a "
            "fixed host list."
        ),
    },
    "static-xxe": {
        "vulnerability": "XML Parser Allows External Entities",
        "severity": "High",
        "cwe_id": "CWE-611",
        "wasc_id": "WASC-43",
        "owasp": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / SC-7",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "An XML parser is constructed in {location} without an obvious "
            "disable of external entities / DTDs. If request XML reaches that "
            "parser, an attacker can read local files or trigger outbound "
            "requests from the server."
        ),
        "remediation": (
            "Disable DTDs and external entities on every XML parser. In Python "
            "use defusedxml; in Java set "
            "disallow-doctype-decl and external-general-entities to false "
            "before parse."
        ),
    },
    "static-cors-star": {
        "vulnerability": "Permissive CORS Origin in Source",
        "severity": "Medium",
        "cwe_id": "CWE-942",
        "wasc_id": "WASC-15",
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 AC-4 / SC-7",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "{location} configures Cross-Origin Resource Sharing with a "
            "wildcard origin or cors() defaults. Any site can then read "
            "responses from a victim's browser for this origin."
        ),
        "remediation": (
            "Reflect only trusted origins. Do not use '*' on authenticated "
            "APIs, and never combine a wildcard with Access-Control-Allow-"
            "Credentials: true."
        ),
    },
    "static-csrf-disabled": {
        "vulnerability": "Cross-Site Request Forgery Protection Disabled",
        "severity": "Medium",
        "cwe_id": "CWE-352",
        "wasc_id": "WASC-9",
        "owasp": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 SC-23 / AC-3",
        "sans": "CWE Top 25 (2025) - #4",
        "description_template": (
            "CSRF protection is switched off or bypassed in {location}. State-"
            "changing requests can then be issued from a third-party page "
            "using the victim's cookies."
        ),
        "remediation": (
            "Keep framework CSRF middleware enabled for cookie-authenticated "
            "state changes. Use SameSite cookies as defence in depth, not as "
            "the only control."
        ),
    },
    "static-upload-sink": {
        "vulnerability": "Unrestricted File Upload Sink",
        "severity": "Medium",
        "cwe_id": "CWE-434",
        "wasc_id": "WASC-20",
        "owasp": "A04:2025 Insecure Design",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / CM-7",
        "sans": "CWE Top 25 (2025) - #10",
        "description_template": (
            "A file-upload API in {location} is reached by request data. "
            "Without type, size and path checks, uploaded files can overwrite "
            "application paths or execute if stored under a web-reachable "
            "directory."
        ),
        "remediation": (
            "Allow-list extensions and MIME types, generate server-side names, "
            "store outside the web root, and never trust client-supplied "
            "paths. Scan or re-encode images where the threat model requires it."
        ),
    },
    "static-sensitive-artifact": {
        "vulnerability": "Sensitive Artifact Committed to Project",
        "severity": "High",
        "cwe_id": "CWE-540",
        "wasc_id": "WASC-13",
        "owasp": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 AC-3 / IA-5",
        "sans": "Not in CWE Top 25 (2025)",
        "description_template": (
            "The archive contains a sensitive-name file at {location} "
            "(key material, database dump, phpinfo, wp-config or similar). "
            "Anyone with the project can read it, and if the file is deployed "
            "under the web root it may also be retrieved over HTTP."
        ),
        "remediation": (
            "Remove the file from version control, add a matching gitignore "
            "rule, store secrets in a manager, and rotate any key or password "
            "that was committed."
        ),
    },
}

# Optional dual-year / multi-control fields. Existing owasp/nist/sans stay
# required so stored findings and STRICT_VALIDATION do not change.
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

# OWASP Top 10 2021 buckets used by Dashboard graphs.
# 2025 codes on each rule are mapped to these buckets at display time.
_STANDARD_ENRICHMENT = {
    "header-xfo": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 SC-18 / CM-6",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "header-csp": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 SC-18 / CM-6 / SI-10",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "header-hsts": {
        "owasp_2021": "A02:2021 Cryptographic Failures",
        "owasp_2025": "A04:2025 Cryptographic Failures",
        "nist": "NIST SP 800-53 Rev. 5 SC-8 / SC-23",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "header-nosniff": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 SC-18 / CM-6",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "header-referrer-policy": {
        "owasp_2021": "A01:2021 Broken Access Control",
        "owasp_2025": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 AC-4 / SC-8",
        "sans": "CWE Top 25 (2024) #16 — CWE-200",
    },
    "header-cors": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 AC-4 / SC-7",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "info-disclosure-server": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 CM-6 / SI-11",
        "sans": "CWE Top 25 (2024) #16 — CWE-200",
    },
    "verbose-error": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 SI-11 / SI-10",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "dir-listing": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 CM-6 / AC-3",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "sensitive-path": {
        "owasp_2021": "A01:2021 Broken Access Control",
        "owasp_2025": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 AC-3 / CM-7",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "sensitive-file": {
        "owasp_2021": "A01:2021 Broken Access Control",
        "owasp_2025": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 AC-3 / AC-6",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "exposed-key-material": {
        "owasp_2021": "A02:2021 Cryptographic Failures",
        "owasp_2025": "A04:2025 Cryptographic Failures",
        "nist": "NIST SP 800-53 Rev. 5 SC-12 / IA-5",
        "sans": "CWE Top 25 (2024) #18 — CWE-798",
    },
    "client-privileged-route": {
        "owasp_2021": "A01:2021 Broken Access Control",
        "owasp_2025": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 AC-3 / CM-6",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "cookie-secure": {
        "owasp_2021": "A02:2021 Cryptographic Failures",
        "owasp_2025": "A04:2025 Cryptographic Failures",
        "nist": "NIST SP 800-53 Rev. 5 SC-8 / SC-23",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "cookie-httponly": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 SC-23 / SI-10",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "cookie-samesite": {
        "owasp_2021": "A01:2021 Broken Access Control",
        "owasp_2025": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 SC-23 / AC-3",
        "sans": "CWE Top 25 (2024) #4 — CWE-352",
    },
    "transport-plaintext": {
        "owasp_2021": "A02:2021 Cryptographic Failures",
        "owasp_2025": "A04:2025 Cryptographic Failures",
        "nist": "NIST SP 800-53 Rev. 5 SC-8 / SC-13",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "xss-reflected": {
        "owasp_2021": "A03:2021 Injection",
        "owasp_2025": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / SC-18",
        "sans": "CWE Top 25 (2024) #1 — CWE-79",
    },
    "sqli-error": {
        "owasp_2021": "A03:2021 Injection",
        "owasp_2025": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / AC-3",
        "sans": "CWE Top 25 (2024) #2 — CWE-89",
    },
    "sqli-auth": {
        "owasp_2021": "A07:2021 Identification and Authentication Failures",
        "owasp_2025": "A07:2025 Authentication Failures",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / IA-2 / IA-5",
        "sans": "CWE Top 25 (2024) #2 — CWE-89",
    },
    "nosqli": {
        "owasp_2021": "A03:2021 Injection",
        "owasp_2025": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / AC-3",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "path-traversal": {
        "owasp_2021": "A01:2021 Broken Access Control",
        "owasp_2025": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 AC-3 / SI-10",
        "sans": "CWE Top 25 (2024) #8 — CWE-22",
    },
    "xxe": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / SC-7",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "cmdi": {
        "owasp_2021": "A03:2021 Injection",
        "owasp_2025": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / CM-7",
        "sans": "CWE Top 25 (2024) #7 — CWE-78",
    },
    "cmd-injection": {
        "owasp_2021": "A03:2021 Injection",
        "owasp_2025": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / CM-7",
        "sans": "CWE Top 25 (2024) #7 — CWE-78",
    },
    "open-redirect": {
        "owasp_2021": "A01:2021 Broken Access Control",
        "owasp_2025": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 AC-4 / SI-10",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "csrf-form": {
        "owasp_2021": "A01:2021 Broken Access Control",
        "owasp_2025": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 SC-23 / AC-3",
        "sans": "CWE Top 25 (2024) #4 — CWE-352",
    },
    "weak-session-id": {
        "owasp_2021": "A07:2021 Identification and Authentication Failures",
        "owasp_2025": "A07:2025 Authentication Failures",
        "nist": "NIST SP 800-53 Rev. 5 IA-5 / SC-23",
        "sans": "CWE Top 25 (2024) #15 — CWE-330",
    },
    "client-validation-bypass": {
        "owasp_2021": "A04:2021 Insecure Design",
        "owasp_2025": "A04:2025 Insecure Design",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / SA-8",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "upload-surface": {
        "owasp_2021": "A04:2021 Insecure Design",
        "owasp_2025": "A04:2025 Insecure Design",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / CM-7",
        "sans": "CWE Top 25 (2024) #10 — CWE-434",
    },
    "static-env-file": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 CM-6 / IA-5",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "static-debug-enabled": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 CM-7 / SI-11",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "static-secret-pattern": {
        "owasp_2021": "A07:2021 Identification and Authentication Failures",
        "owasp_2025": "A07:2025 Authentication Failures",
        "nist": "NIST SP 800-53 Rev. 5 IA-5 / SC-12",
        "sans": "CWE Top 25 (2024) #18 — CWE-798",
    },
    "static-eval": {
        "owasp_2021": "A03:2021 Injection",
        "owasp_2025": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / CM-7",
        "sans": "CWE Top 25 (2024) #11 — CWE-94",
    },
    "static-html-sink": {
        "owasp_2021": "A03:2021 Injection",
        "owasp_2025": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / SC-18",
        "sans": "CWE Top 25 (2024) #1 — CWE-79",
    },
    "static-sql-concat": {
        "owasp_2021": "A03:2021 Injection",
        "owasp_2025": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / AC-3",
        "sans": "CWE Top 25 (2024) #2 — CWE-89",
    },
    "static-command-exec": {
        "owasp_2021": "A03:2021 Injection",
        "owasp_2025": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / CM-7",
        "sans": "CWE Top 25 (2024) #7 — CWE-78",
    },
    "static-weak-crypto": {
        "owasp_2021": "A02:2021 Cryptographic Failures",
        "owasp_2025": "A04:2025 Cryptographic Failures",
        "nist": "NIST SP 800-53 Rev. 5 SC-13 / SC-12",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "static-path-sink": {
        "owasp_2021": "A01:2021 Broken Access Control",
        "owasp_2025": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 AC-3 / SI-10",
        "sans": "CWE Top 25 (2024) #8 — CWE-22",
    },
    "static-jwt-hardcoded": {
        "owasp_2021": "A07:2021 Identification and Authentication Failures",
        "owasp_2025": "A07:2025 Authentication Failures",
        "nist": "NIST SP 800-53 Rev. 5 IA-5 / SC-12",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "static-empty-handler": {
        "owasp_2021": "A09:2021 Security Logging and Monitoring Failures",
        "owasp_2025": "A09:2025 Security Logging and Monitoring Failures",
        "nist": "NIST SP 800-53 Rev. 5 SI-11 / AU-3",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "static-debug-residue": {
        "owasp_2021": "A09:2021 Security Logging and Monitoring Failures",
        "owasp_2025": "A09:2025 Security Logging and Monitoring Failures",
        "nist": "NIST SP 800-53 Rev. 5 SI-11 / AU-3",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "static-todo-secret": {
        "owasp_2021": "A04:2021 Insecure Design",
        "owasp_2025": "A04:2025 Insecure Design",
        "nist": "NIST SP 800-53 Rev. 5 SA-11 / SI-10",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "header-permissions-policy": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 CM-6 / SC-18",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "password-autocomplete": {
        "owasp_2021": "A07:2021 Identification and Authentication Failures",
        "owasp_2025": "A07:2025 Authentication Failures",
        "nist": "NIST SP 800-53 Rev. 5 IA-5 / SC-23",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "static-ssrf": {
        "owasp_2021": "A10:2021 Server-Side Request Forgery",
        "owasp_2025": "A10:2021 Server-Side Request Forgery",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / SC-7",
        "sans": "CWE Top 25 (2024) #19 — CWE-918",
    },
    "static-deser": {
        "owasp_2021": "A08:2021 Software and Data Integrity Failures",
        "owasp_2025": "A08:2025 Software and Data Integrity Failures",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / SI-7",
        "sans": "CWE Top 25 (2024) #16 — CWE-502",
    },
    "static-open-redirect": {
        "owasp_2021": "A01:2021 Broken Access Control",
        "owasp_2025": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 AC-4 / SI-10",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "static-xxe": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A05:2025 Injection",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / SC-7",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "static-cors-star": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 AC-4 / SC-7",
        "sans": "Not in CWE Top 25 (2024)",
    },
    "static-csrf-disabled": {
        "owasp_2021": "A01:2021 Broken Access Control",
        "owasp_2025": "A01:2025 Broken Access Control",
        "nist": "NIST SP 800-53 Rev. 5 SC-23 / AC-3",
        "sans": "CWE Top 25 (2024) #4 — CWE-352",
    },
    "static-upload-sink": {
        "owasp_2021": "A04:2021 Insecure Design",
        "owasp_2025": "A04:2025 Insecure Design",
        "nist": "NIST SP 800-53 Rev. 5 SI-10 / CM-7",
        "sans": "CWE Top 25 (2024) #10 — CWE-434",
    },
    "static-sensitive-artifact": {
        "owasp_2021": "A05:2021 Security Misconfiguration",
        "owasp_2025": "A02:2025 Security Misconfiguration",
        "nist": "NIST SP 800-53 Rev. 5 AC-3 / IA-5",
        "sans": "Not in CWE Top 25 (2024)",
    },
}


def _apply_standard_enrichment() -> None:
    for rid, extra in _STANDARD_ENRICHMENT.items():
        rule = RULES.get(rid)
        if not rule:
            continue
        if extra.get("owasp_2021"):
            rule["owasp_2021"] = extra["owasp_2021"]
        if extra.get("owasp_2025"):
            rule["owasp_2025"] = extra["owasp_2025"]
        if extra.get("nist"):
            rule["nist"] = extra["nist"]
        if extra.get("sans"):
            rule["sans"] = extra["sans"]


_apply_standard_enrichment()


def get_rule(plugin_id: str) -> dict:
    key = str(plugin_id or "").strip()
    if key not in RULES:
        known = ", ".join(sorted(RULES)) or "<none>"
        raise KeyError(f"Unknown rule id {key!r}. Defined rules: {known}")
    return RULES[key]


def list_rule_ids() -> list[str]:
    return sorted(RULES)


def validate_catalogue() -> list[str]:
    problems: list[str] = []
    for rid in sorted(RULES):
        rule = RULES[rid]
        for key in RULE_KEYS:
            if not str(rule.get(key) or "").strip():
                problems.append(f"{rid}: missing {key}")
    return problems


def coverage_rows() -> list[tuple[str, str, str, str, str]]:
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
