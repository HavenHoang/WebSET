from __future__ import annotations
NOTES: dict[str, dict] = {
    "wordpress": {
        "title": "WordPress hardening review",
        "severity": "Medium",
        "match": ("wordpress", "wp-content", "wp-engine"),
        "description": (
            "WordPress was detected on {location}. Core, themes and plugins "
            "share a predictable administrative surface (wp-admin, wp-login.php, "
            "xmlrpc.php) and a large third-party extension ecosystem. Unmaintained "
            "plugins and the built-in theme/plugin file editor are the usual "
            "entry points on this platform."
        ),
        "remediation": (
            "Keep core, themes and plugins on current releases and remove unused "
            "extensions. Set DISALLOW_FILE_EDIT, restrict wp-admin by source IP "
            "or SSO, disable or tightly authenticate xmlrpc.php, turn off "
            "directory listing on wp-content/uploads, and enforce unique "
            "administrator credentials with 2FA."
        ),
    },
    "php": {
        "title": "PHP runtime hardening review",
        "severity": "Low",
        "match": ("php", "php-fpm"),
        "description": (
            "PHP was detected on {location}. Default php.ini values often leave "
            "expose_php enabled (X-Powered-By), display_errors on, and "
            "allow_url_include reachable. Unsupported minor releases stop "
            "receiving security fixes on a published end-of-life calendar."
        ),
        "remediation": (
            "Set expose_php=Off, display_errors=Off and log_errors=On. Disable "
            "allow_url_include and unused dangerous functions (exec, passthru, "
            "shell_exec, system, proc_open) unless the application requires them. "
            "Run a currently supported PHP branch and keep the package channel patched."
        ),
    },
    "nodejs": {
        "title": "Node.js / Express hardening review",
        "severity": "Low",
        "match": ("node", "node.js", "nodejs", "express"),
        "description": (
            "A Node.js runtime or Express service was detected on {location}. "
            "Applications in this ecosystem typically carry a large dependency "
            "tree, and default responses may include an X-Powered-By header."
        ),
        "remediation": (
            "Audit dependencies, keep a lock file under version control, set "
            "NODE_ENV=production, add a generic error handler, and remove the "
            "X-Powered-By header."
        ),
    },
    "socketio": {
        "title": "Realtime channel review",
        "severity": "Low",
        "match": ("socket.io", "socketio"),
        "description": (
            "A Socket.IO style realtime channel was detected on {location}. "
            "These endpoints often sit beside the main HTTP app and inherit "
            "session cookies if CORS and origin checks are loose."
        ),
        "remediation": (
            "Restrict allowed origins, authenticate socket connections, and "
            "avoid exposing internal events to unauthenticated clients."
        ),
    },
    "angular": {
        "title": "Angular SPA hardening review",
        "severity": "Low",
        "match": ("angular",),
        "description": (
            "An Angular front end was detected on {location}. Client-side "
            "routing and template binding mean user-controlled values must be "
            "encoded in the browser as well as on the API."
        ),
        "remediation": (
            "Keep Angular on a supported release, avoid bypassing DomSanitizer "
            "unless necessary, set a strict Content-Security-Policy, and do "
            "not trust API fields when rendering HTML."
        ),
    },
    "react": {
        "title": "React SPA hardening review",
        "severity": "Low",
        "match": ("react", "next.js", "nextjs"),
        "description": (
            "A React or Next.js front end was detected on {location}. "
            "dangerouslySetInnerHTML and server-side rendering increase the "
            "impact of unsanitised content."
        ),
        "remediation": (
            "Avoid raw HTML insertion, keep the framework updated, and set a "
            "strict Content-Security-Policy for script sources."
        ),
    },
    "vue": {
        "title": "Vue SPA hardening review",
        "severity": "Low",
        "match": ("vue", "vue.js"),
        "description": (
            "A Vue front end was detected on {location}. Template interpolation "
            "and v-html can introduce client-side script issues if API data is "
            "trusted."
        ),
        "remediation": (
            "Avoid v-html for untrusted content, keep Vue updated, and set a "
            "strict Content-Security-Policy."
        ),
    },
    "nginx": {
        "title": "Web server configuration review",
        "severity": "Low",
        "match": ("nginx",),
        "description": (
            "nginx was detected serving {location}. Default builds report "
            "their version in the Server header and ship with permissive TLS "
            "defaults."
        ),
        "remediation": (
            "Set server_tokens off, disable directory autoindex unless it is "
            "required, and review the TLS protocol and cipher configuration "
            "against current guidance."
        ),
    },
    "apache": {
        "title": "Web server configuration review",
        "severity": "Low",
        "match": ("apache", "httpd"),
        "description": (
            "Apache HTTP Server was detected serving {location}."
        ),
        "remediation": (
            "If the Server header includes a version, set ServerTokens Prod "
            "and ServerSignature Off."
        ),
    },
    "iis": {
        "title": "Web server configuration review",
        "severity": "Low",
        "match": ("iis", "microsoft-iis", "asp.net"),
        "description": (
            "Microsoft IIS or ASP.NET was detected on {location}. Default "
            "responses include framework version headers and detailed error "
            "pages."
        ),
        "remediation": (
            "Remove the Server, X-Powered-By and X-AspNet-Version headers, "
            "set customErrors to On, and disable trace handling in production."
        ),
    },
    "jquery": {
        "title": "Client-side library review",
        "severity": "Low",
        "match": ("jquery",),
        "description": (
            "jQuery was detected in the client assets of {location}. Older "
            "major versions are no longer maintained."
        ),
        "remediation": (
            "Move to a maintained release, load the library from a controlled "
            "origin or add subresource integrity attributes, and audit plugins."
        ),
    },
    "bootstrap": {
        "title": "Client-side library review",
        "severity": "Low",
        "match": ("bootstrap",),
        "description": (
            "Bootstrap assets were detected on {location}. Outdated front-end "
            "kits can pull in known client-side issues."
        ),
        "remediation": (
            "Use a maintained Bootstrap release and load it from a controlled "
            "origin with integrity checks where possible."
        ),
    },
    "django": {
        "title": "Django deployment review",
        "severity": "Low",
        "match": ("django",),
        "description": (
            "Django was detected on {location}. Debug mode returns settings "
            "and stack traces in error responses."
        ),
        "remediation": (
            "Confirm DEBUG is False and ALLOWED_HOSTS is set explicitly. "
            "Enable SECURE_SSL_REDIRECT, SESSION_COOKIE_SECURE and "
            "CSRF_COOKIE_SECURE."
        ),
    },
    "laravel": {
        "title": "Laravel deployment review",
        "severity": "Low",
        "match": ("laravel",),
        "description": (
            "Laravel was detected on {location}. Debug mode can expose "
            "environment variables; .env must stay outside the web root."
        ),
        "remediation": (
            "Set APP_DEBUG=false and APP_ENV=production, confirm .env is not "
            "reachable over HTTP, and run config and route caching."
        ),
    },
    "java": {
        "title": "Java application hardening review",
        "severity": "Low",
        "match": ("java", "spring", "tomcat"),
        "description": (
            "A Java / Spring style stack was detected on {location}. Default "
            "actuator or error pages can expose internals."
        ),
        "remediation": (
            "Disable unused actuators, avoid verbose error pages in production, "
            "and keep the framework on a supported release."
        ),
    },
    "docker": {
        "title": "Container deployment baseline",
        "severity": "Low",
        "match": ("docker",),
        "description": (
            "Containerisation indicators were detected for {location}. Image "
            "and runtime hardening should be reviewed."
        ),
        "remediation": (
            "Run non-root where possible, pin image tags, and limit privileged "
            "capabilities."
        ),
    },
    "cdn": {
        "title": "Origin exposure review",
        "severity": "Low",
        "match": ("cloudflare", "cloudfront", "akamai", "fastly"),
        "description": (
            "A content delivery network was detected in front of {location}. "
            "The origin server may remain reachable directly."
        ),
        "remediation": (
            "Restrict the origin to accept connections from the CDN only."
        ),
    },
}
END_OF_LIFE: dict[str, tuple[str, ...]] = {
    "jquery": ("1.", "2."),
    "php": ("5.", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1"),
    "python": ("2.",),
    "angularjs": ("1.",),
    "node": ("12.", "14.", "16."),
    "nodejs": ("12.", "14.", "16."),
}
def normalise_stacks(stacks) -> list[dict]:
    out: list[dict] = []
    if isinstance(stacks, (str, bytes)) or stacks is None:
        return out
    try:
        entries = list(stacks)
    except TypeError:
        return out
    for stack in entries:
        if isinstance(stack, dict):
            name = stack.get("name") or stack.get("technology") or stack.get("tech")
            version = stack.get("version") or stack.get("ver") or ""
            category = stack.get("category") or stack.get("type") or ""
        else:
            name, version, category = stack, "", ""
        if not str(name or "").strip():
            continue
        out.append({
            "name": str(name).strip(),
            "version": str(version or "").strip(),
            "category": str(category or "").strip(),
        })
    return out
def _match_note(name: str) -> tuple[str, dict] | None:
    low = name.lower()
    if "http service" in low:
        return None
    for key, note in NOTES.items():
        if any(token in low for token in note["match"]):
            return key, note
    return None
def _is_end_of_life(name: str, version: str) -> bool:
    if not version:
        return False
    low = name.lower()
    for key, prefixes in END_OF_LIFE.items():
        if key in low and version.startswith(prefixes):
            return True
    return False
def build_platform_note(
    *,
    severity: str,
    title: str,
    location: str,
    description: str,
    remediation: str,
    plugin_id: str = "",
    evidence: str = "",
) -> dict:
    return {
        "severity": severity,
        "vulnerability": title,
        "location": location,
        "description": description,
        "remediation": remediation,
        "scan_origin": "Platform",
        "plugin_id": plugin_id,
        "evidence": evidence,
    }
def _evidence_gated_name(name: str) -> bool:
    low = (name or "").lower()
    if "wordpress" in low or "wp-content" in low or "wp-engine" in low:
        return True
    if low == "php" or low.startswith("php ") or "php-fpm" in low:
        return True
    return False


def _origin_of(url: str) -> str:
    from urllib.parse import urlparse
    raw = (url or "").strip()
    if not raw.startswith(("http://", "https://")):
        return ""
    parsed = urlparse(raw)
    if not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _http_get(url: str) -> dict:
    if not str(url or "").startswith(("http://", "https://")):
        return {}
    try:
        import requests
        resp = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "WebSET-StackEval"},
        )
        headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}
        text = resp.text or ""
        if len(text) > 200000:
            text = text[:200000]
        return {
            "ok": True,
            "status": int(resp.status_code or 0),
            "body": text,
            "headers": headers,
            "final_url": str(resp.url or url),
        }
    except Exception:
        return {}


def _zip_members(path: str, basenames: set[str]) -> dict[str, str]:
    import os
    import zipfile
    wanted = {item.lower() for item in basenames}
    out: dict[str, str] = {}
    if not path or not os.path.isfile(path):
        return out
    try:
        if not zipfile.is_zipfile(path):
            return out
        with zipfile.ZipFile(path, "r") as zf:
            for name in zf.namelist():
                if name.endswith("/"):
                    continue
                base = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
                if base not in wanted or base in out:
                    continue
                try:
                    out[base] = zf.read(name).decode("utf-8", "replace")[:200000]
                except Exception:
                    continue
    except zipfile.BadZipFile:
        return {}
    return out


_PHP_INI_KEYS = (
    "expose_php",
    "display_errors",
    "allow_url_include",
    "allow_url_fopen",
    "disable_functions",
)


def _parse_php_ini(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in (text or "").splitlines():
        raw = line.split(";", 1)[0].strip()
        if not raw or raw.startswith("[") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        key = key.strip().lower()
        if key in _PHP_INI_KEYS:
            found[key] = value.strip()
    return found


def _looks_like_ini(text: str, parsed: dict[str, str]) -> bool:
    if parsed:
        return True
    sample = (text or "")[:4000].lower()
    if "<html" in sample and "[php]" not in sample:
        return False
    return "[php]" in sample


def _php_error_displayed(text: str) -> str:
    import re
    match = re.search(
        r"(?i)\b(?:warning|notice|fatal error|parse error|deprecated)\b:.{0,180}\bon line \d+",
        text or "",
    )
    if not match:
        return ""
    return " ".join(match.group(0).split())[:180]


def _looks_phpinfo(text: str) -> bool:
    low = (text or "").lower()
    return "php version" in low and ("phpinfo()" in low or "loaded configuration file" in low)


def _looks_wp_login(page: dict) -> bool:
    if int(page.get("status") or 0) != 200:
        return False
    low = (page.get("body") or "").lower()
    return (
        ("user_login" in low or "wp-submit" in low or 'name="log"' in low)
        and ("wordpress" in low or "wp-login" in low or "loginform" in low)
    )


def _looks_xmlrpc(page: dict) -> bool:
    status = int(page.get("status") or 0)
    if status not in (200, 405):
        return False
    low = (page.get("body") or "").lower()
    return (
        "xml-rpc server accepts post" in low
        or "<methodresponse" in low
        or "faultcode" in low
        or ("xmlrpc" in low and "method" in low)
    )


def _author_exposed(page: dict) -> bool:
    status = int(page.get("status") or 0)
    final = str(page.get("final_url") or "").lower()
    low = (page.get("body") or "").lower()
    if "/author/" in final and status in (200, 301, 302):
        return True
    if status == 200 and "posts by" in low and "wordpress" in low:
        return True
    return False


def note_for_stack(stack: dict, location: str) -> dict | None:
    name = stack.get("name", "")
    version = stack.get("version", "")
    matched = _match_note(name)
    if not matched:
        return None
    key, note = matched
    if key in ("wordpress", "php"):
        return None
    if key == "apache" and str(version or "").strip():
        description = (
            f"Apache HTTP Server {version} was detected serving {location} "
            "from the response fingerprint."
        )
        remediation = (
            "Set ServerTokens Prod and ServerSignature Off so that version "
            "string is not returned."
        )
    else:
        description = note["description"].format(location=location)
        remediation = note["remediation"]
    label = f"{name} {version}".strip()
    severity = note["severity"]
    if _is_end_of_life(name, version):
        severity = "Medium" if severity == "Low" else "High"
        description += (
            f" The detected version ({version}) is on a major release that "
            "no longer receives security updates."
        )
        remediation = "Plan an upgrade to a supported release as the first step. " + remediation
    return build_platform_note(
        severity=severity,
        title=note["title"],
        location=location,
        description=description,
        remediation=remediation,
        plugin_id=f"platform-{key}",
        evidence=f"detected: {label}" if label else "",
    )
def _wordpress_observed_notes(stack: dict, location: str) -> list[dict]:
    name = str(stack.get("name") or "")
    version = str(stack.get("version") or "")
    notes: list[dict] = []
    origin = _origin_of(location)
    label = f"{name} {version}".strip()
    if origin:
        login = _http_get(origin + "/wp-login.php")
        rpc = _http_get(origin + "/xmlrpc.php")
        author = _http_get(origin + "/?author=1")
    else:
        members = _zip_members(location, {"wp-login.php", "xmlrpc.php"})
        login_body = members.get("wp-login.php", "")
        rpc_body = members.get("xmlrpc.php", "")
        login = {"status": 200, "body": login_body, "final_url": location} if login_body else {}
        rpc = {"status": 200, "body": rpc_body, "final_url": location} if rpc_body else {}
        author = {}
    if login and _looks_wp_login(login):
        where = (origin + "/wp-login.php") if origin else "wp-login.php"
        notes.append(build_platform_note(
            severity="Low",
            title="WordPress login surface",
            location=location,
            description=(
                f"The WordPress login form was observed at {where} "
                f"(HTTP {int(login.get('status') or 0)}). "
                "No other WordPress hardening claim is made from the product name alone."
            ),
            remediation=(
                "Restrict wp-login.php by source, rate-limit authentication, "
                "and require 2FA for administrator accounts."
            ),
            plugin_id="platform-wordpress-login",
            evidence=f"observed login form at {where}; detected: {label}".strip(),
        ))
    if rpc and _looks_xmlrpc(rpc):
        where = (origin + "/xmlrpc.php") if origin else "xmlrpc.php"
        snippet = " ".join((rpc.get("body") or "").split())[:140]
        notes.append(build_platform_note(
            severity="Medium",
            title="WordPress XML-RPC endpoint",
            location=location,
            description=(
                f"xmlrpc.php responded at {where} with HTTP {int(rpc.get('status') or 0)}. "
                "The body identifies an XML-RPC handler."
            ),
            remediation=(
                "Disable XML-RPC if remote publishing is not required, "
                "or require authentication and reject system.multicall."
            ),
            plugin_id="platform-wordpress-xmlrpc",
            evidence=f"response: {snippet}" if snippet else f"observed {where}",
        ))
    if author and _author_exposed(author):
        where = author.get("final_url") or (origin + "/?author=1")
        notes.append(build_platform_note(
            severity="Low",
            title="WordPress author enumeration",
            location=location,
            description=(
                f"Requesting {origin}/?author=1 reached {where}, which exposes an author archive."
            ),
            remediation="Block unauthenticated author archives and REST user listing.",
            plugin_id="platform-wordpress-author",
            evidence=f"final url: {where}",
        ))
    return notes


def _php_observed_notes(stack: dict, location: str) -> list[dict]:
    name = str(stack.get("name") or "")
    version = str(stack.get("version") or "")
    notes: list[dict] = []
    origin = _origin_of(location)
    page = _http_get(location) if origin else {}
    headers = page.get("headers") or {}
    powered = str(headers.get("x-powered-by") or "")
    if "php" in powered.lower():
        notes.append(build_platform_note(
            severity="Low",
            title="PHP version banner",
            location=location,
            description=(
                f"The response from {location} includes X-Powered-By: {powered}. "
                "That header shows expose_php is enabled for this response. "
                "display_errors and allow_url_include are not assumed from it."
            ),
            remediation="Set expose_php=Off and remove the X-Powered-By header.",
            plugin_id="platform-php-banner",
            evidence=f"X-Powered-By: {powered}",
        ))
    shown = _php_error_displayed(page.get("body") or "")
    if shown:
        notes.append(build_platform_note(
            severity="Low",
            title="PHP display_errors output",
            location=location,
            description=(
                f"The response body from {location} contains a PHP diagnostic: {shown}. "
                "Errors are being written into the HTTP response for this request."
            ),
            remediation="Set display_errors=Off and log_errors=On on the server.",
            plugin_id="platform-php-display-errors",
            evidence=shown,
        ))
    ini_text = ""
    ini_where = ""
    info_text = ""
    info_where = ""
    if origin:
        ini_page = _http_get(origin + "/php.ini")
        ini_body = ini_page.get("body") or ""
        ini_parsed = _parse_php_ini(ini_body)
        if int(ini_page.get("status") or 0) == 200 and _looks_like_ini(ini_body, ini_parsed):
            ini_text = ini_body
            ini_where = origin + "/php.ini"
        info_page = _http_get(origin + "/phpinfo.php")
        if int(info_page.get("status") or 0) == 200 and _looks_phpinfo(info_page.get("body") or ""):
            info_text = info_page.get("body") or ""
            info_where = origin + "/phpinfo.php"
    else:
        members = _zip_members(location, {"php.ini", "phpinfo.php"})
        if members.get("php.ini"):
            ini_text = members["php.ini"]
            ini_where = "php.ini"
        if members.get("phpinfo.php") and _looks_phpinfo(members["phpinfo.php"]):
            info_text = members["phpinfo.php"]
            info_where = "phpinfo.php"
    parsed = _parse_php_ini(ini_text) if ini_text else {}
    if ini_text and _looks_like_ini(ini_text, parsed):
        if parsed:
            shown_dirs = ", ".join(f"{k}={v}" for k, v in parsed.items())
            risky = any(
                str(parsed.get(key) or "").lower() in {"on", "1", "true", "yes"}
                for key in ("display_errors", "allow_url_include", "expose_php", "allow_url_fopen")
            )
            notes.append(build_platform_note(
                severity="Medium" if risky else "Low",
                title="PHP configuration values",
                location=location,
                description=(
                    f"php.ini was read from {ini_where}. Observed directives: {shown_dirs}. "
                    "Directives that were not present in that file are not reported."
                ),
                remediation=(
                    "Turn off expose_php, display_errors and allow_url_include where this file sets them on. "
                    "Keep disable_functions aligned with what the application actually runs."
                ),
                plugin_id="platform-php-ini",
                evidence=shown_dirs,
            ))
        else:
            notes.append(build_platform_note(
                severity="Low",
                title="PHP configuration file exposed",
                location=location,
                description=(
                    f"A php.ini file was retrieved from {ini_where}. The readable portion did not set "
                    "expose_php, display_errors, allow_url_include, allow_url_fopen or disable_functions, "
                    "so those values are not claimed."
                ),
                remediation="Keep php.ini outside the web root.",
                plugin_id="platform-php-ini",
                evidence=f"readable php.ini at {ini_where}",
            ))
    if info_text:
        notes.append(build_platform_note(
            severity="Medium",
            title="phpinfo page exposed",
            location=location,
            description=(
                f"A phpinfo page was observed at {info_where}. "
                "It discloses the runtime configuration rendered in that response."
            ),
            remediation="Remove phpinfo scripts from the web root.",
            plugin_id="platform-php-phpinfo",
            evidence=f"phpinfo markers at {info_where}",
        ))
    if version and _is_end_of_life(name, version):
        notes.append(build_platform_note(
            severity="Medium",
            title="Unsupported PHP release",
            location=location,
            description=(
                f"The detected PHP version is {version}, which is on a release line that "
                "no longer receives security updates. No php.ini setting was inferred from the version number."
            ),
            remediation="Upgrade to a supported PHP release.",
            plugin_id="platform-php-eol",
            evidence=f"detected version: {version}",
        ))
    return notes


def _extra_platform_notes(stack: dict, location: str) -> list[dict]:
    """WordPress and PHP notes are emitted only from a response or file that was actually read."""
    name = str(stack.get("name") or "")
    low = name.lower()
    if "wordpress" in low or "wp-content" in low or "wp-engine" in low:
        return _wordpress_observed_notes(stack, location)
    if low == "php" or low.startswith("php ") or "php-fpm" in low:
        return _php_observed_notes(stack, location)
    return []


def notes_for_stacks(target: str, stacks) -> list[dict]:
    location = str(target or "").strip()
    if not location:
        return []
    notes: list[dict] = []
    seen: set[str] = set()
    for stack in normalise_stacks(stacks):
        note = note_for_stack(stack, location)
        if note and note["plugin_id"] not in seen:
            seen.add(note["plugin_id"])
            notes.append(note)
        for extra in _extra_platform_notes(stack, location):
            if extra["plugin_id"] in seen:
                continue
            seen.add(extra["plugin_id"])
            notes.append(extra)
    if not notes:
        named = normalise_stacks(stacks)
        if not named:
            return []
        if all(_evidence_gated_name(s.get("name", "")) for s in named):
            return []
        names = [s.get("name", "Unknown") for s in named]
        label = names[0] if names else "the detected service"
        notes.append(
            build_platform_note(
                severity="Low",
                title=f"Platform baseline review ({label})",
                location=location,
                description=(
                    f"Detected stack component: {label}. Platform-specific "
                    "hardening was not assessed in depth."
                ),
                remediation=f"Apply vendor hardening guidance for {label}.",
                plugin_id="platform-generic",
                evidence=f"detected: {label}",
            )
        )
    return notes
