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
            "Apache HTTP Server was detected serving {location}. Default "
            "configurations expose version and module details and may allow "
            "directory listing."
        ),
        "remediation": (
            "Set ServerTokens Prod and ServerSignature Off, disable the "
            "Indexes option unless directory listing is intended, and disable "
            "modules the application does not use."
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
def note_for_stack(stack: dict, location: str) -> dict | None:
    name = stack.get("name", "")
    version = stack.get("version", "")
    matched = _match_note(name)
    if not matched:
        return None
    key, note = matched
    label = f"{name} {version}".strip()
    severity = note["severity"]
    description = note["description"].format(location=location)
    remediation = note["remediation"]
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
def _extra_platform_notes(stack: dict, location: str) -> list[dict]:
    """Deeper evaluation notes for the two platforms called out in scope (PHP, WordPress)."""
    name = str(stack.get("name") or "")
    version = str(stack.get("version") or "")
    low = name.lower()
    extras: list[dict] = []
    if "wordpress" in low or "wp-content" in low or "wp-engine" in low:
        extras.append(
            build_platform_note(
                severity="Medium",
                title="WordPress XML-RPC and author surface",
                location=location,
                description=(
                    f"WordPress on {location} typically exposes xmlrpc.php (pingback / "
                    "multicall brute-force) and /?author=N user enumeration. These are "
                    "platform defaults, not application features, and should be treated "
                    "as attack surface even when no plugin is vulnerable."
                ),
                remediation=(
                    "Disable XML-RPC if the site does not need remote publishing "
                    "(remove xmlrpc.php or return 403). Block author archives and "
                    "REST user listing for anonymous clients. Rate-limit wp-login.php."
                ),
                plugin_id="platform-wordpress-xmlrpc",
                evidence=f"detected: {name} {version}".strip(),
            )
        )
        extras.append(
            build_platform_note(
                severity="Low",
                title="WordPress plugin and theme update discipline",
                location=location,
                description=(
                    f"The WordPress install detected on {location} inherits every "
                    "installed plugin and theme as part of its trusted computing base. "
                    "Abandoned extensions are the most common path to known-CVE compromise "
                    "on this platform."
                ),
                remediation=(
                    "Inventory plugins and themes, remove anything unused, subscribe to "
                    "update notices, and prefer extensions with a current security process. "
                    "Do not copy plugin ZIP files into the web root as downloadable backups."
                ),
                plugin_id="platform-wordpress-plugins",
                evidence=f"detected: {name} {version}".strip(),
            )
        )
    if low == "php" or low.startswith("php ") or "php-fpm" in low:
        extras.append(
            build_platform_note(
                severity="Low",
                title="PHP information leak and dangerous functions",
                location=location,
                description=(
                    f"PHP on {location} commonly advertises its version via X-Powered-By "
                    "or phpinfo() leftovers, and default builds leave exec-family functions "
                    "enabled. Combined with an upload or include flaw this becomes code execution."
                ),
                remediation=(
                    "Remove phpinfo scripts from the web root, hide the runtime banner, "
                    "and disable exec, passthru, shell_exec, system, proc_open and "
                    "allow_url_include unless a documented feature needs them."
                ),
                plugin_id="platform-php-functions",
                evidence=f"detected: {name} {version}".strip(),
            )
        )
    return extras


def notes_for_stacks(target: str, stacks) -> list[dict]:
    location = str(target or "").strip()
    if not location:
        return []
    notes: list[dict] = []
    seen: set[str] = set()
    for stack in normalise_stacks(stacks):
        note = note_for_stack(stack, location)
        if not note or note["plugin_id"] in seen:
            continue
        seen.add(note["plugin_id"])
        notes.append(note)
        for extra in _extra_platform_notes(stack, location):
            if extra["plugin_id"] in seen:
                continue
            seen.add(extra["plugin_id"])
            notes.append(extra)
    if not notes:
        names = [s.get("name", "Unknown") for s in normalise_stacks(stacks)]
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
