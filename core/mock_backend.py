"""
Demo / mock backend for WebSET GUI testing.

When real modules are ready:
  - Dynamic scan → core.scan_manager.run_scan
  - Static scan  → core.scan_manager.run_static_scan
  - Get Stack URL → core.scan_manager.run_stack_eval_url
  - Get Stack ZIP → core.scan_manager.run_stack_eval_static

GUI should only import from here (or scan_manager), not embed demo lists.

Field convention:
  description = what was observed (issue / note only)
  remediation = how to fix (action only)

Start Scan findings (Member 1):
  MUST set cwe_id, wasc_id, owasp, nist, sans (+ confidence).
  Prefer Active Test fields when known:
    method, param (or input), param_location, context, vuln_type, url/endpoint.
  Active Test is only meaningful for injection-style findings
  (xss / sqli / path_traversal / command_injection) with a real param.
  Passive findings (headers, cookies, CSP, info disclosure) use vuln_type="generic"
  and empty param so Alerts hides the Active Test button.
  Injection demo findings use the *same* URL path the user scanned (not a fake /search).
  _enrich() fills any missing mapping fields via core/cwe_map.py (demo only).

Platform evaluation / stack_findings (Get Stack):
  Guidance only — NO CWE / WASC / OWASP / NIST / SANS mapping.
  Keep severity, description, remediation, confidence.
  scan_origin MUST be "Platform".
"""

from urllib.parse import urlparse, urlunparse


def _enrich(findings: list) -> list:
    """Enrich Start Scan findings only — never use on platform notes."""
    try:
        from core.cwe_map import enrich_findings
        return enrich_findings(findings or [])
    except Exception:
        return findings or []


def _origin(url: str) -> str:
    """Scheme + host only (site-wide passive checks)."""
    raw = (url or "").strip()
    if not raw:
        return "http://localhost:3000"
    p = urlparse(raw if "://" in raw else f"http://{raw}")
    if p.scheme and p.netloc:
        return f"{p.scheme}://{p.netloc}"
    return raw.rstrip("/") or "http://localhost:3000"


def _target_url(url: str) -> str:
    """
    Full URL the user scanned, without query/fragment.
    Active Test injection findings point here so path matches Create Scan.
    """
    raw = (url or "").strip()
    if not raw:
        return "http://localhost:3000/"
    if "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    path = p.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    # drop trailing slash except root (stable location string)
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    if p.scheme and p.netloc:
        return urlunparse((p.scheme, p.netloc, path, "", "", ""))
    return raw.split("?")[0].split("#")[0].rstrip("/") or "http://localhost:3000/"


# ---------------------------------------------------------------------------
# Dynamic Start Scan (Member 4 will replace with real run_scan)
# ---------------------------------------------------------------------------
def run_scan(url: str):
    """
    Success: list of findings (full schema for GUI + Active Test fields).
    Failure: {"error": "unreachable"}

    Injection findings (XSS / SQLi) use the exact scanned path.
    Passive findings use origin (host-level headers / cookies).
    """
    if "notexist" in (url or "") or "invalid" in (url or ""):
        return {"error": "unreachable"}

    base = _origin(url)
    target = _target_url(url)

    return _enrich(
        [
            # ---- Active-testable (injection) — same path as scanned URL ----
            {
                "severity": "High",
                "vulnerability": "Potential Reflected XSS",
                "location": target,
                "url": target,
                "endpoint": target,
                "method": "GET",
                "param": "q",
                "input": "q",
                "param_location": "query",
                "context": "html_body",
                "vuln_type": "xss",
                "description": (
                    "User input appears to be directly reflected in the HTML response "
                    "without reliable encoding."
                ),
                "remediation": (
                    "Encode output for the HTML body context; prefer contextual encoding "
                    "libraries and a strict CSP."
                ),
                "cwe_id": "CWE-79",
                "wasc_id": "WASC-8",
                "owasp": "A03",
                "nist": "NIST SP 800-53 SI-10",
                "sans": "SANS CWE Top 25",
                "confidence": "High",
                "plugin_id": "xss-reflected",
                "scan_origin": "Dynamic",
            },
            {
                "severity": "High",
                "vulnerability": "Potential SQL Injection",
                "location": target,
                "url": target,
                "endpoint": target,
                "method": "GET",
                "param": "id",
                "input": "id",
                "param_location": "query",
                "context": "",
                "vuln_type": "sqli",
                "description": (
                    "Parameter id is used in a data-query path; error or behaviour "
                    "indicators suggest insufficient input handling."
                ),
                "remediation": (
                    "Use parameterised queries / prepared statements; never concatenate "
                    "user input into SQL."
                ),
                "cwe_id": "CWE-89",
                "wasc_id": "WASC-19",
                "owasp": "A03",
                "nist": "NIST SP 800-53 SI-10",
                "sans": "SANS CWE Top 25",
                "confidence": "High",
                "plugin_id": "sqli-param",
                "scan_origin": "Dynamic",
            },
            # ---- Passive only (no Active Test button) — host-level ----
            {
                "severity": "High",
                "vulnerability": "Missing Security Header",
                "location": base,
                "url": base,
                "endpoint": base,
                "method": "GET",
                "param": "",
                "input": "",
                "param_location": "header",
                "context": "",
                "vuln_type": "generic",
                "description": "X-Frame-Options header is missing.",
                "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN).",
                "cwe_id": "CWE-1021",
                "wasc_id": "WASC-15",
                "owasp": "A05",
                "nist": "NIST SP 800-53 SC-18",
                "sans": "SANS CWE Top 25",
                "confidence": "High",
                "plugin_id": "header-xfo",
                "scan_origin": "Dynamic",
            },
            {
                "severity": "High",
                "vulnerability": "Insecure Cookie",
                "location": base,
                "url": base,
                "endpoint": base,
                "method": "GET",
                "param": "",
                "input": "",
                "param_location": "cookie",
                "context": "",
                "vuln_type": "generic",
                "description": "Session cookie is set without the Secure flag.",
                "remediation": "Set Secure and HttpOnly flags on all session cookies.",
                "cwe_id": "CWE-614",
                "wasc_id": "WASC-15",
                "owasp": "A05",
                "nist": "NIST SP 800-53 SC-8",
                "sans": "SANS Session Management",
                "confidence": "High",
                "plugin_id": "cookie-flags",
                "scan_origin": "Dynamic",
            },
            {
                "severity": "Medium",
                "vulnerability": "Server Information Disclosure",
                "location": base,
                "url": base,
                "endpoint": base,
                "method": "GET",
                "param": "",
                "input": "",
                "param_location": "header",
                "context": "",
                "vuln_type": "generic",
                "description": "Server / framework version is exposed in response headers.",
                "remediation": "Remove or obfuscate Server and X-Powered-By version headers.",
                "cwe_id": "CWE-200",
                "wasc_id": "WASC-13",
                "owasp": "A05",
                "nist": "NIST SP 800-53 SC-8",
                "sans": "SANS Information Leakage",
                "confidence": "Medium",
                "plugin_id": "info-disclosure",
                "scan_origin": "Dynamic",
            },
            {
                "severity": "Low",
                "vulnerability": "Missing CSP",
                "location": base,
                "url": base,
                "endpoint": base,
                "method": "GET",
                "param": "",
                "input": "",
                "param_location": "header",
                "context": "",
                "vuln_type": "generic",
                "description": "Content-Security-Policy header is not set.",
                "remediation": "Implement a strict Content-Security-Policy header.",
                "cwe_id": "CWE-1021",
                "wasc_id": "WASC-15",
                "owasp": "A05",
                "nist": "NIST SP 800-53 SC-18",
                "sans": "SANS CWE Top 25",
                "confidence": "Medium",
                "plugin_id": "header-csp",
                "scan_origin": "Dynamic",
            },
        ]
    )


# ---------------------------------------------------------------------------
# Static Start Scan (demo)
# ---------------------------------------------------------------------------
def run_static_scan(zip_path: str):
    """
    Success preferred: {"findings": [...], "tech_stacks": [...]}
    Failure: {"error": "invalid_zip"|"empty_zip"|"no_analyzable_files"}
    """
    path = zip_path or ""
    low = path.lower()
    if "empty" in low:
        return {"error": "empty_zip"}
    if "invalid" in low or "corrupt" in low:
        return {"error": "invalid_zip"}
    if "nofile" in low:
        return {"error": "no_analyzable_files"}
    findings = _enrich(
        [
            {
                "severity": "Medium",
                "vulnerability": "Static analysis placeholder",
                "location": path,
                "url": path,
                "endpoint": path,
                "method": "STATIC",
                "param": "",
                "input": "",
                "param_location": "",
                "context": "",
                "vuln_type": "generic",
                "description": "Placeholder finding until Member 1 static rules are connected.",
                "remediation": "Replace this entry with real static-analysis rule output from Member 1.",
                "cwe_id": "CWE-1035",
                "wasc_id": "WASC-15",
                "owasp": "A05",
                "nist": "NIST SP 800-53 SI-10",
                "sans": "SANS CWE Top 25",
                "confidence": "Low",
                "plugin_id": "static-placeholder",
                "scan_origin": "Static",
            }
        ]
    )
    stacks = detect_tech_stack_from_path(path)
    return {"findings": findings, "tech_stacks": stacks}


# ---------------------------------------------------------------------------
# Tech stack detection (demo) — Get Stack
# ---------------------------------------------------------------------------
def detect_tech_stack(url: str = "") -> list:
    host = (url or "").split("://")[-1].split("/")[0] or "target"
    return [
        {
            "name": "Nginx",
            "category": "Web Server",
            "version": "1.24.0",
            "description": f"Reverse proxy / static content indicators for {host}.",
        },
        {
            "name": "Node.js",
            "category": "Runtime",
            "version": "20.x",
            "description": "JavaScript server runtime indicators.",
        },
        {
            "name": "React",
            "category": "Frontend",
            "version": "18.x",
            "description": "UI library markers in client assets.",
        },
        {
            "name": "MySQL",
            "category": "Database",
            "version": "8.0",
            "description": "Relational database layer indicators.",
        },
        {
            "name": "Docker",
            "category": "Infrastructure",
            "version": "",
            "description": "Containerised deployment indicators.",
        },
    ]


def detect_tech_stack_from_path(project_root: str = "") -> list:
    import os

    name = os.path.basename(project_root or "") or "project.zip"
    return [
        {
            "name": "PHP",
            "category": "Language",
            "version": "8.x",
            "description": f"PHP markers inferred from archive ({name}).",
        },
        {
            "name": "WordPress",
            "category": "CMS",
            "version": "6.x",
            "description": "CMS layout patterns in project tree.",
        },
        {
            "name": "MySQL",
            "category": "Database",
            "version": "8.0",
            "description": "Database usage hinted by config files.",
        },
        {
            "name": "Apache",
            "category": "Web Server",
            "version": "",
            "description": "Common web server pairing for PHP apps.",
        },
        {
            "name": "Docker",
            "category": "Infrastructure",
            "version": "",
            "description": "Container metadata in project tree.",
        },
    ]


# ---------------------------------------------------------------------------
# Platform evaluation (Get Stack) — guidance only, NO standards mapping
# ---------------------------------------------------------------------------
def _platform_findings(target: str, stacks: list) -> list:
    location = target or ""
    names = {str(s.get("name", "")).lower() for s in (stacks or [])}
    out = []

    def add(sev, title, desc, rem, plugin, confidence="Medium"):
        out.append(
            {
                "severity": sev,
                "vulnerability": title,
                "location": location,
                "description": desc,
                "remediation": rem,
                "confidence": confidence,
                "plugin_id": plugin,
                "scan_origin": "Platform",
            }
        )

    if any(n in names for n in ("wordpress", "wp")):
        add(
            "High",
            "WordPress configuration exposure risk",
            "WordPress-related stack detected; common exposure points include file editing and version/plugin disclosure.",
            "Disable file editing in wp-config; keep core and plugins updated; restrict admin access.",
            "platform-wordpress",
            "High",
        )
    if "php" in names:
        add(
            "Medium",
            "PHP version / expose_php risk",
            "PHP stack detected; interpreter version may be visible to clients.",
            "Set expose_php=Off; hide PHP version tokens in responses.",
            "platform-php",
            "Medium",
        )
    if any(n in names for n in ("java", "spring", "tomcat")):
        add(
            "Medium",
            "Java / Spring security baseline",
            "Java-related stack detected; default error pages or management endpoints may be exposed.",
            "Lock down actuators; customise error pages; enforce secure headers.",
            "platform-java",
            "Medium",
        )
    if "node.js" in names or "node" in names:
        add(
            "Low",
            "Node.js dependency hygiene",
            "Node.js runtime detected; dependency and error-handling posture should be reviewed.",
            "Audit dependencies regularly; do not expose stack traces in production.",
            "platform-node",
            "Medium",
        )
    if "nginx" in names or "apache" in names:
        add(
            "Low",
            "Web server information disclosure",
            "Web server stack detected; Server banner or weak TLS/header posture may leak detail.",
            "Reduce Server banner detail; harden TLS and security headers.",
            "platform-webserver",
            "Medium",
        )
    if "react" in names:
        add(
            "Low",
            "Frontend build / source-map hygiene",
            "React frontend markers detected; production builds may still expose source maps or verbose errors.",
            "Disable public source maps in production; avoid leaking stack traces to clients.",
            "platform-react",
            "Low",
        )
    if "mysql" in names:
        add(
            "Low",
            "Database exposure baseline",
            "MySQL indicators present; ensure the database is not reachable from untrusted networks.",
            "Bind DB to private interfaces; use strong credentials; restrict remote admin.",
            "platform-mysql",
            "Medium",
        )
    if "docker" in names:
        add(
            "Low",
            "Container deployment baseline",
            "Containerisation indicators detected; image and runtime hardening should be reviewed.",
            "Run non-root where possible; pin image tags; limit privileged capabilities.",
            "platform-docker",
            "Low",
        )

    if not out and stacks:
        first = stacks[0].get("name", "Unknown")
        add(
            "Low",
            f"Platform baseline review ({first})",
            f"Detected stack component: {first}; platform-specific security baseline not yet assessed in depth.",
            f"Apply hardening baseline guidance for {first}.",
            "platform-generic",
            "Low",
        )

    return out


def run_stack_eval_url(url: str) -> dict:
    stacks = detect_tech_stack(url)
    findings = _platform_findings(url, stacks)
    return {"tech_stacks": stacks, "findings": findings}


def run_stack_eval_static(zip_path: str) -> dict:
    path = zip_path or ""
    low = path.lower()
    if "empty" in low:
        return {"error": "empty_zip"}
    if "invalid" in low or "corrupt" in low:
        return {"error": "invalid_zip"}
    if "nofile" in low:
        return {"error": "no_analyzable_files"}
    stacks = detect_tech_stack_from_path(path)
    findings = _platform_findings(path, stacks)
    return {"tech_stacks": stacks, "findings": findings}
