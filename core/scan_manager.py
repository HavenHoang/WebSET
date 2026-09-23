"""
core/scan_manager.py — Real backend (Member 4).

GUI call sites:
    from core.scan_manager import run_scan
    from core.scan_manager import run_static_scan
    from core.scan_manager import run_stack_eval_url
    from core.scan_manager import run_stack_eval_static
"""

from __future__ import annotations

from urllib.parse import urlparse

from crawler import (
    detect_tech_stack,
    detect_tech_stack_from_path,
    open_project_zip,
)
from security_checks import analyse_dynamic, analyse_static

try:
    from security_checks.platform_notes import notes_for_stacks as _real_platform_notes
except Exception:
    _real_platform_notes = None

_FILE_EXT = (
    ".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".cgi",
    ".do", ".action", ".py", ".rb", ".pl",
)


def _fallback_platform_findings(target: str, stacks: list) -> list:
    out = []
    names = " ".join(str(s.get("name") or "").lower() for s in (stacks or []))

    def add(severity, title, detail, rem):
        out.append({
            "severity": severity,
            "vulnerability": title,
            "location": target or "",
            "description": detail,
            "remediation": rem,
            "scan_origin": "Platform",
        })

    if "wordpress" in names or "wp" in names:
        add(
            "Medium",
            "WordPress hardening review",
            "WordPress indicators detected. Review plugins, themes, and admin exposure.",
            "Keep core/plugins/themes updated; disable file edit; restrict wp-admin.",
        )
    if "php" in names:
        add(
            "Low",
            "PHP platform baseline",
            "PHP detected. Display errors and outdated runtimes increase exposure.",
            "Disable display_errors in production; keep the runtime patched.",
        )
    if "java" in names or "tomcat" in names or "spring" in names:
        add(
            "Low",
            "Java platform baseline",
            "Java / servlet stack detected. Review manager endpoints and default pages.",
            "Remove default apps; restrict manager consoles; keep the runtime patched.",
        )
    if "node" in names or "express" in names or "angular" in names:
        add(
            "Low",
            "Node.js / SPA platform baseline",
            "Node.js or SPA indicators detected. Review dependency and header defaults.",
            "Pin dependencies; avoid exposing stack traces; set security headers.",
        )
    if "nginx" in names or "apache" in names:
        add(
            "Low",
            "Web server baseline",
            "Web server fingerprint detected. Default pages and version banners help attackers.",
            "Hide server tokens; disable directory listing; review TLS configuration.",
        )
    if "mysql" in names or "mariadb" in names:
        add(
            "Medium",
            "Database service exposure",
            "Database technology detected in the stack. Confirm it is not reachable from the public web tier.",
            "Bind the DB to internal interfaces only; use least-privilege accounts.",
        )
    if "docker" in names:
        add(
            "Low",
            "Container deployment baseline",
            "Containerisation indicators detected.",
            "Run non-root where possible; pin image tags; limit privileged capabilities.",
        )
    if not out and stacks:
        first = stacks[0].get("name") or "Unknown"
        add(
            "Low",
            f"Platform baseline review ({first})",
            f"Detected stack component: {first}. Platform-specific hardening not assessed in depth.",
            f"Apply vendor hardening guidance for {first}.",
        )
    return out


def _platform_findings(target: str, stacks: list) -> list:
    if _real_platform_notes is not None:
        try:
            notes = _real_platform_notes(target, stacks)
            if notes:
                return list(notes)
        except Exception as exc:
            print("platform_notes:", exc)
    return _fallback_platform_findings(target, stacks)


def _norm_url(raw: str) -> str:
    text = (raw or "").strip()
    if text and "://" not in text:
        text = "http://" + text
    return text


def _directory_prefix(path: str) -> str:
    raw = path or "/"
    if raw in ("", "/"):
        return "/"
    last = raw.rsplit("/", 1)[-1].lower()
    if "." in last and any(last.endswith(ext) for ext in _FILE_EXT):
        parent = raw[: raw.rfind("/")]
        return parent or "/"
    return raw


def _start_parts(url: str) -> tuple[str, str]:
    p = urlparse(_norm_url(url))
    host = (p.netloc or "").lower()
    path = p.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return host, _directory_prefix(path)


def _finding_target(item: dict) -> str:
    return str(
        (item or {}).get("url")
        or (item or {}).get("endpoint")
        or (item or {}).get("location")
        or ""
    )


def _under_start_path(start_url: str, finding: dict) -> bool:
    """Keep same-host findings on the start directory and its subpaths.

    Start at a file in the site root (/login.php, /index.html) → whole host.
    Start at /rest/user/login → keep /rest and below, drop /api/search.
    """
    host, start_path = _start_parts(start_url)
    if not host:
        return True
    raw = _finding_target(finding)
    if not raw:
        return True
    if "://" not in raw and raw.startswith("/"):
        f_host, f_path = host, raw
    else:
        fp = urlparse(_norm_url(raw))
        f_host = (fp.netloc or host).lower()
        f_path = fp.path or "/"
    if f_host and f_host != host:
        return False
    if not f_path.startswith("/"):
        f_path = "/" + f_path
    if f_path != "/" and f_path.endswith("/"):
        f_path = f_path.rstrip("/")
    if start_path in ("", "/"):
        return True
    return f_path == start_path or f_path.startswith(start_path + "/")


def _limit_to_start_path(url: str, findings: list) -> list:
    return [f for f in (findings or []) if _under_start_path(url, f)]


def _apply_start_path(url: str, result):
    if isinstance(result, dict) and result.get("error"):
        return result
    if isinstance(result, list):
        return _limit_to_start_path(url, result)
    if isinstance(result, dict):
        out = dict(result)
        if "findings" in out:
            out["findings"] = _limit_to_start_path(url, out.get("findings") or [])
        return out
    return result


def run_scan(url: str, on_progress=None):
    return _apply_start_path(url, analyse_dynamic(url, on_progress=on_progress))


def run_static_scan(zip_path: str) -> dict:
    result = analyse_static(zip_path)
    if not isinstance(result, dict):
        return {"error": "unreadable_zip"}
    if result.get("error"):
        return {"error": result["error"]}
    findings = result.get("findings") or []
    tech_stacks = detect_tech_stack_from_path(zip_path) or []
    return {"findings": findings, "tech_stacks": tech_stacks}


def run_stack_eval_url(url: str) -> dict:
    stacks = detect_tech_stack(url) or []
    findings = _platform_findings(url, stacks)
    return {"tech_stacks": stacks, "findings": findings}


def run_stack_eval_static(zip_path: str) -> dict:
    project = open_project_zip(zip_path)
    if not project.get("ok"):
        return {"error": project.get("error") or "invalid_zip"}
    stacks = detect_tech_stack_from_path(zip_path) or []
    findings = _platform_findings(zip_path, stacks)
    return {"tech_stacks": stacks, "findings": findings}
