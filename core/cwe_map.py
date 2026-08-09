# DEMO / FALLBACK ONLY (early GUI testing).
# Member 1 must map CWE/WASC/OWASP inside the detection engine for final delivery.
# After Member 1 integration: stop calling this module from db.py / report_tab / alerts_page,
# then this file may be deleted.

from __future__ import annotations

from typing import Any


RULES: list[tuple[list[str], str, str, str, str]] = [
    (["x-frame", "clickjack", "frame-options"], "CWE-1021", "WASC-15", "A05", "header-xfo"),
    (["csp", "content-security-policy"], "CWE-1021", "WASC-15", "A05", "header-csp"),
    (["hsts", "strict-transport"], "CWE-319", "WASC-04", "A02", "header-hsts"),
    (["x-content-type", "nosniff"], "CWE-16", "WASC-15", "A05", "header-xcto"),
    (["cookie", "httponly", "secure flag", "samesite"], "CWE-614", "WASC-15", "A05", "cookie-flags"),
    (
        ["server information", "server version", "x-powered-by", "information disclosure"],
        "CWE-200",
        "WASC-13",
        "A05",
        "info-disclosure",
    ),
    (["xss", "cross-site script", "script-src"], "CWE-79", "WASC-08", "A07", "xss-reflected"),
    (["sql", "sqli", "injection"], "CWE-89", "WASC-19", "A03", "sqli-basic"),
    (["command injection", "os command"], "CWE-78", "WASC-31", "A03", "cmd-injection"),
    (["csrf", "cross-site request"], "CWE-352", "WASC-09", "A01", "csrf"),
    (["path traversal", "lfi", "directory traversal"], "CWE-22", "WASC-33", "A01", "path-traversal"),
    (["ssl", "tls", "certificate", "weak cipher"], "CWE-295", "WASC-04", "A02", "tls-weak"),
    (["auth", "broken access", "idor"], "CWE-284", "WASC-02", "A01", "access-control"),
    (["cors", "access-control-allow"], "CWE-942", "WASC-15", "A05", "cors-misconfig"),
]

DEFAULT_CWE = "CWE-1035"  # generic OWASP-related weakness
DEFAULT_WASC = "WASC-15"  # application misconfiguration
DEFAULT_OWASP = "A05"  # Security Misconfiguration
DEFAULT_PLUGIN = "generic-check"
DEFAULT_CONFIDENCE = "Medium"


def _match_rule(text: str) -> tuple[str, str, str, str] | None:
    for keys, cwe_id, wasc_id, owasp_code, plugin_id in RULES:
        if any(k in text for k in keys):
            return cwe_id, wasc_id, owasp_code, plugin_id
    return None


def enrich_finding(f: dict[str, Any] | None) -> dict[str, Any]:
    """
    Fill CWE / WASC / OWASP / plugin / confidence / tags / url / message_id
    without overwriting values already set by the detection engine.
    """
    out: dict[str, Any] = dict(f or {})
    text = f"{out.get('vulnerability', '')} {out.get('description', '')}".lower()

    matched = _match_rule(text)

    cwe = out.get("cwe_id") or out.get("cweId")
    wasc = out.get("wasc_id") or out.get("wascId")
    owasp = out.get("owasp")
    plugin = out.get("plugin_id") or out.get("pluginId")

    if matched:
        m_cwe, m_wasc, m_owasp, m_plugin = matched
        cwe = cwe or m_cwe
        wasc = wasc or m_wasc
        owasp = owasp or m_owasp
        plugin = plugin or m_plugin

    cwe = cwe or DEFAULT_CWE
    wasc = wasc or DEFAULT_WASC
    owasp = owasp or DEFAULT_OWASP
    plugin = plugin or DEFAULT_PLUGIN

    tags = out.get("tags")
    if not isinstance(tags, list):
        tags = []
    else:
        tags = list(tags)

    owasp_tag = f"OWASP-{owasp}"
    if owasp_tag not in tags:
        tags.append(owasp_tag)
    if cwe not in tags:
        tags.append(cwe)
    if wasc not in tags:
        tags.append(wasc)

    location = out.get("location") or out.get("url") or ""
    url = out.get("url") or location

    confidence = out.get("confidence") or DEFAULT_CONFIDENCE
    if confidence not in ("High", "Medium", "Low"):
        confidence = DEFAULT_CONFIDENCE

    message_id = out.get("message_id") or out.get("messageId")
    if not message_id:
        slug = str(out.get("vulnerability", "finding")).strip().replace(" ", "-")[:24]
        tail = str(location)[-8:] if location else "0"
        message_id = f"msg-{slug}-{tail}"

    out["cwe_id"] = str(cwe)
    out["wasc_id"] = str(wasc)
    out["owasp"] = str(owasp)
    out["plugin_id"] = str(plugin)
    out["confidence"] = confidence
    out["tags"] = tags
    out["url"] = url
    if location and not out.get("location"):
        out["location"] = location
    out["message_id"] = str(message_id)

    out.setdefault("cweId", out["cwe_id"])
    out.setdefault("wascId", out["wasc_id"])
    out.setdefault("pluginId", out["plugin_id"])
    out.setdefault("messageId", out["message_id"])

    return out


def enrich_findings(findings: list | None) -> list[dict[str, Any]]:
    """Enrich a list of findings; returns a new list."""
    return [enrich_finding(f) for f in (findings or [])]


def cwe_summary(findings: list | None) -> dict[str, int]:
    """Count findings per CWE id (for report / dashboard)."""
    counts: dict[str, int] = {}
    for f in enrich_findings(findings):
        key = str(f.get("cwe_id") or DEFAULT_CWE)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))


def owasp_summary(findings: list | None) -> dict[str, int]:
    """Count findings per OWASP code (A01, A03, …)."""
    counts: dict[str, int] = {}
    for f in enrich_findings(findings):
        key = str(f.get("owasp") or DEFAULT_OWASP)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))
