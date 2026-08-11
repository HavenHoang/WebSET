# DEMO / FALLBACK ONLY (early GUI testing).
# Member 1 must map CWE/WASC/OWASP/NIST/SANS inside the detection engine for final delivery.
# After Member 1 integration: stop calling this module from db.py / report / alerts,
# then this file may be deleted.
#
# Platform evaluation (scan_origin == "Platform") is NEVER mapped here.
from __future__ import annotations

from typing import Any

PLATFORM_ORIGIN = "Platform"

# (keywords, cwe_id, wasc_id, owasp, plugin_id, nist, sans)
# Start Scan / vulnerability keywords only — no tech-stack platform rules.
RULES: list[tuple[list[str], str, str, str, str, str, str]] = [
    (
        ["x-frame", "clickjack", "frame-options"],
        "CWE-1021",
        "WASC-15",
        "A05",
        "header-xfo",
        "NIST SP 800-53 SC-18",
        "SANS CWE Top 25",
    ),
    (
        ["csp", "content-security-policy"],
        "CWE-1021",
        "WASC-15",
        "A05",
        "header-csp",
        "NIST SP 800-53 SC-18",
        "SANS CWE Top 25",
    ),
    (
        ["hsts", "strict-transport"],
        "CWE-319",
        "WASC-04",
        "A02",
        "header-hsts",
        "NIST SP 800-53 SC-8",
        "SANS Transport Security",
    ),
    (
        ["x-content-type", "nosniff"],
        "CWE-16",
        "WASC-15",
        "A05",
        "header-xcto",
        "NIST SP 800-53 CM-6",
        "SANS Configuration",
    ),
    (
        ["cookie", "httponly", "secure flag", "samesite"],
        "CWE-614",
        "WASC-15",
        "A05",
        "cookie-flags",
        "NIST SP 800-53 SC-8",
        "SANS Session Management",
    ),
    (
        ["server information", "server version", "x-powered-by", "information disclosure"],
        "CWE-200",
        "WASC-13",
        "A05",
        "info-disclosure",
        "NIST SP 800-53 SC-8",
        "SANS Information Leakage",
    ),
    (
        ["xss", "cross-site script", "script-src"],
        "CWE-79",
        "WASC-08",
        "A07",
        "xss-reflected",
        "NIST SP 800-53 SI-10",
        "SANS Top 25 #2",
    ),
    (
        ["sql", "sqli", "injection"],
        "CWE-89",
        "WASC-19",
        "A03",
        "sqli-basic",
        "NIST SP 800-53 SI-10",
        "SANS Top 25 #3",
    ),
    (
        ["command injection", "os command"],
        "CWE-78",
        "WASC-31",
        "A03",
        "cmd-injection",
        "NIST SP 800-53 SI-10",
        "SANS Top 25 #1",
    ),
    (
        ["csrf", "cross-site request"],
        "CWE-352",
        "WASC-09",
        "A01",
        "csrf",
        "NIST SP 800-53 AC-3",
        "SANS Top 25",
    ),
    (
        ["path traversal", "lfi", "directory traversal"],
        "CWE-22",
        "WASC-33",
        "A01",
        "path-traversal",
        "NIST SP 800-53 AC-3",
        "SANS Top 25 #5",
    ),
    (
        ["ssl", "tls", "certificate", "weak cipher"],
        "CWE-295",
        "WASC-04",
        "A02",
        "tls-weak",
        "NIST SP 800-53 SC-8",
        "SANS Transport Security",
    ),
    (
        ["auth", "broken access", "idor"],
        "CWE-284",
        "WASC-02",
        "A01",
        "access-control",
        "NIST SP 800-53 AC-3",
        "SANS Access Control",
    ),
    (
        ["cors", "access-control-allow"],
        "CWE-942",
        "WASC-15",
        "A05",
        "cors-misconfig",
        "NIST SP 800-53 AC-3",
        "SANS Configuration",
    ),
]

DEFAULT_CWE = "CWE-1035"
DEFAULT_WASC = "WASC-15"
DEFAULT_OWASP = "A05"
DEFAULT_PLUGIN = "generic-check"
DEFAULT_CONFIDENCE = "Medium"
DEFAULT_NIST = "NIST SP 800-53 SI-10"
DEFAULT_SANS = "SANS CWE Top 25"


def _match_rule(text: str) -> tuple[str, str, str, str, str, str] | None:
    for keys, cwe_id, wasc_id, owasp_code, plugin_id, nist, sans in RULES:
        if any(k in text for k in keys):
            return cwe_id, wasc_id, owasp_code, plugin_id, nist, sans
    return None


def enrich_finding(f: dict[str, Any] | None) -> dict[str, Any]:
    """
    Fill CWE / WASC / OWASP / NIST / SANS for Start Scan findings only.
    Platform evaluation notes (scan_origin == Platform) are left without standards.
    """
    out: dict[str, Any] = dict(f or {})
    origin = str(out.get("scan_origin") or "")

    # Platform guidance — no standards mapping, no defaults
    if origin == PLATFORM_ORIGIN:
        location = out.get("location") or out.get("url") or ""
        if location and not out.get("location"):
            out["location"] = location
        if location and not out.get("url"):
            out["url"] = location
        conf = out.get("confidence") or DEFAULT_CONFIDENCE
        if conf not in ("High", "Medium", "Low"):
            conf = DEFAULT_CONFIDENCE
        out["confidence"] = conf
        out["remediation"] = out.get("remediation") or ""
        # ensure standards keys stay empty if absent
        for k in ("cwe_id", "wasc_id", "owasp", "nist", "sans"):
            if k not in out or out[k] is None:
                out[k] = ""
        return out

    text = f"{out.get('vulnerability', '')} {out.get('description', '')}".lower()
    matched = _match_rule(text)

    cwe = out.get("cwe_id") or out.get("cweId")
    wasc = out.get("wasc_id") or out.get("wascId")
    owasp = out.get("owasp")
    plugin = out.get("plugin_id") or out.get("pluginId")
    nist = out.get("nist") or out.get("nist_id")
    sans = out.get("sans") or out.get("sans_id")

    if matched:
        m_cwe, m_wasc, m_owasp, m_plugin, m_nist, m_sans = matched
        cwe = cwe or m_cwe
        wasc = wasc or m_wasc
        owasp = owasp or m_owasp
        plugin = plugin or m_plugin
        nist = nist or m_nist
        sans = sans or m_sans

    cwe = cwe or DEFAULT_CWE
    wasc = wasc or DEFAULT_WASC
    owasp = owasp or DEFAULT_OWASP
    plugin = plugin or DEFAULT_PLUGIN
    nist = nist or DEFAULT_NIST
    sans = sans or DEFAULT_SANS

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
    nist_tag = str(nist)
    if nist_tag and nist_tag not in tags:
        tags.append(nist_tag)
    sans_tag = str(sans)
    if sans_tag and sans_tag not in tags:
        tags.append(sans_tag)

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
    out["nist"] = str(nist)
    out["sans"] = str(sans)
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
    out.setdefault("nistId", out["nist"])
    out.setdefault("sansId", out["sans"])
    return out


def enrich_findings(findings: list | None) -> list[dict[str, Any]]:
    return [enrich_finding(f) for f in (findings or [])]


def cwe_summary(findings: list | None) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in enrich_findings(findings):
        if str(f.get("scan_origin") or "") == PLATFORM_ORIGIN:
            continue
        key = str(f.get("cwe_id") or DEFAULT_CWE)
        if not key:
            continue
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))


def owasp_summary(findings: list | None) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in enrich_findings(findings):
        if str(f.get("scan_origin") or "") == PLATFORM_ORIGIN:
            continue
        key = str(f.get("owasp") or DEFAULT_OWASP)
        if not key:
            continue
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))


def nist_summary(findings: list | None) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in enrich_findings(findings):
        if str(f.get("scan_origin") or "") == PLATFORM_ORIGIN:
            continue
        key = str(f.get("nist") or DEFAULT_NIST)
        if not key:
            continue
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))


def sans_summary(findings: list | None) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in enrich_findings(findings):
        if str(f.get("scan_origin") or "") == PLATFORM_ORIGIN:
            continue
        key = str(f.get("sans") or DEFAULT_SANS)
        if not key:
            continue
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))
