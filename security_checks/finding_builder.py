from __future__ import annotations
from security_checks.rules import get_rule
from security_checks.schema import (
    PASSIVE_VULN_TYPE,
    STRICT_VALIDATION,
    validate_start_scan_finding,
)
class FindingValidationError(ValueError):
    pass
class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"
_RESERVED_KWARGS = frozenset({
    "location", "scan_origin", "severity", "evidence",
    "url", "method", "param", "param_location", "context", "vuln_type",
    "plugin_id",
})
_FALLBACK_RULES = {
    "sqli-error": {
        "severity": "High",
        "vulnerability": "SQL Injection",
        "description_template": "A database error or tautology response was observed on {location} for parameter {param}.",
        "remediation": "Use parameterised queries and reject unexpected input before it reaches SQL.",
        "cwe_id": "CWE-89",
        "wasc_id": "WASC-19",
        "owasp": "A03:2021 Injection",
        "nist": "NIST SP 800-53 SI-10",
        "sans": "CWE Top 25",
    },
    "sqli-auth": {
        "severity": "High",
        "vulnerability": "SQL Injection (authentication)",
        "description_template": "A crafted SQL value in {param} at {location} produced an authenticated response.",
        "remediation": "Use parameterised queries on login fields and reject unexpected input.",
        "cwe_id": "CWE-89",
        "wasc_id": "WASC-19",
        "owasp": "A03:2021 Injection",
        "nist": "NIST SP 800-53 SI-10",
        "sans": "CWE Top 25",
    },
    "xss-reflected": {
        "severity": "High",
        "vulnerability": "Reflected XSS",
        "description_template": "User input from {param} was reflected on {location} without encoding.",
        "remediation": "Encode output for the relevant HTML context and apply a strict CSP.",
        "cwe_id": "CWE-79",
        "wasc_id": "WASC-08",
        "owasp": "A03:2021 Injection",
        "nist": "NIST SP 800-53 SI-10",
        "sans": "CWE Top 25",
    },
    "path-traversal": {
        "severity": "High",
        "vulnerability": "Path Traversal",
        "description_template": "A traversal probe on {param} at {location} returned a foreign file signature.",
        "remediation": "Resolve paths against an allow-list directory and reject .. segments.",
        "cwe_id": "CWE-22",
        "wasc_id": "WASC-33",
        "owasp": "A01:2021 Broken Access Control",
        "nist": "NIST SP 800-53 AC-3",
        "sans": "CWE Top 25",
    },
    "nosqli": {
        "severity": "High",
        "vulnerability": "NoSQL Operator Injection",
        "description_template": "A document-database operator in {param} at {location} produced an authenticated or altered response.",
        "remediation": "Do not pass raw request objects into database APIs. Reject keys that begin with $.",
        "cwe_id": "CWE-943",
        "wasc_id": "WASC-19",
        "owasp": "A03:2021 Injection",
        "nist": "NIST SP 800-53 SI-10",
        "sans": "Not in CWE Top 25",
    },
    "cmd-injection": {
        "severity": "High",
        "vulnerability": "Command Injection",
        "description_template": "A command-separator probe on {param} at {location} returned OS command output.",
        "remediation": "Do not pass user input to a shell. Use a fixed command allow-list and structured arguments.",
        "cwe_id": "CWE-78",
        "wasc_id": "WASC-31",
        "owasp": "A03:2021 Injection",
        "nist": "NIST SP 800-53 SI-10",
        "sans": "CWE Top 25",
    },
}
def _render(template: str, values: dict) -> str:
    try:
        return str(template).format_map(_SafeDict(values))
    except (ValueError, IndexError):
        return str(template)
def _split_template_values(values: dict) -> dict:
    return {k: v for k, v in values.items() if k not in _RESERVED_KWARGS}
def _one_url(*candidates: str) -> str:
    texts = []
    for raw in candidates:
        for part in str(raw or "").replace(",", "\n").splitlines():
            text = part.strip()
            if text:
                texts.append(text)
    if not texts:
        return ""
    http = [t for t in texts if t.startswith(("http://", "https://", "/"))]
    return (http or texts)[0]
def _lookup_rule(plugin_id: str) -> dict:
    try:
        rule = get_rule(plugin_id)
        if rule:
            return rule
    except Exception:
        pass
    if plugin_id in _FALLBACK_RULES:
        return dict(_FALLBACK_RULES[plugin_id])
    return {
        "severity": "Medium",
        "vulnerability": plugin_id.replace("-", " ").title(),
        "description_template": "Issue {plugin_id} observed at {location}.",
        "remediation": "Review the endpoint and apply the matching control.",
        "cwe_id": "CWE-693",
        "wasc_id": "WASC-15",
        "owasp": "A05:2021 Security Misconfiguration",
        "nist": "NIST SP 800-53 SI-10",
        "sans": "Not in CWE Top 25",
    }
def _finalise(finding: dict) -> dict:
    problems = validate_start_scan_finding(finding)
    if problems:
        finding["_validation_problems"] = problems
        if STRICT_VALIDATION:
            finding["_validation_strict"] = True
    return finding
def build_finding(
    *,
    severity: str,
    vulnerability: str,
    location: str,
    description: str,
    remediation: str,
    cwe_id: str,
    wasc_id: str,
    owasp: str,
    nist: str,
    sans: str,
    scan_origin: str = "Dynamic",
    plugin_id: str = "",
    evidence: str = "",
    url: str | None = None,
    method: str | None = None,
    param: str | None = None,
    param_location: str | None = None,
    context: str | None = None,
    vuln_type: str | None = None,
) -> dict:
    target = _one_url(url, location)
    param_value = str(param or "").strip()
    finding = {
        "severity": severity,
        "vulnerability": vulnerability,
        "location": target,
        "description": description,
        "remediation": remediation,
        "evidence": evidence,
        "cwe_id": cwe_id,
        "wasc_id": wasc_id,
        "owasp": owasp,
        "nist": nist,
        "sans": sans,
        "plugin_id": plugin_id,
        "scan_origin": scan_origin,
        "url": target,
        "endpoint": target,
        "method": (method or "GET").upper(),
        "param": param_value,
        "input": param_value,
        "param_location": param_location or "",
        "context": context or "",
        "vuln_type": str(vuln_type or PASSIVE_VULN_TYPE).lower(),
    }
    return _finalise(finding)
def build_from_rule(
    plugin_id: str,
    *,
    location: str,
    scan_origin: str = "Dynamic",
    evidence: str = "",
    severity: str | None = None,
    url: str | None = None,
    method: str | None = None,
    param: str | None = None,
    param_location: str | None = None,
    context: str | None = None,
    vuln_type: str | None = None,
    **template_values,
) -> dict:
    rule = _lookup_rule(plugin_id)
    values = dict(template_values)
    target = _one_url(url, location)
    values.setdefault("location", target)
    values.setdefault("plugin_id", plugin_id)
    if param:
        values.setdefault("param", param)
    description = _render(rule["description_template"], values)
    finding = build_finding(
        severity=severity or rule["severity"],
        vulnerability=rule["vulnerability"],
        location=target,
        description=description,
        remediation=rule["remediation"],
        cwe_id=rule["cwe_id"],
        wasc_id=rule["wasc_id"],
        owasp=rule["owasp"],
        nist=rule["nist"],
        sans=rule["sans"],
        scan_origin=scan_origin,
        plugin_id=plugin_id,
        evidence=evidence,
        url=target,
        method=method,
        param=param,
        param_location=param_location,
        context=context,
        vuln_type=vuln_type,
    )
    finding["owasp_2021"] = str(rule.get("owasp_2021") or rule.get("owasp") or "")
    finding["owasp_2025"] = str(rule.get("owasp_2025") or rule.get("owasp") or "")
    return finding
def build_passive_rule_finding(
    plugin_id: str,
    *,
    location: str,
    scan_origin: str = "Dynamic",
    param_location: str = "header",
    evidence: str = "",
    severity: str | None = None,
    **template_values,
) -> dict:
    return build_from_rule(
        plugin_id,
        location=location,
        scan_origin=scan_origin,
        severity=severity,
        evidence=evidence,
        url=location,
        method="GET",
        param="",
        param_location=param_location,
        context="",
        vuln_type=PASSIVE_VULN_TYPE,
        **_split_template_values(template_values),
    )
def build_injection_rule_finding(
    plugin_id: str,
    *,
    url: str,
    param: str,
    vuln_type: str,
    method: str = "GET",
    param_location: str = "query",
    context: str = "",
    scan_origin: str = "Dynamic",
    evidence: str = "",
    severity: str | None = None,
    **template_values,
) -> dict:
    return build_from_rule(
        plugin_id,
        location=url,
        scan_origin=scan_origin,
        severity=severity,
        evidence=evidence,
        url=url,
        method=method,
        param=param,
        param_location=param_location,
        context=context,
        vuln_type=vuln_type,
        **_split_template_values(template_values),
    )
def build_passive_finding(
    *,
    severity: str,
    vulnerability: str,
    location: str,
    description: str,
    remediation: str,
    cwe_id: str,
    wasc_id: str,
    owasp: str,
    nist: str,
    sans: str,
    scan_origin: str = "Dynamic",
    plugin_id: str = "",
    param_location: str = "header",
    evidence: str = "",
    vuln_type: str | None = None,
) -> dict:
    return build_finding(
        severity=severity,
        vulnerability=vulnerability,
        location=location,
        description=description,
        remediation=remediation,
        cwe_id=cwe_id,
        wasc_id=wasc_id,
        owasp=owasp,
        nist=nist,
        sans=sans,
        scan_origin=scan_origin,
        plugin_id=plugin_id,
        evidence=evidence,
        url=location,
        method="GET",
        param="",
        param_location=param_location,
        context="",
        vuln_type=vuln_type or PASSIVE_VULN_TYPE,
    )
def build_injection_finding(
    *,
    severity: str,
    vulnerability: str,
    url: str,
    description: str,
    remediation: str,
    vuln_type: str,
    param: str,
    cwe_id: str,
    wasc_id: str,
    owasp: str,
    nist: str,
    sans: str,
    method: str = "GET",
    param_location: str = "query",
    context: str = "",
    scan_origin: str = "Dynamic",
    plugin_id: str = "",
    evidence: str = "",
) -> dict:
    return build_finding(
        severity=severity,
        vulnerability=vulnerability,
        location=url,
        description=description,
        remediation=remediation,
        cwe_id=cwe_id,
        wasc_id=wasc_id,
        owasp=owasp,
        nist=nist,
        sans=sans,
        scan_origin=scan_origin,
        plugin_id=plugin_id,
        evidence=evidence,
        url=url,
        method=method,
        param=param,
        param_location=param_location,
        context=context,
        vuln_type=vuln_type,
    )
