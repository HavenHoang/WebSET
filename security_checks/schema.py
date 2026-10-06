from __future__ import annotations

SEVERITY_LEVELS = ("Critical", "High", "Medium", "Low", "Informational")

SCAN_ORIGINS = ("Dynamic", "Static", "Platform")

ACTIVE_VULN_TYPES = frozenset({
    "xss",
    "sqli",
    "nosqli",
    "xxe",
    "path_traversal",
    "command_injection",
    "idor",
})

PASSIVE_VULN_TYPE = "generic"

REQUIRED_START_SCAN_KEYS = (
    "severity",
    "vulnerability",
    "location",
    "description",
    "remediation",
    "scan_origin",
)

STANDARDS_KEYS = ("cwe_id", "wasc_id", "owasp", "nist", "sans")

ACTIVE_TEST_KEYS = (
    "url",
    "endpoint",
    "method",
    "param",
    "param_location",
    "context",
    "vuln_type",
)

REQUIRED_PLATFORM_KEYS = (
    "severity",
    "vulnerability",
    "location",
    "description",
    "remediation",
)

STRICT_VALIDATION = True


def is_active_testable(finding: dict) -> bool:
    if not finding:
        return False
    if str(finding.get("scan_origin") or "") == "Platform":
        return False
    vtype = str(finding.get("vuln_type") or "").lower().strip()
    if vtype not in ACTIVE_VULN_TYPES:
        return False
    url = str(
        finding.get("url")
        or finding.get("endpoint")
        or finding.get("location")
        or ""
    ).strip()
    if not url:
        return False
    param = str(finding.get("param") or finding.get("input") or "").strip()
    if not param:
        return False
    return True


def validate_start_scan_finding(f: dict) -> list[str]:
    if not isinstance(f, dict):
        return ["finding is not a dict"]
    problems: list[str] = []
    for key in REQUIRED_START_SCAN_KEYS:
        if not str(f.get(key) or "").strip():
            problems.append(f"missing {key}")
    for key in STANDARDS_KEYS:
        if not str(f.get(key) or "").strip():
            problems.append(f"missing standards field {key}")
    severity = str(f.get("severity") or "").strip()
    if severity and severity not in SEVERITY_LEVELS:
        problems.append(
            f"severity {severity!r} not one of {', '.join(SEVERITY_LEVELS)}"
        )
    origin = str(f.get("scan_origin") or "").strip()
    if origin == "Platform":
        problems.append("Platform findings must not be returned as scan findings")
    elif origin and origin not in SCAN_ORIGINS:
        problems.append(f"scan_origin {origin!r} is not a known origin")
    if str(f.get("vuln_type") or "").lower() in ACTIVE_VULN_TYPES:
        if not is_active_testable(f):
            problems.append("injection finding is not Active-Test complete")
    return problems


def validate_platform_note(note: dict) -> list[str]:
    if not isinstance(note, dict):
        return ["note is not a dict"]
    problems: list[str] = []
    for key in REQUIRED_PLATFORM_KEYS:
        if not str(note.get(key) or "").strip():
            problems.append(f"missing {key}")
    if str(note.get("scan_origin") or "") != "Platform":
        problems.append("platform note must set scan_origin='Platform'")
    for key in STANDARDS_KEYS:
        if str(note.get(key) or "").strip():
            problems.append(f"platform note must not carry standards field {key}")
    vtype = str(note.get("vuln_type") or "").lower().strip()
    if vtype in ACTIVE_VULN_TYPES:
        problems.append(f"platform note must not use vuln_type {vtype!r}")
    return problems


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_LEVELS.index(str(severity).strip())
    except ValueError:
        return len(SEVERITY_LEVELS)


def sort_findings(findings: list[dict]) -> list[dict]:
    def key(f: dict):
        return (
            severity_rank(f.get("severity", "")),
            str(f.get("vulnerability") or ""),
        )
    return sorted(findings or [], key=key)
