from __future__ import annotations

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

#: Allowed severity values. Ordered most to least serious.
SEVERITY_LEVELS = ("Critical", "High", "Medium", "Low", "Informational")

#: Allowed confidence values. How sure the check is that a finding is real.
CONFIDENCE_LEVELS = ("High", "Medium", "Low")

#: Where a result came from. Platform is Get Stack guidance, never a scan
#: finding, and is stored separately from Dynamic/Static results.
SCAN_ORIGINS = ("Dynamic", "Static", "Platform")

#: Vulnerability types that may expose the Active Test button in Alerts.
ACTIVE_VULN_TYPES = frozenset({
    "xss",
    "sqli",
    "path_traversal",
    "command_injection",
})

#: Vulnerability type used by passive findings (headers, cookies, transport).
PASSIVE_VULN_TYPE = "generic"


# ---------------------------------------------------------------------------
# Field groups
# ---------------------------------------------------------------------------

#: Keys every Start Scan finding must carry with a non-empty value.
REQUIRED_START_SCAN_KEYS = (
    "severity",
    "vulnerability",
    "location",
    "description",
    "remediation",
    "confidence",
    "scan_origin",
)

#: Standards metadata. Start Scan findings only - never Platform notes.
STANDARDS_KEYS = ("cwe_id", "wasc_id", "owasp", "nist", "sans")

#: Context Member 3's payload module needs to build one verification request.
ACTIVE_TEST_KEYS = (
    "url",
    "endpoint",
    "method",
    "param",
    "param_location",
    "context",
    "vuln_type",
)

#: Keys a Platform note must carry. Note the absence of STANDARDS_KEYS.
REQUIRED_PLATFORM_KEYS = (
    "severity",
    "vulnerability",
    "location",
    "description",
    "remediation",
    "confidence",
)


# ---------------------------------------------------------------------------
# Builder behaviour
# ---------------------------------------------------------------------------

#: When True, the builders raise on an invalid finding instead of returning
#: it with a problem list attached. Keep True during development so mistakes
#: surface immediately; the team may flip it to False before the final demo if
#: a crash is worse than one incomplete row in Alerts.
STRICT_VALIDATION = True


# ---------------------------------------------------------------------------
# Active Test eligibility
# ---------------------------------------------------------------------------

def is_active_testable(finding: dict) -> bool:
    """Whether Alerts should offer an Active Test action for this finding.

    A finding qualifies only when it is an injection-style result carrying
    enough context to build exactly one verification request. Passive results
    such as a missing header describe the response itself and have nothing to
    replay, so they never qualify.
    """
    if not finding:
        return False

    # Platform notes are guidance, never a request target.
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

    # Parameter-driven checks cannot be replayed without the parameter name.
    if vtype in {"xss", "sqli"}:
        param = str(finding.get("param") or finding.get("input") or "").strip()
        if not param:
            return False

    return True


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_start_scan_finding(f: dict) -> list[str]:
    """Return a list of problems with a Start Scan finding.

    An empty list means the finding satisfies the contract and is safe to hand
    to the backend.
    """
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

    confidence = str(f.get("confidence") or "").strip()
    if confidence and confidence not in CONFIDENCE_LEVELS:
        problems.append(
            f"confidence {confidence!r} not one of {', '.join(CONFIDENCE_LEVELS)}"
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
    """Return a list of problems with a Get Stack platform note.

    The rules are the mirror image of the Start Scan ones. Platform notes are
    hardening guidance derived from detected technology, not confirmed
    vulnerabilities, so they must not carry standards metadata and must not
    look like something Active Test can replay.
    """
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


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def severity_rank(severity: str) -> int:
    """Sort key for severity, 0 = most serious. Unknown values sort last.

    Useful for ordering Alerts and the report by risk.
    """
    try:
        return SEVERITY_LEVELS.index(str(severity).strip())
    except ValueError:
        return len(SEVERITY_LEVELS)


def sort_findings(findings: list[dict]) -> list[dict]:
    """Return findings ordered by severity, then confidence, then name."""
    def key(f: dict):
        conf = str(f.get("confidence") or "").strip()
        conf_rank = (
            CONFIDENCE_LEVELS.index(conf)
            if conf in CONFIDENCE_LEVELS
            else len(CONFIDENCE_LEVELS)
        )
        return (
            severity_rank(f.get("severity", "")),
            conf_rank,
            str(f.get("vulnerability") or ""),
        )

    return sorted(findings or [], key=key)