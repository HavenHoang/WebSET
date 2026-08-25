from __future__ import annotations

from security_checks.rules import get_rule
from security_checks.schema import (
    PASSIVE_VULN_TYPE,
    STRICT_VALIDATION,
    validate_start_scan_finding,
)


class FindingValidationError(ValueError):
    """Raised when a builder produces a finding that breaks the GUI contract."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

class _SafeDict(dict):
    """Leaves unknown placeholders intact instead of raising KeyError."""

    def __missing__(self, key: str) -> str:  # pragma: no cover - trivial
        return "{" + key + "}"


def _render(template: str, values: dict) -> str:
    """Fill a description template, tolerating missing placeholders.

    A template that references {cookie_name} should not crash the whole scan
    just because one call site forgot to pass it.
    """
    try:
        return str(template).format_map(_SafeDict(values))
    except (ValueError, IndexError):
        # Malformed template (stray brace, positional field). Return it raw so
        # the finding still reaches the user with usable standards metadata.
        return str(template)


#: Builder arguments that must not be overridden by **template_values.
_RESERVED_KWARGS = frozenset({
    "location", "confidence", "scan_origin", "severity", "evidence",
    "url", "method", "param", "param_location", "context", "vuln_type",
    "plugin_id",
})


def _split_template_values(values: dict) -> dict:
    """Drop reserved builder arguments from caller-supplied template values.

    A caller passing ``param="q"`` to a passive builder would otherwise collide
    with the explicit ``param=""`` the wrapper sets. Values the templates
    genuinely need are injected in :func:`build_from_rule` instead.
    """
    return {k: v for k, v in values.items() if k not in _RESERVED_KWARGS}


def _finalise(finding: dict) -> dict:
    """Validate and return, honouring STRICT_VALIDATION."""
    problems = validate_start_scan_finding(finding)
    if problems:
        message = (
            f"Invalid finding {finding.get('plugin_id') or '<no plugin_id>'}: "
            + "; ".join(problems)
        )
        if STRICT_VALIDATION:
            raise FindingValidationError(message)
        finding["_validation_problems"] = problems
    return finding


# ---------------------------------------------------------------------------
# Low-level builder
# ---------------------------------------------------------------------------

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
    confidence: str = "Medium",
    scan_origin: str = "Dynamic",
    plugin_id: str = "",
    evidence: str = "",
    # Active Test fields - set these for injection issues only.
    url: str | None = None,
    method: str | None = None,
    param: str | None = None,
    param_location: str | None = None,
    context: str | None = None,
    vuln_type: str | None = None,
) -> dict:
    """Build a Start Scan finding with every contract field populated.

    ``url``/``endpoint`` and ``param``/``input`` are stored as mirrored pairs
    because different consumers in the team read different names.
    """
    target = str(url or location or "").strip()
    param_value = str(param or "").strip()

    finding = {
        # Presentation
        "severity": severity,
        "vulnerability": vulnerability,
        "location": location,
        "description": description,
        "remediation": remediation,
        "confidence": confidence,
        "evidence": evidence,
        # Standards metadata (Start Scan only)
        "cwe_id": cwe_id,
        "wasc_id": wasc_id,
        "owasp": owasp,
        "nist": nist,
        "sans": sans,
        # Provenance
        "plugin_id": plugin_id,
        "scan_origin": scan_origin,
        # Active Test context
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


# ---------------------------------------------------------------------------
# Catalogue-driven builder (use this one)
# ---------------------------------------------------------------------------

def build_from_rule(
    plugin_id: str,
    *,
    location: str,
    confidence: str = "Medium",
    scan_origin: str = "Dynamic",
    evidence: str = "",
    severity: str | None = None,
    # Active Test context - injection rules only.
    url: str | None = None,
    method: str | None = None,
    param: str | None = None,
    param_location: str | None = None,
    context: str | None = None,
    vuln_type: str | None = None,
    # Extra values for the rule's description template, e.g. cookie_name.
    **template_values,
) -> dict:
    """Build a finding from a catalogue rule.

    The rule supplies the fixed knowledge (name, severity, standards,
    remediation, description template). The caller supplies what was actually
    observed: where it was found, how confident the check is, and any values
    the description template needs.

    Args:
        plugin_id: Key into :data:`security_checks.rules.RULES`.
        location: URL or file path where the issue was observed.
        confidence: How sure the check is that this is real. Decided by the
            detection code, not the rule.
        severity: Overrides the rule's severity. Use sparingly - only when the
            observed instance is genuinely more or less serious than the class
            (for example a non-session cookie missing HttpOnly).
        evidence: Short raw excerpt supporting the finding, such as the header
            line that was seen.
        **template_values: Extra placeholders for the description template.

    Returns:
        A validated finding dict.
    """
    rule = get_rule(plugin_id)

    values = dict(template_values)
    values.setdefault("location", location)
    if param:
        values.setdefault("param", param)

    description = _render(rule["description_template"], values)

    return build_finding(
        severity=severity or rule["severity"],
        vulnerability=rule["vulnerability"],
        location=location,
        description=description,
        remediation=rule["remediation"],
        cwe_id=rule["cwe_id"],
        wasc_id=rule["wasc_id"],
        owasp=rule["owasp"],
        nist=rule["nist"],
        sans=rule["sans"],
        confidence=confidence,
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


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------

def build_passive_rule_finding(
    plugin_id: str,
    *,
    location: str,
    confidence: str = "High",
    scan_origin: str = "Dynamic",
    param_location: str = "header",
    evidence: str = "",
    severity: str | None = None,
    **template_values,
) -> dict:
    """Headers, cookies, transport: standards yes, Active Test no.

    Passive checks default to high confidence because they observe a fact
    about the response (a header is present or it is not) rather than
    inferring behaviour.
    """
    return build_from_rule(
        plugin_id,
        location=location,
        confidence=confidence,
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
    confidence: str = "Medium",
    scan_origin: str = "Dynamic",
    evidence: str = "",
    severity: str | None = None,
    **template_values,
) -> dict:
    """XSS, SQLi and similar: must carry param and vuln_type for Active Test.

    Confidence defaults to Medium rather than High. These checks infer
    behaviour from indicators such as reflection or error strings, and the
    Active Test step exists precisely because that inference needs
    confirmation.
    """
    return build_from_rule(
        plugin_id,
        location=url,
        confidence=confidence,
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


# ---------------------------------------------------------------------------
# Backwards-compatible aliases
# ---------------------------------------------------------------------------
# The original code pack passed standards metadata in by hand. These keep that
# signature working so nothing breaks mid-refactor, but new checks should call
# the *_rule_finding helpers above.

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
    confidence: str = "Medium",
    scan_origin: str = "Dynamic",
    plugin_id: str = "",
    param_location: str = "header",
    evidence: str = "",
) -> dict:
    """Deprecated: prefer :func:`build_passive_rule_finding`."""
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
        confidence=confidence,
        scan_origin=scan_origin,
        plugin_id=plugin_id,
        evidence=evidence,
        url=location,
        method="GET",
        param="",
        param_location=param_location,
        context="",
        vuln_type=PASSIVE_VULN_TYPE,
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
    confidence: str = "Medium",
    scan_origin: str = "Dynamic",
    plugin_id: str = "",
    evidence: str = "",
) -> dict:
    """Deprecated: prefer :func:`build_injection_rule_finding`."""
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
        confidence=confidence,
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