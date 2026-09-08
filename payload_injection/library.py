"""Recommended payloads (manual) and single-request Active Test cases."""

from __future__ import annotations

RECOMMENDED_PAYLOADS: dict[str, list[str]] = {
    "XSS": [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ],
    "SQLi": [
        "' OR '1'='1",
        "' OR 1=1--",
        "1' UNION SELECT null--",
        "admin'--",
    ],
    "Custom": [],
}

ACTIVE_TEST_LIBRARY: dict[str, list[dict]] = {
    "xss": [
        {
            "id": "xss_html_reflection",
            "label": "Reflected XSS — HTML context",
            "marker": "TEST_MARKER_123",
            "hint": "Checks whether a unique marker is reflected unencoded in the HTML body.",
        },
        {
            "id": "xss_attr_context",
            "label": "Reflected XSS — Attribute context",
            "marker": '" TEST_ATTR_456 ',
            "hint": "Checks reflection inside an HTML attribute context.",
        },
        {
            "id": "xss_encoding_check",
            "label": "Encoding / sanitisation check",
            "marker": "<WebSET_ENC_789>",
            "hint": "Checks whether angle brackets are encoded in the response.",
        },
    ],
    "sqli": [
        {
            "id": "sqli_error_based",
            "label": "SQL Injection — error-based indicator",
            "marker": "'",
            "hint": "Single controlled probe; looks for DB error / status change.",
        },
        {
            "id": "sqli_behaviour",
            "label": "SQL Injection — behaviour change",
            "marker": "1 OR 1=1",
            "hint": "Compares response behaviour against a safe baseline expectation.",
        },
    ],
    "path_traversal": [
        {
            "id": "path_controlled",
            "label": "Path traversal — controlled probe",
            "marker": "../",
            "hint": "Non-destructive path segment probe.",
        },
    ],
    "command_injection": [
        {
            "id": "cmd_canary",
            "label": "Command injection — canary",
            "marker": "WEBSET_CANARY",
            "hint": "Non-destructive canary string only.",
        },
    ],
}


def get_payloads(payload_type: str) -> list[str]:
    """Manual mode list for the GUI combo box."""
    return list(RECOMMENDED_PAYLOADS.get(payload_type, []) or [])


def get_active_tests(vuln_type: str) -> list[dict]:
    """Active Test radio options for a finding.vuln_type."""
    key = (vuln_type or "").lower().strip()
    return list(ACTIVE_TEST_LIBRARY.get(key) or [])
