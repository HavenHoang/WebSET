"""Response analysis for a single Active Test request."""

from __future__ import annotations
import re


def _looks_json(body: str) -> bool:
    s = (body or "").lstrip()
    return s.startswith("{") or s.startswith("[")


def _looks_html(body: str) -> bool:
    low = (body or "").lower()
    return "<html" in low or "<body" in low or "<script" in low


def _is_distinctive(marker: str) -> bool:
    if not marker:
        return False
    if len(marker) >= 10:
        return True
    if any(ch in marker for ch in '_<>"\'%{}[]'):
        return True
    has_alpha = any(ch.isalpha() for ch in marker)
    has_digit = any(ch.isdigit() for ch in marker)
    return has_alpha and has_digit and len(marker) >= 8


def _token_hit(marker: str, body: str) -> bool:
    if not marker or not body:
        return False
    if marker.lower() not in body.lower():
        return False
    if _is_distinctive(marker):
        return True
    return re.search(
        r"(?<![A-Za-z0-9_])" + re.escape(marker) + r"(?![A-Za-z0-9_])",
        body,
        flags=re.IGNORECASE,
    ) is not None


def analyse_xss(marker: str, body: str, context: str = "") -> dict:
    body = body or ""
    marker = marker or ""
    found = _token_hit(marker, body)

    encoded = False
    if "<" in marker:
        encoded = ("&lt;" in body) and (marker not in body)
        found = marker in body or encoded

    confidence = "LOW"
    conclusion = "No clear reflection"
    detail = "The probe string was not found as a standalone token in the response body."

    if found and encoded:
        confidence = "MEDIUM"
        conclusion = "Marker reflected but appears encoded"
        detail = (
            "The probe came back in the response, but special characters look escaped "
            "(for example < became &lt;). That is reflection with sanitisation, not a confirmed XSS."
        )
    elif found and not encoded and _is_distinctive(marker) and (
        _looks_html(body) or "<" in marker or ">" in marker or '"' in marker
    ):
        confidence = "HIGH"
        conclusion = "Potential Reflected XSS (unencoded reflection)"
        detail = (
            "A distinctive probe came back unencoded in an HTML-like or markup-sensitive context. "
            "Input appears to be reflected without encoding."
        )
    elif found and not encoded and _is_distinctive(marker) and _looks_json(body):
        confidence = "MEDIUM"
        conclusion = "Probe appears in JSON data"
        detail = (
            "The probe was found in a JSON body. That can be a search or data echo rather than HTML XSS. "
            "Treat as possible reflection, not a confirmed XSS."
        )
    elif found and not encoded and not _is_distinctive(marker):
        confidence = "MEDIUM"
        conclusion = "Possible reflection — probe is not distinctive"
        detail = (
            "The input appears in the body, so reflection is possible. "
            "The probe is short or common-looking, so it may also match normal page or API text. "
            "Re-run with a unique canary such as TEST_MARKER_123 to raise confidence."
        )
    elif found and not encoded:
        confidence = "MEDIUM"
        conclusion = "Unencoded reflection, context unclear"
        detail = (
            "The probe was reflected unencoded, but the response context is not clearly HTML XSS. "
            "Manual review is needed."
        )

    return {
        "found_in_body": found,
        "encoded": encoded,
        "db_error_signal": False,
        "confidence": confidence,
        "conclusion": conclusion,
        "detail": detail,
        "reflection_context": context or "unknown",
    }


def analyse_sqli(marker: str, body: str, status: int) -> dict:
    low = (body or "").lower()
    signals = (
        "sql syntax",
        "mysql",
        "syntax error",
        "odbc",
        "sqlite",
        "postgresql",
        "ora-",
        "unclosed quotation",
    )
    db_error = any(s in low for s in signals)
    weird_status = status >= 500
    hit = db_error or weird_status
    if db_error:
        detail = (
            "The response contains database error text after the single probe. "
            "That is a stronger SQLi signal than a body match alone."
        )
    elif weird_status:
        detail = (
            "HTTP status is 5xx after the probe. That can be a SQLi signal, "
            "but it is weaker than an explicit database error."
        )
    else:
        detail = (
            "No database error text and no 5xx status. "
            "A body match of the probe by itself is not treated as SQLi."
        )
    return {
        "found_in_body": marker in (body or ""),
        "encoded": False,
        "db_error_signal": db_error,
        "confidence": "HIGH" if db_error else ("MEDIUM" if weird_status else "LOW"),
        "conclusion": (
            "Potential SQL Injection indicators present"
            if hit
            else "No strong SQL error/behaviour signal from this single probe"
        ),
        "detail": detail,
        "reflection_context": "",
    }


def analyse_generic(marker: str, body: str) -> dict:
    found = _token_hit(marker or "", body or "")
    if not found:
        conclusion = "Marker not found in body"
        confidence = "LOW"
        detail = "The probe string was not found as a standalone token in the response."
    elif _is_distinctive(marker or ""):
        conclusion = "Distinctive marker reflected"
        confidence = "MEDIUM"
        detail = (
            "A distinctive probe came back in the body. "
            "This is a reflection signal; vulnerability type still depends on context."
        )
    else:
        conclusion = "Possible reflection — probe is not distinctive"
        confidence = "MEDIUM"
        detail = (
            "The input appears in the body. The probe is not unique enough for high confidence. "
            "Re-run with a longer canary to confirm."
        )
    return {
        "found_in_body": found,
        "encoded": False,
        "db_error_signal": False,
        "confidence": confidence,
        "conclusion": conclusion,
        "detail": detail,
        "reflection_context": "",
    }


def analyse_for_vuln_type(
    vuln_type: str,
    marker: str,
    body: str,
    status: int,
    context: str = ""
) -> dict:
    v = (vuln_type or "").lower()
    if v == "xss":
        return analyse_xss(marker, body, context=context)
    if v == "sqli":
        return analyse_sqli(marker, body, status)
    return analyse_generic(marker, body)
