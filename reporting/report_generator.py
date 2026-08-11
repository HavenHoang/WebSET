from datetime import datetime
from collections import Counter


def generate_report(
    url: str,
    findings: list[dict],
    scan_type: str = "Dynamic",
    tech_stacks: list[dict] | None = None,
    stack_findings: list[dict] | None = None,
) -> dict:
    """
    Generate a structured WebSET security assessment report.

    findings       = Start Scan (Alerts) — may include CWE / OWASP / NIST / SANS
    stack_findings = Get Stack platform evaluation — guidance only, no standards mapping
    """
    findings = findings or []
    tech_stacks = tech_stacks or []
    stack_findings = stack_findings or []

    high_count = sum(1 for f in findings if f.get("severity") == "High")
    medium_count = sum(1 for f in findings if f.get("severity") == "Medium")
    low_count = sum(1 for f in findings if f.get("severity") == "Low")
    summary = {
        "High": high_count,
        "Medium": medium_count,
        "Low": low_count,
        "Total": len(findings),
    }

    plat_high = sum(1 for f in stack_findings if f.get("severity") == "High")
    plat_medium = sum(1 for f in stack_findings if f.get("severity") == "Medium")
    plat_low = sum(1 for f in stack_findings if f.get("severity") == "Low")
    platform_summary = {
        "High": plat_high,
        "Medium": plat_medium,
        "Low": plat_low,
        "Total": len(stack_findings),
    }

    combined_summary = {
        "High": high_count + plat_high,
        "Medium": medium_count + plat_medium,
        "Low": low_count + plat_low,
        "Total": len(findings) + len(stack_findings),
    }

    # Standards mapping — Start Scan findings ONLY (never stack_findings)
    cwe_summary = dict(Counter(f.get("cwe_id") for f in findings if f.get("cwe_id")))
    owasp_summary = dict(Counter(f.get("owasp") for f in findings if f.get("owasp")))
    nist_summary = dict(Counter(f.get("nist") for f in findings if f.get("nist")))
    sans_summary = dict(Counter(f.get("sans") for f in findings if f.get("sans")))

    remediation = []
    for f in findings + stack_findings:
        fix = str(f.get("remediation") or "").strip()
        if fix and fix not in remediation:
            remediation.append(fix)
    if not findings and not stack_findings:
        remediation = [
            "No vulnerabilities or platform issues were detected during this assessment."
        ]

    lines = [f"Assessment of {url} completed."]
    if findings:
        lines.append(
            f"• Start Scan: {len(findings)} issue(s) "
            f"({high_count} High, {medium_count} Medium, {low_count} Low)"
        )
    else:
        lines.append("• Start Scan: no vulnerabilities detected")

    if stack_findings:
        lines.append(
            f"• Platform evaluation: {len(stack_findings)} note(s) "
            f"({plat_high} High, {plat_medium} Medium, {plat_low} Low) "
            f"— guidance only, not standards-mapped"
        )
    else:
        lines.append("• Platform evaluation: no notes")

    lines.append(f"• Scan type: {scan_type}")
    if findings:
        lines.append(
            "• Start Scan findings mapped to CWE, WASC, OWASP, NIST and SANS where available"
        )
    if tech_stacks:
        names = [s.get("name", "Unknown") for s in tech_stacks if s.get("name")]
        if names:
            lines.append("• Tech stacks: " + ", ".join(names))

    executive_summary = "\n".join(lines)

    return {
        "title": "WebSET Security Assessment Report",
        "url": url,
        "scan_type": scan_type,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": combined_summary,
        "scan_summary": summary,
        "platform_summary": platform_summary,
        "findings": findings,
        "stack_findings": stack_findings,
        "tech_stacks": tech_stacks,
        "cwe_summary": cwe_summary,
        "owasp_summary": owasp_summary,
        "nist_summary": nist_summary,
        "sans_summary": sans_summary,
        "remediation": remediation,
        "executive_summary": executive_summary,
    }
