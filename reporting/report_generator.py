from datetime import datetime
from collections import Counter


def _collapse_key(f: dict) -> tuple:
    return (
        str(f.get("vulnerability") or f.get("name") or "").strip().lower(),
        str(f.get("severity") or "").strip().lower(),
        str(f.get("cwe_id") or f.get("cweId") or "").strip(),
        str(f.get("owasp") or "").strip(),
        str(f.get("nist") or f.get("nist_id") or "").strip(),
        str(f.get("sans") or f.get("sans_id") or "").strip(),
        " ".join(str(f.get("remediation") or "").split()),
        str(f.get("vuln_type") or "").strip().lower(),
        str(f.get("plugin_id") or "").strip(),
    )


def _collapse_similar_findings(findings: list) -> list:
    groups: dict = {}
    order: list = []
    for f in findings or []:
        key = _collapse_key(f)
        loc = str(f.get("location") or f.get("url") or f.get("endpoint") or "").strip()
        if key not in groups:
            item = dict(f)
            item["_locs"] = [loc] if loc else []
            groups[key] = item
            order.append(key)
        elif loc and loc not in groups[key]["_locs"]:
            groups[key]["_locs"].append(loc)
    out = []
    for key in order:
        item = groups[key]
        locs = item.pop("_locs", [])
        if locs:
            item["location"] = "\n".join(locs)
            if not item.get("url"):
                item["url"] = locs[0]
        out.append(item)
    return out


def _sev_counts(rows: list) -> dict:
    high = sum(1 for f in rows if f.get("severity") == "High")
    medium = sum(1 for f in rows if f.get("severity") == "Medium")
    low = sum(1 for f in rows if f.get("severity") == "Low")
    return {
        "High": high,
        "Medium": medium,
        "Low": low,
        "Total": len(rows),
    }


def generate_report(
    url: str,
    findings: list[dict],
    scan_type: str = "Dynamic",
    tech_stacks: list[dict] | None = None,
    stack_findings: list[dict] | None = None,
) -> dict:
    """
    findings       = Start Scan (Alerts)
    stack_findings = Get Stack platform notes
    Counts use collapsed unique issues (same rule as Alerts / Cases).
    """
    findings = _collapse_similar_findings(findings or [])
    tech_stacks = tech_stacks or []
    stack_findings = _collapse_similar_findings(stack_findings or [])

    summary = _sev_counts(findings)
    platform_summary = _sev_counts(stack_findings)
    combined_summary = {
        "High": summary["High"] + platform_summary["High"],
        "Medium": summary["Medium"] + platform_summary["Medium"],
        "Low": summary["Low"] + platform_summary["Low"],
        "Total": summary["Total"] + platform_summary["Total"],
    }

    cwe_summary = dict(Counter(f.get("cwe_id") for f in findings if f.get("cwe_id")))
    owasp_summary = dict(Counter(
        f.get("owasp_2021") or f.get("owasp")
        for f in findings
        if f.get("owasp_2021") or f.get("owasp")
    ))
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

    high_count = summary["High"]
    medium_count = summary["Medium"]
    low_count = summary["Low"]
    plat_high = platform_summary["High"]
    plat_medium = platform_summary["Medium"]
    plat_low = platform_summary["Low"]

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
            f"({plat_high} High, {plat_medium} Medium, {plat_low} Low)"
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
