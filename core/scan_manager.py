"""core/scan_manager.py -- Backend Core adapter (Member 4) using the crawl package."""
from __future__ import annotations
from crawler import (fetch_target, extract_forms, detect_tech_stack,
                   detect_tech_stack_from_path, open_project_zip)
try:
    from security_checks import engine as _m1real
except Exception:
    _m1real = None
from core import mock_backend as _mock

def _security_checks(url, page):
    if _m1real and hasattr(_m1real, "run_security_checks"):
        return _m1real.run_security_checks(url, page)
    return _mock.run_scan(url)

def _static_analysis(zip_path, project):
    if _m1real and hasattr(_m1real, "run_static_analysis"):
        return _m1real.run_static_analysis(project)
    r = _mock.run_static_scan(zip_path)
    return r.get("findings", []) if isinstance(r, dict) else r

def _eval_url(url, stacks):
    if _m1real and hasattr(_m1real, "evaluate_tech_stacks_url"):
        return _m1real.evaluate_tech_stacks_url(url, stacks)
    try: return _mock._platform_findings(url, stacks)
    except Exception: return []

def _eval_static(root, stacks):
    if _m1real and hasattr(_m1real, "evaluate_tech_stacks_static"):
        return _m1real.evaluate_tech_stacks_static(root, stacks)
    try: return _mock._platform_findings(root, stacks)
    except Exception: return []

def run_scan(url):
    page = fetch_target(url)                          # Member 2: raw artefact
    if not page.get("ok"):
        return {"error": "unreachable"}
    page["request_targets"] = extract_forms(page)    # Member 2: forms/params for Member 1
    return _security_checks(url, page)               # Member 1

def run_static_scan(zip_path):
    project = open_project_zip(zip_path)
    if not project.get("ok"):
        return {"error": project.get("error", "invalid_zip")}
    tech = detect_tech_stack_from_path(zip_path)
    findings = _static_analysis(zip_path, project)
    return {"findings": findings, "tech_stacks": tech or []}

def run_stack_eval_url(url):
    stacks = detect_tech_stack(url)
    return {"tech_stacks": stacks, "findings": _eval_url(url, stacks)}

def run_stack_eval_static(zip_path):
    project = open_project_zip(zip_path)
    if not project.get("ok"):
        return {"error": project.get("error", "invalid_zip")}
    stacks = detect_tech_stack_from_path(zip_path)
    return {"tech_stacks": stacks, "findings": _eval_static(zip_path, stacks)}
