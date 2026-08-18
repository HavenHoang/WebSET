"""
core/scan_manager.py  --  Backend Core adapter (Member 4 / Rafael)
==================================================================

Bridges the GUI to Member 2 (crawler) and Member 1 (security checks), exposing the
four functions the GUI calls. Follows the Integration Guide orchestration.

    Member 2 (crawler.webset_crawler): crawl, detect_tech_stack,
                                       detect_tech_stack_from_path, unpack_zip
    Member 1 (security_checks):        run_security_checks, run_static_analysis,
                                       evaluate_tech_stacks_url, evaluate_tech_stacks_static

Member 1's real engine may not be wired yet, so analysis falls back to
core.mock_backend. Each fallback is marked "M1 TODO".

GUI contract:
    run_scan(url)              -> list[findings]                          | {"error": "unreachable"}
    run_static_scan(zip)       -> {"findings":[...], "tech_stacks":[...]} | {"error": code}
    run_stack_eval_url(url)    -> {"tech_stacks":[...], "findings":[...]}
    run_stack_eval_static(zip) -> {"tech_stacks":[...], "findings":[...]} | {"error": code}
"""
from __future__ import annotations

# --- Member 2 (real) --------------------------------------------------------
from crawler.webset_crawler import (
    crawl, detect_tech_stack, detect_tech_stack_from_path, unpack_zip,
)

# --- Member 1 (real if available, else mock fallback) -----------------------
try:
    from security_checks import engine as _m1real   # Member 1's real module
except Exception:
    _m1real = None
from core import mock_backend as _mock


def _security_checks(url, pages):
    if _m1real and hasattr(_m1real, "run_security_checks"):
        return _m1real.run_security_checks(url, pages)
    return _mock.run_scan(url)                          # M1 TODO

def _static_analysis(zip_path, files):
    if _m1real and hasattr(_m1real, "run_static_analysis"):
        return _m1real.run_static_analysis(files)
    r = _mock.run_static_scan(zip_path)                 # M1 TODO
    return r.get("findings", []) if isinstance(r, dict) else r

def _eval_stacks_url(url, stacks):
    if _m1real and hasattr(_m1real, "evaluate_tech_stacks_url"):
        return _m1real.evaluate_tech_stacks_url(url, stacks)
    try:
        return _mock._platform_findings(url, stacks)    # M1 TODO
    except Exception:
        return []

def _eval_stacks_static(root, stacks):
    if _m1real and hasattr(_m1real, "evaluate_tech_stacks_static"):
        return _m1real.evaluate_tech_stacks_static(root, stacks)
    try:
        return _mock._platform_findings(root, stacks)   # M1 TODO
    except Exception:
        return []


# --------------------------------------------------------------------------- #
def run_scan(url: str):
    pages = crawl(url)                                  # Member 2
    if isinstance(pages, dict) and pages.get("error"):
        return pages                                    # {"error": "unreachable"}
    return _security_checks(url, pages)                 # Member 1


def run_static_scan(zip_path: str):
    files = unpack_zip(zip_path)                        # Member 2
    if isinstance(files, dict) and files.get("error"):
        return files                                    # invalid/empty/no_analyzable
    tech_stacks = detect_tech_stack_from_path(files)    # Member 2
    findings = _static_analysis(zip_path, files)        # Member 1
    return {"findings": findings, "tech_stacks": tech_stacks or []}


def run_stack_eval_url(url: str) -> dict:
    stacks = detect_tech_stack(url)                     # Member 2 (real tech)
    findings = _eval_stacks_url(url, stacks)            # Member 1
    return {"tech_stacks": stacks, "findings": findings}


def run_stack_eval_static(zip_path: str) -> dict:
    files = unpack_zip(zip_path)                        # Member 2
    if isinstance(files, dict) and files.get("error"):
        return files
    stacks = detect_tech_stack_from_path(files)         # Member 2 (real tech)
    findings = _eval_stacks_static(zip_path, stacks)    # Member 1
    return {"tech_stacks": stacks, "findings": findings}
