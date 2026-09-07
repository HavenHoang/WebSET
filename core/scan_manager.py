"""
core/scan_manager.py — Real backend (Member 4).

Connects the three finished modules (crawler, security_checks, reporting is
called directly by the GUI so it is not wired here) behind the exact function
names/signatures the GUI already calls. This file is a drop-in replacement
for core.mock_backend: every GUI call site that currently does

    from core.mock_backend import run_scan
    # from core.scan_manager import run_scan

only needs the commented line uncommented and the mock line deleted (or
commented out) — nothing else in the GUI changes.

Contract (must match core/mock_backend.py exactly, since the GUI branches on
return shape):

    run_scan(url) -> list[finding]                       on success
                   -> {"error": code}                     on failure

    run_static_scan(zip_path) -> {"findings": [...], "tech_stacks": [...]}
                               -> {"error": code}

    run_stack_eval_url(url) -> {"tech_stacks": [...], "findings": [...]}

    run_stack_eval_static(zip_path) -> {"tech_stacks": [...], "findings": [...]}
                                     -> {"error": code}

Known gap, handled deliberately rather than silently:
    security_checks/platform_notes.py (the module that should generate Get
    Stack platform guidance from detected tech) is currently an empty file.
    Until it is implemented, this module falls back to the hand-written
    guidance in core.mock_backend._platform_findings so Get Stack keeps
    returning real, useful notes instead of an empty list. Swap it out the
    moment platform_notes.py has a real evaluate_tech_stacks(target, stacks)
    function — see the try/import below.
"""
from __future__ import annotations

from crawler import (
    detect_tech_stack,
    detect_tech_stack_from_path,
    open_project_zip,
)
from security_checks import analyse_dynamic, analyse_static

# ---------------------------------------------------------------------------
# Platform-note generation is not implemented yet on the security_checks side
# (security_checks/platform_notes.py is currently empty). Fall back to the
# mock's hand-written guidance rather than returning nothing.
# ---------------------------------------------------------------------------
try:
    from security_checks.platform_notes import (
        evaluate_tech_stacks as _real_platform_notes,
    )
except Exception:
    _real_platform_notes = None

from core import mock_backend as _mock


def _platform_findings(target: str, stacks: list) -> list:
    """Guidance notes for detected tech. Real implementation if present,
    otherwise the mock's hand-written rules (see module docstring)."""
    if _real_platform_notes is not None:
        try:
            return _real_platform_notes(target, stacks) or []
        except Exception:
            pass
    return _mock._platform_findings(target, stacks)


# ---------------------------------------------------------------------------
# Start Scan — dynamic (URL)
# ---------------------------------------------------------------------------
def run_scan(url: str):
    """
    Success: list of findings (Active Test fields included where relevant).
    Failure: {"error": code} — invalid_url | timeout | unreachable |
                                ssl_error | bad_response | crawler_unavailable

    NOTE: analyse_dynamic currently only runs passive checks (security
    headers, cookies, transport). Injection detection (XSS / SQLi) is not
    wired in yet — security_checks/injection_checks.py is an empty file, and
    dynamic_analyser.py has a comment marking where it plugs in once ready.
    Until then, a clean dynamic scan can legitimately return zero High/XSS/
    SQLi findings even against a deliberately vulnerable target.
    """
    return analyse_dynamic(url)


# ---------------------------------------------------------------------------
# Start Scan — static (ZIP)
# ---------------------------------------------------------------------------
def run_static_scan(zip_path: str) -> dict:
    """
    Success: {"findings": [...], "tech_stacks": [...]}
    Failure: {"error": code} — invalid_zip | empty_zip | no_analyzable_files |
                                unreadable_zip | crawler_unavailable
    """
    result = analyse_static(zip_path)
    if not isinstance(result, dict):
        return {"error": "unreadable_zip"}
    if result.get("error"):
        return {"error": result["error"]}

    findings = result.get("findings") or []
    # analyse_static intentionally leaves tech_stacks empty (static analysis
    # and tech detection are separate pipelines) — fill it in here so the
    # Static Start Scan page can show detected stacks alongside findings.
    tech_stacks = detect_tech_stack_from_path(zip_path) or []
    return {"findings": findings, "tech_stacks": tech_stacks}


# ---------------------------------------------------------------------------
# Get Stack — URL
# ---------------------------------------------------------------------------
def run_stack_eval_url(url: str) -> dict:
    """Always returns {"tech_stacks": [...], "findings": [...]}."""
    stacks = detect_tech_stack(url) or []
    findings = _platform_findings(url, stacks)
    return {"tech_stacks": stacks, "findings": findings}


# ---------------------------------------------------------------------------
# Get Stack — ZIP
# ---------------------------------------------------------------------------
def run_stack_eval_static(zip_path: str) -> dict:
    """
    Success: {"tech_stacks": [...], "findings": [...]}
    Failure: {"error": code} — invalid_zip | empty_zip | no_analyzable_files
    """
    project = open_project_zip(zip_path)
    if not project.get("ok"):
        return {"error": project.get("error") or "invalid_zip"}

    stacks = detect_tech_stack_from_path(zip_path) or []
    findings = _platform_findings(zip_path, stacks)
    return {"tech_stacks": stacks, "findings": findings}