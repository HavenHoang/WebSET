"""Start Scan entry point and rules for static (ZIP) assessment.

The counterpart to :mod:`security_checks.dynamic_analyser`. It holds both the static
rules and the entry point the GUI calls, because the rule set here is small
enough that a separate module would add a file without adding clarity.

Rules run against the artefact from ``crawler.zip_reader.open_project_zip``,
which supplies two things: ``paths`` (every file name in the archive) and
``sample_texts`` (the contents of a bounded sample of analysable files).

Coverage limits, stated plainly because they set what these findings can
honestly claim:

*   The crawler reads at most 20 files, and at most 4000 characters of each.
*   Which 20 depends on archive order, so it is not predictable.

A content-based check therefore proves a problem exists when it fires, but
never proves absence - a clean result means nothing was found *in the sample*.
Confidence values reflect that. Path-based checks see every file name and are
not sampled, so they score higher.

Contract with Member 4 / Member 5::

    result = analyse_static(zip_path)

    if result.get("error"):
        # show the error toast
    else:
        findings = result["findings"]
        stacks = result.get("tech_stacks") or []

Note the asymmetry with the dynamic path: this function always returns a
``dict``, successful or not. Success is signalled by the absence of an
``error`` key, not by the return type.
"""

from __future__ import annotations

import os
import re

from security_checks.finding_builder import build_passive_rule_finding
from security_checks.schema import sort_findings

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

#: File names that hold environment configuration. Matched on the base name so
#: nested copies are caught too.
ENV_FILE_NAMES = (
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.staging",
    ".env.test",
)

#: Example files are meant to be committed - they hold key names, not values.
ENV_FILE_ALLOWED = (
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
)

#: Assignment of a credential-like name to a non-trivial literal.
#: Requires a quoted value of some length so that ``password = ""`` and
#: ``api_key = os.environ["KEY"]`` do not match.
_SECRET_PATTERN = re.compile(
    r"""(?ix)
    \b(?P<name>
        password | passwd | pwd | secret | secret_key | api_key | apikey |
        access_key | access_token | auth_token | private_key | client_secret |
        db_password | aws_secret_access_key
    )\b
    \s*[:=]\s*
    (?P<quote>["'])
    (?P<value>[^"'\s]{8,})
    (?P=quote)
    """
)

#: Values that look like a secret but are placeholders or references.
_SECRET_PLACEHOLDERS = (
    "changeme", "change_me", "your_", "yourkey", "yourpassword", "placeholder",
    "example", "sample", "dummy", "todo", "xxxxx", "<", "${", "process.env",
    "os.environ", "getenv", "null", "none", "password", "secret", "redacted",
)

#: Debug flags set to an on value, across common frameworks and config formats.
_DEBUG_PATTERN = re.compile(
    r"""(?ix)
    \b(?P<name>
        debug | app_debug | django_debug | flask_debug | debug_mode |
        display_errors | wp_debug
    )\b
    \s*[:=]\s*
    (?P<quote>["']?)
    (?P<value> true | on | 1 | yes )
    (?P=quote)
    (?!\w)
    """
)

#: Files whose contents are documentation or examples rather than live config.
_SAMPLE_PATH_HINTS = (
    "example", "sample", "template", "/test/", "/tests/", "/spec/",
    "/docs/", "/doc/", "readme", "changelog", ".dist",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_name(path: str) -> str:
    """Final path segment, lowercased, handling both separators."""
    return os.path.basename(str(path or "").replace("\\", "/")).lower()


def _is_example_context(path: str) -> bool:
    """Whether a path suggests documentation, tests or example configuration.

    A password in ``config.example.php`` or a test fixture is not a leaked
    credential. Findings from these paths are reported at lower confidence
    rather than suppressed, since a real secret can still end up in one.
    """
    low = "/" + str(path or "").replace("\\", "/").lower()
    return any(hint in low for hint in _SAMPLE_PATH_HINTS)


def _is_placeholder(value: str) -> bool:
    """Whether a matched value is a placeholder rather than a real secret."""
    low = (value or "").strip().lower()
    if not low:
        return True
    if any(marker in low for marker in _SECRET_PLACEHOLDERS):
        return True
    # A single repeated character, e.g. "********" or "aaaaaaaa".
    return len(set(low)) <= 2


def _redact(value: str) -> str:
    """Mask a matched secret, keeping just enough to locate it in the file."""
    text = str(value or "")
    if len(text) <= 4:
        return "*" * len(text)
    return f"{text[:2]}{'*' * (len(text) - 4)}{text[-2:]}"


def _line_of(text: str, index: int) -> int:
    """1-based line number of a character offset."""
    return text.count("\n", 0, index) + 1


# ---------------------------------------------------------------------------
# Path-based checks
# ---------------------------------------------------------------------------

def check_env_files(paths: list) -> list[dict]:
    """Report environment files committed into the archive.

    Sees every path in the archive rather than a sample, so confidence is
    high: either the file is there or it is not.
    """
    findings = []
    for path in paths or []:
        name = _base_name(path)
        if name in ENV_FILE_ALLOWED:
            continue
        if name in ENV_FILE_NAMES or name.startswith(".env."):
            findings.append(
                build_passive_rule_finding(
                    "static-env-file",
                    location=str(path),
                    confidence="High",
                    scan_origin="Static",
                    param_location="",
                    evidence=f"archive path: {path}",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Content-based checks
# ---------------------------------------------------------------------------

def check_hardcoded_secrets(sample_texts: dict) -> list[dict]:
    """Report credential-like assignments in sampled source files.

    At most one finding per file: several matches in the same file share one
    remediation, and separate rows would inflate the Alerts count without
    telling the reader anything new. Every match is listed in the evidence.
    """
    findings = []

    for path, text in (sample_texts or {}).items():
        matches = list(_SECRET_PATTERN.finditer(text or ""))
        real = [
            m for m in matches
            if not _is_placeholder(m.group("value"))
        ]
        if not real:
            continue

        evidence = "; ".join(
            f"line {_line_of(text, m.start())}: "
            f"{m.group('name')}={_redact(m.group('value'))}"
            for m in real[:5]
        )
        if len(real) > 5:
            evidence += f"; (+{len(real) - 5} more)"

        example = _is_example_context(path)
        findings.append(
            build_passive_rule_finding(
                "static-secret-pattern",
                location=str(path),
                # Pattern matching cannot tell a live credential from a
                # convincing fixture, so this never claims High.
                confidence="Low" if example else "Medium",
                scan_origin="Static",
                severity="Low" if example else None,
                param_location="",
                evidence=evidence,
            )
        )

    return findings


def check_debug_flags(sample_texts: dict) -> list[dict]:
    """Report debug settings left enabled in sampled configuration files."""
    findings = []

    for path, text in (sample_texts or {}).items():
        matches = list(_DEBUG_PATTERN.finditer(text or ""))
        if not matches:
            continue

        evidence = "; ".join(
            f"line {_line_of(text, m.start())}: "
            f"{m.group('name')}={m.group('value')}"
            for m in matches[:5]
        )
        hint = f"{matches[0].group('name')}={matches[0].group('value')}"

        example = _is_example_context(path)
        findings.append(
            build_passive_rule_finding(
                "static-debug-enabled",
                location=str(path),
                confidence="Low" if example else "Medium",
                scan_origin="Static",
                severity="Low" if example else None,
                param_location="",
                evidence=evidence,
                evidence_hint=hint,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_static_checks(artefact: dict) -> list[dict]:
    """Run every static rule against an opened project archive.

    Args:
        artefact: Output of ``crawler.zip_reader.open_project_zip``. Expected
            keys are ``paths`` and ``sample_texts``; both degrade to empty
            rather than raising.

    Returns:
        Findings from all static rules, unsorted.
    """
    data = artefact if isinstance(artefact, dict) else {}
    paths = data.get("paths") or []
    samples = data.get("sample_texts") or {}

    findings: list[dict] = []
    findings.extend(check_env_files(paths))
    findings.extend(check_hardcoded_secrets(samples))
    findings.extend(check_debug_flags(samples))
    return findings


def sample_coverage(artefact: dict) -> dict:
    """How much of the archive the content checks actually read.

    The GUI can surface this so a clean static result is not mistaken for a
    guarantee. Returns counts of total files, files sampled, and the ratio.
    """
    data = artefact if isinstance(artefact, dict) else {}
    total = len(data.get("paths") or [])
    sampled = len(data.get("sample_texts") or {})
    return {
        "files_total": total,
        "files_sampled": sampled,
        "ratio": round(sampled / total, 3) if total else 0.0,
    }


#: Error codes the crawler's zip reader produces. Listed so an unexpected code
#: can be spotted rather than passed through silently.
KNOWN_ZIP_ERRORS = frozenset({
    "invalid_zip",
    "empty_zip",
    "no_analyzable_files",
})


def _error(code: str) -> dict:
    """Build the failure shape the GUI expects."""
    return {"error": code}


def analyse_static(zip_path: str, *, open_fn=None) -> dict:
    """Run a static Start Scan against an uploaded project archive.

    Args:
        zip_path: Path to the ZIP the user uploaded.
        open_fn: Optional replacement for
            ``crawler.zip_reader.open_project_zip``, used by the test suite to
            supply a prepared artefact without touching the filesystem.

    Returns:
        On success, ``{"findings": [...], "tech_stacks": [...], "coverage":
        {...}}``. On failure, ``{"error": code}`` where code is one of
        invalid_zip, empty_zip, no_analyzable_files, or unreadable_zip.

        ``coverage`` reports how much of the archive the content rules
        actually read. The content checks see a bounded sample, so an empty
        findings list means nothing was found in that sample rather than that
        the project is clean - the GUI can use these counts to say so.
    """
    if not str(zip_path or "").strip():
        return _error("invalid_zip")

    if open_fn is None:
        try:
            from crawler.zip_reader import open_project_zip as open_fn
        except ImportError:
            return _error("crawler_unavailable")

    try:
        artefact = open_fn(zip_path)
    except Exception:
        # The zip reader returns errors rather than raising, but a stub or a
        # future change might not. One bad upload must never take down the GUI.
        return _error("unreadable_zip")

    if not isinstance(artefact, dict):
        return _error("unreadable_zip")

    if not artefact.get("ok"):
        code = str(artefact.get("error") or "").strip()
        return _error(code if code in KNOWN_ZIP_ERRORS else "unreadable_zip")

    findings = run_static_checks(artefact)

    return {
        "findings": sort_findings(findings),
        # Static technology detection belongs to the Get Stack pipeline and is
        # populated by Member 2. Kept empty here so the two never merge.
        "tech_stacks": [],
        "coverage": sample_coverage(artefact),
    }


# Alias kept for compatibility with the original code pack.
def run_static_scan(zip_path: str) -> dict:
    """Deprecated alias for :func:`analyse_static`."""
    return analyse_static(zip_path)