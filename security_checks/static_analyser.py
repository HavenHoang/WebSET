"""Start Scan entry point and rules for static (ZIP) assessment."""

from __future__ import annotations

import os
import re

from security_checks.finding_builder import build_passive_rule_finding
from security_checks.schema import sort_findings

ENV_FILE_NAMES = (
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.staging",
    ".env.test",
)
ENV_FILE_ALLOWED = (
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
)

_SECRET_PATTERN = re.compile(
    r"""(?ix)
    \b(?P<name>
        password | passwd | pwd | secret | secret_key | api_key | apikey |
        access_key | access_token | auth_token | private_key | client_secret |
        db_password | aws_secret_access_key | jwt | jwt_secret | jwtsecret |
        jwtprivatekey | token
    )\b
    \s*[:=]\s*
    (?P<quote>["'])
    (?P<value>[^"'\s]{6,})
    (?P=quote)
    """
)
_SECRET_PLACEHOLDERS = (
    "changeme", "change_me", "your_", "yourkey", "yourpassword", "placeholder",
    "example", "sample", "dummy", "todo", "xxxxx", "<", "${", "process.env",
    "os.environ", "getenv", "null", "none", "password", "secret", "redacted",
)
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
_EVAL_PATTERN = re.compile(r"\beval\s*\(|\bFunction\s*\(|new\s+Function\s*\(|vm\.runInContext", re.I)
_HTML_SINK_PATTERN = re.compile(
    r"\.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|bypassSecurityTrust",
    re.I,
)
_SQL_CONCAT_PATTERN = re.compile(
    r"""(?ix)
    (SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).{0,80}
    (\+|`\s*\+|\"\s*\+|'\s*\+|\$\{)
    """
)
_CMD_PATTERN = re.compile(
    r"child_process|os\.system\s*\(|subprocess\.|exec\s*\(\s*req\.|popen\s*\(",
    re.I,
)
_WEAK_CRYPTO_PATTERN = re.compile(
    r"""(?ix)
    createHash\(\s*['"]md5['"]|createHash\(\s*['"]sha1['"]|
    \bmd5\s*\(|\bsha1\s*\(|Math\.random\s*\(
    """
)
_PATH_SINK_PATTERN = re.compile(
    r"""(?ix)
    (readFileSync|readFile|createReadStream|sendFile|createWriteStream)\s*\(
    .{0,80}(req\.|params|query|body)
    |
    include\s*\(\s*\$_(GET|POST|REQUEST)
    """
)
_JWT_PATTERN = re.compile(
    r"""(?ix)
    jwt\.decode\s*\(|jwtPrivateKey|jwt_secret|jwtsecret
    """
)
_EMPTY_HANDLER_PATTERN = re.compile(
    r"""(?ix)
    except\s+\w*\s*:\s*(pass|continue)\s*$
    |
    catch\s*\([^)]*\)\s*\{\s*\}
    |
    catch\s*\([^)]*\)\s*\{\s*//[^\n]*\n\s*\}
    """
)
_DEBUG_RESIDUE_PATTERN = re.compile(
    r"""(?ix)
    console\.(log|debug|info)\s*\(
    |
    \bprint\s*\(
    |
    var_dump\s*\(
    |
    error_log\s*\(
    """
)
_TODO_SECRET_PATTERN = re.compile(
    r"""(?ix)
    (TODO|FIXME|XXX|HACK).{0,80}
    (password|passwd|secret|token|auth|credential|api[_-]?key)
    """
)
_SAMPLE_PATH_HINTS = (
    "example", "sample", "template", "/test/", "/tests/", "/spec/",
    "/docs/", "/doc/", "readme", "changelog", ".dist", "/node_modules/",
)


def _base_name(path: str) -> str:
    return os.path.basename(str(path or "").replace("\\", "/")).lower()


def _is_example_context(path: str) -> bool:
    low = "/" + str(path or "").replace("\\", "/").lower()
    return any(hint in low for hint in _SAMPLE_PATH_HINTS)


def _is_placeholder(value: str) -> bool:
    low = (value or "").strip().lower()
    if not low:
        return True
    if any(marker in low for marker in _SECRET_PLACEHOLDERS):
        return True
    return len(set(low)) <= 2


def _redact(value: str) -> str:
    text = str(value or "")
    if len(text) <= 4:
        return "*" * len(text)
    return f"{text[:2]}{'*' * (len(text) - 4)}{text[-2:]}"


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _rule_finding(rule_id: str, **kwargs) -> dict | None:
    try:
        return build_passive_rule_finding(rule_id, **kwargs)
    except Exception:
        return {
            "severity": kwargs.get("severity") or "Medium",
            "vulnerability": rule_id.replace("static-", "").replace("-", " ").title(),
            "location": kwargs.get("location") or "",
            "description": kwargs.get("evidence") or rule_id,
            "remediation": "Review the flagged construct and replace it with a safe API.",
            "scan_origin": "Static",
            "plugin_id": rule_id,
            "evidence": kwargs.get("evidence") or "",
            "vuln_type": "generic",
            "param": "",
        }


def check_env_files(paths: list) -> list[dict]:
    findings = []
    for path in paths or []:
        name = _base_name(path)
        if name in ENV_FILE_ALLOWED:
            continue
        if name in ENV_FILE_NAMES or name.startswith(".env."):
            item = _rule_finding(
                "static-env-file",
                location=str(path),
                scan_origin="Static",
                param_location="",
                evidence=f"archive path: {path}",
            )
            if item:
                findings.append(item)
    return findings


def check_hardcoded_secrets(sample_texts: dict) -> list[dict]:
    findings = []
    for path, text in (sample_texts or {}).items():
        matches = list(_SECRET_PATTERN.finditer(text or ""))
        real = [m for m in matches if not _is_placeholder(m.group("value"))]
        if not real:
            continue
        evidence = "; ".join(
            f"line {_line_of(text, m.start())}: {m.group('name')}={_redact(m.group('value'))}"
            for m in real[:5]
        )
        item = _rule_finding(
            "static-secret-pattern",
            location=str(path),
            scan_origin="Static",
            severity="Low" if _is_example_context(path) else None,
            param_location="",
            evidence=evidence,
        )
        if item:
            findings.append(item)
    return findings


def check_debug_flags(sample_texts: dict) -> list[dict]:
    findings = []
    for path, text in (sample_texts or {}).items():
        matches = list(_DEBUG_PATTERN.finditer(text or ""))
        if not matches:
            continue
        evidence = "; ".join(
            f"line {_line_of(text, m.start())}: {m.group('name')}={m.group('value')}"
            for m in matches[:5]
        )
        item = _rule_finding(
            "static-debug-enabled",
            location=str(path),
            scan_origin="Static",
            severity="Low" if _is_example_context(path) else None,
            param_location="",
            evidence=evidence,
            evidence_hint=f"{matches[0].group('name')}={matches[0].group('value')}",
        )
        if item:
            findings.append(item)
    return findings


def _pattern_hits(sample_texts: dict, pattern, rule_id: str, title_fallback: str) -> list[dict]:
    findings = []
    for path, text in (sample_texts or {}).items():
        low = "/" + path.replace("\\", "/").lower()
        if "/node_modules/" in low:
            continue
        matches = list(pattern.finditer(text or ""))
        if not matches:
            continue
        evidence = "; ".join(
            f"line {_line_of(text, m.start())}: {m.group(0)[:80]}"
            for m in matches[:4]
        )
        item = _rule_finding(
            rule_id,
            location=str(path),
            scan_origin="Static",
            param_location="",
            evidence=evidence,
        )
        if item:
            if item.get("vulnerability") == rule_id.replace("static-", "").replace("-", " ").title():
                item["vulnerability"] = title_fallback
            findings.append(item)
    return findings


def run_static_checks(artefact: dict) -> list[dict]:
    data = artefact if isinstance(artefact, dict) else {}
    paths = data.get("paths") or []
    samples = data.get("sample_texts") or {}
    findings: list[dict] = []
    findings.extend(check_env_files(paths))
    findings.extend(check_hardcoded_secrets(samples))
    findings.extend(check_debug_flags(samples))
    findings.extend(_pattern_hits(samples, _EVAL_PATTERN, "static-eval", "Dangerous dynamic code execution"))
    findings.extend(_pattern_hits(samples, _HTML_SINK_PATTERN, "static-html-sink", "Unencoded HTML sink"))
    findings.extend(_pattern_hits(samples, _SQL_CONCAT_PATTERN, "static-sql-concat", "SQL string concatenation"))
    findings.extend(_pattern_hits(samples, _CMD_PATTERN, "static-command-exec", "OS command execution sink"))
    findings.extend(_pattern_hits(samples, _WEAK_CRYPTO_PATTERN, "static-weak-crypto", "Weak cryptography"))
    findings.extend(_pattern_hits(samples, _PATH_SINK_PATTERN, "static-path-sink", "User-controlled file path"))
    findings.extend(_pattern_hits(samples, _JWT_PATTERN, "static-jwt-hardcoded", "JWT / token handling issue"))
    findings.extend(_pattern_hits(samples, _EMPTY_HANDLER_PATTERN, "static-empty-handler", "Empty error handler"))
    findings.extend(_pattern_hits(samples, _DEBUG_RESIDUE_PATTERN, "static-debug-residue", "Debug residue in source"))
    findings.extend(_pattern_hits(samples, _TODO_SECRET_PATTERN, "static-todo-secret", "TODO near credential handling"))
    return findings


def sample_coverage(artefact: dict) -> dict:
    data = artefact if isinstance(artefact, dict) else {}
    total = len(data.get("paths") or [])
    sampled = len(data.get("sample_texts") or {})
    return {
        "files_total": total,
        "files_sampled": sampled,
        "ratio": round(sampled / total, 3) if total else 0.0,
    }


KNOWN_ZIP_ERRORS = frozenset({"invalid_zip", "empty_zip", "no_analyzable_files"})


def _error(code: str) -> dict:
    return {"error": code}


def analyse_static(zip_path: str, *, open_fn=None) -> dict:
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
        return _error("unreadable_zip")
    if not isinstance(artefact, dict):
        return _error("unreadable_zip")
    if not artefact.get("ok"):
        code = str(artefact.get("error") or "").strip()
        return _error(code if code in KNOWN_ZIP_ERRORS else "unreadable_zip")
    findings = run_static_checks(artefact)
    return {
        "findings": sort_findings(findings),
        "tech_stacks": [],
        "coverage": sample_coverage(artefact),
    }


def run_static_scan(zip_path: str) -> dict:
    return analyse_static(zip_path)
