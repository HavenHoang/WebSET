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

# Intra-file taint: user-controlled sources seen in typical web stacks.
_SOURCE_RE = re.compile(
    r"""(?ix)
    \$_(GET|POST|REQUEST|COOKIE|FILES)\b
    | \breq\s*\.\s*(query|body|params|param|get)\b
    | \brequest\s*\.\s*(args|form|values|json|GET|POST|data|query_params|query_string|files|get_json|getParameter)\b
    | \brequest\.getParameter\s*\(
    | \bgetParameterValues?\s*\(
    | @RequestParam
    | @PathVariable
    | @RequestBody
    | \bcgi\.FieldStorage
    """
)
_ASSIGN_RE = re.compile(
    r"""(?ix)
    (\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\$_(GET|POST|REQUEST|COOKIE|FILES)
    |
    (?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*req\s*\.\s*(query|body|params|param)
    |
    ([A-Za-z_][A-Za-z0-9_]*)\s*=\s*request\s*\.\s*(args|form|values|json|GET|POST|data|query_params|files)
    |
    (?:String|int|Integer|long)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*.{0,40}getParameter
    """
)
_SOURCE_GROUP_SKIP = frozenset({
    "GET", "POST", "REQUEST", "COOKIE", "FILES",
    "query", "body", "params", "param",
    "args", "form", "values", "json", "data", "query_params", "files",
})
_NEAR_SOURCE_LINES = 12

_TAINT_SINKS = (
    (
        "static-sql-concat",
        re.compile(
            r"""(?ix)
            mysql_query\s*\(|mysqli_(query|real_query)\s*\(|pg_query\s*\(
            | sequelize\.query\s*\(|\brawQuery\s*\(
            | cursor\.execute\s*\(|\.execute\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)
            | Statement\.execute(?:Query|Update)?\s*\(
            | createQuery\s*\(|createNativeQuery\s*\(
            | \bWHERE\b.{0,80}(\+|\$\{|\$[A-Za-z_]|req\.|request\.)
            """
        ),
    ),
    (
        "static-html-sink",
        re.compile(
            r"""(?ix)
            \.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML
            | bypassSecurityTrust
            | echo\s+\$_(GET|POST|REQUEST)
            | res\.(send|write|end)\s*\(\s*(req\.|`[^`]*\$\{)
            | print\s*\(\s*\$_(GET|POST|REQUEST)
            """
        ),
    ),
    (
        "static-command-exec",
        re.compile(
            r"""(?ix)
            \b(system|passthru|shell_exec|popen|proc_open|exec)\s*\(
            | child_process|os\.system\s*\(|subprocess\.
            | Runtime\.getRuntime\(\)\.exec
            """
        ),
    ),
    (
        "static-path-sink",
        re.compile(
            r"""(?ix)
            (readFileSync|readFile|createReadStream|sendFile|createWriteStream)\s*\(
            | \b(include|require|include_once|require_once|fopen|file_get_contents|readfile)\s*\(\s*(\$|req\.|request\.)
            | Files\.read(?:String|AllBytes)\s*\(
            | new\s+File(?:InputStream|Reader)?\s*\(
            """
        ),
    ),
    (
        "static-eval",
        re.compile(
            r"""(?ix)
            \beval\s*\(|\bFunction\s*\(|new\s+Function\s*\(
            | vm\.runInContext|vm\.runInNewContext
            | setTimeout\s*\(\s*['"]|setInterval\s*\(\s*['"]
            """
        ),
    ),
    (
        "static-ssrf",
        re.compile(
            r"""(?ix)
            requests\.(get|post|put|head|request)\s*\(
            | urllib\.request\.urlopen\s*\(
            | httpx\.(get|post|request)\s*\(
            | file_get_contents\s*\(\s*(\$|req\.|request\.)
            | curl_exec\s*\(|curl_setopt
            | HttpURLConnection|HttpRequest\.newBuilder
            | \bhttps?\.get\s*\(
            | urllib3\.
            """
        ),
    ),
    (
        "static-open-redirect",
        re.compile(
            r"""(?ix)
            header\s*\(\s*['"]Location:
            | res\.redirect\s*\(|response\.redirect\s*\(
            | sendRedirect\s*\(|HttpResponseRedirect\s*\(
            | redirect\s*\(\s*(req\.|request\.|\$)
            """
        ),
    ),
    (
        "static-xxe",
        re.compile(
            r"""(?ix)
            simplexml_load_(string|file)\s*\(
            | new\s+DOMDocument|loadXML\s*\(
            | XMLParser\s*\(|etree\.XMLParser
            | DocumentBuilderFactory|SAXParserFactory
            | libxml_disable_entity_loader\s*\(\s*false
            | \.parseXml\s*\(
            """
        ),
    ),
    (
        "static-deser",
        re.compile(
            r"""(?ix)
            \bunserialize\s*\(
            | pickle\.loads?\s*\(
            | yaml\.load\s*\(
            | Marshal\.load\s*\(
            | ObjectInputStream
            | readObject\s*\(
            """
        ),
    ),
    (
        "static-upload-sink",
        re.compile(
            r"""(?ix)
            move_uploaded_file\s*\(
            | multer\s*\(
            | \$_FILES\b
            | transferTo\s*\(
            | Files\.copy\s*\(
            | diskStorage\s*\(
            """
        ),
    ),
)

_DESER_API_PATTERN = re.compile(
    r"""(?ix)
    \bunserialize\s*\(
    | pickle\.loads?\s*\(
    | yaml\.load\s*\(
    | Marshal\.load\s*\(
    | new\s+ObjectInputStream
    """
)
_CORS_STAR_PATTERN = re.compile(
    r"""(?ix)
    Access-Control-Allow-Origin['"\s]*[:=]['"\s]*\*
    | cors\s*\(\s*\{[^\}]{0,180}origin\s*:\s*(true|['"]\*['"])
    | \bcors\s*\(\s*\)
    | enableCors\s*\(
    | CrossOrigin\s*\(\s*origins?\s*=\s*['"]\*['"]
    """
)
_CSRF_DISABLED_PATTERN = re.compile(
    r"""(?ix)
    csrf\s*:\s*false
    | csrfProtection\s*[:=]\s*false
    | WTF_CSRF_ENABLED\s*=\s*False
    | CSRF_COOKIE_HTTPONLY\s*=\s*False
    | disablecsrf|skip_csrf|csrf_exempt|csrfexempt
    | csrf\s*\(\s*false\s*\)
    """
)
_SENSITIVE_BASENAMES = frozenset({
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "wp-config.php", "phpinfo.php", ".htpasswd", "shadow",
    "dump.sql", "backup.sql", "web.config",
})
_SENSITIVE_SUFFIXES = (
    ".pem", ".p12", ".pfx", ".jks", ".keystore",
    ".sql.gz", ".bak",
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


def _ident_in(snippet: str, ident: str) -> bool:
    if not ident:
        return False
    if ident.startswith("$"):
        return ident in snippet
    return re.search(r"\b" + re.escape(ident) + r"\b", snippet or "") is not None


def _tainted_idents(text: str) -> set[str]:
    found: set[str] = set()
    for match in _ASSIGN_RE.finditer(text or ""):
        for group in match.groups():
            if not group or group in _SOURCE_GROUP_SKIP:
                continue
            found.add(group)
    return found


def _source_lines(text: str) -> list[int]:
    return [_line_of(text, m.start()) for m in _SOURCE_RE.finditer(text or "")]


def _sink_tainted(text: str, start: int, snippet: str, source_lines: list[int], idents: set[str]) -> bool:
    if _SOURCE_RE.search(snippet or ""):
        return True
    if any(_ident_in(snippet, ident) for ident in idents):
        return True
    line = _line_of(text, start)
    return any(abs(line - src) <= _NEAR_SOURCE_LINES for src in source_lines)


def check_taint_flows(sample_texts: dict) -> list[dict]:
    """Intra-file source→sink taint. Not a compiler CFG; same-file only."""
    findings = []
    for path, text in (sample_texts or {}).items():
        low = "/" + str(path).replace("\\", "/").lower()
        if "/node_modules/" in low or _is_example_context(path):
            continue
        body = text or ""
        if not body:
            continue
        sources = _source_lines(body)
        idents = _tainted_idents(body)
        if not sources and not idents:
            continue
        for rule_id, pattern in _TAINT_SINKS:
            hits = []
            for match in pattern.finditer(body):
                left = max(0, match.start() - 80)
                right = min(len(body), match.end() + 80)
                snippet = body[left:right]
                if not _sink_tainted(body, match.start(), snippet, sources, idents):
                    continue
                hits.append(
                    f"line {_line_of(body, match.start())}: {match.group(0)[:80]}"
                )
                if len(hits) >= 4:
                    break
            if not hits:
                continue
            item = _rule_finding(
                rule_id,
                location=str(path),
                scan_origin="Static",
                param_location="",
                evidence="; ".join(hits),
            )
            if item:
                findings.append(item)
    return findings


def check_sensitive_artifacts(paths: list) -> list[dict]:
    findings = []
    for path in paths or []:
        name = _base_name(path)
        low = "/" + str(path).replace("\\", "/").lower()
        if _is_example_context(path) or "/node_modules/" in low:
            continue
        matched = name in _SENSITIVE_BASENAMES or any(
            name.endswith(suf) for suf in _SENSITIVE_SUFFIXES
        )
        if name.endswith(".key") and name not in {".key"}:
            matched = True
        if not matched:
            continue
        item = _rule_finding(
            "static-sensitive-artifact",
            location=str(path),
            scan_origin="Static",
            param_location="",
            evidence=f"archive path: {path}",
        )
        if item:
            findings.append(item)
    return findings


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for item in findings or []:
        key = (
            str(item.get("plugin_id") or ""),
            str(item.get("location") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


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
    findings.extend(check_taint_flows(samples))
    findings.extend(_pattern_hits(samples, _DESER_API_PATTERN, "static-deser", "Insecure deserialization sink"))
    findings.extend(_pattern_hits(samples, _CORS_STAR_PATTERN, "static-cors-star", "Permissive CORS origin in source"))
    findings.extend(_pattern_hits(samples, _CSRF_DISABLED_PATTERN, "static-csrf-disabled", "CSRF protection disabled"))
    findings.extend(check_sensitive_artifacts(paths))
    return _dedupe_findings(findings)


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
