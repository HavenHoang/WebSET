"""Start Scan entry point and rules for static (ZIP) assessment."""

from __future__ import annotations

import ast
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
_TAINT_SINKS = _TAINT_SINKS + (
    ("static-sql-concat", _SQL_CONCAT_PATTERN),
    ("static-html-sink", _HTML_SINK_PATTERN),
    ("static-command-exec", _CMD_PATTERN),
    ("static-path-sink", _PATH_SINK_PATTERN),
    ("static-eval", _EVAL_PATTERN),
    ("static-deser", _DESER_API_PATTERN),
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


def _line_comment_open(prefix: str) -> bool:
    quote = ""
    i = 0
    n = len(prefix)
    while i < n:
        ch = prefix[i]
        if quote:
            if ch == "\\" and quote != "`":
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"`":
            quote = ch
            i += 1
            continue
        if ch == "/" and i + 1 < n and prefix[i + 1] == "/" and not (i > 0 and prefix[i - 1] == ":"):
            return True
        if ch == "#" and (i == 0 or prefix[i - 1] in " \t("):
            return True
        i += 1
    return False


def _match_in_comment(text: str, start: int) -> bool:
    if start < 0 or not text:
        return False
    last_open = text.rfind("/*", 0, start)
    if last_open >= 0 and text.rfind("*/", 0, start) < last_open:
        return True
    line_start = text.rfind("\n", 0, start) + 1
    return _line_comment_open(text[line_start:start])


def _pattern_hits(sample_texts: dict, pattern, rule_id: str, title_fallback: str) -> list[dict]:
    findings = []
    for path, text in (sample_texts or {}).items():
        low = "/" + path.replace("\\", "/").lower()
        if "/node_modules/" in low:
            continue
        body = text or ""
        matches = [
            m for m in pattern.finditer(body)
            if not _match_in_comment(body, m.start())
        ]
        if not matches:
            continue
        evidence = "; ".join(
            f"line {_line_of(body, m.start())}: {m.group(0)[:80]}"
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


_ALIAS_RE = re.compile(
    r"""(?mx)
    ^[ \t]*
    (\$[A-Za-z_]\w*|[A-Za-z_]\w*)
    \s*=\s*
    (\$[A-Za-z_]\w*|[A-Za-z_]\w*)
    \s*;?[ \t]*$
    """
)
_FUNC_DEF_RE = re.compile(
    r"""(?imx)
    ^[ \t]*
    (?:
        (?:export\s+)?(?:async\s+)?function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)
        |
        (?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)
        |
        (?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?[\w.<>,\[\]?]+\s+([A-Za-z_]\w*)\s*\(([^)]*)\)
    )
    """
)
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\s*\(([^)]{0,240})\)")
_PY_SOURCE_ATTRS = {
    "args", "form", "values", "json", "data", "query_params",
    "GET", "POST", "files", "cookies", "query", "body", "params",
}


def _propagate(idents: set[str], text: str) -> set[str]:
    found = set(idents)
    for _ in range(12):
        changed = False
        for match in _ALIAS_RE.finditer(text or ""):
            dst, src = match.group(1), match.group(2)
            if src in found and dst not in found:
                found.add(dst)
                changed = True
        if not changed:
            break
    return found


def _func_name_params(match: re.Match) -> tuple[str, str]:
    groups = match.groups()
    for index in range(0, len(groups), 2):
        if groups[index]:
            return groups[index], groups[index + 1] or ""
    return "", ""


def _param_names(raw: str) -> list[str]:
    names = []
    for part in (raw or "").split(","):
        token = part.strip().split("=")[0].strip()
        token = token.split(":")[0].strip().replace("$", "")
        bits = token.split()
        token = bits[-1] if bits else ""
        token = token.strip("*&")
        if token and re.match(r"^[A-Za-z_]\w*$", token) and token not in {"self", "cls"}:
            names.append(token)
    return names


def _func_body(text: str, start: int) -> str:
    nxt = _FUNC_DEF_RE.search(text, start)
    end = nxt.start() if nxt else min(len(text), start + 8000)
    return text[start:end]


def _py_is_source(node, known: set[str]) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in known
    if isinstance(node, ast.Attribute):
        if node.attr in _PY_SOURCE_ATTRS:
            base = node.value
            if isinstance(base, ast.Name) and base.id in {"request", "req"}:
                return True
            return _py_is_source(base, known)
        if node.attr in {"get", "getlist", "getParameter"}:
            return _py_is_source(node.value, known)
        return _py_is_source(node.value, known)
    if isinstance(node, ast.Subscript):
        return _py_is_source(node.value, known)
    if isinstance(node, ast.Call):
        if _py_is_source(node.func, known):
            return True
        if any(_py_is_source(arg, known) for arg in node.args):
            return True
        return any(_py_is_source(kw.value, known) for kw in node.keywords)
    if isinstance(node, ast.BinOp):
        return _py_is_source(node.left, known) or _py_is_source(node.right, known)
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(value, ast.FormattedValue) and _py_is_source(value.value, known)
            for value in node.values
        )
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_py_is_source(elt, known) for elt in node.elts)
    if isinstance(node, ast.Dict):
        return any(_py_is_source(value, known) for value in node.values)
    return False


def _py_flow(text: str) -> tuple[set[str], set[str]]:
    try:
        tree = ast.parse(text or "")
    except SyntaxError:
        return set(), set()
    idents: set[str] = set()
    funcs: set[str] = set()

    class Walker(ast.NodeVisitor):
        def __init__(self):
            self.local: set[str] = set()

        def visit_FunctionDef(self, node):
            saved = set(self.local)
            self.local = set(self.local)
            for stmt in node.body:
                self.visit(stmt)
            for stmt in node.body:
                if isinstance(stmt, ast.Return) and _py_is_source(stmt.value, self.local):
                    funcs.add(node.name)
                    break
            self.local = saved

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Assign(self, node):
            if _py_is_source(node.value, self.local):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.local.add(target.id)
                        idents.add(target.id)
            self.generic_visit(node)

        def visit_AnnAssign(self, node):
            if (
                node.value is not None
                and isinstance(node.target, ast.Name)
                and _py_is_source(node.value, self.local)
            ):
                self.local.add(node.target.id)
                idents.add(node.target.id)
            self.generic_visit(node)

    Walker().visit(tree)
    return idents, funcs


def _function_returns_source(body: str) -> bool:
    idents = _propagate(_tainted_idents(body), body)
    for match in re.finditer(r"\breturn\b([^\n;]*)", body or ""):
        expr = match.group(1) or ""
        if _match_in_comment(body, match.start()):
            continue
        if _SOURCE_RE.search(expr) or any(_ident_in(expr, ident) for ident in idents):
            return True
    return False


def _params_reaching_sink(body: str, params: list[str]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for rule_id, pattern in _TAINT_SINKS:
        for match in pattern.finditer(body or ""):
            if _match_in_comment(body, match.start()):
                continue
            snippet = body[match.start(): min(len(body), match.end() + 160)]
            for param in params:
                if not (_ident_in(snippet, param) or _ident_in(snippet, "$" + param)):
                    continue
                key = (rule_id, param)
                if key in seen:
                    continue
                seen.add(key)
                found.append(key)
    return found


def _index_cross_file(sample_texts: dict, on_progress=None) -> tuple[set[str], dict[str, list[tuple[str, str, str]]]]:
    tainted_funcs: set[str] = set()
    sink_params: dict[str, list[tuple[str, str, str]]] = {}
    items = list((sample_texts or {}).items())
    total = len(items)
    for index, (path, text) in enumerate(items, 1):
        if on_progress and total and (index == 1 or index == total or index % 25 == 0):
            try:
                on_progress(index, total, path)
            except Exception:
                pass
        body = text or ""
        low = "/" + str(path).replace("\\", "/").lower()
        if not body or "/node_modules/" in low or _is_example_context(path):
            continue
        if str(path).lower().endswith(".py"):
            _py_idents, py_funcs = _py_flow(body)
            tainted_funcs |= py_funcs
        for match in _FUNC_DEF_RE.finditer(body):
            if _match_in_comment(body, match.start()):
                continue
            name, raw_params = _func_name_params(match)
            if len(name) < 4:
                continue
            params = _param_names(raw_params)
            chunk = _func_body(body, match.end())
            if _function_returns_source(chunk):
                tainted_funcs.add(name)
            for rule_id, param in _params_reaching_sink(chunk, params):
                sink_params.setdefault(name, []).append((rule_id, str(path), param))
    return tainted_funcs, sink_params


def _sink_tainted(text: str, start: int, snippet: str, idents: set[str], tainted_funcs: set[str]) -> bool:
    if _match_in_comment(text, start):
        return False
    if _SOURCE_RE.search(snippet or ""):
        return True
    if any(_ident_in(snippet, ident) for ident in idents):
        return True
    for name in tainted_funcs:
        if re.search(r"\b" + re.escape(name) + r"\s*\(", snippet or ""):
            return True
    return False


def check_taint_flows(sample_texts: dict, on_progress=None) -> list[dict]:
    """Source-to-sink flow inside a file and across files via function returns and parameters.

    Python files also use the stdlib AST. Other languages use assignment and
    function structure, not a same-line keyword guess and not a nearby-line window.
    """
    items = list((sample_texts or {}).items())
    total = max(len(items), 1)

    def _half(done, tot, label, shift):
        if not on_progress:
            return
        try:
            on_progress(shift + int(done or 0), max(int(tot or 1), 1) * 2, label)
        except Exception:
            pass

    tainted_funcs, sink_params = _index_cross_file(
        sample_texts,
        on_progress=(lambda done, tot, label: _half(done, tot, label, 0)) if on_progress else None,
    )
    findings = []
    for index, (path, text) in enumerate(items, 1):
        if on_progress and (index == 1 or index == len(items) or index % 25 == 0):
            try:
                on_progress(total + index, total * 2, path)
            except Exception:
                pass
        low = "/" + str(path).replace("\\", "/").lower()
        if "/node_modules/" in low or _is_example_context(path):
            continue
        body = text or ""
        if not body:
            continue
        idents = _propagate(_tainted_idents(body), body)
        if str(path).lower().endswith(".py"):
            py_idents, _py_funcs = _py_flow(body)
            idents |= py_idents
        rule_hits: dict[str, list[str]] = {}
        for rule_id, pattern in _TAINT_SINKS:
            for match in pattern.finditer(body):
                if _match_in_comment(body, match.start()):
                    continue
                right = min(len(body), match.end() + 160)
                snippet = body[match.start():right]
                if not _sink_tainted(body, match.start(), snippet, idents, tainted_funcs):
                    continue
                bucket = rule_hits.setdefault(rule_id, [])
                if len(bucket) >= 4:
                    break
                bucket.append(f"line {_line_of(body, match.start())}: {match.group(0)[:80]}")
        for call in _CALL_RE.finditer(body):
            if _match_in_comment(body, call.start()):
                continue
            prefix = body[max(0, call.start() - 24):call.start()]
            if re.search(r"(?:function|def|public|private|protected)\s*$", prefix):
                continue
            fname = call.group(1)
            args = call.group(2) or ""
            specs = sink_params.get(fname) or []
            if not specs:
                continue
            arg_tainted = bool(
                _SOURCE_RE.search(args)
                or any(_ident_in(args, ident) for ident in idents)
                or any(
                    re.search(r"\b" + re.escape(fn) + r"\s*\(", args)
                    for fn in tainted_funcs
                )
            )
            if not arg_tainted:
                continue
            seen_rules: set[str] = set()
            for rule_id, def_path, param in specs:
                if rule_id in seen_rules:
                    continue
                seen_rules.add(rule_id)
                bucket = rule_hits.setdefault(rule_id, [])
                if len(bucket) >= 4:
                    continue
                bucket.append(
                    f"line {_line_of(body, call.start())}: {fname}({param}) flows to {def_path}"
                )
        for rule_id, hits in rule_hits.items():
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


def run_static_checks(artefact: dict, on_progress=None) -> list[dict]:
    data = artefact if isinstance(artefact, dict) else {}
    paths = data.get("paths") or []
    samples = data.get("sample_texts") or {}
    steps = (
        ("env files", lambda: check_env_files(paths)),
        ("secrets", lambda: check_hardcoded_secrets(samples)),
        ("debug flags", lambda: check_debug_flags(samples)),
        ("weak crypto", lambda: _pattern_hits(samples, _WEAK_CRYPTO_PATTERN, "static-weak-crypto", "Weak cryptography")),
        ("jwt", lambda: _pattern_hits(samples, _JWT_PATTERN, "static-jwt-hardcoded", "JWT / token handling issue")),
        ("empty handlers", lambda: _pattern_hits(samples, _EMPTY_HANDLER_PATTERN, "static-empty-handler", "Empty error handler")),
        ("debug residue", lambda: _pattern_hits(samples, _DEBUG_RESIDUE_PATTERN, "static-debug-residue", "Debug residue in source")),
        ("data flow", None),
        ("cors", lambda: _pattern_hits(samples, _CORS_STAR_PATTERN, "static-cors-star", "Permissive CORS origin in source")),
        ("csrf", lambda: _pattern_hits(samples, _CSRF_DISABLED_PATTERN, "static-csrf-disabled", "CSRF protection disabled")),
        ("sensitive files", lambda: check_sensitive_artifacts(paths)),
    )
    findings: list[dict] = []
    total = len(steps)

    def _report(done, label):
        if not on_progress:
            return
        try:
            on_progress(done, total, label)
        except Exception:
            pass

    for index, (label, fn) in enumerate(steps, 1):
        if label == "data flow":
            def _flow_progress(done, flow_total, path, step=index):
                frac = (float(done) / float(flow_total)) if flow_total else 1.0
                _report((step - 1) + frac, path)
            findings.extend(check_taint_flows(samples, on_progress=_flow_progress if on_progress else None))
        else:
            findings.extend(fn())
        _report(index, label)
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


def analyse_static(zip_path: str, *, open_fn=None, on_progress=None) -> dict:
    def report(pct, label):
        if not on_progress:
            return
        try:
            on_progress(max(0, min(100, int(pct))), 100, str(label or ""))
        except Exception:
            pass

    if not str(zip_path or "").strip():
        return _error("invalid_zip")
    if open_fn is None:
        try:
            from crawler.zip_reader import open_project_zip as open_fn
        except ImportError:
            return _error("crawler_unavailable")
    report(4, zip_path)

    def zip_progress(done, total, label):
        frac = (float(done) / float(total)) if total else 1.0
        report(6 + 52 * frac, label)

    try:
        try:
            artefact = open_fn(zip_path, on_progress=zip_progress)
        except TypeError:
            artefact = open_fn(zip_path)
    except Exception:
        return _error("unreadable_zip")
    if not isinstance(artefact, dict):
        return _error("unreadable_zip")
    if not artefact.get("ok"):
        code = str(artefact.get("error") or "").strip()
        return _error(code if code in KNOWN_ZIP_ERRORS else "unreadable_zip")

    def check_progress(done, total, label):
        frac = (float(done) / float(total)) if total else 1.0
        report(60 + 34 * frac, label)

    findings = run_static_checks(artefact, on_progress=check_progress)
    report(96, zip_path)
    return {
        "findings": sort_findings(findings),
        "tech_stacks": [],
        "coverage": sample_coverage(artefact),
    }


def run_static_scan(zip_path: str, on_progress=None) -> dict:
    return analyse_static(zip_path, on_progress=on_progress)
