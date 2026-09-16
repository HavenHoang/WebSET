"""Response analysis for Active Test exploit chains.
analyse_* / analyse_for_vuln_type  — one response
summarise_detections               — all checks for one finding
Verdicts:
  CONFIRMED      A chain exploit step matched (auth bypass, raw XSS PoC, …)
  LIKELY         Strong signal, not enough to confirm the exploit step
  NOT CONFIRMED  No useful proof from this suite
"""
from __future__ import annotations
import html
import json
import re
from urllib.parse import unquote
_HTML_LT = chr(38) + "lt;"
_SQL_ERRORS = (
    "sql syntax",
    "you have an error in your sql",
    "unclosed quotation",
    "unterminated quoted string",
    "unterminated string",
    "missing terminating quote",
    "quoted string not properly terminated",
    "supplied argument is not a valid mysql",
    "mysql_fetch",
    "mysql_num",
    "mysqli_sql_exception",
    "pdoexception",
    "syntax error at or near",
    "ora-",
    "sqlstate[",
    "sql error",
    "sql exception",
    "database error",
    "query failed",
    "invalid query",
    "mysql error",
    "sqlite3.error",
    "sqlite3.operationalerror",
    "operationalerror",
    "programmingerror",
    "integrityerror",
    "sequelizedatabaseerror",
    "sequelize/lib",
    "dialects/sqlite",
    "sqlite/query",
    "at database",
    "pg_query",
    "pg_exec",
)
_SQL_STACK_RE = re.compile(
    r"(sequelize[/\\]lib|dialects[/\\]sqlite|[/\\]sqlite[/\\]query|"
    r"node_modules[/\\](?:sequelize|knex|prisma|typeorm|pg|mysql2?|sqlite3)|"
    r"\bat\s+Database\b|SequelizeDatabaseError)",
    re.I,
)
# Engine name only counts next to a real driver/ORM fault — not "WARNING" banners
# or "web server and database" copy.
_SQL_ENGINE_NEAR_ERROR = re.compile(
    r"(mysql|mysqli|mariadb|postgres(?:ql)?|sqlite3?|odbc|jdbc|prisma|knex|sequelize)"
    r".{0,32}(sqlstate|exception|syntax error|query failed|operationalerror|error in your sql)|"
    r"(sqlstate|exception|syntax error|query failed|operationalerror|error in your sql).{0,32}"
    r"(mysql|mysqli|mariadb|postgres(?:ql)?|sqlite3?|odbc|jdbc|prisma|knex|sequelize)",
    re.I,
)
_DOCUMENTED_SQL_RE = re.compile(
    r"(if you see the following|when running the setup script|"
    r"configured on the database|pointed the config file|"
    r"means the username or password|video help|"
    r"check this line in)",
    re.I,
)
_SQL_CHROME_RE = re.compile(
    r"damn vulnerable|do not upload it to your hosting|sqli\s*db\s*:|"
    r"security level\s*:|for the web server and database",
    re.I,
)
_AUTH_KEYS = (
    "token",
    "authentication",
    "access_token",
    "accesstoken",
    "refresh_token",
    "jwt",
    "id_token",
)
_TRAVERSAL_HITS = (
    "root:x:",
    "root:*:",
    "[boot loader]",
    "for 16-bit app support",
)
_FS_ERRORS = (
    "no such file",
    "enoent",
    "failed to open",
    "failed opening",
    "failed to include",
    "open_basedir",
    "not a directory",
    "failed to open stream",
    "include_path",
)
_SHELL_ERRORS = (
    "sh: ",
    "/bin/sh",
    "/bin/bash",
    "not found",
    "command not found",
    "is not recognized as an internal",
    "syntax error near unexpected token",
)
_SHELL_OUTPUT = (
    "uid=",
    "gid=",
    "euid=",
    "groups=",
    "www-data",
    "nt authority",
    "volume serial number",
)
_CANARY_RE = re.compile(r"(WEBSET_[A-Z0-9_]+)", re.I)
_PRE_RE = re.compile(r"<(pre|code|textarea|xmp)\b[^>]*>(.*?)</\1>", re.I | re.S)
_ONLY_DOTS_RE = re.compile(r"^[.\u2026…\s\-]+$")
_CSS_NOISE_RE = re.compile(
    r"(#stacktrace|\bmargin-|\bpadding-|\bfont-family\b|\bdisplay\s*:\s*none\b|"
    r"\bwebkit-|\bbackground\s*:)",
    re.I,
)
_ERROR_LINE_RE = re.compile(
    r"(\bsqlstate\b|sqlite_|syntax error|\borm\b|"
    r"unclosed quotation|unterminated quoted|missing terminating quote|"
    r"you have an error in your sql|database error|sql exception|sql error|"
    r"failed to open stream|failed opening|failed to include|open_basedir|"
    r"no such file or directory|pdoexception|mysqli_sql_exception|"
    r"sequelize|dialects[/\\]sqlite|[/\\]sqlite[/\\]query|\bat\s+Database\b)",
    re.I,
)
_STACK_LINE_RE = re.compile(r"^\s*at\s+\S", re.I)
_HEADER_NOISE_RE = re.compile(
    r"cannot modify header|headers already sent",
    re.I,
)
_CMD_KEEP_RE = re.compile(
    r"(WEBSET_[A-Z0-9_]+|uid=|gid=|euid=|groups=|www-data|"
    r"nt authority|volume serial|rtt min|/avg/max|"
    r"packets transmitted|bytes from|command not found|"
    r"is not recognized as an internal)",
    re.I,
)
_HEADING_RE = re.compile(
    r"^(more information|more info|see also|references|documentation|"
    r"helpful links|related links)$",
    re.I,
)
_ERRORISH_RE = re.compile(
    r"(quote|error|exception|warning|failed|include|sql|denied|undefined|"
    r"unterminated|syntax|stream|fatal)",
    re.I,
)
def _plain(body: str) -> str:
    return html.unescape(body or "")
def _strip_tags(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", text or "")
def _looks_json(body: str) -> bool:
    s = (body or "").lstrip()
    return s.startswith("{") or s.startswith("[")
def _looks_html(body: str) -> bool:
    low = (body or "").lower()
    return "<html" in low or "<body" in low or "<script" in low or "<svg" in low
def _is_xss_poc(marker: str) -> bool:
    low = (marker or "").lower()
    return any(
        token in low
        for token in ("<script", "<svg", "<img", "<iframe", "onerror=", "onload=", "javascript:")
    )
def _is_pathish_probe(marker: str) -> bool:
    """True when the probe is only path-climb characters (not a unique canary)."""
    text = (marker or "").strip()
    if not text:
        return False
    try:
        text = unquote(unquote(text))
    except Exception:
        pass
    compact = re.sub(r"[.\s/\\]", "", text)
    return (not compact) and ("/" in text or "\\" in text or ".." in (marker or ""))
def _is_distinctive(marker: str) -> bool:
    if not marker:
        return False
    if _is_xss_poc(marker):
        return True
    if _is_pathish_probe(marker):
        return False
    if len(marker) >= 10:
        return True
    if any(ch in marker for ch in "_<>\"'%{}[];"):
        return True
    has_alpha = any(ch.isalpha() for ch in marker)
    has_digit = any(ch.isdigit() for ch in marker)
    return has_alpha and has_digit and len(marker) >= 8
def _decode_variants(text: str) -> list[str]:
    out = []
    seen = set()
    def add(s):
        s = str(s or "")
        if not s:
            return
        key = s.lower()
        if key in seen:
            return
        seen.add(key)
        out.append(s)
    add(text)
    try:
        add(unquote(text))
        add(unquote(unquote(text)))
    except Exception:
        pass
    add(html.unescape(text or ""))
    return out
def _token_hit(marker: str, body: str) -> bool:
    if not marker or not body:
        return False
    hay = body
    for needle in _decode_variants(marker):
        if needle.lower() not in hay.lower():
            continue
        if _is_distinctive(needle) or _is_xss_poc(needle):
            return True
        if re.search(
            r"(?<![A-Za-z0-9_])" + re.escape(needle) + r"(?![A-Za-z0-9_])",
            hay,
            flags=re.IGNORECASE,
        ) is not None:
            return True
    return False
def _looks_command_probe(marker: str) -> bool:
    text = (marker or "").strip()
    if not text:
        return False
    if text[:1] in ";|&":
        return True
    if _CANARY_RE.search(text) and any(ch in text for ch in ";|&"):
        return True
    return False
def _canary_tokens(marker: str) -> list[str]:
    found = [m.group(1) for m in _CANARY_RE.finditer(marker or "")]
    out = []
    seen = set()
    for item in found:
        key = item.upper()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
def _clip(text: str, limit: int = 900) -> str:
    text = re.sub(r"[ \t]+\n", "\n", text or "").strip()
    text = re.sub(r"\n{3,}", "\n\n", text)
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"
def _looks_css_noise(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    if re.search(
        r"(<\s*style\b|</\s*style\s*>|<\s*meta\b|<\s*title\b|</\s*title\s*>|"
        r"<!doctype\b|#stacktrace|\bwebkit-|\bfont-family\b|"
        r"\bdisplay\s*:|\bpadding\s*:|\bmargin\s*:|\bbackground\s*:|"
        r"\bpadding-|\bmargin-|\boutline\s*:|\bcharset\s*=)",
        t,
        re.I,
    ):
        return True
    if re.match(r"^[*#.@a-z][^{;]{0,40}\{\s*$", t, re.I):
        return True
    if re.match(r"^[a-z][a-z0-9-]*\s*:\s*[^;{}\n]+;?\s*$", t, re.I):
        return True
    braces = t.count("{") + t.count("}")
    if braces >= 1 and not re.search(
        r"(sql|sequelize|exception|stack|at\s+\S|failed to open|root:x:)",
        t,
        re.I,
    ):
        if len(re.sub(r"[\s\{\}:;#+.*\-]", "", t)) < 24:
            return True
    return False

def _looks_page_heading(line: str) -> bool:
    t = (line or "").strip()
    if not t:
        return True
    if _HEADING_RE.match(t):
        return True
    if t.lower().startswith("http://") or t.lower().startswith("https://"):
        return True
    if _ERRORISH_RE.search(t) or _CANARY_RE.search(t) or _HEADER_NOISE_RE.search(t):
        return False
    words = t.split()
    if 1 <= len(words) <= 4 and "=" not in t and not _CANARY_RE.search(t):
        if t[:1].isupper() and not any(ch.isdigit() for ch in t):
            if not _CMD_KEEP_RE.search(t):
                return True
    return False
def _usable_evidence(text: str) -> bool:
    t = (text or "").strip()
    if len(t) < 3:
        return False
    if _ONLY_DOTS_RE.match(t):
        return False
    if _looks_css_noise(t):
        return False
    core = re.sub(r"[.\u2026…\s]+", "", t)
    return len(core) >= 3
def _command_lines_snippet(body: str, extra: list[str] | tuple[str, ...] = (), limit: int = 700) -> str:
    plain = _strip_tags(_plain(body or ""))
    lines = [ln.strip() for ln in plain.splitlines() if ln.strip()]
    picked = []
    extras = [e for e in (extra or ()) if e]
    for ln in lines:
        if _looks_css_noise(ln) or _looks_page_heading(ln) or _HEADER_NOISE_RE.search(ln):
            continue
        keep = bool(_CMD_KEEP_RE.search(ln) or _CANARY_RE.search(ln))
        if not keep:
            low = ln.lower()
            keep = any(e.lower() in low for e in extras if len(e) >= 4)
        if keep and ln not in picked:
            picked.append(ln)
        if len("\n".join(picked)) >= limit:
            break
    text = _clip("\n".join(picked), limit)
    return text if _usable_evidence(text) else ""
def _error_lines_snippet(body: str, limit: int = 700) -> str:
    raw = _plain(body or "")
    raw = re.sub(r"<style\b[^>]*>.*?</style>", " ", raw, flags=re.I | re.S)
    raw = re.sub(r"<script\b[^>]*>.*?</script>", " ", raw, flags=re.I | re.S)
    plain = _strip_tags(raw)
    lines = [ln.strip() for ln in plain.splitlines() if ln.strip()]
    picked = []
    for i, ln in enumerate(lines):
        if _looks_css_noise(ln) or _looks_page_heading(ln) or _HEADER_NOISE_RE.search(ln):
            continue
        if _ERROR_LINE_RE.search(ln) or _STACK_LINE_RE.search(ln):
            start = max(0, i - 1)
            end = min(len(lines), i + 3)
            for piece in lines[start:end]:
                if _looks_css_noise(piece) or _looks_page_heading(piece) or _HEADER_NOISE_RE.search(piece):
                    continue
                if piece not in picked:
                    picked.append(piece)
        if len("\n".join(picked)) >= limit:
            break
    text = _clip("\n".join(picked), limit)
    return text if _usable_evidence(text) else ""
def _json_snippet(body: str, limit: int = 700) -> str:
    s = (body or "").lstrip()
    if not (s.startswith("{") or s.startswith("[")):
        return ""
    try:
        data = json.loads(s)
        pretty = json.dumps(data, ensure_ascii=False, indent=2)
        return _clip(pretty, limit)
    except Exception:
        return _clip(s, limit)
def _body_fallback(body: str, limit: int = 700) -> str:
    err = _error_lines_snippet(body, limit)
    if _usable_evidence(err):
        return err
    js = _json_snippet(body, limit)
    if _usable_evidence(js):
        return js
    plain = _clip(_strip_tags(_plain(body)), limit)
    if _usable_evidence(plain):
        return plain
    raw = _clip((body or "").strip(), limit)
    return raw if _usable_evidence(raw) else ""
def _keep_markup(needle: str) -> bool:
    text = needle or ""
    if _is_xss_poc(text):
        return True
    return "<" in text and ">" in text
def _window_around(body: str, needle: str, radius: int = 160, keep_markup: bool = False) -> str:
    if not body or not needle:
        return ""
    low = body.lower()
    idx = -1
    matched = needle
    for variant in _decode_variants(needle):
        pos = low.find(variant.lower())
        if pos >= 0:
            idx = pos
            matched = variant
            break
    if idx < 0:
        return ""
    rad = 220 if (keep_markup or _keep_markup(needle) or _keep_markup(matched)) else radius
    start = max(0, idx - rad)
    end = min(len(body), idx + max(len(matched), 1) + rad)
    nl = body.rfind("\n", start, idx)
    if nl >= start:
        start = nl + 1
    else:
        tag = body.rfind("<", start, idx)
        if tag >= start:
            start = tag
    # Prefer the nearest block/script/form open so a page <h1> is not the first line.
    for open_tag in ("<div", "<script", "<pre", "<code", "<textarea", "<form"):
        pos = body.lower().rfind(open_tag, max(0, idx - 400), idx)
        if pos >= 0:
            start = min(start, pos) if start > pos else pos
            break
    chunk = body[start:end]
    if keep_markup or _keep_markup(needle) or _keep_markup(matched):
        out = _clip(chunk, 700)
        return out if _usable_evidence(out) else ""
    cleaned = _clip(_strip_tags(chunk), 700)
    cleaned_ok = _usable_evidence(cleaned) and any(
        v.lower() in cleaned.lower() for v in _decode_variants(needle)
    )
    if cleaned_ok:
        return cleaned
    raw = _clip(chunk, 700)
    return raw if _usable_evidence(raw) else ""
def _evidence_contains_needle(text: str, needles: list[str]) -> bool:
    if not text or not needles:
        return False
    low = text.lower()
    for n in needles:
        for v in _decode_variants(n):
            if v and v.lower() in low:
                return True
    return False
def _block_containing(raw: str, needles: list[str], keep_markup: bool) -> str:
    if not raw or not needles:
        return ""
    for match in _PRE_RE.finditer(raw or ""):
        block = match.group(0) if keep_markup else match.group(2)
        if not _evidence_contains_needle(block, needles) and not _evidence_contains_needle(
            _plain(block), needles
        ):
            continue
        text = _clip(block if keep_markup else _strip_tags(_plain(block)), 700)
        if _usable_evidence(text):
            return text
    return ""
def _evidence_snippet(body: str, needles: list[str] | tuple[str, ...] = ()) -> str:
    raw = body or ""
    plain = _plain(raw)
    wanted = [n for n in (needles or ()) if n]
    wanted.sort(key=lambda n: len(n), reverse=True)
    markup_needles = [n for n in wanted if _keep_markup(n)]
    other_needles = [n for n in wanted if n not in markup_needles]
    keep = bool(markup_needles)
    block = _block_containing(raw, wanted, keep_markup=keep)
    if _usable_evidence(block):
        return block
    for needle in markup_needles:
        hit = _window_around(plain, needle, keep_markup=True)
        if _usable_evidence(hit):
            return hit
        hit = _window_around(raw, needle, keep_markup=True)
        if _usable_evidence(hit):
            return hit
    for needle in other_needles:
        hit = _window_around(plain, needle)
        if _usable_evidence(hit):
            return hit
        hit = _window_around(raw, needle)
        if _usable_evidence(hit):
            return hit
    err = _error_lines_snippet(raw)
    if _usable_evidence(err) and (not wanted or _evidence_contains_needle(err, wanted)):
        return err
    if _usable_evidence(err) and not wanted:
        return err
    return _body_fallback(raw)
def _sql_error(body: str) -> bool:
    text = body or ""
    low = text.lower()
    # Help/setup pages quote example DB errors. Those are not a live probe hit.
    if _DOCUMENTED_SQL_RE.search(text):
        live = (
            "you have an error in your sql syntax",
            "sqlstate[",
            "unclosed quotation mark",
            "unterminated quoted string",
            "quoted string not properly terminated",
        )
        if not any(s in low for s in live):
            return False
    if _SQL_CHROME_RE.search(text) and not any(
        s in low for s in (
            "sql syntax", "sqlstate[", "you have an error in your sql",
            "unclosed quotation", "unterminated quoted",
            "quoted string not properly terminated",
        )
    ):
        return False
    if any(s in low for s in _SQL_ERRORS):
        return True
    if _SQL_STACK_RE.search(text) or _SQL_STACK_RE.search(low):
        return True
    if _SQL_ENGINE_NEAR_ERROR.search(text):
        return True
    return False
def _fs_error(body: str) -> bool:
    low = (body or "").lower()
    return any(s in low for s in _FS_ERRORS)
def _auth_success(status_code: int, body: str) -> bool:
    if int(status_code or 0) not in (200, 201):
        return False
    text = body or ""
    try:
        data = json.loads(text)
    except Exception:
        low = text.lower()
        return "authentication" in low and "token" in low
    if not isinstance(data, dict):
        return False
    blob = data.get("authentication") if isinstance(data.get("authentication"), dict) else data
    if not isinstance(blob, dict):
        blob = data
    lowered = {str(k).lower(): v for k, v in blob.items()}
    return any(k in lowered and lowered.get(k) for k in _AUTH_KEYS)
def _base_result(**kwargs) -> dict:
    out = {
        "found_in_body": False,
        "encoded": False,
        "db_error_signal": False,
        "auth_success": False,
        "confirmation": "NOT CONFIRMED",
        "conclusion": "",
        "detail": "",
        "reflection_context": "",
        "expect": "",
        "step": None,
        "evidence": "",
    }
    out.update(kwargs)
    return out
def analyse_xss(marker: str, body: str, context: str = "", expect: str = "") -> dict:
    raw = body or ""
    body = _plain(body)
    marker = marker or ""
    found = _token_hit(marker, body)
    encoded = False
    if "<" in marker:
        encoded = (_HTML_LT in body) and (marker not in body)
        found = marker in body or encoded
        if not found:
            for v in _decode_variants(marker):
                if v in body:
                    found = True
                    break
            if (_HTML_LT in body) and marker not in body:
                encoded = True
                found = found or encoded
    elif _HTML_LT in body and marker in body:
        encoded = True
    evidence = _evidence_snippet(raw, [marker] if marker else [])
    if not _usable_evidence(evidence):
        evidence = _body_fallback(raw)
    if found and encoded:
        return _base_result(
            found_in_body=True,
            encoded=True,
            confirmation="NOT CONFIRMED",
            conclusion="PoC reflected but encoded",
            detail="Special characters look escaped. The XSS chain stops at encoding.",
            reflection_context=context or "unknown",
            expect=expect,
            evidence=evidence,
        )
    if found and not encoded and _is_xss_poc(marker) and _looks_html(body):
        return _base_result(
            found_in_body=True,
            confirmation="CONFIRMED",
            conclusion="XSS exploit step — PoC markup raw in HTML",
            detail="Proof-of-concept markup came back unencoded in HTML.",
            reflection_context=context or "html_body",
            expect=expect,
            evidence=evidence,
        )
    if found and not encoded and expect == "reflection" and _is_distinctive(marker):
        return _base_result(
            found_in_body=True,
            confirmation="LIKELY",
            conclusion="XSS chain 1 — sink reached",
            detail="Unique marker reflected. Later steps must prove unencoded markup.",
            reflection_context=context or "unknown",
            expect=expect,
            evidence=evidence,
        )
    if found and not encoded and _is_xss_poc(marker) and _looks_json(body):
        return _base_result(
            found_in_body=True,
            confirmation="LIKELY",
            conclusion="XSS PoC echoed in JSON",
            detail="Confirmed reflection only. Execution needs a later HTML render.",
            reflection_context=context or "json",
            expect=expect,
            evidence=evidence,
        )
    if found and not encoded and _is_xss_poc(marker):
        return _base_result(
            found_in_body=True,
            confirmation="LIKELY",
            conclusion="XSS PoC came back raw — page type unclear",
            detail="Unencoded markup returned. Confirm the client renders HTML.",
            reflection_context=context or "unknown",
            expect=expect,
            evidence=evidence,
        )
    if found and not encoded and _looks_json(body):
        return _base_result(
            found_in_body=True,
            confirmation="NOT CONFIRMED",
            conclusion="Marker echoed in JSON only",
            detail="JSON echo is not confirmed HTML XSS.",
            reflection_context="json",
            expect=expect,
            evidence=evidence,
        )
    if found and not encoded:
        return _base_result(
            found_in_body=True,
            confirmation="LIKELY",
            conclusion="Unencoded reflection, context unclear",
            detail="Probe reflected unencoded. Page type needs review.",
            reflection_context=context or "unknown",
            expect=expect,
            evidence=evidence,
        )
    return _base_result(
        conclusion="No clear reflection",
        detail="The probe string was not found as a standalone token.",
        reflection_context=context or "unknown",
        expect=expect,
        evidence=evidence,
    )
def analyse_sqli(marker: str, body: str, status_code: int, expect: str = "") -> dict:
    raw = body or ""
    body = _plain(body)
    db_error = _sql_error(body)
    fs_err = _fs_error(body)
    # Include / open-stream faults are not SQL errors. Page chrome that
    # mentions an engine name must not confirm SQLi by itself.
    if fs_err and not db_error:
        db_error = False
    auth = _auth_success(status_code, body)
    found = (marker or "") in (body or "")
    if not found and marker:
        found = _token_hit(marker, body)
    weird_status = int(status_code or 0) >= 500
    needles = list(_SQL_ERRORS) + list(_AUTH_KEYS)
    if marker and len(str(marker)) >= 4:
        needles.append(marker)
    if fs_err:
        needles = list(_FS_ERRORS) + needles
    evidence = ""
    err_ev = _error_lines_snippet(raw)
    if (db_error or weird_status) and _usable_evidence(err_ev):
        evidence = err_ev
    if not _usable_evidence(evidence):
        evidence = _evidence_snippet(raw, needles)
    if fs_err:
        fs_ev = _error_lines_snippet(raw)
        if _usable_evidence(fs_ev):
            evidence = fs_ev
    if not _usable_evidence(evidence):
        evidence = err_ev or _body_fallback(raw)
    if auth and expect in ("auth_success", "boolean_or_auth", ""):
        return _base_result(
            found_in_body=found,
            db_error_signal=db_error,
            auth_success=True,
            confirmation="CONFIRMED",
            conclusion="SQLi exploit step — authentication bypass",
            detail=(
                "Login-like response contains a session token or user object "
                "after a SQL tautology. The password check was not required."
            ),
            expect=expect,
            evidence=evidence,
        )
    if db_error:
        return _base_result(
            found_in_body=found,
            db_error_signal=True,
            confirmation="CONFIRMED",
            conclusion="SQLi chain — query broken (database error)",
            detail=(
                "Database / ORM error after the probe. That confirms injection "
                "into SQL. It is not a data dump."
            ),
            expect=expect,
            evidence=evidence,
        )
    if weird_status:
        return _base_result(
            found_in_body=found,
            confirmation="LIKELY",
            conclusion="SQLi likely — server error after probe",
            detail="HTTP 5xx after SQL input. Weaker than an explicit SQL error.",
            expect=expect,
            evidence=evidence,
        )
    return _base_result(
        found_in_body=found,
        conclusion="SQLi not confirmed by this probe",
        detail="No SQL error, no 5xx, and no authentication success signal.",
        expect=expect,
        evidence=evidence,
    )
def analyse_path_traversal(marker: str, body: str, status_code: int, expect: str = "") -> dict:
    raw = body or ""
    body = _plain(body)
    hit = any(sig in body for sig in _TRAVERSAL_HITS)
    found = _token_hit(marker or "", body)
    fs_err = _fs_error(body)
    needles = list(_TRAVERSAL_HITS) + list(_FS_ERRORS) + ([marker] if marker else [])
    evidence = _evidence_snippet(raw, needles)
    if not _usable_evidence(evidence):
        evidence = _body_fallback(raw)
    if hit:
        return _base_result(
            found_in_body=True,
            confirmation="CONFIRMED",
            conclusion="Traversal exploit step — foreign file signature",
            detail="Response body matches a file outside the intended directory.",
            expect=expect,
            evidence=evidence,
        )
    if int(status_code or 0) >= 500 or fs_err:
        return _base_result(
            found_in_body=found,
            confirmation="LIKELY",
            conclusion="Traversal likely — filesystem error",
            detail="Path probe produced a filesystem-style error. That is not proof a foreign file was read.",
            expect=expect,
            evidence=evidence,
        )
    return _base_result(
        found_in_body=found,
        conclusion="Traversal not confirmed",
        detail="No foreign-file signature and no filesystem error.",
        expect=expect,
        evidence=evidence,
    )
def analyse_command(marker: str, body: str, expect: str = "") -> dict:
    raw = body or ""
    body = _plain(body)
    low = body.lower()
    shell = any(s in low for s in _SHELL_ERRORS)
    output = any(s in low for s in _SHELL_OUTPUT)
    canaries = _canary_tokens(marker)
    canary_hit = any(_token_hit(token, body) for token in canaries)
    needles = list(_SHELL_OUTPUT) + list(_SHELL_ERRORS) + canaries
    evidence = _command_lines_snippet(raw, needles)
    if not _usable_evidence(evidence):
        evidence = _evidence_snippet(raw, needles)
    if not _usable_evidence(evidence):
        evidence = _body_fallback(raw)
    if output:
        return _base_result(
            found_in_body=True,
            confirmation="CONFIRMED",
            conclusion="Command exploit step — command output",
            detail="Response includes command output after the probe. No destructive command was sent.",
            expect=expect,
            evidence=evidence,
        )
    if canary_hit:
        return _base_result(
            found_in_body=True,
            confirmation="CONFIRMED",
            conclusion="Command exploit step — echo canary",
            detail="A unique canary from the probe appeared in the response after a shell separator.",
            expect=expect,
            evidence=evidence,
        )
    if expect == "shell_error_or_canary" and canaries:
        return _base_result(
            confirmation="NOT CONFIRMED",
            conclusion="Command canary did not execute",
            detail="No command output and the echo canary did not come back.",
            expect=expect,
        )
    if shell:
        return _base_result(
            found_in_body=False,
            confirmation="LIKELY",
            conclusion="Command chain — shell error",
            detail="Response looks like a shell error after the probe.",
            expect=expect,
            evidence=evidence,
        )
    return _base_result(
        confirmation="NOT CONFIRMED",
        conclusion="Command injection not confirmed",
        detail=(
            "No command output (uid=/gid=/groups) and no echo canary in the response. "
            "Reflection of the raw probe string is not used as proof."
        ),
        expect=expect,
        evidence=evidence,
    )
def analyse_generic(marker: str, body: str, expect: str = "") -> dict:
    raw = body or ""
    body = _plain(body)
    found = _token_hit(marker or "", body)
    evidence = _evidence_snippet(raw, [marker] if marker else [])
    if not _usable_evidence(evidence):
        evidence = _body_fallback(raw)
    if not found:
        return _base_result(
            conclusion="Marker not found in body",
            detail="The probe string was not found as a standalone token.",
            expect=expect,
        )
    if _is_distinctive(marker or ""):
        return _base_result(
            found_in_body=True,
            confirmation="LIKELY",
            conclusion="Distinctive marker reflected",
            detail="Supports the finding; type-specific exploit step not matched.",
            expect=expect,
            evidence=evidence,
        )
    return _base_result(
        found_in_body=True,
        conclusion="Possible reflection — probe is not distinctive",
        detail="Input appears in the body but is not unique enough to confirm.",
        expect=expect,
        evidence=evidence,
    )
def analyse_nosqli(marker: str, body: str, status: int, expect: str = "") -> dict:
    text = body or ""
    low = text.lower()
    hints = (
        "mongoerror",
        "mongodb",
        "bson",
        "cast to objectid",
        "cannot apply $",
        "unknown operator",
        "modified",
        "nmodified",
        "updated",
    )
    operator_hit = any(h in low for h in hints)
    success = False
    write_hit = False
    auth_ok = False
    rows = None
    try:
        parsed = json.loads(text)
    except Exception:
        parsed = None
    if isinstance(parsed, dict):
        if str(parsed.get("status") or "").lower() == "success":
            success = True
        for key, val in parsed.items():
            if str(key).lower() in ("modified", "nmodified", "updated", "matched"):
                if isinstance(val, (int, float)) and val >= 1:
                    write_hit = True
                    success = True
        auth = parsed.get("authentication") if isinstance(parsed.get("authentication"), dict) else parsed
        if isinstance(auth, dict) and any(auth.get(k) for k in ("token", "access_token", "jwt")):
            auth_ok = True
            success = True
        rows = parsed.get("data", parsed.get("orders", parsed.get("results")))
    elif isinstance(parsed, list):
        rows = parsed

    ids = []
    if isinstance(rows, dict):
        rows = [rows]
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                for key in ("orderId", "id", "_id", "email", "username"):
                    if row.get(key) is not None:
                        ids.append(str(row.get(key)))
                        break
            elif row is not None:
                ids.append(str(row))

    marker_compact = "".join(str(marker or "").split())
    foreign = []
    echoed = []
    for item in ids:
        compact = item.replace("\\", "").replace(" ", "")
        if (
            compact == marker_compact
            or marker_compact in compact
            or any(op in item for op in ("$ne", "$gt", "$regex", "$eq", "$nin"))
        ):
            echoed.append(item)
        else:
            foreign.append(item)

    leaked = bool(foreign) or (len(ids) >= 2 and len(foreign) >= 1)
    if int(status or 0) in (200, 201) and (write_hit or auth_ok or leaked):
        return {
            "found_in_body": True,
            "encoded": False,
            "db_error_signal": False,
            "auth_success": auth_ok,
            "confirmation": "CONFIRMED",
            "conclusion": "CONFIRMED — NoSQL operator changed a lookup or write",
            "detail": (
                "Returned identifiers that are not the probe string."
                if leaked else
                "Write/auth result after a document operator."
            ),
            "expect": expect,
            "evidence": (text[:240] if text else f"HTTP {status}"),
        }
    if int(status or 0) in (200, 201) and success and echoed and not foreign:
        return {
            "found_in_body": True,
            "encoded": False,
            "db_error_signal": False,
            "auth_success": False,
            "confirmation": "LIKELY",
            "conclusion": "LIKELY — response echoed the operator, no extra records",
            "detail": "HTTP success with the probe reflected as the identifier is not a data leak.",
            "expect": expect,
            "evidence": (text[:240] if text else f"HTTP {status}"),
        }
    if int(status or 0) in (200, 201) and operator_hit:
        return {
            "found_in_body": True,
            "encoded": False,
            "db_error_signal": True,
            "auth_success": False,
            "confirmation": "LIKELY",
            "conclusion": "LIKELY — query engine mentioned a document operator",
            "detail": "Operator error without a confirmed record dump.",
            "expect": expect,
            "evidence": (text[:240] if text else f"HTTP {status}"),
        }
    if int(status or 0) >= 500 and expect in ("nosql_operator", "nosql_error", ""):
        if operator_hit or any(tok in low for tok in ("error", "unexpected", "mongo", "cast", "syntax")):
            return {
                "found_in_body": True,
                "encoded": False,
                "db_error_signal": True,
                "auth_success": False,
                "confirmation": "CONFIRMED",
                "conclusion": "CONFIRMED — NoSQL operator reached the query engine",
                "detail": "Server error after a document operator in the identifier.",
                "expect": expect,
                "evidence": (text[:240] if text else f"HTTP {status}"),
            }
    if int(status or 0) == 401:
        return {
            "found_in_body": False,
            "encoded": False,
            "db_error_signal": False,
            "auth_success": False,
            "confirmation": "NOT CONFIRMED",
            "conclusion": "NOT CONFIRMED — endpoint required authentication",
            "detail": "Replay the operator with a session obtained from the login JSON probe.",
            "expect": expect,
            "evidence": f"HTTP {status}",
        }
    return {
        "found_in_body": False,
        "encoded": False,
        "db_error_signal": False,
        "auth_success": False,
        "confirmation": "NOT CONFIRMED",
        "conclusion": "NOT CONFIRMED — no document-operator signal",
        "detail": f"HTTP {status}",
        "expect": expect,
        "evidence": f"HTTP {status}",
    }


def _xxe_evidence(body: str, limit: int = 700) -> str:
    raw = _plain(body or "")
    raw = re.sub(r"<style\b[^>]*>.*?</style>", " ", raw, flags=re.I | re.S)
    titles = re.findall(r"<title[^>]*>(.*?)</title>", raw, flags=re.I | re.S)
    heads = re.findall(r"<h[12][^>]*>(.*?)</h[12]>", raw, flags=re.I | re.S)
    chunks = []
    for block in titles + heads:
        plain = _strip_tags(block)
        plain = re.sub(r"\s+", " ", plain).strip()
        if not plain:
            continue
        low = re.sub(r"\s+", " ", plain.lower())
        if any(low in re.sub(r"\s+", " ", x.lower()) or re.sub(r"\s+", " ", x.lower()) in low for x in chunks):
            continue
        chunks.append(plain)
    if chunks:
        text = "\n".join(chunks)
        return _clip(text, limit)
    err = _error_lines_snippet(raw)
    if _usable_evidence(err):
        return err
    plain = _clip(_strip_tags(raw), limit)
    return plain if _usable_evidence(plain) else _clip(raw, limit)


def analyse_xxe(marker: str, body: str, status: int, expect: str = "") -> dict:
    text = body or ""
    low = text.lower()
    file_hits = (
        "root:x:",
        "root:*:",
        "[boot loader]",
        "for 16-bit app support",
        "opendirectoryd",
        "nobody:*",
        "unprivileged user",
        "failed to load file://",
        "failed to load &quot;file://",
        "no such file or directory",
    )
    parse_hits = ("external entity", "doctype", "entity", "xmlparse", "dtd")
    if any(h in text for h in file_hits) or any(h in low for h in file_hits) or "root:x:" in low:
        return {
            "found_in_body": True,
            "encoded": False,
            "db_error_signal": False,
            "auth_success": False,
            "confirmation": "CONFIRMED",
            "conclusion": "CONFIRMED — XXE file disclosure",
            "detail": "Entity expansion returned a local file signature.",
            "expect": expect,
            "evidence": _xxe_evidence(text),
        }
    if any(tok in low for tok in ("unexpected path", "cannot get", "cannot post", "cannot put")):
        return {
            "found_in_body": False,
            "encoded": False,
            "db_error_signal": False,
            "auth_success": False,
            "confirmation": "NOT CONFIRMED",
            "conclusion": "NOT CONFIRMED — routing error, not an XML parser",
            "detail": "The server rejected the path. That is not entity expansion.",
            "expect": expect,
            "evidence": _xxe_evidence(text) or f"HTTP {status}",
        }
    marker_l = str(marker or "").lower()
    sent_entity = "<!doctype" in marker_l or "<!entity" in marker_l or "file://" in marker_l
    if int(status or 0) in (200, 410, 500) and any(h in low for h in (
        "b2b customer complaints", "deprecated for security",
    )):
        conf = "CONFIRMED" if any(h in text for h in file_hits) or "root:x:" in low else "LIKELY"
        return {
            "found_in_body": True,
            "encoded": False,
            "db_error_signal": False,
            "auth_success": False,
            "confirmation": conf,
            "conclusion": (
                "CONFIRMED — XXE file disclosure"
                if conf == "CONFIRMED"
                else "LIKELY — deprecated XML upload parsed an entity payload"
            ),
            "detail": "The upload endpoint parsed XML and returned a deprecation fault.",
            "expect": expect,
            "evidence": _xxe_evidence(text),
        }
    if int(status or 0) in (200, 410, 500) and any(h in low for h in parse_hits):
        return {
            "found_in_body": True,
            "encoded": False,
            "db_error_signal": False,
            "auth_success": False,
            "confirmation": "LIKELY",
            "conclusion": "LIKELY — XML parser touched the entity",
            "detail": "Parser error or entity mention without a clear file dump.",
            "expect": expect,
            "evidence": _xxe_evidence(text) or f"HTTP {status}",
        }
    if int(status or 0) >= 500 and sent_entity and any(h in low for h in parse_hits):
        return {
            "found_in_body": False,
            "encoded": False,
            "db_error_signal": True,
            "auth_success": False,
            "confirmation": "LIKELY",
            "conclusion": "LIKELY — XML parser errored after an entity payload",
            "detail": "Parser language in a 5xx body, without a local-file dump.",
            "expect": expect,
            "evidence": _xxe_evidence(text) or f"HTTP {status}",
        }
    return {
        "found_in_body": False,
        "encoded": False,
        "db_error_signal": False,
        "auth_success": False,
        "confirmation": "NOT CONFIRMED",
        "conclusion": "NOT CONFIRMED — no XXE file or parser signal",
        "detail": f"HTTP {status}",
        "expect": expect,
        "evidence": f"HTTP {status}",
    }


def analyse_for_vuln_type(
    vuln_type: str,
    marker: str,
    body: str,
    status: int,
    context: str = "",
    expect: str = "",
) -> dict:
    v = (vuln_type or "").lower()
    if v == "xss":
        return analyse_xss(marker, body, context=context, expect=expect)
    if v == "sqli":
        return analyse_sqli(marker, body, status, expect=expect)
    if v in ("nosqli", "nosql"):
        return analyse_nosqli(marker, body, status, expect=expect)
    if v == "xxe":
        return analyse_xxe(marker, body, status, expect=expect)
    if v == "path_traversal":
        return analyse_path_traversal(marker, body, status, expect=expect)
    if v in ("command_injection", "cmdi", "cmd") or _looks_command_probe(marker):
        return analyse_command(marker, body, expect=expect)
    return analyse_generic(marker, body, expect=expect)
def _rank(label: str) -> int:
    return {"CONFIRMED": 2, "LIKELY": 1, "NOT CONFIRMED": 0}.get(
        str(label or "NOT CONFIRMED").upper(), 0
    )
def summarise_detections(vuln_type: str, detections: list[dict]) -> dict:
    vtype = (vuln_type or "").lower()
    reflected = False
    encoded_hit = False
    unencoded_hit = False
    db_error = False
    auth_ok = False
    best = "NOT CONFIRMED"
    any_result = False
    evidence = ""
    for det in detections or []:
        if not det:
            continue
        any_result = True
        if det.get("found_in_body"):
            reflected = True
            if det.get("encoded"):
                encoded_hit = True
            else:
                unencoded_hit = True
        if det.get("db_error_signal"):
            db_error = True
        if det.get("auth_success"):
            auth_ok = True
        label = str(det.get("confirmation") or "").upper() or "NOT CONFIRMED"
        ev = str(det.get("evidence") or "")
        if _rank(label) > _rank(best):
            best = label
            if _usable_evidence(ev):
                evidence = ev
        elif _rank(label) == _rank(best) and not _usable_evidence(evidence) and _usable_evidence(ev):
            evidence = ev
    if vtype == "sqli" and auth_ok:
        best = "CONFIRMED"
        verdict = (
            "Authentication succeeded after a SQL tautology (session token or "
            "user object). That is an exploit-chain confirmation of login SQL injection."
        )
        conclusion = "CONFIRMED — SQL injection authentication bypass"
    elif vtype == "sqli" and db_error:
        best = "CONFIRMED"
        verdict = (
            "A database error appeared after proof-of-concept SQL input. "
            "Injection into the query is confirmed. This is not a data dump."
        )
        conclusion = "CONFIRMED — SQL injection (query break)"
    elif best == "CONFIRMED" and vtype == "xss":
        verdict = (
            "Proof-of-concept XSS markup came back unencoded in HTML. "
            "The reflected XSS chain reached an exploit step."
        )
        conclusion = "CONFIRMED — reflected XSS"
    elif best == "CONFIRMED":
        verdict = "At least one exploit-chain step confirmed the finding type."
        conclusion = f"CONFIRMED — {vtype or 'finding'}"
    elif best == "LIKELY":
        verdict = (
            "A chain step produced a strong signal, but not the final exploit "
            "condition (for SQLi: token or SQL error; for XSS: raw markup in HTML)."
        )
        conclusion = "LIKELY — chain incomplete"
    elif reflected and encoded_hit and not unencoded_hit:
        verdict = "Input came back encoded. The exploit chain stops at sanitisation."
        conclusion = "NOT CONFIRMED — encoded reflection only"
        best = "NOT CONFIRMED"
    elif any_result:
        verdict = (
            "The suite did not confirm an exploit step. "
            "Alerts severity is unchanged."
        )
        conclusion = "NOT CONFIRMED"
        best = "NOT CONFIRMED"
    else:
        verdict = "No usable Active Test results were produced."
        conclusion = "NOT CONFIRMED"
        best = "NOT CONFIRMED"
    return {
        "confirmation": best,
        "conclusion": conclusion,
        "verdict": verdict,
        "reflected": reflected,
        "encoded_hit": encoded_hit,
        "unencoded_hit": unencoded_hit,
        "db_error_signal": db_error,
        "auth_success": auth_ok,
        "evidence": evidence,
    }
