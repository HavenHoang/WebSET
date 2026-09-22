import json
import re
import time
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QLineEdit,
    QPushButton, QComboBox, QFrame, QStyleFactory, QListView, QSizePolicy,
    QScrollArea, QLayout, QLayoutItem
)
from PyQt6.QtCore import Qt, QTimer, QPoint, QRect, QSize
from PyQt6.QtGui import QPalette, QColor, QGuiApplication
from urllib.parse import urlparse, quote, unquote, urlencode
import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from payload_injection.library import (
    get_payloads,
    get_active_tests,
    ACTIVE_TEST_LIBRARY,
)
from payload_injection.active_test import plain_suite_analysis
from payload_injection.injector import send_payload
from payload_injection.request_builder import build_request_from_finding, with_form_controls
from payload_injection.http_client import send_once

_ACTIVE_TYPES = frozenset(set(ACTIVE_TEST_LIBRARY.keys()) | {"xxe", "nosqli"})
_VTYPE_PAYLOAD_LABEL = {
    "xss": "XSS",
    "sqli": "SQLi",
    "nosqli": "NoSQLi",
    "xxe": "XXE",
    "path_traversal": "Path Traversal",
    "command_injection": "Command Injection",
    "idor": "IDOR",
}
_SQLI_ERROR_SIGNS = [
    "sql syntax", "you have an error in your sql", "ora-", "syntax error",
    "unclosed quotation", "unterminated quoted", "missing quote",
    "sequelizedatabaseerror", "sequelize/lib", "dialects/sqlite",
    "sqlite/query", "at database", "database error", "sqlstate", "sql error",
    "sql exception", "query failed", "pdoexception", "pg_query",
    "mysql error", "mysql_fetch", "mysqli_sql_exception", "operationalerror",
]
_SQLI_LIVE_RE = re.compile(
    r"sql syntax|sqlstate|you have an error in your sql|"
    r"pdoexception|unclosed quotation|unterminated quoted|"
    r"mysqli_sql_exception|sequelize|dialects[/\\]sqlite|"
    r"sqlite[/\\]query|\bat\s+database\b|operationalerror",
    re.I,
)
_SQLI_CHROME_RE = re.compile(
    r"\bsqli\s*db\b|\bdbms\b|security level|"
    r"damn vulnerable|do not upload it to your hosting|"
    r"for the web server and database",
    re.I,
)
_PATH_TRAVERSAL_SIGNS = [
    "root:x:0:0", "root:x:", "root:*:", "[boot loader]", "etc/passwd",
    "[extensions]", "failed to open", "failed opening", "failed to include",
    "no such file", "open_basedir", "failed to open stream",
]
_CMD_INJECTION_SIGNS = ["uid=", "gid=", "root@", "directory of ", "volume in drive"]

POPUP_VIEW_QSS = """
QListView {
    background-color: #ffffff;
    border: 1px solid #94a3b8;
    outline: 0;
    padding: 2px;
}
QListView::item {
    min-height: 22px;
    max-height: 26px;
    padding: 3px 8px;
    color: #0f172a;
    background-color: #ffffff;
}
QListView::item:hover {
    background-color: #dbeafe;
    color: #0f172a;
}
QListView::item:selected {
    background-color: #bfdbfe;
    color: #0f172a;
}
QListView::item:selected:hover {
    background-color: #93c5fd;
    color: #0f172a;
}
"""
COMBO_QSS = """
QComboBox#payloadCombo {
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #94a3b8;
    border-radius: 8px;
    padding: 6px 10px;
    min-height: 32px;
    font-size: 13px;
}
QComboBox#payloadCombo:hover {
    border: 1px solid #1e3a8a;
}
QComboBox#payloadCombo::drop-down {
    border: none;
    width: 28px;
}
"""



class _ChipFlow(QLayout):
    """Wrap chips/badges so they do not overlap the next row."""

    def __init__(self, parent=None, h_spacing=8, v_spacing=6):
        super().__init__(parent)
        self._items: list[QLayoutItem] = []
        self._hs = h_spacing
        self._vs = v_spacing
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item):
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, index):
        if 0 <= index < len(self._items):
            return self._items[index]
        return None

    def takeAt(self, index):
        if 0 <= index < len(self._items):
            return self._items.pop(index)
        return None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self._do_layout(QRect(0, 0, width, 0), True)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._do_layout(rect, False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        w = h = 0
        for item in self._items:
            s = item.sizeHint()
            w = max(w, s.width())
            h = max(h, s.height())
        m = self.contentsMargins()
        return QSize(w + m.left() + m.right(), h + m.top() + m.bottom())

    def _do_layout(self, rect, test_only):
        x = rect.x()
        y = rect.y()
        line_h = 0
        right = rect.x() + rect.width()
        for item in self._items:
            sz = item.sizeHint()
            if x + sz.width() > right and line_h:
                x = rect.x()
                y += line_h + self._vs
                line_h = 0
            if not test_only:
                item.setGeometry(QRect(x, y, sz.width(), sz.height()))
            x += sz.width() + self._hs
            line_h = max(line_h, sz.height())
        return y + line_h - rect.y()


class ReadableCombo(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("payloadCombo")
        self.setStyle(QStyleFactory.create("Fusion"))
        self.setEditable(False)
        self.setMaxVisibleItems(8)
        self.setStyleSheet(COMBO_QSS)
        view = QListView(self)
        view.setUniformItemSizes(True)
        view.setSpacing(0)
        view.setStyleSheet(POPUP_VIEW_QSS)
        self.setView(view)
        self._apply_palette()

    def _apply_palette(self):
        pal = self.palette()
        pal.setColor(QPalette.ColorRole.Base, QColor("#ffffff"))
        pal.setColor(QPalette.ColorRole.Text, QColor("#0f172a"))
        pal.setColor(QPalette.ColorRole.WindowText, QColor("#0f172a"))
        pal.setColor(QPalette.ColorRole.Button, QColor("#ffffff"))
        pal.setColor(QPalette.ColorRole.ButtonText, QColor("#0f172a"))
        pal.setColor(QPalette.ColorRole.Highlight, QColor("#bfdbfe"))
        pal.setColor(QPalette.ColorRole.HighlightedText, QColor("#0f172a"))
        self.setPalette(pal)
        self.view().setPalette(pal)
        self.view().setStyleSheet(POPUP_VIEW_QSS)

    def showPopup(self):
        self._apply_palette()
        super().showPopup()
        try:
            view = self.view()
            view.setStyleSheet(POPUP_VIEW_QSS)
            view.setPalette(self.palette())
            popup = view.window()
            below = self.mapToGlobal(QPoint(0, self.height()))
            popup.move(below)
            view.setMinimumWidth(self.width())
        except Exception:
            pass


def _infer_vuln_type(finding: dict) -> str:
    v = str(finding.get("vuln_type") or finding.get("vulnerability_type") or "").lower().strip()
    name = str(finding.get("vulnerability") or finding.get("name") or "").lower()
    plugin = str(finding.get("plugin_id") or "").lower()
    if v in ("nosqli", "nosql") or plugin == "nosqli" or "nosql" in name:
        return "nosqli"
    if v == "xxe" or plugin == "xxe" or "external entity" in name or "xxe" in name:
        return "xxe"
    if (
        v in ("idor", "bola")
        or plugin == "idor-bola"
        or "insecure direct" in name
        or "broken object" in name
    ):
        return "idor"
    if v in _ACTIVE_TYPES:
        return v
    if "xss" in name or "cross-site" in name:
        return "xss"
    if "sql" in name and "injection" in name:
        return "sqli"
    if "sql injection" in name or name.strip() == "sqli":
        return "sqli"
    if "path" in name or "traversal" in name:
        return "path_traversal"
    if "file inclusion" in name or "lfi" in name or "rfi" in name:
        return "path_traversal"
    if "command" in name and "injection" in name:
        return "command_injection"
    return ""


def _finding_targets(finding: dict) -> list:
    raw = list((finding or {}).get("active_test_targets") or [])
    out = []
    seen = set()
    for t in raw:
        if not isinstance(t, dict):
            continue
        url = str(t.get("url") or t.get("endpoint") or "").strip()
        if not url:
            continue
        param = str(t.get("param") or t.get("input") or t.get("parameter") or "").strip()
        method = str(t.get("method") or "GET").upper() or "GET"
        key = (url, param, method)
        if key in seen:
            continue
        seen.add(key)
        item = dict(t)
        item["url"] = url
        item["endpoint"] = url
        item["param"] = param
        item["input"] = param
        item["method"] = method
        out.append(item)
    if out:
        vtype = _infer_vuln_type(finding or {})
        if vtype == "sqli":
            fileish = re.compile(
                r"^(page|doc|document|file|filename|filepath|path|include|dir|template)$",
                re.I,
            )
            filtered = []
            for item in out:
                if fileish.match(str(item.get("param") or "")):
                    continue
                path = urlparse(str(item.get("url") or "")).path.lower()
                if re.search(r"/(instructions?|help|docs?|about)(/|\\.php|\\.html|$)", path):
                    continue
                filtered.append(item)
            if filtered:
                out = filtered
        return out
    url = str(
        (finding or {}).get("url")
        or (finding or {}).get("endpoint")
        or str((finding or {}).get("location") or "").split("\n")[0]
        or ""
    ).strip()
    if not url:
        return []
    param = str(
        (finding or {}).get("param")
        or (finding or {}).get("input")
        or (finding or {}).get("parameter")
        or ""
    ).strip()
    return [{
        "url": url,
        "endpoint": url,
        "param": param,
        "input": param,
        "method": str((finding or {}).get("method") or "GET").upper() or "GET",
        "param_location": str(
            (finding or {}).get("param_location")
            or (finding or {}).get("input_location")
            or "query"
        ),
    }]


def _is_active_testable(finding: dict) -> bool:
    if not finding:
        return False
    if str(finding.get("scan_origin") or "") == "Platform":
        return False
    vtype = _infer_vuln_type(finding)
    if vtype not in _ACTIVE_TYPES:
        return False
    targets = _finding_targets(finding)
    if not targets:
        url = str(
            finding.get("url")
            or finding.get("endpoint")
            or str(finding.get("location") or "").split("\n")[0]
            or ""
        ).strip()
        if url:
            targets = [{"url": url}]
    if not targets:
        return False
    if vtype in {"xss", "sqli"}:
        return any(str(t.get("param") or "").strip() for t in targets)
    return True


def _parse_url_parts(url: str) -> tuple[str, str]:
    raw = (url or "").strip()
    if not raw:
        return "example.com", "/"
    if "://" not in raw:
        raw = "http://" + raw
    try:
        p = urlparse(raw)
        host = p.netloc or "example.com"
        path = p.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        return host, path
    except Exception:
        host = raw.replace("https://", "").replace("http://", "")
        host = host.split("/")[0].split("?")[0] or "example.com"
        return host, "/"


def _build_active_request(finding: dict, marker: str) -> str:
    finding = dict(finding or {})
    marker = str(marker or "")
    vtype = str(finding.get("vuln_type") or "").lower()
    loc = str(
        finding.get("param_location") or finding.get("input_location") or "query"
    ).lower()
    if vtype == "idor" or loc in ("header", "headers"):
        method = str(finding.get("method") or "GET").upper()
        url = str(
            finding.get("url")
            or finding.get("endpoint")
            or finding.get("location")
            or ""
        )
        host, path = _parse_url_parts(url)
        raw = url if "://" in (url or "") else ("http://" + (url or ""))
        query = ""
        try:
            query = urlparse(raw).query or ""
        except Exception:
            query = ""
        target = path + (("?" + query) if query else "")
        return (
            f"{method} {target} HTTP/1.1\n"
            f"Host: {host}\n"
            f"Accept: application/json\n"
            f"User-Agent: WebSET-ActiveTest\n"
            f"Connection: close\n\n"
        )
    if vtype in ("command_injection", "cmdi", "cmd") and marker[:1] in ";|&":
        base = str(
            finding.get("original_value")
            or finding.get("sample_value")
            or finding.get("param_value")
            or ""
        ).strip() or "localhost"
        marker = base + marker
    try:
        text = build_request_from_finding(finding, marker)
        if text and str(text).strip():
            return str(text)
    except Exception:
        pass
    method = str(finding.get("method") or "GET").upper()
    url = str(
        finding.get("url")
        or finding.get("endpoint")
        or finding.get("location")
        or ""
    )
    param = str(
        finding.get("param")
        or finding.get("input")
        or finding.get("parameter")
        or "q"
    )
    loc = str(
        finding.get("param_location") or finding.get("input_location") or "query"
    ).lower()
    host, path = _parse_url_parts(url)
    encoded = quote(marker, safe="")
    if method == "GET" or (loc in ("query", "url", "get") and method not in ("POST", "PUT", "PATCH")):
        fields = with_form_controls({param: marker}, param)
        return (
            f"{method} {path}?{urlencode(fields)} HTTP/1.1\n"
            f"Host: {host}\n"
            f"User-Agent: WebSET-ActiveTest\n"
            f"Connection: close\n\n"
        )
    if loc in ("json", "body_json"):
        body = f'{{"{param}": "{marker}"}}'
        return (
            f"{method} {path} HTTP/1.1\n"
            f"Host: {host}\n"
            f"Content-Type: application/json\n"
            f"User-Agent: WebSET-ActiveTest\n"
            f"Connection: close\n"
            f"Content-Length: {len(body)}\n\n"
            f"{body}"
        )
    body = f"{param}={encoded}&Submit=Submit&submit=Submit"
    return (
        f"{method} {path} HTTP/1.1\n"
        f"Host: {host}\n"
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"User-Agent: WebSET-ActiveTest\n"
        f"Content-Length: {len(body)}\n\n"
        f"{body}"
    )


def _json_login_token(target_url: str) -> str:
    raw = str(target_url or "")
    if raw and "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    if not parsed.scheme or not parsed.netloc:
        return ""
    origin = f"{parsed.scheme}://{parsed.netloc}"
    paths = (
        "/rest/user/login",
        "/api/login",
        "/api/auth/login",
        "/login",
        "/auth/login",
        "/user/login",
    )
    tauts = (
        "' OR true-- ",
        "' OR '1'='1'-- ",
        "' OR 1=1-- ",
        "' OR true--",
        "' OR '1'='1'--",
        "' OR 1=1--",
    )
    fields = ("email", "username", "user", "login")
    for path in paths:
        for field in fields:
            for taut in tauts:
                resp = send_once(
                    method="POST",
                    url=origin + path,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "WebSET-ActiveTest",
                    },
                    data=json.dumps({field: taut, "password": "webset"}),
                )
                text = str((resp or {}).get("body") or "")
                try:
                    data = json.loads(text)
                except Exception:
                    continue
                if not isinstance(data, dict):
                    continue
                blob = data.get("authentication") if isinstance(data.get("authentication"), dict) else data
                if not isinstance(blob, dict):
                    continue
                for key in ("token", "access_token", "accessToken", "jwt"):
                    if blob.get(key):
                        return str(blob.get(key))
    nonce = str(abs(hash(origin)) % 10 ** 10)
    email = "webset" + nonce + "@example.com"
    password = "WebsetPass1!"
    register_body = json.dumps({
        "email": email,
        "password": password,
        "username": "webset" + nonce,
        "user": email,
    })
    for path in (
        "/api/users",
        "/api/Users",
        "/api/user",
        "/api/register",
        "/register",
        "/signup",
        "/api/signup",
        "/api/accounts",
        "/api/Accounts",
    ):
        resp = send_once(
            method="POST",
            url=origin + path,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "WebSET-ActiveTest",
            },
            data=register_body,
        )
        if int((resp or {}).get("status") or 0) not in (200, 201):
            continue
        text = str((resp or {}).get("body") or "")
        try:
            data = json.loads(text)
        except Exception:
            data = None
        if isinstance(data, dict):
            blob = data.get("authentication") if isinstance(data.get("authentication"), dict) else data
            if isinstance(blob, dict):
                for key in ("token", "access_token", "accessToken", "jwt"):
                    if blob.get(key):
                        return str(blob.get(key))
        for field in ("email", "username"):
            for login_path in paths:
                resp = send_once(
                    method="POST",
                    url=origin + login_path,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "WebSET-ActiveTest",
                    },
                    data=json.dumps({field: email, "password": password}),
                )
                text = str((resp or {}).get("body") or "")
                try:
                    data = json.loads(text)
                except Exception:
                    continue
                if not isinstance(data, dict):
                    continue
                blob = data.get("authentication") if isinstance(data.get("authentication"), dict) else data
                if not isinstance(blob, dict):
                    continue
                for key in ("token", "access_token", "accessToken", "jwt"):
                    if blob.get(key):
                        return str(blob.get(key))
    return ""


def _with_bearer(request_text: str, token: str) -> str:
    if not token or not request_text:
        return request_text
    if re.search(r"(?im)^authorization:", request_text):
        return request_text
    if "\n\n" in request_text:
        head, rest = request_text.split("\n\n", 1)
        return head + f"\nAuthorization: Bearer {token}\n\n" + rest
    return request_text.rstrip() + f"\nAuthorization: Bearer {token}\n\n"


def _extract_status_code(response_text: str) -> str:
    """Best-effort HTTP status-code extraction from a raw response blob."""
    if not response_text:
        return "—"
    for line in response_text.splitlines():
        low = line.lower().strip()
        if low.startswith("http status") or (
            low.startswith("status") and ":" in line and not low.startswith("status bar")
        ):
            rest = line.split(":", 1)[-1].strip()
            m = re.search(r"\b(\d{3})\b", rest)
            if m:
                return m.group(1)
        m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", line)
        if m:
            return m.group(1)
    m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", response_text)
    if m:
        return m.group(1)
    return "—"




def _field_from_blob(text: str, names: tuple[str, ...]) -> str:
    """Read a labelled field from injector / active_test output."""
    if not text:
        return ""
    lines = (text or "").splitlines()
    wanted = {n.lower() for n in names}
    evidence_keys = {"evidence", "evidence snippet"}
    for i, line in enumerate(lines):
        raw = line.strip()
        if ":" not in raw:
            continue
        key, val = raw.split(":", 1)
        key_l = key.strip().lower()
        if key_l not in wanted:
            continue
        collected = val.strip()
        extra = []
        k = i + 1
        blank_run = 0
        while k < len(lines):
            nxt = lines[k]
            raw_nxt = nxt.strip()
            if raw_nxt.startswith("-----"):
                break
            if (
                raw_nxt
                and ":" in raw_nxt
                and re.match(r"^[A-Za-z][A-Za-z0-9 /_-]*\s*:", raw_nxt)
                and not re.match(
                    r"^(warning|notice|fatal error|parse error|error|include|"
                    r"failed|deprecated)\b",
                    raw_nxt,
                    re.I,
                )
            ):
                break
            # Do not abort evidence on a blank line or a leftover heading
            # fragment — those used to hide the probe that sits on the next line.
            if key_l in evidence_keys and raw_nxt and _looks_page_heading(raw_nxt):
                k += 1
                continue
            if not raw_nxt:
                blank_run += 1
                if blank_run >= 2:
                    break
                extra.append("")
            else:
                blank_run = 0
                extra.append(nxt.rstrip())
            k += 1
        if extra:
            collected = (collected + "\n" + "\n".join(extra)).rstrip()
        if key_l in evidence_keys:
            collected = _clean_evidence_text(collected)
        return collected
    return ""


def _backend_meaning(response_text: str) -> str:
    """GUI display only — text is owned by payload_injection.injector / active_test."""
    conclusion = _field_from_blob(response_text, ("conclusion",))
    detail = _field_from_blob(response_text, ("detail",))
    parts = [p for p in (conclusion, detail) if p and p not in ("—", "-", "–")]
    return "\n\n".join(parts)


def _meaning_for_result(response_text: str, result: dict, vtype: str = "") -> str:
    """Prefer the classified verdict over a stale injector conclusion."""
    level = str((result or {}).get("level") or "").lower()
    confirmed = bool((result or {}).get("confirmed"))
    signal = str((result or {}).get("signal") or "")
    expect = str((result or {}).get("expect") or "").lower()
    raw = _backend_meaning(response_text)
    if vtype == "idor":
        if confirmed or level == "confirmed":
            if expect == "idor_denied":
                return (
                    "Collection leaked users without a bearer token\n\n"
                    "An unauthenticated GET already returned more than one user identity."
                )
            return (
                "Authenticated session read other users' records\n\n"
                "The Bearer GET returned JSON with more than one user identity. "
                "The server is not enforcing object-level authorisation on this collection."
            )
        if level == "likely":
            return (
                "Collection requires authentication\n\n"
                "Unauthenticated GET was denied (401/403). That is reachability, not a dump. "
                "The bearer step is the exploit check."
            )
    if vtype == "sqli" and expect == "auth_success":
        if confirmed or level == "confirmed":
            return raw or (
                "Login succeeded with a crafted SQL value\n\n"
                "The login check accepted the tautology without a valid password."
            )
        if _SQLI_LIVE_RE.search(response_text or ""):
            return (
                "The tautology broke the query — login did not succeed\n\n"
                "A database / ORM error after the authentication probe means the "
                "field reaches SQL. This step is only confirmed when the response "
                "is a session token, user object, or a logged-in page — not an error page."
            )
        return (
            "Authentication bypass not confirmed\n\n"
            "No session token, user object, or logged-in page after the tautology."
        )
    if confirmed or level == "confirmed":
        return raw
    if level == "likely":
        if vtype == "sqli":
            blob = response_text or ""
            if _SQLI_LIVE_RE.search(blob):
                return (
                    "The field broke the database query\n\n"
                    "The response includes a database / ORM stack after the probe. "
                    "That is a live query error, not generic page copy."
                )
            return (
                "The server errored after this SQL probe\n\n"
                "HTTP 5xx without an explicit database / ORM error string. "
                "That is a weaker signal than a SQL error — the field may have "
                "reached a query, but this step is not exploit proof."
            )
        return raw
    if "page copy mentioned a database" in signal.lower():
        return (
            "Documentation mentioned a database — not a live SQL error\n\n"
            "The response is help or setup copy that talks about a database. "
            "That is not proof the probe broke a query."
        )
    if vtype == "sqli":
        return (
            "SQL injection not confirmed by this probe\n\n"
            "No live SQL / ORM error and no authentication bypass after the probe."
        )
    if vtype == "idor":
        if expect == "idor_dump":
            return (
                "Authenticated collection did not dump other users\n\n"
                "The Bearer GET did not return JSON with more than one user identity."
            )
        if expect == "idor_denied":
            return (
                "Unauthenticated collection did not leak users\n\n"
                "No user dump without a token. A 401/403 here only means the route is gated."
            )
        return (
            "IDOR not confirmed by this probe\n\n"
            "The collection GET did not return multiple user identities."
        )
    return raw or signal


def _yes(value: str) -> bool:
    return str(value or "").strip().lower() in ("yes", "y", "true", "1")


def _response_body_only(response_text: str) -> str:
    text = response_text or ""
    marker = "----- Response body"
    idx = text.find(marker)
    if idx >= 0:
        return text[idx:]
    return text


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
        if len(re.sub(r"[\s\{\}:;#+\.*\-]", "", t)) < 24:
            return True
    return False


def _error_lines_from_text(body: str, limit: int = 700) -> str:
    raw = body or ""
    raw = raw.replace("&lt;", "<").replace("&gt;", ">").replace("&nbsp;", " ")
    raw = raw.replace("&quot;", '"').replace("&#39;", "'")
    plain = re.sub(r"<style\b[^>]*>.*?</style>", " ", raw, flags=re.I | re.S)
    plain = re.sub(r"<script\b[^>]*>.*?</script>", " ", plain, flags=re.I | re.S)
    plain = re.sub(r"<[^>]+>", " ", plain)
    lines = [ln.strip() for ln in plain.splitlines() if ln.strip()]
    picked = []
    for i, ln in enumerate(lines):
        if _looks_css_noise(ln):
            continue
        if re.search(
            r"(\berror\b|\bexception\b|\bsqlstate\b|\bdatabase\b|sqlite_|syntax error|\borm\b|"
            r"unclosed quotation|unterminated|missing quote|sequelize|"
            r"dialects[/\\]sqlite|sqlite[/\\]query)",
            ln,
            re.I,
        ) or re.match(r"^\s*at\s+\S", ln, re.I):
            if re.search(r"cannot modify header|headers already sent", ln, re.I):
                continue
            for piece in lines[max(0, i - 1): min(len(lines), i + 3)]:
                if _looks_css_noise(piece):
                    continue
                if piece not in picked:
                    picked.append(piece)
        if len("\n".join(picked)) >= limit:
            break
    text = "\n".join(picked).strip()
    if not text or _looks_css_noise(text):
        return ""
    if len(re.sub(r"[.\u2026…\s]+", "", text)) < 3:
        return ""
    return text[:limit]

def _looks_page_heading(line: str) -> bool:
    t = (line or "").strip()
    if not t:
        return False
    low = t.lower()
    if re.search(
        r"(<\s*script\b|<\s*iframe\b|<\s*svg\b|<\s*img\b|onerror\s*=|javascript:|"
        r"webset_|uid=|gid=|root:x:|<!doctype|<!entity|file://)",
        t,
        re.I,
    ):
        return False
    if re.search(r"</h[1-6]\s*>|<\s*h[1-6]\b|</title\s*>|<\s*title\b", t, re.I):
        if not re.search(r"[<>].*[<>].*(script|iframe|onerror|alert\s*\()", t, re.I):
            return True
    if re.match(
        r"^(more information|more info|see also|references|documentation|"
        r"helpful links|related links)$",
        t,
        re.I,
    ):
        return True
    if low.startswith("http://") or low.startswith("https://"):
        return True
    if re.search(
        r"(quote|error|exception|warning|failed|include|sql|denied|undefined|"
        r"unterminated|syntax|stream|fatal|webset_)",
        t,
        re.I,
    ):
        return False
    words = t.split()
    if 1 <= len(words) <= 4 and "=" not in t and "webset_" not in low and "<" not in t:
        if t[:1].isupper() and not any(ch.isdigit() for ch in t):
            if not re.search(r"uid=|gid=|rtt min|packets transmitted", t, re.I):
                return True
    return False


def _clean_evidence_text(text: str) -> str:
    kept = []
    for ln in (text or "").splitlines():
        s = ln.strip()
        if not s or _looks_page_heading(s) or _looks_css_noise(s):
            continue
        if re.match(r"^(warning!|damn vulnerable|do not upload it to your hosting)", s, re.I):
            continue
        kept.append(s)
    return "\n".join(kept).strip()


def _usable_evidence(text: str) -> bool:
    t = (text or "").strip()
    if len(t) < 3:
        return False
    if re.match(r"^[.\u2026…\s\-]+$", t):
        return False
    if _looks_css_noise(t):
        return False
    core = re.sub(r"[.\u2026…\s]+", "", t)
    return len(core) >= 3


def _json_or_body_snippet(body: str, limit: int = 700) -> str:
    s = (body or "").lstrip()
    if s.startswith("{") or s.startswith("["):
        try:
            import json
            pretty = json.dumps(json.loads(s), ensure_ascii=False, indent=2)
            return pretty[:limit]
        except Exception:
            return s[:limit]
    text = re.sub(r"[ \t]+\n", "\n", s)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text[:limit]


def _probe_variants(probe: str) -> list[str]:
    out = []
    seen = set()
    def add(s):
        s = str(s or "").strip()
        if not s:
            return
        key = s.lower()
        if key in seen:
            return
        seen.add(key)
        out.append(s)
    add(probe)
    try:
        add(unquote(probe or ""))
        add(unquote(unquote(probe or "")))
    except Exception:
        pass
    return out


def _window_around_body(body: str, needle: str, keep_markup: bool = False, radius: int = 280) -> str:
    if not body or not needle:
        return ""
    low = body.lower()
    idx = -1
    matched = needle
    for variant in _probe_variants(needle):
        pos = low.find(variant.lower())
        if pos >= 0:
            idx = pos
            matched = variant
            break
    if idx < 0:
        return ""
    start = max(0, idx - radius)
    end = min(len(body), idx + max(len(matched), 1) + radius)
    # Snap to a tag or line start so the box does not open mid-heading.
    cut = body.rfind("\n", start, idx)
    if cut >= start:
        start = cut + 1
    else:
        tag = body.rfind("<", start, idx)
        if tag >= start:
            start = tag
    nxt = body.find("\n", idx + len(matched), end)
    if nxt >= 0:
        end = max(end, min(len(body), nxt))
    chunk = body[start:end].strip()
    if not keep_markup:
        chunk = re.sub(r"<[^>]+>", " ", chunk)
    chunk = _clean_evidence_text(chunk)
    return chunk if _usable_evidence(chunk) else ""


def _evidence_matches_probe(evidence: str, probe: str, vtype: str) -> bool:
    if not _usable_evidence(evidence):
        return False
    if not probe or len(probe) < 3:
        return True
    if vtype == "sqli" and len(probe) <= 3:
        return True
    low = evidence.lower()
    for variant in _probe_variants(probe):
        if variant and variant.lower() in low:
            return True
    return False


def _php_include_warnings(blob: str) -> str:
    raw = (blob or "").replace("&lt;", "<").replace("&gt;", ">").replace("&nbsp;", " ")
    raw = re.sub(r"<br\s*/?>", "\n", raw, flags=re.I)
    raw = re.sub(r"<[^>]+>", " ", raw)
    raw = re.sub(r"[ \t]+", " ", raw)
    hits = []
    for m in re.finditer(
        r"(?:Warning|Notice|Fatal error|Parse error)\s*:\s*.{0,400}?on line\s+\d+",
        raw,
        flags=re.I | re.S,
    ):
        line = re.sub(r"\s+", " ", m.group(0)).strip()
        if re.search(r"cannot modify header|headers already sent", line, re.I):
            continue
        if line not in hits:
            hits.append(line)
        if len(hits) >= 3:
            break
    return "\n".join(hits).strip()


def _evidence_from_blob(text: str, vtype: str = "", marker: str = "") -> str:
    probe = (marker or "").strip() or _field_from_blob(
        text, ("probe / marker", "probe", "marker / input")
    )
    labeled = _field_from_blob(text, ("evidence", "evidence snippet"))
    labeled = _clean_evidence_text(labeled)
    body = _response_body_only(text or "")
    if body.startswith("-----"):
        body = body.split("\n", 1)[-1] if "\n" in body else ""
    vt = (vtype or "").lower()

    def _xxe_from_html(blob: str) -> str:
        raw = (blob or "").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
        raw = raw.replace("&nbsp;", " ").replace("&#39;", "'")
        parts = []
        for rx in (
            r"<title[^>]*>(.*?)</title>",
            r"<h[12][^>]*>(.*?)</h[12]>",
        ):
            for block in re.findall(rx, raw, flags=re.I | re.S):
                plain = re.sub(r"<[^>]+>", " ", block)
                plain = re.sub(r"\s+", " ", plain).strip()
                if not plain:
                    continue
                low = re.sub(r"\s+", " ", plain.lower())
                if any(low in re.sub(r"\s+", " ", x.lower()) or re.sub(r"\s+", " ", x.lower()) in low for x in parts):
                    continue
                parts.append(plain)
        text_out = "\n".join(parts).strip()
        if text_out:
            return text_out[:2400]
        return ""

    if vt == "path_traversal":
        fs = _php_include_warnings(body) or _php_include_warnings(text or "")
        if _usable_evidence(fs):
            return fs[:2400]
    if vt == "xxe":
        xxe_ev = _xxe_from_html(body) or _xxe_from_html(text or "")
        if _usable_evidence(xxe_ev):
            return xxe_ev
    if (
        _usable_evidence(labeled)
        and labeled not in ("—", "-", "–")
        and not re.match(
            r"^(</?html|^</?head|^</?body|^<s$|ies/|on line \d+$)",
            labeled.strip(),
            re.I,
        )
        and _evidence_matches_probe(labeled, probe, vtype)
    ):
        return labeled
    keep_markup = vt == "xss"
    if vt in ("sqli", "path_traversal", "xxe"):
        err = _error_lines_from_text(body)
        if _usable_evidence(err) and not re.match(
            r"^(ies/|/var/www|on line \d+$)", err.strip(), re.I
        ):
            return err
    if probe and len(probe) >= 3:
        hit = _window_around_body(body, probe, keep_markup=keep_markup)
        if _usable_evidence(hit):
            return hit[:2400]
    if vt == "sqli":
        err = _error_lines_from_text(body)
        if _usable_evidence(err):
            return err
    needles = []
    if vt == "command_injection":
        needles = list(_CMD_INJECTION_SIGNS) + [
            "webset_cmd", "webset_canary", "webset_cmd_ok", "rtt min",
        ]
    elif vt == "sqli":
        needles = list(_SQLI_ERROR_SIGNS)
    elif vt == "path_traversal":
        needles = list(_PATH_TRAVERSAL_SIGNS) + ["root:x:", "root:*:"]
    # XSS: never search generic javascript:/<script across the whole page —
    # that hits site chrome (theme toggles, first <script> in <head>).
    # The probe window above is the only XSS locator.
    low = body.lower()
    for needle in sorted(needles, key=len, reverse=True):
        idx = low.find(needle.lower())
        if idx < 0:
            continue
        start = max(0, idx - 80)
        end = min(len(body), idx + max(len(needle), 12) + 160)
        chunk = body[start:end].strip()
        if vt != "xss":
            chunk = re.sub(r"<[^>]+>", " ", chunk)
        chunk = _clean_evidence_text(chunk)
        if _usable_evidence(chunk):
            return chunk[:2400]
    if vt == "sqli":
        err = _error_lines_from_text(body)
        if _usable_evidence(err):
            return err
    if _usable_evidence(labeled) and labeled not in ("—", "-", "–"):
        return labeled
    fallback = _clean_evidence_text(_json_or_body_snippet(body))
    return fallback if _usable_evidence(fallback) else ""


def _idor_dump_from_text(text: str) -> tuple[bool, str]:
    raw = (text or "").strip()

    def _idents_from_data(data) -> list:
        rows = []
        if isinstance(data, list):
            rows = [x for x in data if isinstance(x, dict)]
        elif isinstance(data, dict):
            for key in (
                "data", "users", "accounts", "members", "results",
                "items", "rows", "records",
            ):
                val = data.get(key)
                if isinstance(val, list):
                    rows = [x for x in val if isinstance(x, dict)]
                    break
            if not rows and isinstance(data.get("data"), dict):
                nested = data.get("data")
                for key in (
                    "users", "accounts", "members", "results",
                    "items", "rows", "records",
                ):
                    val = nested.get(key)
                    if isinstance(val, list):
                        rows = [x for x in val if isinstance(x, dict)]
                        break
        user_fields = {
            "email", "username", "user_name", "role", "roles", "isadmin",
            "is_admin", "password", "passwd", "hash", "account",
        }
        idents = []
        for rec in rows:
            lowered = {str(k).lower(): v for k, v in rec.items()}
            if not set(lowered).intersection(user_fields):
                continue
            ident = ""
            for key in ("email", "username", "user_name", "userid", "user_id", "id"):
                val = lowered.get(key)
                if val not in (None, ""):
                    ident = str(val)
                    break
            if ident and ident not in idents:
                idents.append(ident)
        return idents

    def _try_json(blob: str):
        blob = (blob or "").strip()
        if not blob or blob[0] not in "{[":
            return None
        try:
            return json.loads(blob)
        except Exception:
            pass
        trimmed = re.sub(r",\s*$", "", blob.rstrip())
        for _ in range(8):
            try:
                return json.loads(trimmed)
            except Exception:
                if trimmed.count("{") > trimmed.count("}"):
                    trimmed += "}"
                elif trimmed.count("[") > trimmed.count("]"):
                    trimmed += "]"
                else:
                    break
        return None

    start = raw.find("{")
    alt = raw.find("[")
    if start >= 0 or alt >= 0:
        if start < 0:
            idx = alt
        elif alt < 0:
            idx = start
        else:
            idx = min(start, alt)
        data = _try_json(raw[idx:])
        if data is not None:
            idents = _idents_from_data(data)
            if len(idents) >= 2:
                return True, ", ".join(idents[:3])

    emails = []
    for m in re.finditer(r'(?i)"email"\s*:\s*"([^"]+)"', raw):
        val = (m.group(1) or "").strip()
        if val and val not in emails:
            emails.append(val)
    if len(emails) >= 2:
        return True, ", ".join(emails[:3])
    names = []
    for m in re.finditer(r'(?i)"(?:username|user_name)"\s*:\s*"([^"]+)"', raw):
        val = (m.group(1) or "").strip()
        if val and val not in names:
            names.append(val)
    if len(names) >= 2:
        return True, ", ".join(names[:3])
    return False, ""


def _classify_test_result(vtype: str, request_text: str, response_text: str, test: dict) -> dict:
    """Use injector detection flags. Do not treat a reflected probe as confirmation."""
    text = response_text or ""
    body = _response_body_only(text)
    body_lower = body.lower()
    status_code = _extract_status_code(text)
    found = _field_from_blob(text, ("found in body",))
    encoded = _field_from_blob(text, ("encoded",))
    db_err = _field_from_blob(text, ("db error signal",))
    auth = _field_from_blob(text, ("auth success",))
    confirmation = str(_field_from_blob(text, ("confirmation",))).strip().upper()
    expect = str((test or {}).get("expect") or "").lower()
    probe = _field_from_blob(text, ("probe / marker", "probe", "marker / input")) or str(
        (test or {}).get("marker") or ""
    )
    confirmed = False
    level = "none"
    signal = "No signal detected"
    if vtype == "sqli":
        body_for_sql = body or text or ""
        chrome_only = bool(_SQLI_CHROME_RE.search(body_for_sql)) and not any(
            s in body_for_sql.lower() for s in (
                "sql syntax", "sqlstate", "you have an error in your sql",
                "pdoexception", "unclosed quotation", "unterminated quoted",
                "mysqli_sql_exception",
            )
        )
        live_stack = bool(_SQLI_LIVE_RE.search(body_for_sql))
        if chrome_only and not live_stack:
            confirmed = False
            signal = "Page copy mentioned a database — not a SQL error"
        elif live_stack:
            confirmed = True
            signal = "Database / ORM error detected"
        elif _yes(db_err) and not chrome_only:
            confirmed = True
            signal = "Database error detected"
        elif _yes(auth):
            confirmed = True
            signal = "Login succeeded without a valid password"
        else:
            for sign in _SQLI_ERROR_SIGNS:
                if sign in body_lower and not _SQLI_CHROME_RE.search(body_lower):
                    # Bare engine names in chrome ("SQLi DB: mysql") are not errors.
                    if sign in ("mysql", "sqlite", "odbc") and "error" not in body_lower and "exception" not in body_lower:
                        continue
                    confirmed = True
                    signal = "Database error detected"
                    break
            if any(s in body_lower for s in (
                "failed to open stream", "failed opening", "failed to include",
                "no such file or directory",
            )) and "sql syntax" not in body_lower and "sqlstate" not in body_lower:
                confirmed = False
                if confirmation != "CONFIRMED":
                    signal = "Filesystem include error — not a SQL error"
            if not confirmed and (
                '"token"' in body_lower
                or '"authentication"' in body_lower
                or "session token" in body_lower
            ):
                confirmed = True
                signal = "Login succeeded without a valid password"
    elif vtype == "nosqli":
        if confirmation == "CONFIRMED":
            confirmed = True
            signal = "Document operator leaked or wrote records"
        elif confirmation == "LIKELY":
            signal = "Operator echoed — not a record dump"
        elif str(status_code) == "401":
            signal = "Endpoint required authentication"
    elif vtype == "xxe":
        if confirmation == "CONFIRMED":
            confirmed = True
            signal = "XML entity returned local file or parser fault"
        elif any(tok in (body or text or "") for tok in ("root:x:", "root:*:", "[boot loader]")):
            confirmed = True
            signal = "Local file signature in XML response"
        elif str(status_code) in ("404", "405"):
            signal = "Path not found — use the URL from the finding"
        elif confirmation == "LIKELY":
            signal = "XML upload parsed (deprecated / parser fault)"
        elif str(status_code) == "500":
            signal = "Server error — no XML parser signature"
    elif vtype == "xss":
        if _yes(found) and not _yes(encoded):
            signal = "Probe reflected unencoded"
        elif _yes(found) and _yes(encoded):
            signal = "Probe reflected encoded"
    elif vtype == "path_traversal":
        for sign in ("root:x:", "root:*:", "[boot loader]", "for 16-bit app support"):
            if sign in body_lower:
                confirmed = True
                signal = "File contents disclosed"
                break
        if not confirmed and _yes(found):
            signal = "Probe reflected — not distinctive"
    elif vtype == "command_injection":
        for sign in _CMD_INJECTION_SIGNS:
            if sign in body_lower:
                confirmed = True
                signal = "Command output returned"
                break
        if not confirmed and _yes(found):
            signal = "Probe reflected — not distinctive"
    if confirmation == "NOT CONFIRMED":
        confirmed = False
        level = "none"
        if "disclosed" in signal.lower() or "output returned" in signal.lower():
            signal = "Probe reflected — not distinctive"
    elif confirmation == "LIKELY":
        confirmed = False
        level = "likely"
        if vtype == "xss":
            signal = "Probe reflected — not exploit proof"
        elif vtype == "sqli":
            if _yes(db_err):
                signal = "Database error detected"
            elif str(status_code).isdigit() and int(status_code) >= 500:
                signal = "Server error after SQL probe"
            elif signal == "No signal detected":
                signal = "Likely — incomplete SQL proof"
        elif vtype == "path_traversal":
            if signal == "No signal detected" or "not distinctive" in signal.lower():
                low_blob = (body or text or "").lower()
                if any(s in low_blob for s in ("failed to open", "failed opening", "no such file", "open_basedir")):
                    signal = "Filesystem error — file not disclosed"
                else:
                    signal = "Probe reflected — not distinctive"
        elif signal == "No signal detected":
            signal = "Likely — weak / non-distinctive signal"
    elif confirmation == "CONFIRMED" or confirmed:
        confirmed = True
        level = "confirmed"
    if vtype == "sqli" and confirmed:
        blob = (body or text or "")
        if _SQLI_CHROME_RE.search(blob) and not _SQLI_LIVE_RE.search(blob):
            confirmed = False
            level = "none"
            signal = "Page copy mentioned a database — not a SQL error"
    if expect == "auth_success":
        if _yes(auth):
            confirmed = True
            level = "confirmed"
            signal = "Login succeeded without a valid password"
        else:
            confirmed = False
            level = "none"
            blob = body or text or ""
            if _yes(db_err) or _SQLI_LIVE_RE.search(blob):
                signal = "Query broke — login did not succeed"
            else:
                signal = "Authentication bypass not confirmed"
    if vtype == "idor":
        dump, _ev = _idor_dump_from_text(body or text or "")
        if expect == "idor_dump":
            if dump:
                confirmed = True
                level = "confirmed"
                signal = "Collection returned multiple user identities"
            else:
                confirmed = False
                level = "none"
                signal = "Authenticated collection did not dump other users"
        elif expect == "idor_denied":
            if dump:
                confirmed = True
                level = "confirmed"
                signal = "Collection leaked users without a bearer token"
            elif str(status_code) in ("401", "403"):
                confirmed = False
                level = "likely"
                signal = "Unauthenticated request was denied"
            else:
                confirmed = False
                level = "none"
                signal = "Unauthenticated probe did not dump users"
        elif dump:
            confirmed = True
            level = "confirmed"
            signal = "Collection returned multiple user identities"
    return {
        "confirmed": confirmed,
        "level": level,
        "status_code": status_code,
        "signal": signal,
        "evidence": _evidence_from_blob(text, vtype, probe),
        "expect": expect,
    }


def _tests_for_finding(finding: dict, vtype: str) -> list:
    """GUI display only — library chooses which checks to run."""
    return list(get_active_tests(vtype, finding) or [])


def _detection_from_blob(text: str) -> dict:
    """Map injector / active_test flags into the dict plain_suite_analysis expects."""
    return {
        "found_in_body": _yes(_field_from_blob(text, ("found in body",))),
        "encoded": _yes(_field_from_blob(text, ("encoded",))),
        "db_error_signal": _yes(_field_from_blob(text, ("db error signal",))),
        "auth_success": _yes(_field_from_blob(text, ("auth success",))),
        "confidence": _field_from_blob(text, ("confidence",)),
        "conclusion": _field_from_blob(text, ("conclusion",)),
        "confirmation": _field_from_blob(text, ("confirmation",)),
    }


def _runs_for_suite(results: list) -> list:
    runs = []
    for test, _req, res_text, verdict in results:
        blob = res_text or ""
        err = blob.startswith("[Error]")
        runs.append({
            "test": test or {},
            "detection": {} if err else _detection_from_blob(blob),
            "status": (verdict or {}).get("status_code") or _extract_status_code(blob),
            "error": blob[8:].strip() if err else None,
            "text": blob,
        })
    return runs


def _request_display(request_text: str, response_text: str, test: dict) -> str:
    raw = (request_text or "").rstrip()
    probe = _field_from_blob(response_text, ("probe / marker", "probe", "marker / input"))
    if not probe:
        probe = str((test or {}).get("marker") or "").strip()
    sent = _field_from_blob(response_text, ("sent to",))
    method = _field_from_blob(response_text, ("method",))
    extra = []
    if method:
        extra.append(f"Method         : {method}")
    if sent:
        extra.append(f"Sent to        : {sent}")
    extra.append(f"Probe / marker : {probe or '—'}")
    if not raw:
        return "\n".join(extra)
    return raw + "\n\n" + "\n".join(extra)


class TestResultCard(QFrame):
    """One collapsible evidence card per Active Test check."""

    def __init__(self, index: int, test: dict, request_text: str,
                 response_text: str, result: dict, vtype: str = "", parent=None):
        super().__init__(parent)
        self._request_text = request_text or ""
        self._response_text = response_text or "(no response)"
        self._detail_edits = []
        self.setObjectName("testResultCard")
        level = str(result.get("level") or "").lower()
        if not level:
            level = "confirmed" if result.get("confirmed") else "none"
        if level == "confirmed":
            badge_txt, border, icon, icon_color = "CONFIRMED", "#99f6e4", "✓", "#0f766e"
            badge_bg, badge_fg = "#ccfbf1", "#0f766e"
        elif level == "likely":
            badge_txt, border, icon, icon_color = "LIKELY", "#fde68a", "◐", "#92400e"
            badge_bg, badge_fg = "#fef3c7", "#92400e"
        else:
            badge_txt, border, icon, icon_color = "NOT CONFIRMED", "#e2e8f0", "○", "#94a3b8"
            badge_bg, badge_fg = "#f1f5f9", "#64748b"
        self.setStyleSheet(f"""
            QFrame#testResultCard {{
                background: #ffffff;
                border: 1px solid {border};
                border-radius: 12px;
            }}
            QFrame#testResultCard QLabel {{ background: transparent; border: none; }}
        """)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 10)
        outer.setSpacing(6)
        top = QHBoxLayout()
        title = test.get("label") or test.get("id") or f"Check {index}"
        name_lab = QLabel(f"{icon}  {title}")
        name_lab.setStyleSheet(f"font-size: 13px; font-weight: 800; color: {icon_color}; border: none;")
        top.addWidget(name_lab)
        top.addStretch()
        badge = QLabel(badge_txt)
        badge.setStyleSheet(f"""
            background: {badge_bg};
            color: {badge_fg};
            border: none;
            border-radius: 8px;
            padding: 2px 10px;
            font-size: 10.5px;
            font-weight: 800;
        """)
        top.addWidget(badge)
        outer.addLayout(top)
        first_line = self._request_text.splitlines()[0] if self._request_text else "—"
        preview = QLabel(f"{first_line}   →   {result.get('status_code', '—')} · {result.get('signal', '')}")
        preview.setWordWrap(True)
        preview.setStyleSheet("font-size: 11.5px; color: #64748b; font-weight: 600; border: none;")
        outer.addWidget(preview)
        toggle_row = QHBoxLayout()
        self.toggle_btn = QPushButton("View details  ▾")
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_btn.setStyleSheet("""
            QPushButton {
                background: #f8fafc;
                color: #1f2a44;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: 700;
            }
            QPushButton:hover { background: #eef2f7; }
        """)
        self.toggle_btn.clicked.connect(self._toggle_details)
        toggle_row.addWidget(self.toggle_btn)
        toggle_row.addStretch()
        outer.addLayout(toggle_row)
        self.details = QFrame()
        self.details.setStyleSheet("background: transparent; border: none;")
        d_l = QVBoxLayout(self.details)
        d_l.setContentsMargins(0, 6, 0, 0)
        d_l.setSpacing(6)
        explain = _meaning_for_result(self._response_text, result, vtype)
        if explain:
            d_l.addLayout(self._labeled_box("WHAT THIS MEANS", explain, dark=False))
        req_view = _request_display(self._request_text, self._response_text, test)
        d_l.addLayout(self._labeled_box("REQUEST", req_view, dark=False))
        if level in ("confirmed", "likely"):
            evidence = str((result or {}).get("evidence") or "").strip()
            if not _usable_evidence(evidence):
                evidence = _evidence_from_blob(self._response_text, vtype)
            if _usable_evidence(evidence):
                d_l.addLayout(self._labeled_box("EVIDENCE", evidence, dark=True))
        d_l.addLayout(self._labeled_box("RESPONSE", self._response_text, dark=True))
        self.details.hide()
        outer.addWidget(self.details)


    def _fit_edit(self, box):
        box.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        box.document().setDocumentMargin(4)
        width = box.viewport().width()
        if width < 120:
            width = max(self.width() - 56, 0)
        if width < 120:
            width = 640
        box.document().setTextWidth(width)
        doc_h = int(box.document().size().height()) + 16
        h = min(max(doc_h, 36), 480)
        box.setMinimumHeight(0)
        box.setFixedHeight(h)
        box.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
            if doc_h > 480
            else Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        box.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)


    def _labeled_box(self, label_text, content, dark):
        row = QVBoxLayout()
        row.setSpacing(4)
        head = QHBoxLayout()
        lab = QLabel(label_text)
        lab.setStyleSheet("font-size: 10.5px; font-weight: 800; color: #1f2a44; border: none;")
        head.addWidget(lab)
        head.addStretch()
        copy_btn = QPushButton("Copy")
        copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        copy_btn.setFixedHeight(20)
        copy_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #2563eb;
                border: none;
                font-size: 10.5px;
                font-weight: 700;
            }
            QPushButton:hover { text-decoration: underline; }
        """)
        copy_btn.clicked.connect(lambda: QGuiApplication.clipboard().setText(content))
        head.addWidget(copy_btn)
        row.addLayout(head)
        box = QTextEdit()
        box.setReadOnly(True)
        box.setPlainText(content)
        box.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        box.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        box.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        if dark:
            box.setStyleSheet("""
                QTextEdit {
                    background: #0f172a; border: 1px solid #1e293b; border-radius: 8px;
                    padding: 8px; font-family: Menlo, Monaco, Consolas, monospace;
                    font-size: 11.5px; color: #e2e8f0;
                }
            """)
        else:
            box.setStyleSheet("""
                QTextEdit {
                    background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px;
                    padding: 8px; font-family: Menlo, Monaco, Consolas, monospace;
                    font-size: 11.5px; color: #0f172a;
                }
            """)
        self._fit_edit(box)
        self._detail_edits.append(box)
        row.addWidget(box)
        return row


    def _toggle_details(self):
        show = not self.details.isVisible()
        self.details.setVisible(show)
        self.toggle_btn.setText("Hide details  ▴" if show else "View details  ▾")
        if show:
            QTimer.singleShot(0, self._refit_detail_edits)
    

    def _refit_detail_edits(self):
        for box in self._detail_edits:
            self._fit_edit(box)


class PayloadTab(QWidget):
    def __init__(self):
        super().__init__()
        self._draft_request = ""
        self._mode = "manual"
        self._active_finding = None
        self._active_tests = []
        self._run_state = "idle"  # idle | running | completed
        self._last_results = []   # list of (test, request_text, response_text, result)
        self._active_targets = []
        self.init_ui()

    # ------------------------------------------------------------------ UI
    def init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        pal = QPalette()
        pal.setColor(QPalette.ColorRole.Window, QColor("#eef1f6"))
        pal.setColor(QPalette.ColorRole.Base, QColor("#eef1f6"))
        scroll.setAutoFillBackground(True)
        scroll.setPalette(pal)
        scroll.viewport().setAutoFillBackground(True)
        scroll.viewport().setPalette(pal)
        scroll.viewport().setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, True)
        scroll.viewport().setAttribute(Qt.WidgetAttribute.WA_StaticContents, True)
        outer.addWidget(scroll)
        body = QWidget()
        body.setAutoFillBackground(True)
        body.setPalette(pal)
        body.setStyleSheet("background: #eef1f6;")
        root = QVBoxLayout(body)
        root.setSpacing(14)
        root.setContentsMargins(0, 0, 4, 12)
        scroll.setWidget(body)

        # ---- Header banner (slim, shared between manual / active) -----
        banner = QFrame()
        banner.setObjectName("payloadBanner")
        banner.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        banner.setMaximumHeight(88)
        banner.setStyleSheet("""
            QFrame#payloadBanner {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1f2a57, stop:1 #0f3d5e
                );
                border: none;
                border-radius: 14px;
            }
            QFrame#payloadBanner QLabel {
                background: transparent;
                color: white;
                border: none;
            }
        """)
        b_l = QVBoxLayout(banner)
        b_l.setContentsMargins(18, 12, 18, 12)
        b_l.setSpacing(4)
        head = QHBoxLayout()
        self.banner_title = QLabel("Manual Payload Injection")
        self.banner_title.setStyleSheet("font-size: 17px; font-weight: 800; border: none;")
        head.addWidget(self.banner_title)
        head.addStretch()
        self.status_chip = QLabel("No target")
        self.status_chip.setFixedHeight(24)
        self.status_chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_chip.setStyleSheet(self._chip_qss(active=False))
        head.addWidget(self.status_chip, 0, Qt.AlignmentFlag.AlignTop)
        b_l.addLayout(head)
        self.target_label = QLabel(
            "Enter host, path and parameter below. A scan session is not required."
        )
        self.target_label.setWordWrap(True)
        self.target_label.setStyleSheet("font-size: 13px; color: rgba(255,255,255,0.9); border: none;")
        b_l.addWidget(self.target_label)
        root.addWidget(banner)

        # ---- Active Test card -------------------------------------------------
        self.active_card = QFrame()
        self.active_card.setObjectName("activeCard")
        self.active_card.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        self.active_card.setStyleSheet("""
            QFrame#activeCard {
                background: #ecfdf5;
                border: 1px solid #99f6e4;
                border-radius: 14px;
            }
            QFrame#activeCard QLabel {
                background: transparent;
                color: #0f766e;
                border: none;
            }
        """)
        ac = QVBoxLayout(self.active_card)
        ac.setContentsMargins(16, 14, 16, 14)
        ac.setSpacing(10)
        ac_head = QHBoxLayout()
        ac_title = QLabel("Active Test")
        ac_title.setStyleSheet("font-size: 13px; font-weight: 800; color: #0f766e; border: none;")
        ac_head.addWidget(ac_title)
        ac_head.addStretch()
        self.clear_active_btn = QPushButton("Back to Manual")
        self.clear_active_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_active_btn.setStyleSheet("""
            QPushButton {
                background: #ffffff;
                color: #0f766e;
                border: 1px solid #99f6e4;
                border-radius: 8px;
                padding: 4px 10px;
                font-weight: 700;
                font-size: 11px;
            }
            QPushButton:hover { background: #ccfbf1; }
        """)
        self.clear_active_btn.clicked.connect(self.clear_active_test)
        ac_head.addWidget(self.clear_active_btn)
        ac.addLayout(ac_head)
        self.active_meta = QLabel("—")
        self.active_meta.setWordWrap(True)
        self.active_meta.setStyleSheet("font-size: 12px; font-weight: 600; color: #115e59; border: none;")
        ac.addWidget(self.active_meta)
        self.path_lab = QLabel("PATH TO TEST")
        self.path_lab.setStyleSheet("font-size: 11px; font-weight: 800; color: #0f766e; border: none;")
        ac.addWidget(self.path_lab)
        self.path_combo = ReadableCombo()
        self.path_combo.setMaxVisibleItems(12)
        self.path_combo.currentIndexChanged.connect(self._on_path_chosen)
        ac.addWidget(self.path_combo)

        # Pending checklist, shown before a run has been executed
        self.pending_lab = QLabel("Checks queued")
        self.pending_lab.setStyleSheet("font-size: 11px; font-weight: 800; color: #0f766e; border: none;")
        ac.addWidget(self.pending_lab)
        self.tests_host = QWidget()
        self.tests_host.setStyleSheet("background: transparent;")
        self.tests_layout = QVBoxLayout(self.tests_host)
        self.tests_layout.setContentsMargins(0, 0, 0, 0)
        self.tests_layout.setSpacing(4)
        ac.addWidget(self.tests_host)

        # Summary strip (verdict / confidence / stats) — populated after a run
        self.summary_card = QFrame()
        self.summary_card.setStyleSheet("""
            QFrame { background: #ffffff; border: none; border-radius: 12px; }
            QFrame QLabel { background: transparent; border: none; }
        """)
        self.summary_layout = QVBoxLayout(self.summary_card)
        self.summary_layout.setContentsMargins(16, 14, 16, 14)
        self.summary_layout.setSpacing(8)
        self.summary_card.hide()
        ac.addWidget(self.summary_card)

        # Per-check result cards
        self.results_lab = QLabel("TEST RESULTS")
        self.results_lab.setStyleSheet("font-size: 11px; font-weight: 800; color: #0f766e; border: none;")
        self.results_lab.hide()
        ac.addWidget(self.results_lab)
        self.results_host = QWidget()
        self.results_host.setStyleSheet("background: transparent;")
        self.results_layout = QVBoxLayout(self.results_host)
        self.results_layout.setContentsMargins(0, 0, 0, 0)
        self.results_layout.setSpacing(8)
        self.results_host.hide()
        ac.addWidget(self.results_host)

        self.active_card.hide()
        root.addWidget(self.active_card)

        # ---- Manual controls ---------------------------------------------
        self.manual_controls = QFrame()
        self.manual_controls.setObjectName("payloadCard")
        self.manual_controls.setStyleSheet("""
            QFrame#payloadCard {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 14px;
            }
            QFrame#payloadCard QLabel {
                background: transparent;
                color: #475569;
                font-weight: 700;
                font-size: 12px;
                border: none;
            }
        """)
        field_qss = """
            QLineEdit {
                background: #ffffff; border: 1px solid #94a3b8;
                border-radius: 8px; padding: 6px 10px; color: #0f172a;
                min-height: 32px; font-size: 13px;
            }
        """
        c_l = QVBoxLayout(self.manual_controls)
        c_l.setContentsMargins(16, 14, 16, 14)
        c_l.setSpacing(10)
        row1 = QHBoxLayout()
        row1.setSpacing(12)
        type_box = QVBoxLayout()
        type_box.setSpacing(4)
        type_box.addWidget(QLabel("PAYLOAD TYPE"))
        self.payload_type = ReadableCombo()
        self.payload_type.addItems(["XSS", "SQLi", "Custom"])
        self.payload_type.setMinimumWidth(140)
        type_box.addWidget(self.payload_type)
        row1.addLayout(type_box)
        rec_box = QVBoxLayout()
        rec_box.setSpacing(4)
        self.payload_label = QLabel("RECOMMENDED PAYLOAD")
        rec_box.addWidget(self.payload_label)
        self.payload_list = ReadableCombo()
        self.payload_list.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        rec_box.addWidget(self.payload_list)
        self.custom_payload = QLineEdit()
        self.custom_payload.setPlaceholderText("Type your own payload")
        self.custom_payload.setStyleSheet(field_qss)
        self.custom_payload.hide()
        rec_box.addWidget(self.custom_payload)
        row1.addLayout(rec_box, 1)
        c_l.addLayout(row1)
        row2 = QHBoxLayout()
        row2.setSpacing(12)
        method_box = QVBoxLayout()
        method_box.setSpacing(4)
        method_box.addWidget(QLabel("METHOD"))
        self.manual_method = ReadableCombo()
        self.manual_method.addItems(["GET", "POST"])
        self.manual_method.setMinimumWidth(110)
        method_box.addWidget(self.manual_method)
        row2.addLayout(method_box)
        host_box = QVBoxLayout()
        host_box.setSpacing(4)
        host_box.addWidget(QLabel("HOST"))
        self.manual_host = QLineEdit()
        self.manual_host.setPlaceholderText("localhost:3000")
        self.manual_host.setStyleSheet(field_qss)
        host_box.addWidget(self.manual_host)
        row2.addLayout(host_box, 1)
        path_box = QVBoxLayout()
        path_box.setSpacing(4)
        path_box.addWidget(QLabel("PATH"))
        self.manual_path = QLineEdit()
        self.manual_path.setPlaceholderText("/search")
        self.manual_path.setStyleSheet(field_qss)
        path_box.addWidget(self.manual_path)
        row2.addLayout(path_box, 1)
        param_box = QVBoxLayout()
        param_box.setSpacing(4)
        param_box.addWidget(QLabel("PARAMETER"))
        self.manual_param = QLineEdit()
        self.manual_param.setPlaceholderText("e.g. q, email, id")
        self.manual_param.setStyleSheet(field_qss)
        param_box.addWidget(self.manual_param)
        row2.addLayout(param_box, 1)
        c_l.addLayout(row2)
        hint = QLabel(
            "Enter host, path and parameter."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(
            "font-size: 11px; font-weight: 600; color: #64748b; border: none;"
        )
        c_l.addWidget(hint)
        root.addWidget(self.manual_controls)

        btn_row = QHBoxLayout()
        self.send_button = QPushButton("Send Payload")
        self.send_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.send_button.setMinimumHeight(40)
        self.send_button.setMinimumWidth(160)
        self.send_button.setStyleSheet(self._send_btn_qss(active=False))
        btn_row.addWidget(self.send_button)
        btn_row.addStretch()
        root.addLayout(btn_row)

        # ---- Manual raw HTTP boxes (hidden entirely in Active Test mode) --
        self.manual_split_widget = QWidget()
        self.manual_split_widget.setStyleSheet("background: transparent;")
        split = QVBoxLayout(self.manual_split_widget)
        split.setContentsMargins(0, 0, 0, 0)
        split.setSpacing(12)
        req_card = QFrame()
        req_card.setObjectName("payloadCard")
        req_card.setStyleSheet("""
            QFrame#payloadCard { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 14px; }
        """)
        req_l = QVBoxLayout(req_card)
        req_l.setContentsMargins(14, 12, 14, 12)
        req_l.setSpacing(8)
        req_title = QLabel("Generated HTTP Request")
        req_title.setStyleSheet("font-size: 13px; font-weight: 800; color: #1f2a44; background: transparent; border: none;")
        req_l.addWidget(req_title)
        req_note = QLabel("Built from method, path, parameter and payload. Edit only if you need a custom body.")
        req_note.setWordWrap(True)
        req_note.setStyleSheet("font-size: 11px; color: #64748b; font-weight: 600; background: transparent; border: none;")
        req_l.addWidget(req_note)
        self.request_editor = QTextEdit()
        self.request_editor.setPlaceholderText(
            "Fill method, path and parameter above, then pick a recommended payload."
        )
        self.request_editor.setStyleSheet("""
            QTextEdit {
                background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px;
                padding: 10px; font-family: Menlo, Monaco, Consolas, monospace;
                font-size: 12.5px; color: #0f172a;
            }
        """)
        self.request_editor.textChanged.connect(self._save_request_draft)
        req_l.addWidget(self.request_editor, 1)
        split.addWidget(req_card, 1)
        res_card = QFrame()
        res_card.setObjectName("payloadCard")
        res_card.setStyleSheet("""
            QFrame#payloadCard { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 14px; }
        """)
        res_l = QVBoxLayout(res_card)
        res_l.setContentsMargins(14, 12, 14, 12)
        res_l.setSpacing(8)
        res_head = QHBoxLayout()
        res_title = QLabel("Server Response / Detection")
        res_title.setStyleSheet("font-size: 13px; font-weight: 800; color: #1f2a44; background: transparent; border: none;")
        res_head.addWidget(res_title)
        res_head.addStretch()
        clear_btn = QPushButton("Clear")
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_btn.setFixedHeight(28)
        clear_btn.setStyleSheet("""
            QPushButton {
                background: #eef2f7; color: #475569; border: none; border-radius: 6px;
                padding: 0 12px; font-weight: 700; font-size: 12px;
            }
            QPushButton:hover { background: #dbe3ee; }
        """)
        res_head.addWidget(clear_btn)
        res_l.addLayout(res_head)
        self.response_area = QTextEdit()
        self.response_area.setReadOnly(True)
        self.response_area.setPlaceholderText("Response will appear here…")
        self.response_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.response_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.response_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.response_area.setStyleSheet("""
            QTextEdit {
                background: #0f172a; border: 1px solid #1e293b; border-radius: 10px;
                padding: 10px; font-family: Menlo, Monaco, Consolas, monospace;
                font-size: 12.5px; color: #e2e8f0;
            }
        """)
        clear_btn.clicked.connect(self._clear_response)
        self.response_area.textChanged.connect(self._fit_response_area)
        res_l.addWidget(self.response_area)
        split.addWidget(res_card, 1)
        root.addWidget(self.manual_split_widget)
        root.addStretch(1)

        self.payload_type.currentTextChanged.connect(self.update_payload_list)
        self.payload_list.currentTextChanged.connect(self.insert_payload)
        self.manual_method.currentTextChanged.connect(self._rebuild_manual_request)
        self.manual_host.textChanged.connect(self._rebuild_manual_request)
        self.manual_path.textChanged.connect(self._rebuild_manual_request)
        self.manual_param.textChanged.connect(self._rebuild_manual_request)
        self.custom_payload.textChanged.connect(self._rebuild_manual_request)
        self.send_button.clicked.connect(self.send_payload)
        self.update_payload_list("XSS")

    # ---------------------------------------------------------- style helpers
    def _chip_qss(self, active: bool, tone: str = "neutral") -> str:
        if tone == "running":
            bg = "#f59e0b"
        elif tone == "completed":
            bg = "#27ae60"
        elif active:
            bg = "#27ae60"
        else:
            bg = "rgba(255,255,255,0.18)"
        return f"""
            background: {bg};
            color: white;
            border: none;
            border-radius: 10px;
            padding: 4px 12px;
            font-size: 11px;
            font-weight: 700;
        """

    def _send_btn_qss(self, active: bool) -> str:
        if active:
            return """
                QPushButton {
                    background-color: #0f766e; color: white; font-weight: 800;
                    border-radius: 10px; border: none; padding: 0 18px;
                }
                QPushButton:hover { background-color: #0d9488; }
                QPushButton:disabled { background-color: #99c9c4; }
            """
        return """
            QPushButton {
                background-color: #e74c3c; color: white; font-weight: 800;
                border-radius: 10px; border: none; padding: 0 18px;
            }
            QPushButton:hover { background-color: #c0392b; }
        """

    def _save_request_draft(self):
        self._draft_request = self.request_editor.toPlainText()

    def _clear_response(self):
        self.response_area.clear()
        self._fit_response_area()

    def _fit_response_area(self):
        box = self.response_area
        box.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        width = box.viewport().width()
        if width < 40:
            width = max(self.width() - 80, 360)
        box.document().setTextWidth(width)
        text = box.toPlainText().strip()
        if not text:
            box.setFixedHeight(140)
            return
        h = int(box.document().size().height()) + 22
        box.setFixedHeight(max(140, min(h, 900)))

    def _manual_payload_value(self) -> str:
        ptype = self.payload_type.currentText() if hasattr(self, "payload_type") else "XSS"
        if ptype == "Custom":
            return (self.custom_payload.text() if hasattr(self, "custom_payload") else "").strip()
        payload = self.payload_list.currentText() if hasattr(self, "payload_list") else ""
        if not payload or payload.startswith("(No recommended"):
            return ""
        return payload

    def _manual_host_path(self) -> tuple[str, str]:
        host = (self.manual_host.text() if hasattr(self, "manual_host") else "").strip()
        path = (self.manual_path.text() if hasattr(self, "manual_path") else "").strip()
        raw = path or host
        if raw and ("://" in raw or raw.startswith("http")):
            parsed = urlparse(raw if "://" in raw else "http://" + raw)
            if parsed.netloc:
                host = parsed.netloc
                path = parsed.path or "/"
        if host.startswith("http://"):
            host = host[7:]
        elif host.startswith("https://"):
            host = host[8:]
        host = host.split("/")[0]
        if path and not path.startswith("/"):
            path = "/" + path
        if not path:
            path = "/"
        if "#" in path:
            path = path.split("#", 1)[0] or "/"
        return host or "example.com", path

    def _rebuild_manual_request(self, *_args):
        if self._mode == "active":
            return
        method = (self.manual_method.currentText() if hasattr(self, "manual_method") else "GET") or "GET"
        param = (self.manual_param.text() if hasattr(self, "manual_param") else "").strip()
        payload = self._manual_payload_value()
        host, path = self._manual_host_path()
        if not param:
            text = (
                f"{method} {path} HTTP/1.1\n"
                f"Host: {host}\n"
                f"User-Agent: WebSET\n\n"
            )
        elif method.upper() == "POST":
            body = f"{param}={payload}"
            text = (
                f"POST {path} HTTP/1.1\n"
                f"Host: {host}\n"
                f"Content-Type: application/x-www-form-urlencoded\n"
                f"User-Agent: WebSET\n"
                f"Content-Length: {len(body)}\n\n"
                f"{body}"
            )
        else:
            text = (
                f"{method} {path}?{param}={payload} HTTP/1.1\n"
                f"Host: {host}\n"
                f"User-Agent: WebSET\n\n"
            )
        self.request_editor.blockSignals(True)
        self.request_editor.setPlainText(text)
        self.request_editor.blockSignals(False)
        self._draft_request = text

    # -------------------------------------------------------------- lifecycle
    def showEvent(self, event):
        super().showEvent(event)
        finding = None
        try:
            from core.shared_state import SharedState
            finding = getattr(SharedState, "active_test_finding", None)
        except Exception:
            finding = None
        if finding and _is_active_testable(finding):
            self.load_from_finding(finding)
        else:
            if finding and not _is_active_testable(finding):
                try:
                    from core.shared_state import SharedState
                    if hasattr(SharedState, "clear_active_test_finding"):
                        SharedState.clear_active_test_finding()
                    else:
                        SharedState.active_test_finding = None
                except Exception:
                    pass
            if self._mode != "active":
                self.refresh_target()

    def _extract_host(self, url: str) -> str:
        host, _ = _parse_url_parts(url)
        return host

    def _selected_target(self) -> dict:
        idx = -1
        if hasattr(self, "path_combo"):
            idx = self.path_combo.currentIndex()
        if 0 <= idx < len(getattr(self, "_active_targets", []) or []):
            return dict(self._active_targets[idx])
        targets = _finding_targets(self._active_finding or {})
        return dict(targets[0]) if targets else {}

    def _apply_selected_target(self):
        t = self._selected_target()
        if not t or not self._active_finding:
            return
        self._active_finding["url"] = t.get("url") or ""
        self._active_finding["endpoint"] = t.get("url") or ""
        self._active_finding["param"] = t.get("param") or ""
        self._active_finding["input"] = t.get("param") or ""
        self._active_finding["method"] = t.get("method") or "GET"
        if t.get("param_location"):
            self._active_finding["param_location"] = t.get("param_location")
        method = self._active_finding.get("method") or "GET"
        _, path = _parse_url_parts(str(self._active_finding.get("url") or ""))
        self.target_label.setText(f"{method}  {path}")
        param = self._active_finding.get("param") or "—"
        n = len(self._active_targets or [])
        extra = f"  ·  {n} path(s)" if n > 1 else ""
        self.active_meta.setText(f"<b>Parameter:</b> {param}{extra}")

    def _on_path_chosen(self, *_args):
        if self._mode != "active":
            return
        self._apply_selected_target()
        if self._run_state == "completed":
            self._last_results = []
            self._run_state = "idle"
            self._reset_result_sections()
            vtype = _infer_vuln_type(self._active_finding or {})
            self._rebuild_pending_list(vtype)
            self.send_button.setEnabled(True)
            self.send_button.setText("Run Active Test")
            self._set_status_chip("Ready", tone="completed")

    def _current_target_url(self) -> str:
        if self._mode == "active":
            t = self._selected_target()
            u = str((t or {}).get("url") or "").strip()
            if u:
                return u
            if self._active_finding:
                u = (
                    self._active_finding.get("url")
                    or self._active_finding.get("endpoint")
                    or ""
                )
                if u:
                    return str(u).strip()
        if hasattr(self, "manual_host"):
            host, path = self._manual_host_path()
            if host and host != "example.com":
                return f"http://{host}{path}"
        return ""

    def _set_status_chip(self, text: str, tone: str = "neutral"):
        self.status_chip.setText(text)
        self.status_chip.setStyleSheet(self._chip_qss(active=(tone != "neutral"), tone=tone))

    def refresh_target(self):
        if self._mode == "active" and self._active_finding:
            return
        host, path = self._manual_host_path() if hasattr(self, "manual_host") else ("", "/")
        if host and host != "example.com":
            self.target_label.setText(f"http://{host}{path}")
            self._set_status_chip("Ready", tone="completed")
        else:
            self.target_label.setText(
                "Enter host, path and parameter below. A scan session is not required."
            )
            self._set_status_chip("Manual", tone="neutral")
        if self._mode == "manual":
            self._rebuild_manual_request()

    def update_host_in_request(self, url):
        text = self.request_editor.toPlainText()
        if not text.strip():
            return
        host = self._extract_host(url)
        lines = text.splitlines()
        new_lines = []
        for line in lines:
            if line.lower().startswith("host:"):
                new_lines.append(f"Host: {host}")
            else:
                new_lines.append(line)
        self.request_editor.setPlainText("\n".join(new_lines))

    # ------------------------------------------------------------- active mode
    def load_from_finding(self, finding: dict):
        if not finding:
            return
        finding = dict(finding)
        finding["vuln_type"] = _infer_vuln_type(finding)
        if not _is_active_testable(finding):
            main = self.window()
            if main and hasattr(main, "show_toast"):
                main.show_toast(
                    "Active Test not available — passive finding (no injection probe)"
                )
            self.clear_active_test()
            return
        self._mode = "active"
        self._run_state = "idle"
        self._last_results = []
        finding = dict(finding)
        finding["vuln_type"] = _infer_vuln_type(finding)
        self._active_finding = finding
        try:
            from core.shared_state import SharedState
            if hasattr(SharedState, "set_active_test_finding"):
                SharedState.set_active_test_finding(dict(finding))
            else:
                SharedState.active_test_finding = dict(finding)
        except Exception:
            pass
        self.banner_title.setText("Active Test")
        self.manual_controls.hide()
        self.manual_split_widget.hide()
        self.active_card.show()
        self.send_button.setText("Run Active Test")
        self.send_button.setStyleSheet(self._send_btn_qss(active=True))
        self._active_targets = _finding_targets(finding)
        finding["active_test_targets"] = list(self._active_targets)
        self.path_combo.blockSignals(True)
        self.path_combo.clear()
        for t in self._active_targets:
            _, path = _parse_url_parts(str(t.get("url") or ""))
            param = t.get("param") or "—"
            method = t.get("method") or "GET"
            self.path_combo.addItem(f"{method} {path}  ·  {param}")
        if self.path_combo.count() == 0:
            self.path_combo.addItem("(no path)")
        self.path_combo.setCurrentIndex(0)
        self.path_combo.blockSignals(False)
        self.path_lab.setVisible(True)
        self.path_combo.setVisible(True)
        vtype = finding.get("vuln_type") or ""
        self._apply_selected_target()
        self._set_status_chip("Ready", tone="completed")
        self._rebuild_pending_list(vtype)
        self._reset_result_sections()
        self.response_area.clear()

    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def _rebuild_pending_list(self, vtype: str):
        self._clear_layout(self.tests_layout)
        tests = _tests_for_finding(self._active_finding or {}, vtype)
        self._active_tests = tests
        self.tests_host.show()
        self.pending_lab.show()
        if not tests:
            lab = QLabel("No recommended Active Tests for this vulnerability type.")
            lab.setStyleSheet("color: #64748b; font-size: 12px; border: none;")
            self.tests_layout.addWidget(lab)
            return
        for i, t in enumerate(tests, start=1):
            lab = QLabel(f"○  {t.get('label') or t.get('id') or f'Check {i}'}")
            lab.setToolTip(t.get("hint") or "")
            lab.setWordWrap(True)
            lab.setStyleSheet("color: #64748b; font-size: 12px; font-weight: 600; border: none;")
            self.tests_layout.addWidget(lab)

    def _reset_result_sections(self):
        self.summary_card.hide()
        self.results_lab.hide()
        self.results_host.hide()
        self._clear_layout(self.summary_layout)
        self._clear_layout(self.results_layout)

    def clear_active_test(self):
        self._mode = "manual"
        self._active_finding = None
        self._active_tests = []
        self._active_targets = []
        self._run_state = "idle"
        self._last_results = []
        if hasattr(self, "path_combo"):
            self.path_combo.blockSignals(True)
            self.path_combo.clear()
            self.path_combo.blockSignals(False)
        try:
            from core.shared_state import SharedState
            if hasattr(SharedState, "clear_active_test_finding"):
                SharedState.clear_active_test_finding()
            else:
                SharedState.active_test_finding = None
        except Exception:
            pass
        self.banner_title.setText("Manual Payload Injection")
        self.active_card.hide()
        self._reset_result_sections()
        self.manual_controls.show()
        self.manual_split_widget.show()
        self.send_button.setText("Send Payload")
        self.send_button.setEnabled(True)
        self.send_button.setStyleSheet(self._send_btn_qss(active=False))
        self.response_area.clear()
        self.refresh_target()
        self.update_payload_list(self.payload_type.currentText())

    # ------------------------------------------------------------ manual mode
    def update_payload_list(self, payload_type):
        if self._mode == "active":
            return
        custom = str(payload_type or "") == "Custom"
        if hasattr(self, "payload_label"):
            self.payload_label.setText("YOUR PAYLOAD" if custom else "RECOMMENDED PAYLOAD")
        if hasattr(self, "custom_payload"):
            self.custom_payload.setVisible(custom)
        self.payload_list.setVisible(not custom)
        self.payload_list.blockSignals(True)
        self.payload_list.clear()
        payloads = [] if custom else (get_payloads(payload_type) or [])
        if not custom:
            if payloads:
                self.payload_list.addItems(payloads)
            else:
                self.payload_list.addItem("(No recommended payloads – enter manually)")
        self.payload_list.blockSignals(False)
        self.response_area.clear()
        self._rebuild_manual_request()
        self._fit_response_area()

    def insert_payload(self, payload):
        if self._mode == "active":
            return
        self._rebuild_manual_request()
        self.response_area.clear()
        self._fit_response_area()

    # ---------------------------------------------------------------- sending
    def send_payload(self):
        QTimer.singleShot(0, self._do_send_payload)

    def _do_send_payload(self):
        if self._mode == "active":
            self._run_active_test()
        else:
            self._run_manual_payload()

    def _run_active_test(self):
        finding = dict(self._active_finding or {})
        if not _is_active_testable(finding):
            self.response_area.setText(
                "[Error] Active Test is only for injection-style findings "
                "(XSS, SQLi, path traversal, command injection).\n"
                "Passive findings (headers, cookies, CSP) are verified by the scan itself."
            )
            return
        vtype = _infer_vuln_type(finding)
        finding["vuln_type"] = vtype
        tests = list(self._active_tests or _tests_for_finding(finding, vtype) or [])
        if not tests:
            self.response_area.setText("[Error] No recommended Active Tests for this finding.")
            return
        if not self._current_target_url():
            self.response_area.setText(
                "[Error] No target on this finding.\n"
                "Return to Alerts and choose a finding with a URL/location."
            )
            return
        self.request_editor.clearFocus()
        self._run_state = "running"
        self._set_status_chip("● Running", tone="running")
        self.send_button.setEnabled(False)
        self.send_button.setText("Running…")
        self._reset_result_sections()
        self._apply_selected_target()
        finding = dict(self._active_finding or finding)
        finding["vuln_type"] = vtype
        payload_label = _VTYPE_PAYLOAD_LABEL.get(vtype, "Custom")
        cookies = None
        try:
            from core.shared_state import SharedState
            cookies = getattr(SharedState, "scan_cookies", None)
        except Exception:
            cookies = None
        results = []
        started = time.time()
        bearer = ""
        if vtype in ("nosqli", "idor"):
            bearer = _json_login_token(self._current_target_url() or "")
        for test in tests:
            request_text = _build_active_request(finding, test.get("marker") or "TEST")
            want_auth = vtype == "nosqli" or str(test.get("auth") or "").lower() in (
                "1", "true", "yes",
            ) or str(test.get("expect") or "").lower() == "idor_dump"
            if bearer and want_auth:
                request_text = _with_bearer(request_text, bearer)
            url = self._current_target_url()
            try:
                try:
                    response_text = send_payload(
                        url, request_text, payload_label,
                        marker=str(test.get("marker") or ""),
                        cookies=cookies,
                        expect=str(test.get("expect") or ""),
                    )
                except TypeError:
                    try:
                        response_text = send_payload(
                            url, request_text, payload_label,
                            marker=str(test.get("marker") or ""),
                            cookies=cookies,
                        )
                    except TypeError:
                        response_text = send_payload(url, request_text, payload_label)
            except Exception as exc:
                response_text = f"[Error] {exc}"
            verdict = _classify_test_result(vtype, request_text, response_text, test)
            results.append((test, request_text, response_text, verdict))
        elapsed = time.time() - started
        self._last_results = results
        self._run_state = "completed"
        self._set_status_chip("✓ Completed", tone="completed")
        self.send_button.setEnabled(True)
        self.send_button.setText("Run Again")
        self._render_results(results, elapsed)
        main_window = self.window()
        if main_window and hasattr(main_window, "show_toast"):
            main_window.show_toast(f"Active Test completed — {len(tests)} request(s)")

    def _summary_badge(self, text: str, bg: str, fg: str) -> QLabel:
        lab = QLabel(text)
        lab.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lab.setStyleSheet(
            f"background: {bg}; color: {fg}; border: none; border-radius: 8px; "
            "padding: 5px 11px; font-size: 10.5px; font-weight: 800;"
        )
        return lab

    def _signal_chip(self, text: str) -> QLabel:
        lab = QLabel(text)
        lab.setWordWrap(False)
        lab.setStyleSheet(
            "background: #ecfdf5; color: #0f766e; border: 1px solid #99f6e4; "
            "border-radius: 8px; padding: 3px 9px; font-size: 11px; font-weight: 700;"
        )
        return lab

    def _chip_matches_type(self, label: str, vtype: str) -> bool:
        low = (label or "").lower()
        if vtype == "xss":
            return "xss" in low or "cross-site" in low or "script" in low
        if vtype == "sqli":
            return "sql" in low
        if vtype == "path_traversal":
            return "path" in low or "traversal" in low
        if vtype == "command_injection":
            return "command" in low
        if vtype == "idor":
            return "idor" in low or "object" in low or "collection" in low
        return True

    def _render_results(self, results, elapsed: float):
        self.tests_host.hide()
        self.pending_lab.hide()
        confirmed = [r for r in results if r[3].get("confirmed")]
        likely = [r for r in results if str(r[3].get("level") or "") == "likely"]
        total = len(results)
        n_ok = len(confirmed)
        n_likely = len(likely)
        finding = self._active_finding or {}
        vuln_name = finding.get("vulnerability") or finding.get("name") or "Vulnerability"
        param = finding.get("param") or finding.get("input") or finding.get("parameter") or "—"
        vtype = _infer_vuln_type(finding)
        if n_ok:
            analysis = (
                f"{n_ok} of {total} checks confirmed a distinctive signal "
                f"on parameter `{param}`."
            )
        elif n_likely:
            if vtype == "xss":
                analysis = (
                    f"{n_likely} of {total} checks were LIKELY only. "
                    "A short reflected probe is not exploit proof."
                )
            elif vtype == "sqli":
                analysis = (
                    f"{n_likely} of {total} checks were LIKELY only. "
                    "HTTP 5xx without an explicit database error is not exploit proof."
                )
            elif vtype == "path_traversal":
                analysis = (
                    f"{n_likely} of {total} checks were LIKELY only. "
                    "A path probe reflection or filesystem error is not proof a foreign file was read."
                )
            elif vtype == "command_injection":
                analysis = (
                    f"{n_likely} of {total} checks were LIKELY only. "
                    "Reflection of a command probe is not proof a command ran."
                )
            else:
                analysis = f"{n_likely} of {total} checks were LIKELY only."
        else:
            analysis = (
                f"0 of {total} checks confirmed a distinctive signal. "
                "Reflection of a short probe is not evidence of a working exploit."
            )

        head = QLabel("SUMMARY")
        head.setStyleSheet(
            "font-size: 11px; font-weight: 800; color: #0f766e; border: none;"
        )
        self.summary_layout.addWidget(head)

        desc = QLabel(f"{vuln_name}  ·  parameter `{param}`")
        desc.setWordWrap(True)
        desc.setStyleSheet(
            "font-size: 13px; font-weight: 800; color: #1f2a44; border: none;"
        )
        self.summary_layout.addWidget(desc)

        if n_ok:
            tone_bg, tone_fg, tone_txt = "#ccfbf1", "#0f766e", "SIGNAL"
        elif n_likely:
            tone_bg, tone_fg, tone_txt = "#fef3c7", "#92400e", "LIKELY"
        else:
            tone_bg, tone_fg, tone_txt = "#f1f5f9", "#64748b", "NO SIGNAL"

        badge_host = QWidget()
        badge_host.setStyleSheet("background: transparent;")
        badge_flow = _ChipFlow(badge_host, h_spacing=8, v_spacing=6)
        badge_host.setLayout(badge_flow)
        badge_flow.addWidget(self._summary_badge(tone_txt, tone_bg, tone_fg))
        badge_flow.addWidget(self._summary_badge(
            f"{n_ok}/{total} SIGNAL", "#ecfdf5", "#0f766e" if n_ok else "#64748b"
        ))
        badge_flow.addWidget(self._summary_badge(f"{total} REQUESTS", "#eff6ff", "#1d4ed8"))
        badge_flow.addWidget(self._summary_badge(f"{elapsed:.1f}s", "#f8fafc", "#475569"))
        self.summary_layout.addWidget(badge_host)

        labels = []
        seen = set()
        for test, _req, _res, verdict in results:
            if not (verdict or {}).get("confirmed"):
                continue
            lab = str((test or {}).get("label") or (test or {}).get("id") or "").strip()
            if not lab or lab.lower() in seen:
                continue
            if vtype and not self._chip_matches_type(lab, vtype):
                continue
            seen.add(lab.lower())
            labels.append(lab)
        if labels:
            chip_lab = QLabel("Signal on")
            chip_lab.setStyleSheet(
                "font-size: 11px; font-weight: 800; color: #64748b; border: none;"
            )
            self.summary_layout.addWidget(chip_lab)
            chip_host = QWidget()
            chip_host.setStyleSheet("background: transparent;")
            chip_flow = _ChipFlow(chip_host, h_spacing=6, v_spacing=6)
            chip_host.setLayout(chip_flow)
            for lab in labels:
                chip_flow.addWidget(self._signal_chip(lab))
            self.summary_layout.addWidget(chip_host)

        skip_prefixes = (
            "webset sent",
            "3 of ",
            f"{n_ok} of ",
            "signal on:",
        )
        paras = []
        for block in (analysis or "").split("\n"):
            line = block.strip()
            if not line:
                continue
            low_line = line.lower()
            if any(low_line.startswith(p) for p in skip_prefixes):
                continue
            if low_line.startswith(f"{n_ok} of {total}"):
                continue
            paras.append(line)
        if paras:
            body = QLabel("\n\n".join(paras))
            body.setWordWrap(True)
            body.setStyleSheet(
                "font-size: 12.5px; font-weight: 600; color: #334155; border: none;"
            )
            self.summary_layout.addWidget(body)

        self.summary_card.show()

        for i, (test, req_text, res_text, verdict_data) in enumerate(results, start=1):
            card = TestResultCard(i, test, req_text, res_text, verdict_data, vtype=vtype)
            self.results_layout.addWidget(card)
        self.results_lab.show()
        self.results_host.show()


    def _run_manual_payload(self):
        host, path = self._manual_host_path()
        if not host or host == "example.com":
            self.response_area.setText(
                "[Error] Enter a host first.\n"
                "Example: localhost:3000"
            )
            self._fit_response_area()
            return
        if not (self.manual_param.text() if hasattr(self, "manual_param") else "").strip():
            self.response_area.setText(
                "[Error] Enter a parameter name.\n"
                "Example: q, email, id"
            )
            self._fit_response_area()
            return
        url = f"http://{host}{path}"
        payload_type = self.payload_type.currentText()
        self.request_editor.clearFocus()
        request_text = self.request_editor.toPlainText()
        if request_text is None:
            request_text = ""
        request_text = request_text.strip()
        if not request_text:
            request_text = (getattr(self, "_draft_request", "") or "").strip()
        if not request_text:
            self.response_area.setText(
                "[Error] Please enter an HTTP request first.\n"
                "Type your request in the HTTP Request box, then click Send Payload."
            )
            return
        result = send_payload(url, request_text, payload_type)
        self.response_area.setText(result)
        QTimer.singleShot(0, self._fit_response_area)
        main_window = self.window()
        if main_window and hasattr(main_window, "show_toast"):
            main_window.show_toast("Payload sent")
