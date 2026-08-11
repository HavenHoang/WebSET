from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QComboBox, QFrame, QStyleFactory, QListView, QSizePolicy,
    QButtonGroup, QRadioButton, QScrollArea
)
from PyQt6.QtCore import Qt, QTimer, QPoint
from PyQt6.QtGui import QPalette, QColor
from urllib.parse import urlparse, quote
import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ========== DELETE when Member 3 provides get_payloads / active test library ==========
RECOMMENDED_PAYLOADS = {
    "XSS": [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ],
    "SQLi": [
        "' OR '1'='1",
        "' OR 1=1--",
        "1' UNION SELECT null--",
        "admin'--",
    ],
    "Custom": [],
}

# Controlled single-request active tests (not full exploit lists)
ACTIVE_TEST_LIBRARY = {
    "xss": [
        {
            "id": "xss_html_reflection",
            "label": "Reflected XSS — HTML context",
            "marker": "TEST_MARKER_123",
            "hint": "Checks whether a unique marker is reflected unencoded in the HTML body.",
        },
        {
            "id": "xss_attr_context",
            "label": "Reflected XSS — Attribute context",
            "marker": "\" TEST_ATTR_456 ",
            "hint": "Checks reflection inside an HTML attribute context.",
        },
        {
            "id": "xss_encoding_check",
            "label": "Encoding / sanitisation check",
            "marker": "<WebSET_ENC_789>",
            "hint": "Checks whether angle brackets are encoded in the response.",
        },
    ],
    "sqli": [
        {
            "id": "sqli_error_based",
            "label": "SQL Injection — error-based indicator",
            "marker": "'",
            "hint": "Single controlled probe; looks for DB error / status change.",
        },
        {
            "id": "sqli_behaviour",
            "label": "SQL Injection — behaviour change",
            "marker": "1 OR 1=1",
            "hint": "Compares response behaviour against a safe baseline expectation.",
        },
    ],
    "path_traversal": [
        {
            "id": "path_controlled",
            "label": "Path traversal — controlled probe",
            "marker": "../",
            "hint": "Non-destructive path segment probe.",
        },
    ],
    "command_injection": [
        {
            "id": "cmd_canary",
            "label": "Command injection — canary",
            "marker": "WEBSET_CANARY",
            "hint": "Non-destructive canary string only.",
        },
    ],
}
# ========== DELETE end ==========

_ACTIVE_TYPES = frozenset(ACTIVE_TEST_LIBRARY.keys())

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
    if v in _ACTIVE_TYPES:
        return v
    name = str(finding.get("vulnerability") or finding.get("name") or "").lower()
    if "xss" in name or "cross-site" in name:
        return "xss"
    if "sql" in name and "injection" in name:
        return "sqli"
    if "sql injection" in name or name.strip() == "sqli":
        return "sqli"
    if "path" in name or "traversal" in name:
        return "path_traversal"
    if "command" in name and "injection" in name:
        return "command_injection"
    return ""


def _is_active_testable(finding: dict) -> bool:
    if not finding:
        return False
    if str(finding.get("scan_origin") or "") == "Platform":
        return False
    vtype = _infer_vuln_type(finding)
    if vtype not in _ACTIVE_TYPES:
        return False
    url = str(
        finding.get("url")
        or finding.get("endpoint")
        or finding.get("location")
        or ""
    ).strip()
    if not url:
        return False
    if vtype in {"xss", "sqli"}:
        param = str(
            finding.get("param")
            or finding.get("input")
            or finding.get("parameter")
            or ""
        ).strip()
        if not param:
            return False
    return True


def _parse_url_parts(url: str) -> tuple[str, str]:
    """Return (host, path) for request building."""
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
    """Build ONE controlled HTTP request from finding + selected test marker."""
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
    param_location = str(
        finding.get("param_location") or finding.get("input_location") or "query"
    ).lower()

    host, path = _parse_url_parts(url)
    encoded_marker = quote(marker, safe="")

    if param_location in ("query", "url", "get") or method == "GET":
        line = f"{method} {path}?{param}={encoded_marker} HTTP/1.1"
        return f"{line}\nHost: {host}\nUser-Agent: WebSET-ActiveTest\n\n"

    if param_location in ("json", "body_json"):
        body = f'{{"{param}": "{marker}"}}'
        return (
            f"{method} {path} HTTP/1.1\n"
            f"Host: {host}\n"
            f"Content-Type: application/json\n"
            f"User-Agent: WebSET-ActiveTest\n"
            f"Content-Length: {len(body)}\n\n"
            f"{body}"
        )

    body = f"{param}={encoded_marker}"
    return (
        f"{method} {path} HTTP/1.1\n"
        f"Host: {host}\n"
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"User-Agent: WebSET-ActiveTest\n"
        f"Content-Length: {len(body)}\n\n"
        f"{body}"
    )


class PayloadTab(QWidget):
    def __init__(self):
        super().__init__()
        self._draft_request = ""
        self._mode = "manual"  # manual | active
        self._active_finding = None
        self._active_tests = []
        self._test_group = None
        self.init_ui()

    def init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        outer.addWidget(scroll)

        body = QWidget()
        body.setStyleSheet("background: transparent;")
        root = QVBoxLayout(body)
        root.setSpacing(14)
        root.setContentsMargins(0, 0, 4, 12)
        scroll.setWidget(body)

        banner = QFrame()
        banner.setObjectName("payloadBanner")
        banner.setStyleSheet("""
            QFrame#payloadBanner {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1f2a57, stop:1 #0f3d5e
                );
                border-radius: 14px;
            }
            QFrame#payloadBanner QLabel {
                background: transparent;
                color: white;
            }
        """)
        b_l = QVBoxLayout(banner)
        b_l.setContentsMargins(18, 16, 18, 16)
        b_l.setSpacing(6)

        head = QHBoxLayout()
        self.banner_title = QLabel("Manual Payload Injection")
        self.banner_title.setStyleSheet("font-size: 17px; font-weight: 800;")
        head.addWidget(self.banner_title)
        head.addStretch()
        self.status_chip = QLabel("No target")
        self.status_chip.setStyleSheet("""
            background: rgba(255,255,255,0.18);
            color: white;
            border-radius: 10px;
            padding: 4px 12px;
            font-size: 11px;
            font-weight: 700;
        """)
        head.addWidget(self.status_chip)
        b_l.addLayout(head)

        self.target_label = QLabel(
            "Run Get Stack or Start Scan in Create Scan, then return here."
        )
        self.target_label.setWordWrap(True)
        self.target_label.setStyleSheet("font-size: 13px; color: rgba(255,255,255,0.9);")
        b_l.addWidget(self.target_label)
        root.addWidget(banner)

        # ---- Active Test context card (hidden in manual mode) ----
        self.active_card = QFrame()
        self.active_card.setObjectName("activeCard")
        self.active_card.setStyleSheet("""
            QFrame#activeCard {
                background: #ecfdf5;
                border: 1px solid #99f6e4;
                border-radius: 14px;
            }
            QFrame#activeCard QLabel {
                background: transparent;
                color: #0f766e;
            }
        """)
        ac = QVBoxLayout(self.active_card)
        ac.setContentsMargins(16, 14, 16, 14)
        ac.setSpacing(8)
        ac_head = QHBoxLayout()
        ac_title = QLabel("Active Test (from Alerts)")
        ac_title.setStyleSheet("font-size: 13px; font-weight: 800; color: #0f766e;")
        ac_head.addWidget(ac_title)
        ac_head.addStretch()
        self.clear_active_btn = QPushButton("Clear · Manual mode")
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
        self.active_meta.setStyleSheet(
            "font-size: 12px; font-weight: 600; color: #115e59;"
        )
        ac.addWidget(self.active_meta)

        tests_lab = QLabel("Recommended tests (select ONE — one request only)")
        tests_lab.setStyleSheet("font-size: 11px; font-weight: 800; color: #0f766e;")
        ac.addWidget(tests_lab)

        self.tests_host = QWidget()
        self.tests_host.setStyleSheet("background: transparent;")
        self.tests_layout = QVBoxLayout(self.tests_host)
        self.tests_layout.setContentsMargins(0, 0, 0, 0)
        self.tests_layout.setSpacing(4)
        ac.addWidget(self.tests_host)

        self.active_hint = QLabel(
            "Constraint: one Active Test run = one controlled request. "
            "Only injection-style findings (XSS, SQLi, …)."
        )
        self.active_hint.setWordWrap(True)
        self.active_hint.setStyleSheet("font-size: 11px; color: #64748b; font-weight: 600;")
        ac.addWidget(self.active_hint)
        self.active_card.hide()
        root.addWidget(self.active_card)

        # ---- Manual controls ----
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
            }
        """)
        c_l = QHBoxLayout(self.manual_controls)
        c_l.setContentsMargins(16, 14, 16, 14)
        c_l.setSpacing(12)

        type_box = QVBoxLayout()
        type_box.setSpacing(4)
        type_box.addWidget(QLabel("PAYLOAD TYPE"))
        self.payload_type = ReadableCombo()
        self.payload_type.addItems(["XSS", "SQLi", "Custom"])
        self.payload_type.setMinimumWidth(140)
        type_box.addWidget(self.payload_type)
        c_l.addLayout(type_box)

        rec_box = QVBoxLayout()
        rec_box.setSpacing(4)
        rec_box.addWidget(QLabel("RECOMMENDED PAYLOAD"))
        self.payload_list = ReadableCombo()
        self.payload_list.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        rec_box.addWidget(self.payload_list)
        c_l.addLayout(rec_box, 1)
        root.addWidget(self.manual_controls)

        # ---- Action button row ----
        btn_row = QHBoxLayout()
        self.send_button = QPushButton("Send Payload")
        self.send_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.send_button.setMinimumHeight(40)
        self.send_button.setMinimumWidth(160)
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                font-weight: 800;
                border-radius: 10px;
                border: none;
                padding: 0 18px;
            }
            QPushButton:hover { background-color: #c0392b; }
        """)
        btn_row.addWidget(self.send_button)
        btn_row.addStretch()
        root.addLayout(btn_row)

        split = QHBoxLayout()
        split.setSpacing(12)

        req_card = QFrame()
        req_card.setObjectName("payloadCard")
        req_card.setStyleSheet("""
            QFrame#payloadCard {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 14px;
            }
        """)
        req_l = QVBoxLayout(req_card)
        req_l.setContentsMargins(14, 12, 14, 12)
        req_l.setSpacing(8)
        req_title = QLabel("HTTP Request")
        req_title.setStyleSheet(
            "font-size: 13px; font-weight: 800; color: #1f2a44; background: transparent;"
        )
        req_l.addWidget(req_title)
        self.request_editor = QTextEdit()
        self.request_editor.setPlaceholderText(
            "GET /search?q=test HTTP/1.1\nHost: example.com\nUser-Agent: WebSET\n\n"
        )
        self.request_editor.setStyleSheet("""
            QTextEdit {
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 10px;
                padding: 10px;
                font-family: Menlo, Monaco, Consolas, monospace;
                font-size: 12.5px;
                color: #0f172a;
            }
        """)
        self.request_editor.textChanged.connect(self._save_request_draft)
        req_l.addWidget(self.request_editor, 1)
        split.addWidget(req_card, 1)

        res_card = QFrame()
        res_card.setObjectName("payloadCard")
        res_card.setStyleSheet("""
            QFrame#payloadCard {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 14px;
            }
        """)
        res_l = QVBoxLayout(res_card)
        res_l.setContentsMargins(14, 12, 14, 12)
        res_l.setSpacing(8)
        res_head = QHBoxLayout()
        res_title = QLabel("Server Response / Detection")
        res_title.setStyleSheet(
            "font-size: 13px; font-weight: 800; color: #1f2a44; background: transparent;"
        )
        res_head.addWidget(res_title)
        res_head.addStretch()
        clear_btn = QPushButton("Clear")
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_btn.setFixedHeight(28)
        clear_btn.setStyleSheet("""
            QPushButton {
                background: #eef2f7;
                color: #475569;
                border: none;
                border-radius: 6px;
                padding: 0 12px;
                font-weight: 700;
                font-size: 12px;
            }
            QPushButton:hover { background: #dbe3ee; }
        """)
        res_head.addWidget(clear_btn)
        res_l.addLayout(res_head)
        self.response_area = QTextEdit()
        self.response_area.setReadOnly(True)
        self.response_area.setPlaceholderText("Response will appear here…")
        self.response_area.setStyleSheet("""
            QTextEdit {
                background: #0f172a;
                border: 1px solid #1e293b;
                border-radius: 10px;
                padding: 10px;
                font-family: Menlo, Monaco, Consolas, monospace;
                font-size: 12.5px;
                color: #e2e8f0;
            }
        """)
        clear_btn.clicked.connect(self.response_area.clear)
        res_l.addWidget(self.response_area, 1)
        split.addWidget(res_card, 1)

        root.addLayout(split, 1)

        self.payload_type.currentTextChanged.connect(self.update_payload_list)
        self.payload_list.currentTextChanged.connect(self.insert_payload)
        self.send_button.clicked.connect(self.send_payload)
        self.update_payload_list("XSS")

    def _save_request_draft(self):
        self._draft_request = self.request_editor.toPlainText()

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

    def _current_target_url(self) -> str:
        if self._mode == "active" and self._active_finding:
            u = (
                self._active_finding.get("url")
                or self._active_finding.get("endpoint")
                or self._active_finding.get("location")
                or ""
            )
            if u:
                return str(u).strip()
        try:
            from core.shared_state import SharedState
            url = getattr(SharedState, "current_url", None) or ""
            return str(url).strip()
        except Exception:
            return ""

    def _set_status_chip(self, text: str, ready: bool = False):
        self.status_chip.setText(text)
        if ready:
            self.status_chip.setStyleSheet("""
                background: #27ae60;
                color: white;
                border-radius: 10px;
                padding: 4px 12px;
                font-size: 11px;
                font-weight: 700;
            """)
        else:
            self.status_chip.setStyleSheet("""
                background: rgba(255,255,255,0.18);
                color: white;
                border-radius: 10px;
                padding: 4px 12px;
                font-size: 11px;
                font-weight: 700;
            """)

    def refresh_target(self):
        if self._mode == "active" and self._active_finding:
            return
        url = self._current_target_url()
        if url:
            self.target_label.setText(url)
            self._set_status_chip("Ready", ready=True)
            self.update_host_in_request(url)
        else:
            self.target_label.setText(
                "Run Get Stack or Start Scan in Create Scan, then return here."
            )
            self._set_status_chip("No target", ready=False)
            if self._mode == "manual":
                self.request_editor.clear()
                self.response_area.clear()
                self._draft_request = ""

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

    # Active Test mode (from Alerts)
    def load_from_finding(self, finding: dict):
        """Called from AlertsPage Active Test button / SharedState hand-off."""
        if not finding:
            return

        if not _is_active_testable(finding):
            main = self.window()
            if main and hasattr(main, "show_toast"):
                main.show_toast(
                    "Active Test not available — passive finding (no injection probe)"
                )
            self.clear_active_test()
            return

        self._mode = "active"
        self._active_finding = dict(finding)
        try:
            from core.shared_state import SharedState
            if hasattr(SharedState, "set_active_test_finding"):
                SharedState.set_active_test_finding(dict(finding))
            else:
                SharedState.active_test_finding = dict(finding)
        except Exception:
            pass

        self.banner_title.setText("Active Test — single-request verification")
        self.manual_controls.hide()
        self.active_card.show()
        self.send_button.setText("Run Active Test")
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #0f766e;
                color: white;
                font-weight: 800;
                border-radius: 10px;
                border: none;
                padding: 0 18px;
            }
            QPushButton:hover { background-color: #0d9488; }
        """)

        url = (
            finding.get("url")
            or finding.get("endpoint")
            or finding.get("location")
            or "—"
        )
        method = finding.get("method") or "GET"
        param = (
            finding.get("param")
            or finding.get("input")
            or finding.get("parameter")
            or "—"
        )
        ploc = finding.get("param_location") or finding.get("input_location") or "query"
        ctx = finding.get("context") or "—"
        vtype = _infer_vuln_type(finding)
        name = finding.get("vulnerability") or finding.get("name") or "Finding"

        self.target_label.setText(str(url))
        self._set_status_chip("Active Test", ready=True)
        self.active_meta.setText(
            f"<b>{name}</b><br/>"
            f"Method: {method} &nbsp;·&nbsp; Parameter: {param} "
            f"&nbsp;·&nbsp; Location: {ploc}<br/>"
            f"Context: {ctx} &nbsp;·&nbsp; Type: {vtype}"
        )

        self._rebuild_test_radios(vtype)
        self._apply_selected_active_test()
        self.response_area.clear()

    def _clear_tests_layout(self):
        while self.tests_layout.count():
            item = self.tests_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def _rebuild_test_radios(self, vtype: str):
        self._clear_tests_layout()
        self._test_group = QButtonGroup(self)
        self._test_group.setExclusive(True)
        tests = list(ACTIVE_TEST_LIBRARY.get(vtype) or [])
        self._active_tests = tests
        if not tests:
            lab = QLabel("No recommended Active Tests for this vulnerability type.")
            lab.setStyleSheet("color: #64748b; font-size: 12px;")
            self.tests_layout.addWidget(lab)
            return
        for i, t in enumerate(tests):
            rb = QRadioButton(t["label"])
            rb.setToolTip(t.get("hint") or "")
            rb.setStyleSheet(
                "QRadioButton { color: #0f172a; font-size: 12px; font-weight: 600; }"
            )
            if i == 0:
                rb.setChecked(True)
            self._test_group.addButton(rb, i)
            self.tests_layout.addWidget(rb)
            rb.toggled.connect(self._on_test_toggled)

    def _on_test_toggled(self, checked: bool):
        if checked:
            self._apply_selected_active_test()

    def _selected_active_test(self) -> dict | None:
        if not self._test_group or not self._active_tests:
            return None
        idx = self._test_group.checkedId()
        if idx < 0 or idx >= len(self._active_tests):
            return self._active_tests[0]
        return self._active_tests[idx]

    def _apply_selected_active_test(self):
        if not self._active_finding:
            return
        test = self._selected_active_test()
        if not test:
            return
        req = _build_active_request(self._active_finding, test["marker"])
        self.request_editor.setPlainText(req)
        self._draft_request = req

    def clear_active_test(self):
        self._mode = "manual"
        self._active_finding = None
        self._active_tests = []
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
        self.manual_controls.show()
        self.send_button.setText("Send Payload")
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                font-weight: 800;
                border-radius: 10px;
                border: none;
                padding: 0 18px;
            }
            QPushButton:hover { background-color: #c0392b; }
        """)
        self.response_area.clear()
        self.refresh_target()
        self.update_payload_list(self.payload_type.currentText())


    def update_payload_list(self, payload_type):
        if self._mode == "active":
            return
        self.payload_list.blockSignals(True)
        self.payload_list.clear()
        # ========== UNCOMMENT when Member 3 provides get_payloads ==========
        # from payload_injection.payloads import get_payloads
        # payloads = get_payloads(payload_type) or []
        # ========== UNCOMMENT end ==========
        # ========== DELETE when Member 3 provides get_payloads ==========
        payloads = RECOMMENDED_PAYLOADS.get(payload_type, [])
        # ========== DELETE end ==========
        if payloads:
            self.payload_list.addItems(payloads)
        else:
            self.payload_list.addItem("(No recommended payloads – enter manually)")
        self.payload_list.blockSignals(False)
        self.response_area.clear()
        if payloads:
            self.insert_payload(payloads[0])
        else:
            self.request_editor.clear()
            self._draft_request = ""

    def insert_payload(self, payload):
        if self._mode == "active":
            return
        if not payload or payload.startswith("(No recommended"):
            return
        url = self._current_target_url()
        host = self._extract_host(url) if url else "example.com"
        template = (
            f"GET /search?q={payload} HTTP/1.1\n"
            f"Host: {host}\n"
            f"User-Agent: WebSET\n\n"
        )
        self.request_editor.setPlainText(template)
        self.response_area.clear()


    def send_payload(self):
        QTimer.singleShot(0, self._do_send_payload)

    def _do_send_payload(self):
        if self._mode == "active":
            self._run_active_test()
        else:
            self._run_manual_payload()

    def _run_active_test(self):
        """Exactly ONE controlled request for the selected recommended test."""
        finding = self._active_finding or {}
        if not _is_active_testable(finding):
            self.response_area.setText(
                "[Error] Active Test is only for injection-style findings "
                "(XSS, SQLi, path traversal, command injection).\n"
                "Passive findings (headers, cookies, CSP) are verified by the scan itself."
            )
            return

        test = self._selected_active_test()
        if not test:
            self.response_area.setText("[Error] Select one recommended Active Test.")
            return

        url = self._current_target_url()
        if not url:
            self.response_area.setText(
                "[Error] No target on this finding.\n"
                "Return to Alerts and choose a finding with a URL/location."
            )
            return

        self.request_editor.clearFocus()
        request_text = (self.request_editor.toPlainText() or "").strip()
        if not request_text:
            request_text = _build_active_request(finding, test["marker"])
            self.request_editor.setPlainText(request_text)

        marker = test["marker"]
        # ========== UNCOMMENT when Member 3 provides active verifier ==========
        # from payload_injection.active_test import run_active_test
        # result = run_active_test(finding, test, request_text)
        # self.response_area.setText(result)
        # return
        # ========== UNCOMMENT end ==========

        # ========== DELETE: demo detection output (1 request) ==========
        reflected = True
        encoded = False
        status = 200
        self.response_area.setText(
            f"[Active Test] Single-request verification\n\n"
            f"Test            : {test['label']}\n"
            f"Test id         : {test['id']}\n"
            f"Marker / input  : {marker}\n"
            f"Target          : {url}\n"
            f"Method          : {finding.get('method') or 'GET'}\n"
            f"Parameter       : {finding.get('param') or finding.get('input') or '—'}\n"
            f"Param location  : {finding.get('param_location') or 'query'}\n"
            f"Context         : {finding.get('context') or '—'}\n"
            f"Requests sent   : 1\n\n"
            f"----- Detection (demo) -----\n"
            f"HTTP status     : {status}\n"
            f"Found in body   : {'YES' if reflected else 'NO'}\n"
            f"Encoded         : {'YES' if encoded else 'NO'}\n"
            f"DB error signal : NO\n"
            f"Confidence      : HIGH (demo)\n"
            f"Conclusion      : Potential issue indicators present — validate manually\n\n"
            f"----- Request sent -----\n"
            f"{request_text}\n"
        )
        # ========== DELETE end ==========

        main_window = self.window()
        if main_window and hasattr(main_window, "show_toast"):
            main_window.show_toast("Active Test completed — 1 request")

    def _run_manual_payload(self):
        url = self._current_target_url()
        if not url:
            self.response_area.setText(
                "[Error] No target URL available.\n"
                "Go to Create Scan and run Get Stack or Start Scan first."
            )
            return

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

        # ========== UNCOMMENT when connecting to real Payload module (Member 3) ==========
        # from payload_injection.injector import send_payload
        # result = send_payload(url, request_text, payload_type)
        # self.response_area.setText(result)
        # return
        # ========== UNCOMMENT end ==========

        # ========== DELETE when connecting to real Payload module (Member 3) ==========
        selected_payload = self.payload_list.currentText()
        if not selected_payload or selected_payload.startswith("(No recommended"):
            first_line = (
                request_text.splitlines()[0] if request_text else "Custom (manual input)"
            )
            selected_payload = first_line
        self.response_area.setText(
            f"[Demo] Payload sent successfully\n\n"
            f"Target : {url}\n"
            f"Type : {payload_type}\n"
            f"Payload : {selected_payload}\n"
            f"Status : 200 OK\n\n"
            f"----- Request sent -----\n"
            f"{request_text}\n\n"
            f"This is a simulated response."
        )
        # ========== DELETE end ==========

        main_window = self.window()
        if main_window and hasattr(main_window, "show_toast"):
            main_window.show_toast("Payload sent")
