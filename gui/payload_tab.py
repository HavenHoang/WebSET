from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QComboBox, QFrame, QStyleFactory, QListView, QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer, QPoint
from PyQt6.QtGui import QPalette, QColor
import sys
import os
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ========== DELETE when Member 3 provides get_payloads(payload_type) ==========
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
# ========== DELETE end ==========

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
class PayloadTab(QWidget):
    def __init__(self):
        super().__init__()
        self._draft_request = ""
        self.init_ui()
    def init_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(14)
        root.setContentsMargins(0, 0, 0, 0)
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
        title = QLabel("Manual Payload Injection")
        title.setStyleSheet("font-size: 17px; font-weight: 800;")
        head.addWidget(title)
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
        self.target_label = QLabel("Scan a URL in Create Scan, then return here.")
        self.target_label.setWordWrap(True)
        self.target_label.setStyleSheet("font-size: 13px; color: rgba(255,255,255,0.9);")
        b_l.addWidget(self.target_label)
        root.addWidget(banner)
        controls = QFrame()
        controls.setObjectName("payloadCard")
        controls.setStyleSheet("""
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
        c_l = QHBoxLayout(controls)
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
        self.payload_list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        rec_box.addWidget(self.payload_list)
        c_l.addLayout(rec_box, 1)
        self.send_button = QPushButton("Send Payload")
        self.send_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.send_button.setMinimumHeight(40)
        self.send_button.setMinimumWidth(140)
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                font-weight: 800;
                border-radius: 10px;
                border: none;
                margin-top: 14px;
                padding: 0 16px;
            }
            QPushButton:hover { background-color: #c0392b; }
        """)
        c_l.addWidget(self.send_button)
        root.addWidget(controls)
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
        res_title = QLabel("Server Response")
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
        self.refresh_target()
    def _extract_host(self, url: str) -> str:
        if not url:
            return "example.com"
        host = url.replace("https://", "").replace("http://", "")
        host = host.split("/")[0].split("?")[0].strip()
        return host if host else "example.com"
    def refresh_target(self):
        try:
            from core.shared_state import SharedState
        except Exception:
            return
        if SharedState.has_scan_data():
            url = SharedState.current_url
            self.target_label.setText(url)
            self.status_chip.setText("Ready")
            self.status_chip.setStyleSheet("""
                background: #27ae60;
                color: white;
                border-radius: 10px;
                padding: 4px 12px;
                font-size: 11px;
                font-weight: 700;
            """)
            self.update_host_in_request(url)
        else:
            self.target_label.setText("Scan a URL in Create Scan, then return here.")
            self.status_chip.setText("No target")
            self.status_chip.setStyleSheet("""
                background: rgba(255,255,255,0.18);
                color: white;
                border-radius: 10px;
                padding: 4px 12px;
                font-size: 11px;
                font-weight: 700;
            """)
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
    def update_payload_list(self, payload_type):
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
        if not payload or payload.startswith("(No recommended"):
            return
        try:
            from core.shared_state import SharedState
            if SharedState.has_scan_data():
                host = self._extract_host(SharedState.current_url)
            else:
                host = "example.com"
        except Exception:
            host = "example.com"
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
        try:
            from core.shared_state import SharedState
        except Exception:
            self.response_area.setText("[Error] SharedState not available.")
            return
        if not SharedState.has_scan_data():
            self.response_area.setText(
                "[Error] No target URL available.\n"
                "Please go to Create Scan and run a scan first."
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
        # result = send_payload(SharedState.current_url, request_text, payload_type)
        # self.response_area.setText(result)
        # return
        # ========== UNCOMMENT end ==========
        # ========== DELETE when connecting to real Payload module (Member 3) ==========
        selected_payload = self.payload_list.currentText()
        if not selected_payload or selected_payload.startswith("(No recommended"):
            first_line = request_text.splitlines()[0] if request_text else "Custom (manual input)"
            selected_payload = first_line
        self.response_area.setText(
            f"[Demo] Payload sent successfully\n\n"
            f"Target : {SharedState.current_url}\n"
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
