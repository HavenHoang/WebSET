import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QStatusBar, QStackedWidget, QFrame
)
from PyQt6.QtCore import Qt, QTimer
from payload_tab import PayloadTab
from report_tab import ReportTab
from dashboard_page import DashboardPage
from cases_page import CasesPage
from alerts_page import AlertsPage
from tech_stack_page import TechStackPage
from create_scan_page import CreateScanPage
from login_page import LoginPage


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WebSET - Website Security Evaluation Tool")
        self.setGeometry(100, 50, 1320, 860)
        self.dark_mode = False
        self.init_ui()
        self.apply_light_theme()

    def init_ui(self):
        central = QWidget()
        central.setObjectName("centralRoot")
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Sidebar
        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(220)
        side = QVBoxLayout(self.sidebar)
        side.setContentsMargins(16, 22, 16, 16)
        side.setSpacing(6)

        self.brand = QLabel("WebSET")
        self.brand.setObjectName("brandTitle")
        side.addWidget(self.brand)

        self.brand_sub = QLabel("Security Evaluation")
        self.brand_sub.setObjectName("brandSub")
        side.addWidget(self.brand_sub)
        side.addSpacing(18)

        self.nav_items = [
            ("Dashboard", 0),
            ("Cases", 1),
            ("Create Scan", 2),
            ("Alerts", 3),
            ("Tech Stack", 4),
            ("Payload", 5),
            ("Report", 6),
        ]
        self.nav_buttons = []
        for text, idx in self.nav_items:
            btn = QPushButton(text)
            btn.setObjectName("navBtn")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, i=idx: self.switch_page(i))
            side.addWidget(btn)
            self.nav_buttons.append(btn)

        side.addStretch()

        self.theme_button = QPushButton("Dark Mode")
        self.theme_button.setObjectName("themeBtn")
        self.theme_button.clicked.connect(self.toggle_theme)
        side.addWidget(self.theme_button)
        root.addWidget(self.sidebar)

        # Content
        self.content = QFrame()
        self.content.setObjectName("contentArea")
        content_layout = QVBoxLayout(self.content)
        content_layout.setContentsMargins(24, 20, 24, 14)
        content_layout.setSpacing(12)

        top = QHBoxLayout()
        self.page_title = QLabel("Dashboard")
        self.page_title.setObjectName("pageTitle")
        top.addWidget(self.page_title)
        top.addStretch()

        self.user_chip = QLabel("Not signed in")
        self.user_chip.setObjectName("userChip")
        top.addWidget(self.user_chip)

        self.signin_btn = QPushButton("Sign in")
        self.signin_btn.setObjectName("signInBtn")
        self.signin_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.signin_btn.setFixedHeight(34)
        self.signin_btn.clicked.connect(self.open_login_page)
        top.addWidget(self.signin_btn)

        self.signout_btn = QPushButton("Sign out")
        self.signout_btn.setObjectName("signOutBtn")
        self.signout_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.signout_btn.setFixedHeight(34)
        self.signout_btn.clicked.connect(self.sign_out)
        self.signout_btn.hide()
        top.addWidget(self.signout_btn)
        content_layout.addLayout(top)

        self.stack = QStackedWidget()
        self.dashboard_page = DashboardPage()
        self.cases_page = CasesPage()
        self.create_scan_page = CreateScanPage()
        self.alerts_page = AlertsPage()
        self.tech_stack_page = TechStackPage()
        self.payload_tab = PayloadTab()
        # Alias used by AlertsPage Active Test hand-off
        self.payload_page = self.payload_tab
        self.report_tab = ReportTab()
        for page in [
            self.dashboard_page,
            self.cases_page,
            self.create_scan_page,
            self.alerts_page,
            self.tech_stack_page,
            self.payload_tab,
            self.report_tab,
        ]:
            self.stack.addWidget(page)

        self.login_page = LoginPage()
        self.login_page.login_succeeded.connect(self.on_login_succeeded)
        self.login_index = self.stack.count()
        self.stack.addWidget(self.login_page)

        self.create_scan_page.scan_finished.connect(self.on_scan_finished)
        content_layout.addWidget(self.stack)
        root.addWidget(self.content, 1)

        self.status = QStatusBar()
        self.status.setObjectName("appStatusBar")
        self.setStatusBar(self.status)
        self.status.showMessage("Ready | WebSET v0.3")

        self.toast = QLabel("", self)
        self.toast.setObjectName("toast")
        self.toast.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.toast.hide()
        self.toast_timer = QTimer(self)
        self.toast_timer.setSingleShot(True)
        self.toast_timer.timeout.connect(self.toast.hide)

        self.switch_page(0)

    # ------------------------------------------------------------------
    # Active Test navigation (Alerts → Payload)
    # ------------------------------------------------------------------
    def show_payload_page(self):
        """Open Payload tab; load Active Test finding if SharedState has one."""
        self.switch_page(5)
        finding = None
        try:
            from core.shared_state import SharedState
            finding = getattr(SharedState, "active_test_finding", None)
        except Exception:
            finding = None
        if finding and hasattr(self.payload_tab, "load_from_finding"):
            self.payload_tab.load_from_finding(finding)
        elif hasattr(self.payload_tab, "refresh_target"):
            self.payload_tab.refresh_target()

    def go_to_payload(self):
        self.show_payload_page()

    def open_payload_page(self):
        self.show_payload_page()

    def open_login_page(self):
        self.stack.setCurrentIndex(self.login_index)
        self.page_title.setText("Sign in")
        for btn in self.nav_buttons:
            btn.setChecked(False)

    def on_login_succeeded(self, user_id: int, display_name: str):
        from core.shared_state import SharedState
        SharedState.set_user(user_id, display_name)
        self.user_chip.setText(f"Signed in: {display_name}")
        self.signin_btn.setText("Account")
        self.signout_btn.show()
        self.switch_page(0)
        if hasattr(self.dashboard_page, "refresh"):
            self.dashboard_page.refresh()
        if hasattr(self.cases_page, "refresh"):
            self.cases_page.refresh()
        self.status.showMessage(f"Signed in as {display_name}")
        self.show_toast(f"Welcome, {display_name}")

    def sign_out(self):
        from core.shared_state import SharedState
        SharedState.current_user_id = None
        SharedState.current_user_name = None
        if hasattr(SharedState, "clear_active_test_finding"):
            SharedState.clear_active_test_finding()
        else:
            SharedState.active_test_finding = None
        self.user_chip.setText("Not signed in")
        self.signin_btn.setText("Sign in")
        self.signout_btn.hide()
        self.status.showMessage("Signed out")
        self.show_toast("Signed out")
        if hasattr(self.cases_page, "refresh"):
            self.cases_page.refresh()
        if hasattr(self.dashboard_page, "refresh"):
            self.dashboard_page.refresh()

    def on_scan_finished(self):
        for page in [
            self.dashboard_page,
            self.cases_page,
            self.alerts_page,
            self.tech_stack_page,
        ]:
            if hasattr(page, "refresh"):
                page.refresh()
        # Payload target may have changed after scan / get stack
        if hasattr(self.payload_tab, "refresh_target"):
            try:
                from core.shared_state import SharedState
                if not getattr(SharedState, "active_test_finding", None):
                    self.payload_tab.refresh_target()
            except Exception:
                self.payload_tab.refresh_target()

    def switch_page(self, index: int):
        titles = [n for n, _ in self.nav_items]
        self.stack.setCurrentIndex(index)
        if 0 <= index < len(titles):
            self.page_title.setText(titles[index])
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)
        if index == 0:
            self.dashboard_page.refresh()
        elif index == 1:
            self.cases_page.refresh()
        elif index == 3:
            self.alerts_page.refresh()
        elif index == 4:
            self.tech_stack_page.refresh()
        elif index == 5:
            # Prefer Active Test hand-off; otherwise refresh session target
            finding = None
            try:
                from core.shared_state import SharedState
                finding = getattr(SharedState, "active_test_finding", None)
            except Exception:
                finding = None
            if finding and hasattr(self.payload_tab, "load_from_finding"):
                self.payload_tab.load_from_finding(finding)
            elif hasattr(self.payload_tab, "refresh_target"):
                self.payload_tab.refresh_target()

    def show_toast(self, message: str, duration_ms: int = 2500):
        self.toast.setText(message)
        self.toast.adjustSize()
        x = (self.width() - self.toast.width()) // 2
        y = self.height() - 72
        self.toast.move(max(12, x), max(12, y))
        self.toast.show()
        self.toast.raise_()
        self.toast_timer.start(duration_ms)

    def _refresh_page_themes(self):
        """Update page titles that sit on the content shell (light vs dark)."""
        for page in (self.alerts_page, self.tech_stack_page):
            if page is not None and hasattr(page, "apply_page_theme"):
                page.apply_page_theme()

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.apply_dark_theme()
            self.theme_button.setText("Light Mode")
        else:
            self.apply_light_theme()
            self.theme_button.setText("Dark Mode")
        self._refresh_page_themes()
        QTimer.singleShot(0, self._refresh_page_themes)
        if hasattr(self.alerts_page, "apply_table_font"):
            QTimer.singleShot(60, self.alerts_page.apply_table_font)
        if hasattr(self.dashboard_page, "refresh"):
            QTimer.singleShot(60, self.dashboard_page.refresh)

    def apply_light_theme(self):
        self.setStyleSheet("""
            QMainWindow {
                background: #eef1f6;
            }
            #contentArea {
                background: #eef1f6;
            }
            #sidebar {
                background: #1f2a57;
                border: none;
            }
            #brandTitle {
                color: #ffffff;
                font-size: 24px;
                font-weight: 800;
                background: transparent;
            }
            #brandSub {
                color: #aeb8d6;
                font-size: 11px;
                background: transparent;
            }
            #navBtn {
                background: transparent;
                color: #d9def0;
                text-align: left;
                padding: 11px 12px;
                border: none;
                border-radius: 8px;
                font-size: 13px;
                font-weight: 600;
            }
            #navBtn:checked {
                background: #2f3f7a;
                color: #ffffff;
            }
            #navBtn:hover:!checked {
                background: #273568;
            }
            #themeBtn {
                background: #2f3f7a;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px;
                font-weight: 600;
            }
            #pageTitle {
                font-size: 22px;
                font-weight: 800;
                color: #1f2a44;
                background: transparent;
            }
            #userChip {
                color: #64748b;
                font-size: 12px;
                background: transparent;
                padding-right: 8px;
            }
            #signInBtn {
                background: #1f2a57;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 8px 14px;
                font-weight: 700;
            }
            #signInBtn:hover {
                background: #2f3f7a;
            }
            #signOutBtn {
                background: #64748b;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 8px 14px;
                font-weight: 700;
            }
            #signOutBtn:hover {
                background: #475569;
            }
            QStatusBar, #appStatusBar {
                background: #1f2a57;
                color: #e8ecf8;
                border-top: 1px solid #2f3f7a;
            }
            QLineEdit, QTextEdit, QComboBox {
                background: #ffffff;
                color: #1f2a44;
                border: 1px solid #d7dbe7;
                border-radius: 8px;
                padding: 8px 10px;
                selection-background-color: #1f2a57;
            }
            QComboBox QAbstractItemView {
                background: white;
                color: #1f2a44;
                selection-background-color: #1f2a57;
                selection-color: white;
            }
            QTableWidget {
                background: white;
                color: #1f2a44;
                gridline-color: #eef0f5;
                border: 1px solid #e3e7f0;
                border-radius: 10px;
            }
            QHeaderView::section {
                background: #1f2a57;
                color: white;
                padding: 9px;
                border: none;
                font-weight: 700;
            }
            QFrame#card {
                background: #ffffff;
                border: 1px solid #e3e7f0;
                border-radius: 12px;
            }
            QProgressBar {
                border: none;
                background: #e6eaf3;
                border-radius: 6px;
                min-height: 10px;
            }
            QProgressBar::chunk {
                background: #3b82f6;
                border-radius: 6px;
            }
            #toast {
                background: #1f2a57;
                color: white;
                padding: 12px 18px;
                border-radius: 10px;
                font-weight: 700;
            }
            QPushButton {
                border: none;
                border-radius: 8px;
            }
            QLabel {
                background: transparent;
            }
        """)

    def apply_dark_theme(self):
        """Dark shell: sidebar, content, and status bar use distinct colors."""
        self.setStyleSheet("""
            QMainWindow {
                background: #0b1220;
            }
            #contentArea {
                background: #111827;
            }
            #sidebar {
                background: #1e3a5f;
                border-right: 1px solid #2d4a6f;
            }
            #brandTitle {
                color: #f8fafc;
                font-size: 24px;
                font-weight: 800;
                background: transparent;
            }
            #brandSub {
                color: #93c5fd;
                font-size: 11px;
                background: transparent;
            }
            #navBtn {
                background: transparent;
                color: #e2e8f0;
                text-align: left;
                padding: 11px 12px;
                border: none;
                border-radius: 8px;
                font-size: 13px;
                font-weight: 600;
            }
            #navBtn:checked {
                background: #3b82f6;
                color: #ffffff;
            }
            #navBtn:hover:!checked {
                background: #2a4a6e;
                color: #ffffff;
            }
            #themeBtn {
                background: #2563eb;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px;
                font-weight: 700;
            }
            #themeBtn:hover {
                background: #3b82f6;
            }
            #pageTitle {
                font-size: 22px;
                font-weight: 800;
                color: #f1f5f9;
                background: transparent;
            }
            #userChip {
                color: #94a3b8;
                font-size: 12px;
                background: transparent;
                padding-right: 8px;
            }
            #signInBtn {
                background: #2563eb;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 8px 14px;
                font-weight: 700;
            }
            #signInBtn:hover {
                background: #3b82f6;
            }
            #signOutBtn {
                background: #475569;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 8px 14px;
                font-weight: 700;
            }
            #signOutBtn:hover {
                background: #64748b;
            }
            QStatusBar, #appStatusBar {
                background: #1e293b;
                color: #e2e8f0;
                border-top: 1px solid #334155;
                font-size: 12px;
                font-weight: 600;
                min-height: 28px;
            }
            QLineEdit, QTextEdit, QComboBox {
                background: #1e293b;
                color: #f1f5f9;
                border: 1px solid #475569;
                border-radius: 8px;
                padding: 8px 10px;
                selection-background-color: #2563eb;
            }
            QComboBox QAbstractItemView {
                background: #1e293b;
                color: #f1f5f9;
                selection-background-color: #2563eb;
                selection-color: white;
                border: 1px solid #475569;
            }
            QTableWidget {
                background: #1e293b;
                color: #f1f5f9;
                gridline-color: #334155;
                border: 1px solid #334155;
                border-radius: 10px;
            }
            QHeaderView::section {
                background: #1e3a5f;
                color: white;
                padding: 9px;
                border: none;
                font-weight: 700;
            }
            QFrame#card {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
            }
            QProgressBar {
                border: none;
                background: #334155;
                border-radius: 6px;
                min-height: 10px;
            }
            QProgressBar::chunk {
                background: #3b82f6;
                border-radius: 6px;
            }
            #toast {
                background: #2563eb;
                color: white;
                padding: 12px 18px;
                border-radius: 10px;
                font-weight: 700;
            }
            QLabel {
                color: #e2e8f0;
                background: transparent;
            }
            QPushButton {
                border: none;
                border-radius: 8px;
            }
        """)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
