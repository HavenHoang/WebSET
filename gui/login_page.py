from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal
import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)


class LoginPage(QWidget):
    login_succeeded = pyqtSignal(int, str)

    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        root = QVBoxLayout(self)
        root.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame()
        card.setObjectName("loginCard")
        card.setFixedWidth(420)
        card.setStyleSheet("""
            QFrame#loginCard {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 16px;
            }
            QFrame#loginCard QLabel {
                background: transparent;
                border: none;
                padding: 0;
            }
            QFrame#loginCard QLineEdit {
                background: #f8fafc;
                border: 1px solid #cbd5e1;
                border-radius: 10px;
                padding: 10px 12px;
                min-height: 20px;
                color: #0f172a;
            }
            QFrame#loginCard QLineEdit:focus {
                border: 1px solid #1f2a57;
            }
        """)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(10)

        title = QLabel("WebSET")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 26px; font-weight: 800; color: #1f2a57;")
        layout.addWidget(title)

        sub = QLabel("Sign in or create an analyst profile")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet("font-size: 13px; color: #64748b;")
        layout.addWidget(sub)
        layout.addSpacing(8)

        u_lab = QLabel("Username")
        u_lab.setStyleSheet("font-size: 12px; font-weight: 700; color: #475569;")
        layout.addWidget(u_lab)
        self.username = QLineEdit()
        self.username.setPlaceholderText("Choose a username")
        layout.addWidget(self.username)

        p_lab = QLabel("Password")
        p_lab.setStyleSheet("font-size: 12px; font-weight: 700; color: #475569;")
        layout.addWidget(p_lab)
        self.password = QLineEdit()
        self.password.setPlaceholderText("Enter password (min 4 characters)")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password)

        layout.addSpacing(6)
        row = QHBoxLayout()
        self.login_btn = QPushButton("Login")
        self.register_btn = QPushButton("Register")
        for b in (self.login_btn, self.register_btn):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setMinimumHeight(40)
        self.login_btn.setStyleSheet("""
            QPushButton {
                background: #1f2a57; color: white; font-weight: 800;
                border: none; border-radius: 10px;
            }
            QPushButton:hover { background: #2f3f7a; }
        """)
        self.register_btn.setStyleSheet("""
            QPushButton {
                background: #16a34a; color: white; font-weight: 800;
                border: none; border-radius: 10px;
            }
            QPushButton:hover { background: #15803d; }
        """)
        row.addWidget(self.login_btn)
        row.addWidget(self.register_btn)
        layout.addLayout(row)

        danger = QHBoxLayout()
        self.delete_btn = QPushButton("Delete this user")
        self.reset_users_btn = QPushButton("Reset all profiles")
        for b in (self.delete_btn, self.reset_users_btn):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setMinimumHeight(36)
        self.delete_btn.setStyleSheet("""
            QPushButton {
                background: #b91c1c; color: white; font-weight: 700;
                border: none; border-radius: 8px;
            }
            QPushButton:hover { background: #991b1b; }
        """)
        self.reset_users_btn.setStyleSheet("""
            QPushButton {
                background: #7f1d1d; color: white; font-weight: 700;
                border: none; border-radius: 8px;
            }
            QPushButton:hover { background: #641616; }
        """)
        danger.addWidget(self.delete_btn)
        danger.addWidget(self.reset_users_btn)
        layout.addLayout(danger)

        self.hint = QLabel("")
        self.hint.setWordWrap(True)
        self.hint.setStyleSheet("font-size: 12px; color: #94a3b8;")
        layout.addWidget(self.hint)

        root.addWidget(card)

        self.login_btn.clicked.connect(self.do_login)
        self.register_btn.clicked.connect(self.do_register)
        self.delete_btn.clicked.connect(self.do_delete_user)
        self.reset_users_btn.clicked.connect(self.do_reset_profiles)
        self.password.returnPressed.connect(self.do_login)

    def _clear_session_ui(self):
        try:
            from core.shared_state import SharedState
            SharedState.current_user_id = None
            SharedState.current_user_name = None
        except Exception:
            pass
        main = self.window()
        if main and hasattr(main, "user_chip"):
            main.user_chip.setText("Not signed in")
        if main and hasattr(main, "signin_btn"):
            main.signin_btn.setText("Sign in")

    def do_login(self):
        username = self.username.text().strip()
        password = self.password.text()
        if not username:
            self.hint.setText("Enter a username to login.")
            return
        if not password:
            self.hint.setText("Enter your password.")
            return
        try:
            from core.db import authenticate_user
            user = authenticate_user(username, password)
            if not user:
                self.hint.setText(
                    "Invalid username or password."
                )
                return
            self.hint.setText("")
            self.password.clear()
            self.login_succeeded.emit(int(user["id"]), user["display_name"])
        except Exception as e:
            self.hint.setText(f"Login error: {e}")

    def do_register(self):
        username = self.username.text().strip()
        password = self.password.text()
        if not username:
            self.hint.setText("Username is required to register.")
            return
        if len(password) < 4:
            self.hint.setText("Password must be at least 4 characters.")
            return
        try:
            from core.db import register_user
            user = register_user(username, password, display_name=username)
            self.hint.setText("")
            self.password.clear()
            self.login_succeeded.emit(int(user["id"]), user["display_name"])
        except ValueError as e:
            self.hint.setText(str(e))
        except Exception as e:
            self.hint.setText(f"Register error: {e}")

    def do_delete_user(self):
        username = self.username.text().strip()
        password = self.password.text()
        if not username:
            self.hint.setText("Enter the username to delete.")
            return
        if not password:
            self.hint.setText("Enter the password for this user to delete.")
            return

        try:
            from core.db import authenticate_user, delete_user_by_username
            from core.shared_state import SharedState

            user = authenticate_user(username, password)
            if not user:
                self.hint.setText(
                    "Cannot delete: username or password is incorrect."
                )
                return

            reply = QMessageBox.question(
                self,
                "Delete user",
                f"Delete user “{username}” permanently?\n\n"
                "This account will be removed. Scan history is kept under archive.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                self.hint.setText("Delete cancelled.")
                return

            ok = delete_user_by_username(username)
            if not ok:
                self.hint.setText("User not found.")
                return

            if SharedState.current_user_id is not None:
                try:
                    if int(SharedState.current_user_id) == int(user["id"]):
                        SharedState.current_user_id = None
                        SharedState.current_user_name = None
                        SharedState.clear()
                except Exception:
                    SharedState.current_user_id = None
                    SharedState.current_user_name = None

            self._clear_session_ui()
            self.password.clear()
            self.hint.setText(f"Deleted user: {username}")
            main = self.window()
            if main and hasattr(main, "cases_page"):
                main.cases_page.refresh()
            if main and hasattr(main, "dashboard_page"):
                main.dashboard_page.refresh()
        except Exception as e:
            self.hint.setText(f"Delete error: {e}")

    def do_reset_profiles(self):
        reply = QMessageBox.question(
            self,
            "Reset all profiles",
            "Delete ALL user profiles?\n\n"
            "Scan history is kept under archive. You will need to register again.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            self.hint.setText("Reset cancelled.")
            return
        try:
            from core.db import reset_user_profiles
            from core.shared_state import SharedState
            reset_user_profiles()
            SharedState.current_user_id = None
            SharedState.current_user_name = None
            SharedState.clear()
            self._clear_session_ui()
            self.password.clear()
            self.hint.setText(
                "All user profiles cleared. Register a new account to continue."
            )
            main = self.window()
            if main and hasattr(main, "cases_page"):
                main.cases_page.refresh()
            if main and hasattr(main, "dashboard_page"):
                main.dashboard_page.refresh()
        except Exception as e:
            self.hint.setText(f"Reset error: {e}")
