from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QProgressBar, QFrame, QFileDialog
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Backend error code → status message (dynamic + static)
_SCAN_ERROR_MESSAGES = {
    "unreachable": "Target website does not exist or is unreachable",
    "invalid_zip": "Invalid or corrupt ZIP file",
    "empty_zip": "ZIP is empty — nothing to analyse",
    "no_analyzable_files": "No analysable source files found in the ZIP",
}

# ========== DELETE when Member 2 tech detection is ready ==========
def _demo_tech_stacks(url: str = "") -> list:
    """Demo stacks for live URL — Get Stack (dynamic)."""
    host = (url or "").split("://")[-1].split("/")[0] or "target"
    return [
        {
            "name": "Nginx",
            "category": "Web Server",
            "version": "1.24.0",
            "description": f"Reverse proxy / static content (demo for {host}).",
        },
        {
            "name": "Node.js",
            "category": "Runtime",
            "version": "20.x",
            "description": "JavaScript server runtime (demo).",
        },
        {
            "name": "React",
            "category": "Frontend",
            "version": "18.x",
            "description": "UI library detected from client assets (demo).",
        },
        {
            "name": "MySQL",
            "category": "Database",
            "version": "8.0",
            "description": "Relational database layer (demo).",
        },
        {
            "name": "Docker",
            "category": "Infrastructure",
            "version": "",
            "description": "Containerised deployment indicators (demo).",
        },
    ]


def _demo_tech_stacks_from_zip(zip_path: str = "") -> list:
    """Demo stacks for Static ZIP — Get Stack (ZIP) / static scan fallback."""
    name = os.path.basename(zip_path or "") or "project.zip"
    return [
        {
            "name": "PHP",
            "category": "Language",
            "version": "8.x",
            "description": f"PHP markers inferred from archive demo ({name}).",
        },
        {
            "name": "WordPress",
            "category": "CMS",
            "version": "6.x",
            "description": "CMS layout patterns (static demo).",
        },
        {
            "name": "MySQL",
            "category": "Database",
            "version": "8.0",
            "description": "DB usage hinted by config files (static demo).",
        },
        {
            "name": "Apache",
            "category": "Web Server",
            "version": "",
            "description": "Common stack pairing for PHP apps (static demo).",
        },
        {
            "name": "Docker",
            "category": "Infrastructure",
            "version": "",
            "description": "Container metadata in project tree (static demo).",
        },
    ]
# ========== DELETE end ==========


def _enrich(findings: list) -> list:
    # ========== DELETE when Member 1 always returns full CWE/WASC/OWASP fields ==========
    try:
        from core.cwe_map import enrich_findings
        return enrich_findings(findings or [])
    except Exception:
        return findings or []
    # ========== DELETE end ==========
    # ========== UNCOMMENT when Member 1 always returns full CWE/WASC/OWASP fields ==========
    # return findings or []
    # ========== UNCOMMENT end ==========


class CreateScanPage(QWidget):
    scan_finished = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._progress_value = 0
        self._current_scan_url = None
        self._findings = []
        self._zip_path = None
        self._timer = None
        self._scan_gen = 0
        self._scan_failed = False
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(0, 0, 0, 0)

        subtitle = QLabel(
            "Application = Case name (same name reuses the same case for the current user). "
            "Target URL = dynamic scan. ZIP = static analysis. "
            "Sign in required before Get Stack / Scan. "
            "Get Stack works for URL (dynamic) and ZIP (static)."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(
            "color: #64748b; font-size: 12px; background: transparent; border: none;"
        )
        layout.addWidget(subtitle)

        # ===== Dynamic card =====
        card = QFrame()
        card.setObjectName("createCard")
        card.setStyleSheet("""
            QFrame#createCard {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 14px;
            }
            QFrame#createCard QLabel {
                background: transparent;
                border: none;
                color: #475569;
                font-weight: 700;
            }
        """)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 14, 16, 14)
        card_layout.setSpacing(12)

        row_app = QHBoxLayout()
        row_app.addWidget(QLabel("Application:"))
        self.app_input = QLineEdit()
        self.app_input.setPlaceholderText("Sample App")
        self.app_input.setMinimumHeight(34)
        self.app_input.setStyleSheet("""
            QLineEdit {
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 6px 10px;
                color: #0f172a;
            }
        """)
        row_app.addWidget(self.app_input)
        card_layout.addLayout(row_app)

        row_url = QHBoxLayout()
        row_url.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://localhost:3000 or https://example.com")
        self.url_input.setMinimumHeight(34)
        self.url_input.setStyleSheet("""
            QLineEdit {
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 6px 10px;
                color: #0f172a;
            }
        """)
        row_url.addWidget(self.url_input)
        card_layout.addLayout(row_url)

        btn_row = QHBoxLayout()
        self.stack_button = QPushButton("Get Stack")
        self.stack_button.setFixedWidth(120)
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setFixedWidth(120)
        self.clear_button = QPushButton("Clear")
        self.clear_button.setFixedWidth(90)
        btn_row.addWidget(self.stack_button)
        btn_row.addWidget(self.scan_button)
        btn_row.addWidget(self.clear_button)
        btn_row.addStretch()
        card_layout.addLayout(btn_row)
        layout.addWidget(card)

        # ===== Static ZIP card =====
        zip_card = QFrame()
        zip_card.setObjectName("createCard")
        zip_card.setStyleSheet("""
            QFrame#createCard {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 14px;
            }
            QFrame#createCard QLabel {
                background: transparent;
                border: none;
                color: #475569;
                font-weight: 700;
            }
        """)
        zip_layout = QVBoxLayout(zip_card)
        zip_layout.setContentsMargins(16, 14, 16, 14)
        zip_layout.setSpacing(10)

        zip_title = QLabel("Upload and Scan (Static Analysis)")
        zip_title.setStyleSheet(
            "font-size: 14px; font-weight: 800; color: #1f2a44; "
            "background: transparent; border: none;"
        )
        zip_layout.addWidget(zip_title)

        zip_row = QHBoxLayout()
        self.zip_label = QLineEdit()
        self.zip_label.setPlaceholderText("No file selected")
        self.zip_label.setReadOnly(True)
        self.zip_label.setMinimumHeight(34)
        self.zip_label.setStyleSheet("""
            QLineEdit {
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 6px 10px;
                color: #0f172a;
            }
        """)
        self.browse_button = QPushButton("Browse…")
        self.browse_button.setFixedWidth(100)
        self.static_stack_button = QPushButton("Get Stack (ZIP)")
        self.static_stack_button.setFixedWidth(130)
        self.static_scan_button = QPushButton("Start Static Scan")
        self.static_scan_button.setFixedWidth(150)
        zip_row.addWidget(self.zip_label)
        zip_row.addWidget(self.browse_button)
        zip_row.addWidget(self.static_stack_button)
        zip_row.addWidget(self.static_scan_button)
        zip_layout.addLayout(zip_row)

        zip_note = QLabel(
            "Static: Get Stack (ZIP) detects tech from the archive (scope: tech stack "
            "during static analysis). Start Static Scan runs Member 2 unpack + Member 1 "
            "rules via backend. Dynamic URL scan is above."
        )
        zip_note.setWordWrap(True)
        zip_note.setStyleSheet(
            "color: #94a3b8; font-size: 12px; font-weight: 500; "
            "background: transparent; border: none;"
        )
        zip_layout.addWidget(zip_note)
        layout.addWidget(zip_card)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setMinimumHeight(12)
        self.progress.setStyleSheet("""
            QProgressBar {
                background: #e2e8f0;
                border: none;
                border-radius: 6px;
            }
            QProgressBar::chunk {
                background: #1f2a57;
                border-radius: 6px;
            }
        """)
        layout.addWidget(self.progress)

        self.status_label = QLabel("Ready to scan.")
        self.status_label.setStyleSheet(
            "color: #64748b; background: transparent; border: none;"
        )
        layout.addWidget(self.status_label)
        layout.addStretch()

        primary = """
            QPushButton {
                background-color: #1f2a57;
                color: white;
                font-weight: 700;
                padding: 9px;
                border-radius: 8px;
                border: none;
            }
            QPushButton:hover { background-color: #2f3f7a; }
            QPushButton:disabled { background-color: #94a3b8; }
        """
        secondary = """
            QPushButton {
                background-color: #64748b;
                color: white;
                font-weight: 700;
                padding: 9px;
                border-radius: 8px;
                border: none;
            }
            QPushButton:hover { background-color: #475569; }
        """
        teal = """
            QPushButton {
                background-color: #0f766e;
                color: white;
                font-weight: 700;
                padding: 9px;
                border-radius: 8px;
                border: none;
            }
            QPushButton:hover { background-color: #0d9488; }
            QPushButton:disabled { background-color: #94a3b8; }
        """
        self.scan_button.setStyleSheet(primary)
        self.stack_button.setStyleSheet(primary)
        self.static_scan_button.setStyleSheet(primary)
        self.static_stack_button.setStyleSheet(teal)
        self.clear_button.setStyleSheet(secondary)
        self.browse_button.setStyleSheet(secondary)

        for b in (
            self.scan_button,
            self.stack_button,
            self.static_scan_button,
            self.static_stack_button,
            self.clear_button,
            self.browse_button,
        ):
            b.setCursor(Qt.CursorShape.PointingHandCursor)

        self.scan_button.clicked.connect(self.start_dynamic_scan)
        self.stack_button.clicked.connect(self.get_stack)
        self.clear_button.clicked.connect(self.clear_form)
        self.browse_button.clicked.connect(self.browse_zip)
        self.static_stack_button.clicked.connect(self.get_stack_static)
        self.static_scan_button.clicked.connect(self.start_static_scan)

    def update_status(self, message: str):
        self.status_label.setText(message)
        main_window = self.window()
        if main_window and hasattr(main_window, "status"):
            main_window.status.showMessage(message)

    def _require_signed_in(self):
        try:
            from core.shared_state import SharedState
            if not SharedState.is_signed_in():
                self.update_status("Please Sign in first.")
                return None
            return SharedState.current_user_id
        except Exception:
            self.update_status("Please Sign in first.")
            return None

    def _stop_timer(self):
        if self._timer is not None:
            try:
                self._timer.stop()
            except Exception:
                pass
            self._timer = None

    def _format_scan_error(self, err) -> str:
        key = str(err or "").strip()
        return _SCAN_ERROR_MESSAGES.get(key, f"Scan failed: {key}")

    def clear_form(self):
        self._stop_timer()
        self._scan_failed = True
        self._scan_gen += 1
        self.app_input.clear()
        self.url_input.clear()
        self.zip_label.clear()
        self._zip_path = None
        self.progress.setValue(0)
        self.scan_button.setEnabled(True)
        self.static_scan_button.setEnabled(True)
        self.static_stack_button.setEnabled(True)
        self._current_scan_url = None
        self._findings = []
        try:
            from core.shared_state import SharedState
            SharedState.clear()
        except Exception:
            pass
        self.update_status("Ready | WebSET")
        main_window = self.window()
        if main_window and hasattr(main_window, "tech_stack_page"):
            main_window.tech_stack_page.refresh()

    def browse_zip(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select web project ZIP", "", "ZIP files (*.zip)"
        )
        if path:
            self._zip_path = path
            self.zip_label.setText(path)

    def get_stack(self):
        """Tech stack from live URL (dynamic)."""
        if self._require_signed_in() is None:
            return
        url = self.url_input.text().strip()
        if not url:
            self.update_status("Enter a target URL before Get Stack")
            return
        try:
            from core.shared_state import SharedState

            # ========== UNCOMMENT when Member 2 tech detection is ready ==========
            # from crawler.tech_detect import detect_tech_stack
            # SharedState.tech_stacks = detect_tech_stack(url)
            # ========== UNCOMMENT end ==========

            # ========== DELETE when Member 2 tech detection is ready ==========
            SharedState.tech_stacks = _demo_tech_stacks(url)
            # ========== DELETE end ==========

            SharedState.current_url = SharedState.current_url or url
            SharedState.case_name = self.app_input.text().strip() or "Sample App"
            n = len(SharedState.tech_stacks or [])
            self.update_status(
                f"Tech stack (URL): {n} technologies detected. Open Tech Stack page."
            )
            main_window = self.window()
            if main_window and hasattr(main_window, "show_toast"):
                main_window.show_toast(f"Stack (URL): {n} tech(s)")
            if main_window and hasattr(main_window, "tech_stack_page"):
                main_window.tech_stack_page.refresh()
        except Exception as e:
            self.update_status(f"Get Stack error: {e}")

    def get_stack_static(self):
        """Tech stack from ZIP (static analysis path)."""
        if self._require_signed_in() is None:
            return
        if not self._zip_path or not os.path.isfile(self._zip_path):
            self.update_status("Select a valid ZIP file before Get Stack (ZIP)")
            return
        try:
            from core.shared_state import SharedState

            # ========== UNCOMMENT when Member 2 detect_tech_stack_from_path is ready ==========
            # from crawler.unzip import unpack_zip
            # from crawler.tech_detect import detect_tech_stack_from_path
            # files = unpack_zip(self._zip_path)
            # if isinstance(files, dict) and files.get("error"):
            #     self.update_status(self._format_scan_error(files.get("error")))
            #     return
            # project_root = ...  # path Member 2 unpacks to — agree API
            # SharedState.tech_stacks = detect_tech_stack_from_path(project_root)
            # ========== UNCOMMENT end ==========

            # ========== DELETE when Member 2 detect_tech_stack_from_path is ready ==========
            SharedState.tech_stacks = _demo_tech_stacks_from_zip(self._zip_path)
            # ========== DELETE end ==========

            SharedState.current_url = SharedState.current_url or self._zip_path
            SharedState.case_name = (
                self.app_input.text().strip() or "Static ZIP case"
            )
            n = len(SharedState.tech_stacks or [])
            self.update_status(
                f"Tech stack (ZIP): {n} technologies detected. Open Tech Stack page."
            )
            main_window = self.window()
            if main_window and hasattr(main_window, "show_toast"):
                main_window.show_toast(f"Stack (ZIP): {n} tech(s)")
            if main_window and hasattr(main_window, "tech_stack_page"):
                main_window.tech_stack_page.refresh()
        except Exception as e:
            self.update_status(f"Get Stack (ZIP) error: {e}")

    def start_dynamic_scan(self):
        self._stop_timer()
        QTimer.singleShot(0, self._do_dynamic_scan)

    def _do_dynamic_scan(self):
        if self._require_signed_in() is None:
            return

        url = self.url_input.text().strip()
        if not url:
            self.update_status("Please enter a target URL")
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            self.update_status("Invalid URL. Please start with http:// or https://")
            return
        host_part = url.split("://", 1)[1]
        if not host_part or host_part.startswith("/") or " " in host_part:
            self.update_status("Invalid URL. Please enter a full URL")
            return

        self.scan_button.setEnabled(False)
        self.progress.setValue(0)
        self._current_scan_url = url
        self._scan_failed = False
        self._scan_gen += 1
        gen = self._scan_gen
        self.update_status(f"Sending URL to backend: {url}")

        try:
            # ========== DELETE when connecting to real backend (Member 4) ==========
            from core.mock_backend import run_scan
            # ========== DELETE end ==========

            # ========== UNCOMMENT when connecting to real backend (Member 4) ==========
            # from core.scan_manager import run_scan
            # ========== UNCOMMENT end ==========

            result = run_scan(url)

            if isinstance(result, dict) and result.get("error"):
                self._scan_failed = True
                self._stop_timer()
                self.progress.setValue(0)
                self.scan_button.setEnabled(True)
                self.update_status(self._format_scan_error(result.get("error")))
                return

            if not isinstance(result, list):
                self._scan_failed = True
                self._stop_timer()
                self.progress.setValue(0)
                self.scan_button.setEnabled(True)
                self.update_status("Unexpected response from backend")
                return

            self._findings = _enrich(result)
        except Exception as e:
            self._scan_failed = True
            self._stop_timer()
            self.progress.setValue(0)
            self.scan_button.setEnabled(True)
            self.update_status(f"Error calling backend: {e}")
            return

        if gen != self._scan_gen:
            return

        self.update_status("Backend is processing the target...")
        self._progress_value = 0
        self._stop_timer()
        self._timer = QTimer(self)
        self._timer.timeout.connect(lambda: self._update_progress(gen))
        self._timer.start(25)

    def _update_progress(self, gen: int):
        if gen != self._scan_gen or self._scan_failed:
            self._stop_timer()
            return
        self._progress_value += 10
        self.progress.setValue(min(self._progress_value, 100))
        if self._progress_value >= 100:
            self._stop_timer()
            self._save_and_finish_dynamic(gen)

    def _save_and_finish_dynamic(self, gen: int):
        if gen != self._scan_gen or self._scan_failed:
            self.scan_button.setEnabled(True)
            return
        try:
            from core.shared_state import SharedState
            from core.db import save_full_scan

            user_id = self._require_signed_in()
            if user_id is None:
                self.scan_button.setEnabled(True)
                return

            SharedState.current_url = self._current_scan_url
            SharedState.findings = _enrich(self._findings)
            SharedState.scan_type = "Dynamic"
            SharedState.case_name = self.app_input.text().strip() or "Sample App"

            existing_stacks = getattr(SharedState, "tech_stacks", None) or []
            stacks_to_save = existing_stacks if existing_stacks else None

            ids = save_full_scan(
                application_name=SharedState.case_name,
                url=SharedState.current_url,
                scan_type=SharedState.scan_type,
                findings=SharedState.findings,
                tech_stacks=stacks_to_save,
                user_id=user_id,
            )
            SharedState.case_id = ids["case_id"]
            SharedState.scan_id = ids["scan_id"]
            if ids.get("findings") is not None:
                SharedState.findings = ids["findings"]
        except Exception as e:
            self.update_status(f"Scan completed (DB save warning: {e})")
            self.scan_button.setEnabled(True)
            self.scan_finished.emit()
            return

        self.scan_button.setEnabled(True)
        n = len(self._findings or [])
        if n == 0:
            self.update_status(
                "Scan completed successfully — no issues found | WebSET"
            )
            toast = "Scan completed — no issues found"
        else:
            self.update_status(
                f"Scan completed successfully — {n} finding(s) | WebSET"
            )
            toast = "Scan completed successfully"

        main_window = self.window()
        if main_window and hasattr(main_window, "show_toast"):
            main_window.show_toast(toast)
        self.scan_finished.emit()

    def start_static_scan(self):
        if self._require_signed_in() is None:
            return
        if not self._zip_path:
            self.update_status("Please choose a ZIP file first")
            return

        self._stop_timer()
        self.static_scan_button.setEnabled(False)
        self.static_stack_button.setEnabled(False)
        self.progress.setValue(0)
        self.update_status(f"Static scan queued for: {self._zip_path}")

        # ========== UNCOMMENT when static backend is ready (Member 4 + 1 + 2) ==========
        # from core.scan_manager import run_static_scan
        # result = run_static_scan(self._zip_path)
        # if isinstance(result, dict) and result.get("error"):
        #     self.update_status(self._format_scan_error(result.get("error")))
        #     self.static_scan_button.setEnabled(True)
        #     self.static_stack_button.setEnabled(True)
        #     self.progress.setValue(0)
        #     return
        # # Preferred shape: {"findings": [...], "tech_stacks": [...]}
        # if isinstance(result, dict) and "findings" in result:
        #     self._findings = _enrich(result.get("findings") or [])
        #     stacks = result.get("tech_stacks") or []
        #     try:
        #         from core.shared_state import SharedState
        #         if stacks:
        #             SharedState.tech_stacks = stacks
        #     except Exception:
        #         pass
        # elif isinstance(result, list):
        #     self._findings = _enrich(result)
        # else:
        #     self.update_status("Unexpected response from static backend")
        #     self.static_scan_button.setEnabled(True)
        #     self.static_stack_button.setEnabled(True)
        #     self.progress.setValue(0)
        #     return
        # self._current_scan_url = self._zip_path
        # self._save_and_finish_static()
        # return
        # ========== UNCOMMENT end ==========

        # ========== DELETE when static backend is ready ==========
        QTimer.singleShot(400, self._finish_static_demo)
        # ========== DELETE end ==========

    def _save_and_finish_static(self):
        """Used when real run_static_scan is connected (UNCOMMENT path)."""
        try:
            from core.shared_state import SharedState
            from core.db import save_full_scan

            user_id = self._require_signed_in()
            if user_id is None:
                self.static_scan_button.setEnabled(True)
                self.static_stack_button.setEnabled(True)
                return

            SharedState.case_name = self.app_input.text().strip() or "Static ZIP case"
            SharedState.scan_type = "Static"
            SharedState.current_url = self._current_scan_url or self._zip_path
            SharedState.findings = _enrich(self._findings)

            existing_stacks = getattr(SharedState, "tech_stacks", None) or []
            stacks_to_save = existing_stacks if existing_stacks else None

            ids = save_full_scan(
                application_name=SharedState.case_name,
                url=SharedState.current_url,
                scan_type=SharedState.scan_type,
                findings=SharedState.findings,
                tech_stacks=stacks_to_save,
                user_id=user_id,
            )
            SharedState.case_id = ids["case_id"]
            SharedState.scan_id = ids["scan_id"]
            if ids.get("findings") is not None:
                SharedState.findings = ids["findings"]
        except Exception as e:
            self.update_status(f"Static scan completed (DB save warning: {e})")
            self.static_scan_button.setEnabled(True)
            self.static_stack_button.setEnabled(True)
            self.progress.setValue(100)
            self.scan_finished.emit()
            return

        self.progress.setValue(100)
        self.static_scan_button.setEnabled(True)
        self.static_stack_button.setEnabled(True)
        n = len(self._findings or [])
        if n == 0:
            self.update_status("Static scan completed — no issues found | WebSET")
            toast = "Static scan — no issues found"
        else:
            self.update_status(f"Static scan completed — {n} finding(s) | WebSET")
            toast = "Static scan completed"

        main_window = self.window()
        if main_window and hasattr(main_window, "show_toast"):
            main_window.show_toast(toast)
        if main_window and hasattr(main_window, "tech_stack_page"):
            main_window.tech_stack_page.refresh()
        self.scan_finished.emit()

    def _finish_static_demo(self):
        try:
            from core.shared_state import SharedState
            from core.db import save_full_scan

            user_id = self._require_signed_in()
            if user_id is None:
                self.static_scan_button.setEnabled(True)
                self.static_stack_button.setEnabled(True)
                return

            SharedState.case_name = self.app_input.text().strip() or "Static ZIP case"
            SharedState.scan_type = "Static"
            SharedState.current_url = self._zip_path

            # ========== DELETE when static backend is ready ==========
            raw = [
                {
                    "severity": "Medium",
                    "vulnerability": "Static analysis placeholder",
                    "location": self._zip_path,
                    "description": "Replace with Member 1 static rules output",
                    "scan_origin": "Static",
                    "confidence": "Low",
                }
            ]
            SharedState.findings = _enrich(raw)

            # Prefer stacks from Get Stack (ZIP); otherwise demo detect from ZIP
            existing_stacks = getattr(SharedState, "tech_stacks", None) or []
            if existing_stacks:
                stacks_to_save = existing_stacks
            else:
                stacks_to_save = _demo_tech_stacks_from_zip(self._zip_path)
                SharedState.tech_stacks = stacks_to_save
            # ========== DELETE end ==========

            ids = save_full_scan(
                application_name=SharedState.case_name,
                url=SharedState.current_url,
                scan_type=SharedState.scan_type,
                findings=SharedState.findings,
                tech_stacks=stacks_to_save,
                user_id=user_id,
            )
            SharedState.case_id = ids["case_id"]
            SharedState.scan_id = ids["scan_id"]
            if ids.get("findings") is not None:
                SharedState.findings = ids["findings"]
        except Exception as e:
            self.update_status(f"Static scan demo warning: {e}")

        self.progress.setValue(100)
        self.static_scan_button.setEnabled(True)
        self.static_stack_button.setEnabled(True)
        self.update_status("Static scan demo completed (replace with real backend)")
        main_window = self.window()
        if main_window and hasattr(main_window, "show_toast"):
            main_window.show_toast("Static scan demo done")
        if main_window and hasattr(main_window, "tech_stack_page"):
            main_window.tech_stack_page.refresh()
        self.scan_finished.emit()
