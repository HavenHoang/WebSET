from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QProgressBar, QFrame, QFileDialog, QApplication,
    QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer, QObject, QThread, pyqtSignal
from urllib.parse import urlparse, urlunparse
import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

_SCAN_ERROR_MESSAGES = {
    "unreachable": "Target website does not exist or is unreachable",
    "out_of_scope": "Target redirected to a different host, so the scan stopped",
    "invalid_zip": "Invalid or corrupt ZIP file",
    "empty_zip": "ZIP is empty — nothing to analyse",
    "no_analyzable_files": "No analysable source files found in the ZIP",
}
_FIELD_QSS = """
    QLineEdit {
        background: #f8fafc; border: 1px solid #e2e8f0;
        border-radius: 8px; padding: 6px 10px; color: #0f172a;
    }
"""


def _clean_target_url(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    if "://" not in text:
        host = text.split("/")[0].split(":")[0].lower()
        if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".local"):
            text = "http://" + text
        else:
            text = "https://" + text
    p = urlparse(text)
    if not p.netloc:
        return text
    host, sep, port = p.netloc.partition(":")
    if host.lower() in ("localhost", "::1"):
        host = "127.0.0.1"
        netloc = f"{host}:{port}" if port else host
    else:
        netloc = p.netloc
    path = p.path or "/"
    return urlunparse((p.scheme, netloc, path, "", p.query, ""))


def _enrich(findings: list) -> list:
    return findings or []


def _start_scan_only(rows: list) -> list:
    out = []
    for row in rows or []:
        origin = str((row or {}).get("scan_origin") or "").strip().lower()
        if origin == "platform":
            continue
        out.append(row)
    return out


def _display_finding_count(rows: list) -> int:
    rows = rows or []
    try:
        from alerts_page import _collapse_similar_findings
        return len(_collapse_similar_findings(rows))
    except Exception:
        try:
            from gui.alerts_page import _collapse_similar_findings
            return len(_collapse_similar_findings(rows))
        except Exception:
            return len(rows)


def _short_scan_path(label: str) -> str:
    text = str(label or "").strip()
    if "://" in text:
        left, _, rest = text.partition(" · ")
        try:
            parsed = urlparse(left)
            left = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        except Exception:
            pass
        text = f"{left} · {rest}" if rest else left
    if len(text) > 88:
        text = text[:42] + "…" + text[-42:]
    return text or "/"


class _DynamicScanWorker(QObject):
    progress = pyqtSignal(int, int, str)
    done = pyqtSignal(object)

    def __init__(self, url: str):
        super().__init__()
        self._url = url

    def run(self):
        try:
            from core.scan_manager import run_scan
            result = run_scan(self._url, on_progress=self._on_progress)
        except Exception as exc:
            result = {"error": f"Error calling backend: {exc}"}
        self.done.emit(result)

    def _on_progress(self, done, total, label):
        self.progress.emit(int(done or 0), int(total or 0), str(label or ""))


class _StaticScanWorker(QObject):
    progress = pyqtSignal(int, int, str)
    done = pyqtSignal(object)

    def __init__(self, zip_path: str):
        super().__init__()
        self._zip_path = zip_path

    def run(self):
        try:
            from core.scan_manager import run_static_scan
            result = run_static_scan(self._zip_path, on_progress=self._on_progress)
        except Exception as exc:
            result = {"error": f"Error calling backend: {exc}"}
        self.done.emit(result)

    def _on_progress(self, done, total, label):
        self.progress.emit(int(done or 0), int(total or 0), str(label or ""))


class CreateScanPage(QWidget):
    scan_finished = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._progress_value = 0
        self._current_scan_url = None
        self._pending_case_name = None
        self._findings = []
        self._zip_path = None
        self._timer = None
        self._scan_gen = 0
        self._scan_failed = False
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        card = QFrame()
        card.setObjectName("createCard")
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
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
        card_layout.setSpacing(10)
        row_app = QHBoxLayout()
        row_app.addWidget(QLabel("Application/Case Name:"))
        self.app_input = QLineEdit()
        self.app_input.setPlaceholderText("Case name (required)")
        self.app_input.setMinimumHeight(34)
        self.app_input.setStyleSheet(_FIELD_QSS)
        row_app.addWidget(self.app_input)
        card_layout.addLayout(row_app)
        row_url = QHBoxLayout()
        row_url.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://localhost:3000 or https://example.com")
        self.url_input.setMinimumHeight(34)
        self.url_input.setStyleSheet(_FIELD_QSS)
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
        zip_card = QFrame()
        zip_card.setObjectName("createCard")
        zip_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
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
        row_static_app = QHBoxLayout()
        row_static_app.addWidget(QLabel("Application/Case Name:"))
        self.static_app_input = QLineEdit()
        self.static_app_input.setPlaceholderText("Case name for this ZIP scan (required)")
        self.static_app_input.setMinimumHeight(34)
        self.static_app_input.setStyleSheet(_FIELD_QSS)
        row_static_app.addWidget(self.static_app_input)
        zip_layout.addLayout(row_static_app)
        zip_row = QHBoxLayout()
        self.zip_label = QLineEdit()
        self.zip_label.setPlaceholderText("No file selected")
        self.zip_label.setReadOnly(True)
        self.zip_label.setMinimumHeight(34)
        self.zip_label.setStyleSheet(_FIELD_QSS)
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
        layout.addWidget(zip_card)
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(10)
        self.progress.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.progress.setStyleSheet("""
            QProgressBar {
                background: #e2e8f0; border: none; border-radius: 6px;
            }
            QProgressBar::chunk {
                background: #1f2a57; border-radius: 6px;
            }
        """)
        layout.addWidget(self.progress)
        self.status_label = QLabel("Ready to scan.")
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet(
            "color: #334155; background: transparent; border: none;"
        )
        layout.addWidget(self.status_label)
        layout.addStretch(1)
        primary = """
            QPushButton {
                background-color: #1f2a57; color: white; font-weight: 700;
                padding: 9px; border-radius: 8px; border: none;
            }
            QPushButton:hover { background-color: #2f3f7a; }
            QPushButton:disabled { background-color: #94a3b8; }
        """
        secondary = """
            QPushButton {
                background-color: #64748b; color: white; font-weight: 700;
                padding: 9px; border-radius: 8px; border: none;
            }
            QPushButton:hover { background-color: #475569; }
        """
        teal = """
            QPushButton {
                background-color: #0f766e; color: white; font-weight: 700;
                padding: 9px; border-radius: 8px; border: none;
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
            self.scan_button, self.stack_button, self.static_scan_button,
            self.static_stack_button, self.clear_button, self.browse_button,
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

    def _toast(self, message: str):
        main_window = self.window()
        if main_window and hasattr(main_window, "show_toast"):
            main_window.show_toast(message)

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

    def _commit_inputs(self):
        for w in (self.app_input, self.url_input, self.static_app_input):
            if w.hasFocus():
                w.clearFocus()
        QApplication.processEvents()

    def _dynamic_case_name(self) -> str | None:
        name = self.app_input.text().strip()
        return name or None

    def _static_case_name(self) -> str | None:
        name = self.static_app_input.text().strip()
        return name or None

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

    def _fail_dynamic(self, message: str):
        self._scan_failed = True
        self._findings = []
        self._stop_timer()
        self.progress.setValue(0)
        self.scan_button.setEnabled(True)
        self.update_status(message)
        self._toast(message)

    def _refresh_related_pages(self, include_alerts: bool = True, include_tech: bool = True):
        main_window = self.window()
        if not main_window:
            return
        if include_tech and hasattr(main_window, "tech_stack_page"):
            main_window.tech_stack_page.refresh()
        if include_alerts and hasattr(main_window, "alerts_page"):
            main_window.alerts_page.refresh()
        if hasattr(main_window, "cases_page"):
            main_window.cases_page.refresh()
        if hasattr(main_window, "dashboard_page"):
            main_window.dashboard_page.refresh()

    def _session_matches(self, case_name: str, url: str) -> bool:
        try:
            from core.shared_state import SharedState
            sid = getattr(SharedState, "scan_id", None)
            if not sid:
                return False
            prev_case = (getattr(SharedState, "case_name", None) or "").strip().lower()
            new_case = (case_name or "").strip().lower()
            if prev_case != new_case:
                return False
            prev_url = _clean_target_url(getattr(SharedState, "current_url", None) or "").rstrip("/")
            new_url = _clean_target_url(url or "").rstrip("/")
            if prev_url and new_url and prev_url != new_url:
                return False
            return True
        except Exception:
            return False

    def _reset_pipeline_for_target(self, case_name: str, url: str):
        try:
            from core.shared_state import SharedState
        except Exception:
            self._findings = []
            return

        reuse = self._session_matches(case_name, url)
        self._findings = []
        SharedState.findings = []

        if hasattr(SharedState, "scan_cookies"):
            SharedState.scan_cookies = None

        if hasattr(SharedState, "clear_active_test_finding"):
            try:
                SharedState.clear_active_test_finding()
            except Exception:
                SharedState.active_test_finding = None
        else:
            if hasattr(SharedState, "active_test_finding"):
                SharedState.active_test_finding = None

        if not reuse:
            SharedState.scan_id = None
            SharedState.case_id = None
            SharedState.tech_stacks = []
            SharedState.stack_findings = []
            SharedState.current_url = url
            SharedState.case_name = case_name

            if hasattr(SharedState, "_start_scan_active"):
                SharedState._start_scan_active = False


    def _persist_scan_history(self) -> bool:
        try:
            from core.shared_state import SharedState
            from core.db import update_scan_findings_and_stacks
            sid = getattr(SharedState, "scan_id", None)
            if not sid:
                return False
            return bool(
                update_scan_findings_and_stacks(
                    int(sid),
                    getattr(SharedState, "findings", None) or [],
                    getattr(SharedState, "tech_stacks", None),
                    getattr(SharedState, "stack_findings", None) or [],
                )
            )
        except Exception as e:
            print("persist scan history error:", e)
            return False

    def _save_stack_history(
        self,
        *,
        url: str,
        case_name: str,
        scan_type: str,
        stacks: list,
        stack_findings: list,
    ) -> bool:
        try:
            from core.shared_state import SharedState
            from core.db import save_full_scan, update_scan_findings_and_stacks
            user_id = self._require_signed_in()
            if user_id is None:
                return False
            sid = getattr(SharedState, "scan_id", None)
            if not sid:
                ids = save_full_scan(
                    application_name=case_name,
                    url=url,
                    scan_type=scan_type,
                    findings=[],
                    tech_stacks=stacks or None,
                    stack_findings=stack_findings or None,
                    user_id=user_id,
                )
                SharedState.case_id = ids["case_id"]
                SharedState.scan_id = ids["scan_id"]
                SharedState.case_name = case_name
                return True
            return bool(
                update_scan_findings_and_stacks(
                    int(sid),
                    findings=None,
                    tech_stacks=stacks,
                    stack_findings=stack_findings or [],
                )
            )
        except Exception as e:
            print("save stack history error:", e)
            return False

    def clear_form(self):
        self._stop_timer()
        self._scan_failed = True
        self._scan_gen += 1
        self.app_input.clear()
        self.url_input.clear()
        self.static_app_input.clear()
        self.zip_label.clear()
        self._zip_path = None
        self._pending_case_name = None
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
        self._refresh_related_pages(include_alerts=True, include_tech=True)

    def browse_zip(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select web project ZIP", "", "ZIP files (*.zip)"
        )
        if path:
            self._zip_path = path
            self.zip_label.setText(path)

    def get_stack(self):
        if self._require_signed_in() is None:
            return
        self._commit_inputs()
        case_name = self._dynamic_case_name()
        if not case_name:
            self.update_status("Enter Application (case name) before Get Stack")
            self._toast("Enter Application name")
            return
        url = _clean_target_url(self.url_input.text())
        if url:
            self.url_input.setText(url)
        if not url:
            self.update_status("Enter a target URL before Get Stack")
            return
        try:
            from core.shared_state import SharedState
            from core.scan_manager import run_stack_eval_url
            result = run_stack_eval_url(url)
            if isinstance(result, dict) and result.get("error"):
                msg = self._format_scan_error(result.get("error"))
                self.update_status(msg)
                self._toast(msg)
                return
            if not isinstance(result, dict):
                self.update_status("Unexpected response from stack evaluation")
                return
            stacks = result.get("tech_stacks") or []
            stack_findings = result.get("findings") or []
            if not self._session_matches(case_name, url):
                SharedState.scan_id = None
                SharedState.case_id = None
            SharedState.set_stack_result(
                url=url,
                tech_stacks=stacks,
                stack_findings=stack_findings,
                case_name=case_name,
            )
            hist_ok = self._save_stack_history(
                url=url,
                case_name=case_name,
                scan_type="Dynamic",
                stacks=stacks,
                stack_findings=stack_findings,
            )
            n_s, n_f = len(stacks), len(stack_findings)
            if hist_ok:
                status = (
                    f"Tech stack (URL): {n_s} tech(s), {n_f} platform finding(s). "
                    f"Case “{case_name}”. Saved to Cases history."
                )
            else:
                status = (
                    f"Tech stack (URL): {n_s} tech(s), {n_f} platform finding(s). "
                    "Shown on Tech Stack. (History save failed — check DB.)"
                )
            self.update_status(status)
            self._toast(f"Stack: {n_s} tech · {n_f} platform notes")
            self._refresh_related_pages(include_alerts=True, include_tech=True)
        except Exception as e:
            self.update_status(f"Get Stack error: {e}")

    def get_stack_static(self):
        if self._require_signed_in() is None:
            return
        if not self._zip_path or not os.path.isfile(self._zip_path):
            self.update_status("Select a valid ZIP file before Get Stack (ZIP)")
            return
        self._commit_inputs()
        case_name = self._static_case_name()
        if not case_name:
            self.update_status("Enter Application (case name) for the static scan")
            self._toast("Enter Application name for static scan")
            return
        try:
            from core.shared_state import SharedState
            target = self._zip_path
            from core.scan_manager import run_stack_eval_static
            result = run_stack_eval_static(self._zip_path)
            if isinstance(result, dict) and result.get("error"):
                msg = self._format_scan_error(result.get("error"))
                self.update_status(msg)
                self._toast(msg)
                return
            if not isinstance(result, dict):
                self.update_status("Unexpected response from static stack evaluation")
                return
            stacks = result.get("tech_stacks") or []
            stack_findings = result.get("findings") or []
            if not self._session_matches(case_name, target):
                SharedState.scan_id = None
                SharedState.case_id = None
            SharedState.set_stack_result(
                url=target,
                tech_stacks=stacks,
                stack_findings=stack_findings,
                case_name=case_name,
            )
            hist_ok = self._save_stack_history(
                url=target,
                case_name=case_name,
                scan_type="Static",
                stacks=stacks,
                stack_findings=stack_findings,
            )
            n_s, n_f = len(stacks), len(stack_findings)
            if hist_ok:
                status = (
                    f"Tech stack (ZIP): {n_s} tech(s), {n_f} platform finding(s). "
                    f"Case “{case_name}”. Saved to Cases history."
                )
            else:
                status = (
                    f"Tech stack (ZIP): {n_s} tech(s), {n_f} platform finding(s). "
                    "Shown on Tech Stack. (History save failed — check DB.)"
                )
            self.update_status(status)
            self._toast(f"Stack (ZIP): {n_s} tech · {n_f} platform notes")
            self._refresh_related_pages(include_alerts=True, include_tech=True)
        except Exception as e:
            self.update_status(f"Get Stack (ZIP) error: {e}")

    def start_dynamic_scan(self):
        self._stop_timer()
        QTimer.singleShot(0, self._do_dynamic_scan)

    def _do_dynamic_scan(self):
        if self._require_signed_in() is None:
            return
        self._commit_inputs()
        case_name = self._dynamic_case_name()
        if not case_name:
            self.update_status("Enter Application (case name) before Start Scan")
            self._toast("Enter Application name")
            return
        url = _clean_target_url(self.url_input.text())
        if url:
            self.url_input.setText(url)
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
        self._reset_pipeline_for_target(case_name, url)
        self.scan_button.setEnabled(False)
        self.progress.setValue(0)
        self._current_scan_url = url
        self._pending_case_name = case_name
        self._scan_failed = False
        self._findings = []
        self._scan_gen += 1
        gen = self._scan_gen
        self._progress_value = 6
        self.progress.setValue(6)
        self.update_status(f"Scanning  {_short_scan_path(url)}")
        self._start_dynamic_worker(url, gen)

    def _start_dynamic_worker(self, url: str, gen: int):
        thread = QThread(self)
        worker = _DynamicScanWorker(url)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(
            lambda done, total, label, g=gen: self._on_dynamic_progress(g, done, total, label)
        )
        worker.done.connect(
            lambda result, g=gen: self._on_dynamic_worker_done(g, result)
        )
        worker.done.connect(thread.quit)
        worker.done.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        self._scan_thread = thread
        self._scan_worker = worker
        thread.start()

    def _on_dynamic_progress(self, gen: int, done: int, total: int, label: str):
        if gen != self._scan_gen or self._scan_failed:
            return
        shown = _short_scan_path(label)
        if total > 0:
            page_pct = min(92, max(6, int(done * 92 / max(total, 1))))
            self._progress_value = max(self._progress_value, page_pct)
            self.update_status(f"Scanning {done}/{total}  {shown}")
        else:
            self._progress_value = min(90, self._progress_value + 1)
            self.update_status(f"Scanning  {shown}")
        self.progress.setValue(self._progress_value)

    def _on_dynamic_worker_done(self, gen: int, result):
        self._scan_worker = None
        if gen != self._scan_gen or self._scan_failed:
            self.scan_button.setEnabled(True)
            return
        if isinstance(result, dict) and result.get("error"):
            self._fail_dynamic(self._format_scan_error(result.get("error")))
            return
        if not isinstance(result, list):
            self._fail_dynamic("Unexpected response from backend")
            return
        self._findings = _start_scan_only(_enrich(result))
        self.progress.setValue(96)
        self.update_status("Saving scan results...")
        self._save_and_finish_dynamic(gen)

    def _save_and_finish_dynamic(self, gen: int):
        if gen != self._scan_gen or self._scan_failed:
            self.scan_button.setEnabled(True)
            return
        if not self._current_scan_url:
            self.scan_button.setEnabled(True)
            return
        session_n = 0
        try:
            from core.shared_state import SharedState
            from core.db import save_full_scan, update_scan_findings_and_stacks
            user_id = self._require_signed_in()
            if user_id is None:
                self.scan_button.setEnabled(True)
                return
            case_name = self._pending_case_name or self._dynamic_case_name()
            if not case_name:
                self.update_status("Enter Application (case name) before Start Scan")
                self.scan_button.setEnabled(True)
                return
            findings = _start_scan_only(_enrich(self._findings))
            reuse = self._session_matches(case_name, self._current_scan_url)
            existing_sid = getattr(SharedState, "scan_id", None) if reuse else None
            if not reuse:
                SharedState.scan_id = None
                SharedState.case_id = None
                SharedState.tech_stacks = []
                SharedState.stack_findings = []
            stacks_to_save = getattr(SharedState, "tech_stacks", None) or None
            if stacks_to_save == []:
                stacks_to_save = None
            stack_findings = getattr(SharedState, "stack_findings", None) or None
            SharedState.set_scan_result(
                url=self._current_scan_url,
                findings=findings,
                scan_type="Dynamic",
                case_name=case_name,
                tech_stacks=stacks_to_save,
            )
            if existing_sid:
                update_scan_findings_and_stacks(
                    int(existing_sid),
                    findings=findings,
                    tech_stacks=stacks_to_save,
                    stack_findings=None,
                )
                SharedState.scan_id = existing_sid
            else:
                ids = save_full_scan(
                    application_name=case_name,
                    url=self._current_scan_url,
                    scan_type="Dynamic",
                    findings=findings,
                    tech_stacks=stacks_to_save,
                    stack_findings=stack_findings,
                    user_id=user_id,
                )
                SharedState.case_id = ids["case_id"]
                SharedState.scan_id = ids["scan_id"]
                returned = _start_scan_only(ids.get("findings") or findings)
                SharedState.findings = returned or findings
            session_n = _display_finding_count(findings)
        except Exception as e:
            self.progress.setValue(100)
            self.update_status(f"Scan completed (DB save warning: {e})")
            self.scan_button.setEnabled(True)
            self.scan_finished.emit()
            return
        self.progress.setValue(100)
        self.scan_button.setEnabled(True)
        if session_n == 0:
            self.update_status("Scan completed successfully — no issues found | WebSET")
            toast = "Scan completed — no issues found"
        else:
            self.update_status(
                f"Scan completed successfully — {session_n} finding(s) | WebSET"
            )
            toast = f"Scan completed — {session_n} finding(s)"
        self._toast(toast)
        self._refresh_related_pages(include_alerts=True, include_tech=True)
        self.scan_finished.emit()

    def start_static_scan(self):
        if self._require_signed_in() is None:
            return
        if not self._zip_path:
            self.update_status("Please choose a ZIP file first")
            return
        self._commit_inputs()
        case_name = self._static_case_name()
        if not case_name:
            self.update_status("Enter Application (case name) for the static scan")
            self._toast("Enter Application name for static scan")
            return
        self._reset_pipeline_for_target(case_name, self._zip_path)
        self._stop_timer()
        self._pending_case_name = case_name
        self.static_scan_button.setEnabled(False)
        self.static_stack_button.setEnabled(False)
        self._scan_failed = False
        self._findings = []
        self._current_scan_url = self._zip_path
        self._scan_gen += 1
        gen = self._scan_gen
        self.progress.setValue(0)
        self._progress_value = 6
        self.progress.setValue(6)
        self.update_status(f"Static scan  {_short_scan_path(self._zip_path)}")
        self._start_static_worker(self._zip_path, gen)

    def _start_static_worker(self, zip_path: str, gen: int):
        thread = QThread(self)
        worker = _StaticScanWorker(zip_path)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(
            lambda done, total, label, g=gen: self._on_static_progress(g, done, total, label)
        )
        worker.done.connect(
            lambda result, g=gen: self._on_static_worker_done(g, result)
        )
        worker.done.connect(thread.quit)
        worker.done.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        self._static_thread = thread
        self._static_worker = worker
        thread.start()

    def _on_static_progress(self, gen: int, done: int, total: int, label: str):
        if gen != self._scan_gen or self._scan_failed:
            return
        shown = _short_scan_path(label)
        if total > 0:
            page_pct = min(92, max(6, int(done * 92 / max(total, 1))))
            self._progress_value = max(self._progress_value, page_pct)
            self.update_status(f"Static scan {done}/{total}  {shown}")
        else:
            self._progress_value = min(90, self._progress_value + 1)
            self.update_status(f"Static scan  {shown}")
        self.progress.setValue(self._progress_value)

    def _on_static_worker_done(self, gen: int, result):
        self._static_worker = None
        if gen != self._scan_gen:
            self.static_scan_button.setEnabled(True)
            self.static_stack_button.setEnabled(True)
            return
        if isinstance(result, dict) and result.get("error"):
            msg = self._format_scan_error(result.get("error"))
            self.update_status(msg)
            self._toast(msg)
            self.static_scan_button.setEnabled(True)
            self.static_stack_button.setEnabled(True)
            self.progress.setValue(0)
            return
        if isinstance(result, dict) and "findings" in result:
            self._findings = _start_scan_only(_enrich(result.get("findings") or []))
        elif isinstance(result, list):
            self._findings = _start_scan_only(_enrich(result))
        else:
            self.update_status("Unexpected response from static backend")
            self.static_scan_button.setEnabled(True)
            self.static_stack_button.setEnabled(True)
            self.progress.setValue(0)
            return
        self._current_scan_url = self._zip_path
        self.progress.setValue(96)
        self.update_status("Saving static scan results...")
        self._save_and_finish_static()

    def _save_and_finish_static(self):
        session_n = 0
        try:
            from core.shared_state import SharedState
            from core.db import save_full_scan, update_scan_findings_and_stacks
            user_id = self._require_signed_in()
            if user_id is None:
                self.static_scan_button.setEnabled(True)
                self.static_stack_button.setEnabled(True)
                return
            target = self._current_scan_url or self._zip_path
            case_name = self._pending_case_name or self._static_case_name()
            if not case_name:
                self.update_status("Enter Application (case name) for the static scan")
                self.static_scan_button.setEnabled(True)
                self.static_stack_button.setEnabled(True)
                return
            findings = _start_scan_only(_enrich(self._findings))
            reuse = self._session_matches(case_name, target)
            existing_sid = getattr(SharedState, "scan_id", None) if reuse else None
            if not reuse:
                SharedState.scan_id = None
                SharedState.case_id = None
                SharedState.tech_stacks = []
                SharedState.stack_findings = []
            stacks_to_save = getattr(SharedState, "tech_stacks", None) or None
            if stacks_to_save == []:
                stacks_to_save = None
            stack_findings = getattr(SharedState, "stack_findings", None) or None
            SharedState.set_scan_result(
                url=target,
                findings=findings,
                scan_type="Static",
                case_name=case_name,
                tech_stacks=stacks_to_save,
            )
            if existing_sid:
                update_scan_findings_and_stacks(
                    int(existing_sid),
                    findings=findings,
                    tech_stacks=stacks_to_save,
                    stack_findings=None,
                )
                SharedState.scan_id = existing_sid
            else:
                ids = save_full_scan(
                    application_name=case_name,
                    url=target,
                    scan_type="Static",
                    findings=findings,
                    tech_stacks=stacks_to_save,
                    stack_findings=stack_findings,
                    user_id=user_id,
                )
                SharedState.case_id = ids["case_id"]
                SharedState.scan_id = ids["scan_id"]
                returned = _start_scan_only(ids.get("findings") or findings)
                SharedState.findings = returned or findings
            session_n = _display_finding_count(findings)
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
        if session_n == 0:
            self.update_status("Static scan completed — no issues found | WebSET")
            toast = "Static scan — no issues found"
        else:
            self.update_status(
                f"Static scan completed — {session_n} finding(s) | WebSET"
            )
            toast = f"Static scan — {session_n} finding(s)"
        self._toast(toast)
        self._refresh_related_pages(include_alerts=True, include_tech=True)
        self.scan_finished.emit()
