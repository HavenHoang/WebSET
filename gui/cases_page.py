from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QPushButton, QFrame,
    QProgressBar, QMessageBox, QComboBox, QSplitter,
    QStyleFactory, QListView, QDialog, QAbstractItemView, QScrollArea,
    QSizePolicy
)
from PyQt6.QtCore import Qt, QPoint
from PyQt6.QtGui import QColor, QFont, QPainter, QBrush, QPixmap, QIcon, QPalette
import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

PLATFORM_ORIGIN = "Platform"


def _short_url(url: str, max_len: int = 42) -> str:
    if not url:
        return ""
    text = url.strip()
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def _short_time(created: str) -> str:
    if not created:
        return ""
    text = str(created).replace("T", " ")
    try:
        date_part, time_part = text.split(" ")
        y, m, d = date_part.split("-")
        hhmm = time_part[:5]
        months = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ]
        return f"{int(d):02d} {months[int(m) - 1]} {hhmm}"
    except Exception:
        return text[:16]


def _shorten(text: str, limit: int = 48) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _enrich_findings(findings: list) -> list:
    """Fill CWE/WASC/OWASP/NIST/SANS on historical rows if missing (demo fallback)."""
    # ========== DELETE when Member 1 always returns full CWE/WASC/OWASP/NIST/SANS fields ==========
    try:
        from core.cwe_map import enrich_findings
        return enrich_findings(findings or [])
    except Exception:
        return findings or []
    # ========== DELETE end ==========
    # ========== UNCOMMENT when Member 1 always returns full CWE/WASC/OWASP/NIST/SANS fields ==========
    # return findings or []
    # ========== UNCOMMENT end ==========


def _standards_cell(f: dict) -> str:
    cwe = str(f.get("cwe_id") or f.get("cweId") or "—")
    owasp = str(f.get("owasp") or "").strip()
    nist = str(f.get("nist") or f.get("nist_id") or "—")
    sans = str(f.get("sans") or f.get("sans_id") or "—")
    lines = [f"CWE: {cwe}"]
    if owasp:
        lines.append(f"OWASP: {owasp}")
    lines.append(f"NIST: {_shorten(nist, 32)}")
    lines.append(f"SANS: {_shorten(sans, 32)}")
    return "\n".join(lines)


def _std_tip(f: dict) -> str:
    parts = [
        f"CWE: {f.get('cwe_id') or f.get('cweId') or '—'}",
        f"WASC: {f.get('wasc_id') or f.get('wascId') or '—'}",
        f"OWASP: {f.get('owasp') or '—'}",
        f"NIST: {f.get('nist') or f.get('nist_id') or '—'}",
        f"SANS: {f.get('sans') or f.get('sans_id') or '—'}",
        f"Confidence: {f.get('confidence') or '—'}",
        f"Plugin: {f.get('plugin_id') or f.get('pluginId') or '—'}",
    ]
    rem = str(f.get("remediation") or "").strip()
    if rem:
        parts.append(f"Remediation: {rem}")
    desc = str(f.get("description") or "").strip()
    if desc:
        parts.append(f"Description: {desc}")
    return "\n".join(parts)


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
QComboBox#sortCombo {
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #94a3b8;
    border-radius: 8px;
    padding: 6px 10px;
    min-height: 32px;
    font-size: 13px;
}
QComboBox#sortCombo:hover {
    border: 1px solid #1e3a8a;
}
QComboBox#sortCombo::drop-down {
    border: none;
    width: 28px;
}
"""


class ReadableCombo(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sortCombo")
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


class ScanDetailDialog(QDialog):
    def __init__(self, scan: dict, findings: list, local_scan_no: int | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan detail")
        self.setMinimumSize(1100, 680)
        self.resize(1180, 760)
        self.setStyleSheet("""
            QDialog {
                background: #f1f5f9;
            }
        """)
        self._build(scan, findings, local_scan_no)

    def _badge(self, severity: str) -> QWidget:
        colors = {
            "High": ("#fecaca", "#991b1b"),
            "Medium": ("#fde68a", "#92400e"),
            "Low": ("#e2e8f0", "#334155"),
        }
        bg, fg = colors.get(severity, colors["Low"])
        lab = QLabel(severity)
        lab.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lab.setFixedHeight(26)
        lab.setMinimumWidth(72)
        lab.setStyleSheet(
            f"background:{bg}; color:{fg}; border-radius:8px; "
            f"font-weight:700; font-size:12px; padding:2px 10px;"
        )
        wrap = QWidget()
        wrap.setStyleSheet("background: transparent;")
        lay = QHBoxLayout(wrap)
        lay.setContentsMargins(6, 10, 6, 10)
        lay.addWidget(lab)
        return wrap

    def _item(self, text: str, *, bold=False, color="#0f172a", center=False, tip=None):
        it = QTableWidgetItem(str(text))
        font = QFont("Arial", 11, QFont.Weight.Bold if bold else QFont.Weight.Normal)
        it.setFont(font)
        it.setForeground(QBrush(QColor(color)))
        if center:
            it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        else:
            it.setTextAlignment(
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft
            )
        if tip:
            it.setToolTip(str(tip))
        return it

    def _make_empty_card(self, title: str, body: str) -> QFrame:
        """Polished empty state — used when a findings table has no rows."""
        card = QFrame()
        card.setObjectName("emptyCard")
        card.setMinimumHeight(100)
        card.setStyleSheet("""
            QFrame#emptyCard {
                background: #ffffff;
                border: 1px dashed #cbd5e1;
                border-radius: 12px;
            }
        """)
        lay = QVBoxLayout(card)
        lay.setContentsMargins(20, 22, 20, 22)
        lay.setSpacing(6)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)

        t = QLabel(title)
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        t.setStyleSheet(
            "font-size: 14px; font-weight: 800; color: #475569; "
            "background: transparent; border: none;"
        )
        lay.addWidget(t)

        b = QLabel(body)
        b.setAlignment(Qt.AlignmentFlag.AlignCenter)
        b.setWordWrap(True)
        b.setStyleSheet(
            "font-size: 13px; font-weight: 500; color: #94a3b8; "
            "background: transparent; border: none;"
        )
        lay.addWidget(b)
        return card

    def _make_findings_table(self, findings: list) -> QTableWidget:
        table = QTableWidget(0, 7)
        table.setHorizontalHeaderLabels(
            ["Risk", "Vulnerability", "Standards", "Conf.", "Location", "Description", "Remediation"]
        )
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setWordWrap(True)
        table.setMouseTracking(True)
        table.viewport().setMouseTracking(True)
        table.setTextElideMode(Qt.TextElideMode.ElideNone)
        table.setMinimumHeight(160)
        hh = table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        table.setColumnWidth(0, 88)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        table.setColumnWidth(2, 150)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        table.setColumnWidth(3, 64)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        table.setStyleSheet("""
            QTableWidget {
                background: #ffffff;
                color: #0f172a;
                border: 1px solid #e2e8f0;
                border-radius: 10px;
                gridline-color: #e2e8f0;
                alternate-background-color: #f8fafc;
            }
            QHeaderView::section {
                background: #1e3a5f;
                color: #ffffff;
                padding: 10px 8px;
                border: none;
                font-weight: 700;
            }
            QTableWidget::item {
                color: #0f172a;
                padding: 6px;
            }
            QTableWidget::item:selected {
                background: #dbeafe;
                color: #0f172a;
            }
        """)

        name_font = QFont("Arial", 11, QFont.Weight.Bold)
        normal = QFont("Arial", 11)
        std_font = QFont("Arial", 10)
        vcenter = Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft

        for i, f in enumerate(findings):
            table.insertRow(i)
            tip_text = _std_tip(f)
            sev = str(f.get("severity", "Low"))
            table.setCellWidget(i, 0, self._badge(sev))

            name = str(f.get("vulnerability", f.get("name", "")))
            name_item = self._item(name, bold=True, color="#0f172a", tip=tip_text)
            name_item.setFont(name_font)
            table.setItem(i, 1, name_item)

            std_text = _standards_cell(f)
            std_item = QTableWidgetItem(std_text)
            std_item.setFont(std_font)
            std_item.setForeground(QBrush(QColor("#1d4ed8")))
            std_item.setTextAlignment(vcenter)
            std_item.setToolTip(tip_text)
            table.setItem(i, 2, std_item)

            conf = str(f.get("confidence") or "—")
            table.setItem(
                i, 3, self._item(conf, color="#334155", center=True, tip=tip_text)
            )

            loc = str(f.get("location") or f.get("url") or "")
            loc_item = self._item(
                _short_url(loc, 52), color="#475569", tip=loc or tip_text
            )
            loc_item.setFont(normal)
            table.setItem(i, 4, loc_item)

            desc = str(f.get("description") or "")
            desc_item = self._item(desc, color="#334155", tip=desc or tip_text)
            desc_item.setFont(normal)
            table.setItem(i, 5, desc_item)

            rem = str(f.get("remediation") or "").strip() or "—"
            rem_item = self._item(
                rem, color="#0f766e", tip=rem if rem != "—" else tip_text
            )
            rem_item.setFont(normal)
            table.setItem(i, 6, rem_item)

            lines = max(
                std_text.count("\n") + 1,
                max(1, (len(desc) // 48) + 1),
                max(1, (len(rem) // 48) + 1),
                2,
            )
            table.setRowHeight(i, max(72, 22 * lines + 16))
        return table

    def _build(self, scan: dict, findings: list, local_scan_no: int | None):
        findings = _enrich_findings(findings or [])
        scan_findings = [
            f for f in findings
            if str(f.get("scan_origin") or "") != PLATFORM_ORIGIN
        ]
        platform_findings = [
            f for f in findings
            if str(f.get("scan_origin") or "") == PLATFORM_ORIGIN
        ]

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        outer.addWidget(scroll, 1)

        body = QWidget()
        body.setStyleSheet("background: transparent;")
        root = QVBoxLayout(body)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(12)
        scroll.setWidget(body)

        case_name = scan.get("case_name") or "—"
        sid = scan.get("scan_id")
        url = scan.get("url") or "—"
        stype = scan.get("scan_type") or "Dynamic"
        status = scan.get("status") or "—"
        created = _short_time(scan.get("created_at") or "")
        no_label = f"#{local_scan_no}" if local_scan_no else f"ID {sid}"

        header = QLabel(f"Scan {no_label} · Case: {case_name}")
        header.setStyleSheet(
            "font-size: 18px; font-weight: 800; color: #0f172a; background: transparent;"
        )
        root.addWidget(header)

        meta = QFrame()
        meta.setStyleSheet(
            "QFrame { background:#ffffff; border:1px solid #e2e8f0; border-radius:12px; }"
        )
        ml = QVBoxLayout(meta)
        ml.setContentsMargins(14, 12, 14, 12)
        ml.setSpacing(4)
        for line in (
            f"<b>URL / path:</b> {url}",
            f"<b>Type:</b> {stype} &nbsp;&nbsp; <b>Status:</b> {status} "
            f"&nbsp;&nbsp; <b>Created:</b> {created}",
            f"<b>Global scan id:</b> {sid}",
        ):
            lab = QLabel(line)
            lab.setWordWrap(True)
            lab.setTextFormat(Qt.TextFormat.RichText)
            lab.setStyleSheet(
                "color:#334155; font-size:13px; background:transparent; border:none;"
            )
            ml.addWidget(lab)
        root.addWidget(meta)

        counts = {"High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            sev = str(f.get("severity", "Low"))
            if sev not in counts:
                sev = "Low"
            counts[sev] += 1
        total = sum(counts.values())

        sum_row = QHBoxLayout()
        for key, color in (
            ("High", "#b91c1c"),
            ("Medium", "#b45309"),
            ("Low", "#475569"),
            ("Total", "#1e3a8a"),
        ):
            val = total if key == "Total" else counts[key]
            chip = QLabel(f"{key}: {val}")
            chip.setStyleSheet(
                f"background:{color}; color:white; font-weight:700; "
                f"padding:6px 12px; border-radius:8px; font-size:12px;"
            )
            sum_row.addWidget(chip)
        sum_row.addStretch()
        note = QLabel(
            f"Start Scan: {len(scan_findings)} · Platform (Get Stack): {len(platform_findings)}"
        )
        note.setStyleSheet("color:#64748b; font-size:12px; font-weight:600;")
        sum_row.addWidget(note)
        root.addLayout(sum_row)

        tip = QLabel(
            "Historical record · Scan findings and Platform evaluation are stored separately "
            "(CWE / OWASP / NIST / SANS / remediation)."
        )
        tip.setStyleSheet("color:#64748b; font-size:11px; background: transparent;")
        tip.setWordWrap(True)
        root.addWidget(tip)

        # ---- Start Scan findings ----
        sec1 = QLabel("Scan findings (Start Scan)")
        sec1.setStyleSheet(
            "font-size: 14px; font-weight: 800; color: #0f172a; background: transparent;"
        )
        root.addWidget(sec1)
        if scan_findings:
            root.addWidget(self._make_findings_table(scan_findings), 1)
        else:
            root.addWidget(
                self._make_empty_card(
                    "No Start Scan findings",
                    "Run Start Scan from Create Scan to store scan findings here.",
                )
            )

        # ---- Platform evaluation ----
        sec2 = QLabel("Platform evaluation (Get Stack)")
        sec2.setStyleSheet(
            "font-size: 14px; font-weight: 800; color: #0f172a; background: transparent;"
        )
        root.addWidget(sec2)
        if platform_findings:
            root.addWidget(self._make_findings_table(platform_findings), 1)
        else:
            root.addWidget(
                self._make_empty_card(
                    "No platform evaluation notes",
                    "Run Get Stack (URL or ZIP) from Create Scan to add them.",
                )
            )

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setFixedWidth(120)
        close_btn.setMinimumHeight(36)
        close_btn.setStyleSheet("""
            QPushButton {
                background:#1f2a57; color:white; font-weight:800;
                border:none; border-radius:8px;
            }
            QPushButton:hover { background:#2f3f7a; }
        """)
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)
        root.addLayout(btn_row)


class CasesPage(QWidget):
    def __init__(self):
        super().__init__()
        self._cases = []
        self._selected_case_id = None
        self._scan_local_nos = {}
        self.init_ui()
        self.refresh()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 0, 0, 0)

        top = QHBoxLayout()
        self.hint = QLabel("Sign in to view your cases")
        self.hint.setStyleSheet(
            "color: #94a3b8; font-size: 12px; background: transparent; border: none;"
        )
        top.addWidget(self.hint)
        top.addStretch()

        sort_lab = QLabel("Sort")
        sort_lab.setStyleSheet(
            "color: #94a3b8; font-size: 12px; background: transparent;"
        )
        top.addWidget(sort_lab)

        self.sort_combo = ReadableCombo()
        self.sort_combo.addItem("Newest first", "newest")
        self.sort_combo.addItem("Name A–Z", "name")
        self.sort_combo.addItem("Most scans", "scans")
        self.sort_combo.setFixedWidth(150)
        self.sort_combo.currentIndexChanged.connect(self.refresh)
        top.addWidget(self.sort_combo)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background: #1f2a57; color: white; font-weight: 700;
                border: none; border-radius: 8px; padding: 8px 14px;
            }
            QPushButton:hover { background: #2f3f7a; }
        """)
        self.refresh_btn.clicked.connect(self.refresh)
        top.addWidget(self.refresh_btn)

        self.delete_btn = QPushButton("Delete case")
        self.delete_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.delete_btn.setStyleSheet("""
            QPushButton {
                background: #b45309; color: white; font-weight: 700;
                border: none; border-radius: 8px; padding: 8px 14px;
            }
            QPushButton:hover { background: #92400e; }
        """)
        self.delete_btn.clicked.connect(self.delete_selected_case)
        top.addWidget(self.delete_btn)

        self.clear_btn = QPushButton("Clear my history")
        self.clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background: #e74c3c; color: white; font-weight: 700;
                border: none; border-radius: 8px; padding: 8px 14px;
            }
            QPushButton:hover { background: #c0392b; }
        """)
        self.clear_btn.clicked.connect(self.clear_history)
        top.addWidget(self.clear_btn)
        layout.addLayout(top)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)

        cases_panel = QFrame()
        cases_panel.setObjectName("casesPanel")
        cases_panel.setStyleSheet("""
            QFrame#casesPanel {
                background: #0f2744;
                border-radius: 14px;
            }
        """)
        cp_l = QVBoxLayout(cases_panel)
        cp_l.setContentsMargins(16, 14, 16, 14)
        cp_l.setSpacing(8)

        self.head = QLabel("Your cases")
        self.head.setStyleSheet(
            "color: white; font-size: 15px; font-weight: 800; "
            "background: transparent; border: none;"
        )
        cp_l.addWidget(self.head)

        self.cases_table = QTableWidget()
        self.cases_table.setColumnCount(4)
        self.cases_table.setHorizontalHeaderLabels(
            ["CASE", "APPLICATION", "SCANS", "CREATED"]
        )
        ch = self.cases_table.horizontalHeader()
        ch.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        ch.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        ch.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        ch.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.cases_table.verticalHeader().setVisible(False)
        self.cases_table.setShowGrid(False)
        self.cases_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.cases_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.cases_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.cases_table.setStyleSheet(self._table_qss())
        self.cases_table.itemSelectionChanged.connect(self._on_case_selected)
        cp_l.addWidget(self.cases_table, 1)

        self.empty_wrap = QWidget()
        self.empty_wrap.setStyleSheet("background: transparent;")
        empty_l = QVBoxLayout(self.empty_wrap)
        empty_l.addStretch(1)
        self.empty_label = QLabel("Sign in to view your cases")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setStyleSheet(
            "color: #94a3b8; font-size: 15px; font-weight: 600; "
            "background: transparent; border: none;"
        )
        empty_l.addWidget(self.empty_label)
        empty_l.addStretch(1)
        cp_l.addWidget(self.empty_wrap, 1)
        self.empty_wrap.hide()
        splitter.addWidget(cases_panel)

        scans_panel = QFrame()
        scans_panel.setObjectName("casesPanel")
        scans_panel.setStyleSheet("""
            QFrame#casesPanel {
                background: #0f2744;
                border-radius: 14px;
            }
        """)
        sp_l = QVBoxLayout(scans_panel)
        sp_l.setContentsMargins(16, 14, 16, 14)
        sp_l.setSpacing(8)

        self.scan_head = QLabel("Scans in selected case")
        self.scan_head.setStyleSheet(
            "color: white; font-size: 14px; font-weight: 800; "
            "background: transparent; border: none;"
        )
        sp_l.addWidget(self.scan_head)

        self.scan_tip = QLabel(
            "Double-click a scan row to open detail. "
            "FINDINGS = Start Scan · PLATFORM = Get Stack notes."
        )
        self.scan_tip.setStyleSheet(
            "color: #94a3b8; font-size: 12px; background: transparent; border: none;"
        )
        self.scan_tip.setWordWrap(True)
        sp_l.addWidget(self.scan_tip)

        self.scans_table = QTableWidget()
        self.scans_table.setColumnCount(6)
        self.scans_table.setHorizontalHeaderLabels(
            ["SCAN", "TYPE", "STATUS", "PROGRESS", "FINDINGS", "PLATFORM"]
        )
        sh = self.scans_table.horizontalHeader()
        sh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, 6):
            sh.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.scans_table.verticalHeader().setVisible(False)
        self.scans_table.setShowGrid(False)
        self.scans_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.scans_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.scans_table.setStyleSheet(self._table_qss())
        self.scans_table.cellDoubleClicked.connect(self._on_scan_double_clicked)
        sp_l.addWidget(self.scans_table, 1)
        splitter.addWidget(scans_panel)

        splitter.setSizes([320, 280])
        layout.addWidget(splitter, 1)

    def _table_qss(self) -> str:
        return """
            QTableWidget {
                background: transparent;
                color: #e2e8f0;
                border: none;
                font-size: 13px;
            }
            QHeaderView::section {
                background: #0f2744;
                color: #94a3b8;
                border: none;
                padding: 8px 4px;
                font-weight: 700;
                font-size: 11px;
            }
            QTableWidget::item:selected { background: #1a3a5c; }
        """

    def _make_avatar(self, letter: str) -> QIcon:
        pm = QPixmap(32, 32)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(QColor("#2dd4bf")))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(0, 0, 32, 32)
        p.setPen(QColor("white"))
        p.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        p.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter, (letter or "S")[:1].upper())
        p.end()
        return QIcon(pm)

    def refresh(self):
        self.cases_table.setRowCount(0)
        self.scans_table.setRowCount(0)
        self._cases = []
        self._selected_case_id = None
        self._scan_local_nos = {}
        self.scan_head.setText("Scans in selected case")

        signed_in = False
        try:
            from core.shared_state import SharedState
            from core.db import list_cases
            if SharedState.is_signed_in():
                signed_in = True
                self.hint.setText(f"Signed in as {SharedState.current_user_name}")
                self._cases = list_cases(user_id=SharedState.current_user_id)
            else:
                self.hint.setText("Sign in to view your cases")
                self._cases = []
        except Exception as e:
            self.hint.setText(f"Could not load cases: {e}")
            print("Cases load error:", e)
            self._cases = []

        mode = self.sort_combo.currentData()
        if mode == "name":
            self._cases.sort(key=lambda c: (c.get("case_name") or "").lower())
        elif mode == "scans":
            self._cases.sort(key=lambda c: int(c.get("scan_count") or 0), reverse=True)
        else:
            self._cases.sort(key=lambda c: int(c.get("case_id") or 0), reverse=True)

        if not self._cases:
            self.cases_table.hide()
            self.empty_wrap.show()
            self.empty_label.setText(
                "No cases yet — create one from Create Scan"
                if signed_in
                else "Sign in to view your cases"
            )
            return

        self.empty_wrap.hide()
        self.cases_table.show()

        by_id = sorted(self._cases, key=lambda c: int(c.get("case_id") or 0))
        case_no_map = {
            int(c["case_id"]): idx + 1
            for idx, c in enumerate(by_id)
            if c.get("case_id") is not None
        }

        for i, row in enumerate(self._cases):
            self.cases_table.insertRow(i)
            self.cases_table.setRowHeight(i, 48)
            cid = int(row.get("case_id") or 0)
            display_no = case_no_map.get(cid, i + 1)

            case_item = QTableWidgetItem(f"#{display_no}")
            case_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            case_item.setData(Qt.ItemDataRole.UserRole, cid)
            self.cases_table.setItem(i, 0, case_item)

            name = row.get("case_name") or "Untitled"
            name_item = QTableWidgetItem(name)
            name_item.setIcon(self._make_avatar(name[:1]))
            name_item.setFont(QFont("Arial", 12, QFont.Weight.DemiBold))
            name_item.setForeground(QColor("#f1f5f9"))
            name_item.setData(Qt.ItemDataRole.UserRole, cid)
            self.cases_table.setItem(i, 1, name_item)

            scan_item = QTableWidgetItem(str(row.get("scan_count", 0)))
            scan_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.cases_table.setItem(i, 2, scan_item)

            created = _short_time(row.get("created_at") or "")
            created_item = QTableWidgetItem(created)
            created_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.cases_table.setItem(i, 3, created_item)

    def _on_case_selected(self):
        rows = self.cases_table.selectionModel().selectedRows()
        if not rows:
            self._selected_case_id = None
            self.scans_table.setRowCount(0)
            self.scan_head.setText("Scans in selected case")
            return
        r = rows[0].row()
        item = self.cases_table.item(r, 0)
        if not item:
            return
        case_id = item.data(Qt.ItemDataRole.UserRole)
        if case_id is None:
            return
        self._selected_case_id = int(case_id)
        name = ""
        for c in self._cases:
            if int(c.get("case_id") or 0) == self._selected_case_id:
                name = c.get("case_name") or ""
                break
        self.scan_head.setText(
            f"Scans in case: {name}" if name else "Scans in selected case"
        )
        self._load_scans_for_case(self._selected_case_id)

    def _load_scans_for_case(self, case_id: int):
        self.scans_table.setRowCount(0)
        self._scan_local_nos = {}
        try:
            from core.db import list_scans_for_case
            scans = list_scans_for_case(case_id)
        except Exception as e:
            print("Load scans error:", e)
            return

        ordered = sorted(scans, key=lambda s: int(s.get("scan_id") or 0))
        scan_no_map = {
            int(s["scan_id"]): idx + 1
            for idx, s in enumerate(ordered)
            if s.get("scan_id") is not None
        }
        self._scan_local_nos = scan_no_map

        for i, row in enumerate(scans):
            self.scans_table.insertRow(i)
            self.scans_table.setRowHeight(i, 48)
            sid = int(row.get("scan_id") or 0)
            local_no = scan_no_map.get(sid, i + 1)
            url = row.get("url") or ""
            created = _short_time(row.get("created_at") or "")
            label = f"Scan #{local_no}"
            if created:
                label += f" · {created}"
            if url:
                label += f"\n{_short_url(url)}"
            cell = QTableWidgetItem(label)
            cell.setFont(QFont("Arial", 11, QFont.Weight.DemiBold))
            cell.setForeground(QColor("#f1f5f9"))
            cell.setData(Qt.ItemDataRole.UserRole, sid)
            cell.setToolTip(url or f"Scan id {sid}")
            self.scans_table.setItem(i, 0, cell)

            type_item = QTableWidgetItem(str(row.get("scan_type") or "Dynamic"))
            type_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.scans_table.setItem(i, 1, type_item)

            status_item = QTableWidgetItem(f"● {row.get('status') or 'Complete'}")
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            status_item.setForeground(QColor("#fbbf24"))
            self.scans_table.setItem(i, 2, status_item)

            wrap = QWidget()
            wrap.setStyleSheet("background: transparent;")
            wl = QHBoxLayout(wrap)
            wl.setContentsMargins(6, 12, 6, 12)
            bar = QProgressBar()
            pct = int(row.get("progress") or 100)
            bar.setValue(pct)
            bar.setFormat(f"{pct}%")
            bar.setFixedHeight(16)
            bar.setStyleSheet("""
                QProgressBar {
                    background: #1e3a5f; border: none; border-radius: 8px;
                    color: white; text-align: center; font-size: 11px; font-weight: 700;
                }
                QProgressBar::chunk { background: #ef4444; border-radius: 8px; }
            """)
            wl.addWidget(bar)
            self.scans_table.setCellWidget(i, 3, wrap)

            find_item = QTableWidgetItem(str(row.get("findings_count", 0)))
            find_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            find_item.setToolTip("Start Scan findings (non-Platform)")
            self.scans_table.setItem(i, 4, find_item)

            plat_item = QTableWidgetItem(str(row.get("platform_findings_count", 0)))
            plat_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            plat_item.setToolTip("Get Stack platform evaluation notes")
            self.scans_table.setItem(i, 5, plat_item)

    def _on_scan_double_clicked(self, row: int, _col: int):
        item = self.scans_table.item(row, 0)
        if not item:
            return
        scan_id = item.data(Qt.ItemDataRole.UserRole)
        if scan_id is None:
            return
        self.open_scan_detail(int(scan_id))

    def open_scan_detail(self, scan_id: int):
        try:
            from core.db import get_scan_by_id, list_findings_for_scan
            scan = get_scan_by_id(scan_id)
            findings = list_findings_for_scan(scan_id)
        except Exception as e:
            QMessageBox.warning(self, "Scan detail", f"Could not load scan: {e}")
            return
        if not scan:
            QMessageBox.information(self, "Scan detail", "Scan not found.")
            return
        local_no = self._scan_local_nos.get(int(scan_id))
        dlg = ScanDetailDialog(scan, findings, local_scan_no=local_no, parent=self)
        dlg.exec()

    def delete_selected_case(self):
        try:
            from core.shared_state import SharedState
            if not SharedState.is_signed_in():
                QMessageBox.information(self, "Delete case", "Sign in first.")
                return
            if self._selected_case_id is None:
                QMessageBox.information(
                    self, "Delete case", "Select a case in the list first."
                )
                return
            user_id = SharedState.current_user_id
        except Exception:
            return
        reply = QMessageBox.question(
            self,
            "Delete case",
            "Delete this case and all its scans/findings?\n"
            "(Only this case — other cases stay.)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            from core.db import delete_case
            ok = delete_case(self._selected_case_id, user_id)
            if not ok:
                QMessageBox.warning(
                    self, "Delete case", "Could not delete (not owner or missing)."
                )
                return
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))
            return
        self.refresh()

    def clear_history(self):
        try:
            from core.shared_state import SharedState
            if not SharedState.is_signed_in():
                QMessageBox.information(
                    self,
                    "Clear my history",
                    "Sign in to clear your own case history.",
                )
                return
            user_id = SharedState.current_user_id
        except Exception:
            return
        reply = QMessageBox.question(
            self,
            "Clear my history",
            "Clear only YOUR cases and scans from this account?\n"
            "Global dashboard history will be kept.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            from core.db import clear_user_history
            clear_user_history(user_id)
            SharedState.current_url = None
            SharedState.findings = []
            if hasattr(SharedState, "stack_findings"):
                SharedState.stack_findings = []
            SharedState.case_name = None
            SharedState.scan_type = None
            SharedState.tech_stacks = []
            SharedState.case_id = None
            SharedState.scan_id = None
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))
            return
        self.refresh()
