from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
    QAbstractItemView, QPushButton, QMessageBox, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt, QRectF
from PyQt6.QtGui import QPainter, QColor, QPen, QFont, QBrush
import sys
import os
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
PLATFORM_ORIGIN = "Platform"
OWASP_RULES = [
    ("A01", "Broken Access Control", ["access", "idor", "traversal", "csrf", "redirect"]),
    ("A02", "Cryptographic Failures", ["cookie", "secure flag", "crypto", "tls", "ssl", "hsts", "plaintext"]),
    ("A03", "Injection", ["injection", "sqli", "sql", "xss", "nosql", "command", "xxe"]),
    ("A04", "Insecure Design", ["insecure design", "client-side validation", "upload"]),
    ("A05", "Security Misconfiguration", ["header", "csp", "misconfig", "server information", "x-frame", "cors", "listing"]),
    ("A06", "Vulnerable and Outdated Components", ["outdated", "end of life", "cve", "supply chain"]),
    ("A07", "Identification and Authentication Failures", ["authentication", "session", "credential", "password"]),
    ("A08", "Software and Data Integrity Failures", ["integrity", "deserialization", "ci/cd"]),
    ("A09", "Security Logging and Monitoring Failures", ["logging", "monitoring", "audit"]),
    ("A10", "Server-Side Request Forgery", ["ssrf", "server-side request"]),
]
_OWASP_2025_TO_2021 = {
    "A01": "A01",
    "A02": "A05",
    "A03": "A06",
    "A04": "A02",
    "A05": "A03",
    "A06": "A04",
    "A07": "A07",
    "A08": "A08",
    "A09": "A09",
    "A10": "A05",
}
def _owasp_code(raw: str) -> str:
    text = str(raw or "").upper().replace("OWASP-", "").strip()
    for code, _, _ in OWASP_RULES:
        if text.startswith(code) or f"{code}:" in text or f"{code} " in text:
            return code
    return ""
def map_finding_to_owasp(name: str, description: str = "", owasp: str | None = None, owasp_2021: str | None = None) -> str:
    code_2021 = _owasp_code(owasp_2021 or "")
    if code_2021:
        return code_2021
    raw = str(owasp or "").strip()
    code = _owasp_code(raw)
    if code:
        if "2025" in raw:
            return _OWASP_2025_TO_2021.get(code, code)
        return code
    text = f"{name} {description}".lower()
    for item_code, _, keys in OWASP_RULES:
        if any(k in text for k in keys):
            return item_code
    return "A05"
def _is_platform(f: dict) -> bool:
    return str((f or {}).get("scan_origin") or "") == PLATFORM_ORIGIN
def _platform_note_counts(rows: list) -> list:
    tallies: dict[str, dict] = {}
    for item in rows or []:
        name = str(
            item.get("vulnerability")
            or item.get("name")
            or item.get("note")
            or ""
        ).strip()
        if not name:
            continue
        sev = str(item.get("severity") or "Low")
        cnt = int(item.get("count") or item.get("cnt") or 1)
        rec = tallies.get(name)
        if rec is None:
            tallies[name] = {"note": name, "severity": sev, "count": cnt}
        else:
            rec["count"] += cnt
            if sev == "High" or (sev == "Medium" and rec["severity"] == "Low"):
                rec["severity"] = sev
    return sorted(tallies.values(), key=lambda r: (-r["count"], r["note"]))
def _load_platform_note_rows() -> list:
    try:
        from core.db import get_platform_note_counts
        rows = get_platform_note_counts()
        if rows:
            return list(rows)
    except Exception:
        pass
    try:
        from core import db as core_db
        conn = core_db._connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT vulnerability, severity, COUNT(*) AS cnt
            FROM findings
            WHERE scan_origin = ?
            GROUP BY vulnerability, severity
            ORDER BY cnt DESC
            """,
            (PLATFORM_ORIGIN,),
        )
        rows = [
            {
                "vulnerability": r[0],
                "severity": r[1],
                "count": r[2],
            }
            for r in cur.fetchall()
        ]
        conn.close()
        return rows
    except Exception:
        return []
class LineChartWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(260)
        self.totals = []
        self.highs = []
        self.labels = []
    def set_data(self, labels, totals, highs):
        self.labels = labels or []
        self.totals = totals or []
        self.highs = highs or []
        self.update()
    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor("#0f3d5e"))
        rect = self.rect().adjusted(44, 28, -16, -36)
        if len(self.totals) < 1:
            p.setPen(QColor("#9ec3d9"))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No scan history yet")
            return
        n = len(self.totals)
        max_v = max(max(self.totals + self.highs), 1)
        def point(i, v):
            if n == 1:
                x = rect.left() + rect.width() / 2
            else:
                x = rect.left() + i * (rect.width() / (n - 1))
            y = rect.bottom() - (v / max_v) * rect.height()
            return x, y
        p.setFont(QFont("Arial", 9))
        for g in range(5):
            y = rect.top() + g * (rect.height() / 4)
            val = int(max_v * (1 - g / 4))
            p.setPen(QPen(QColor("#1a5270"), 1))
            p.drawLine(rect.left(), int(y), rect.right(), int(y))
            p.setPen(QColor("#9ec3d9"))
            p.drawText(4, int(y) + 4, str(val))
        def draw_series(values, color):
            if not values:
                return
            p.setPen(QPen(QColor(color), 2))
            if n == 1:
                x, y = point(0, values[0])
                p.setBrush(QColor(color))
                p.drawEllipse(int(x) - 4, int(y) - 4, 8, 8)
                return
            for i in range(n - 1):
                x1, y1 = point(i, values[i])
                x2, y2 = point(i + 1, values[i + 1])
                p.drawLine(int(x1), int(y1), int(x2), int(y2))
            for i, v in enumerate(values):
                x, y = point(i, v)
                p.setBrush(QColor(color))
                p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(int(x) - 4, int(y) - 4, 8, 8)
        draw_series(self.totals, "#ffffff")
        draw_series(self.highs, "#48dbfb")
        p.setPen(QColor("#9ec3d9"))
        p.setFont(QFont("Arial", 9))
        for i, lab in enumerate(self.labels):
            x, _ = point(i, 0)
            p.drawText(
                int(x) - 28, self.height() - 10, 56, 16,
                Qt.AlignmentFlag.AlignCenter, lab
            )
        p.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        p.setBrush(QColor("#ffffff"))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(16, 10, 8, 8)
        p.setPen(QColor("#ffffff"))
        p.drawText(28, 18, "Total findings")
        p.setBrush(QColor("#48dbfb"))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(140, 10, 8, 8)
        p.setPen(QColor("#48dbfb"))
        p.drawText(152, 18, "High severity")
class BarChartWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(260)
        self.rows = []
    def set_rows(self, rows):
        self.rows = rows or []
        self.update()
    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor("#ffffff"))
        margin_l, margin_b, margin_t, margin_r = 28, 40, 20, 12
        w = self.width() - margin_l - margin_r
        h = self.height() - margin_t - margin_b
        if not self.rows:
            p.setPen(QColor("#8a94a6"))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No findings to map")
            return
        n = len(self.rows)
        max_v = max(max(c for _, c in self.rows), 1)
        group_w = w / n
        bar_w = group_w * 0.55
        for i, (lab, count) in enumerate(self.rows):
            gx = margin_l + i * group_w
            bh = (count / max_v) * h if max_v else 0
            x = gx + (group_w - bar_w) / 2
            y = margin_t + h - bh
            p.setBrush(QColor("#e84393"))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawRoundedRect(QRectF(x, y, bar_w, bh), 4, 4)
            p.setPen(QColor("#1f2a44"))
            p.setFont(QFont("Arial", 9, QFont.Weight.Bold))
            p.drawText(
                int(x), int(y) - 16, int(bar_w), 14,
                Qt.AlignmentFlag.AlignCenter, str(count)
            )
            p.setPen(QColor("#5d6b86"))
            p.setFont(QFont("Arial", 10, QFont.Weight.Bold))
            p.drawText(
                int(gx), self.height() - 28, int(group_w), 18,
                Qt.AlignmentFlag.AlignCenter, lab
            )
class DashboardPage(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.refresh()
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
        layout = QVBoxLayout(body)
        layout.setSpacing(16)
        layout.setContentsMargins(0, 0, 4, 20)
        scroll.setWidget(body)
        top_bar = QHBoxLayout()
        top_bar.addStretch()
        self.clear_global_btn = QPushButton("Clear all history")
        self.clear_global_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_global_btn.setStyleSheet("""
            QPushButton {
                background: #e74c3c; color: white; font-weight: 700;
                border: none; border-radius: 8px; padding: 8px 14px;
            }
            QPushButton:hover { background: #c0392b; }
        """)
        self.clear_global_btn.clicked.connect(self.clear_global_history)
        top_bar.addWidget(self.clear_global_btn)
        layout.addLayout(top_bar)
        kpi = QHBoxLayout()
        kpi.setSpacing(12)
        self.card_cases = self._kpi_card("NO. OF CASES", "0", "#0984e3", "All users")
        self.card_scans = self._kpi_card("NO. OF SCANS", "0", "#f39c12", "All history")
        self.card_vulns = self._kpi_card("NO. OF VULNERABILITIES", "0", "#e84393", "Start Scan findings")
        self.card_libs = self._kpi_card("NO. OF TECHNOLOGIES", "0", "#00b894", "Detected stacks")
        for c in [self.card_cases, self.card_scans, self.card_vulns, self.card_libs]:
            kpi.addWidget(c)
        layout.addLayout(kpi)
        charts = QHBoxLayout()
        charts.setSpacing(12)
        left = QFrame()
        left.setObjectName("dashCard")
        left.setStyleSheet("QFrame#dashCard { background: #0f3d5e; border-radius: 12px; }")
        left_l = QVBoxLayout(left)
        left_l.setContentsMargins(12, 10, 12, 10)
        t1 = QLabel("OVERVIEW · Findings per scan")
        t1.setStyleSheet("color: white; font-weight: 800; font-size: 13px; background: transparent;")
        left_l.addWidget(t1)
        self.line_chart = LineChartWidget()
        left_l.addWidget(self.line_chart)
        charts.addWidget(left, 3)
        right = QFrame()
        right.setObjectName("dashCardLight")
        right.setStyleSheet(
            "QFrame#dashCardLight { background: white; border-radius: 12px; border: 1px solid #e6eaf2; }"
        )
        right_l = QVBoxLayout(right)
        right_l.setContentsMargins(12, 10, 12, 10)
        t2 = QLabel("OWASP TOP 10 · Finding counts (Start Scan)")
        t2.setStyleSheet("color: #1f2a44; font-weight: 800; font-size: 13px; background: transparent;")
        right_l.addWidget(t2)
        self.bar_chart = BarChartWidget()
        right_l.addWidget(self.bar_chart)
        charts.addWidget(right, 2)
        layout.addLayout(charts)
        mid = QHBoxLayout()
        mid.setSpacing(12)
        files_card = self._panel("Findings by location (Start Scan)")
        fl = files_card.layout()
        self.files_table = self._table(
            ["Location", "Severity", "CWE", "Issue"], min_height=280
        )
        self.files_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.files_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.files_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.files_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        fl.addWidget(self.files_table)
        mid.addWidget(files_card, 3)
        owasp_card = self._panel("OWASP mapping detail (Start Scan)")
        ol = owasp_card.layout()
        self.owasp_table = self._table(["Category", "Code", "Count"], min_height=280)
        self.owasp_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.owasp_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.owasp_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        ol.addWidget(self.owasp_table)
        mid.addWidget(owasp_card, 2)
        layout.addLayout(mid)
        standards = QHBoxLayout()
        standards.setSpacing(12)
        cwe_card = self._panel("CWE mapping (Start Scan)")
        cl = cwe_card.layout()
        self.cwe_table = self._table(["CWE", "Count"], min_height=220)
        self.cwe_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.cwe_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        cl.addWidget(self.cwe_table)
        standards.addWidget(cwe_card, 1)
        nist_card = self._panel("NIST mapping (Start Scan)")
        nl = nist_card.layout()
        self.nist_table = self._table(["NIST", "Count"], min_height=220)
        self.nist_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.nist_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        nl.addWidget(self.nist_table)
        standards.addWidget(nist_card, 1)
        sans_card = self._panel("SANS mapping (Start Scan)")
        sl = sans_card.layout()
        self.sans_table = self._table(["SANS", "Count"], min_height=220)
        self.sans_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.sans_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        sl.addWidget(self.sans_table)
        standards.addWidget(sans_card, 1)
        layout.addLayout(standards)
        bottom = QHBoxLayout()
        bottom.setSpacing(12)
        tech_card = self._panel("Most used tech stacks")
        tl = tech_card.layout()
        self.tech_table = self._table(["Technology", "Count"], min_height=220)
        self.tech_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tech_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        tl.addWidget(self.tech_table)
        bottom.addWidget(tech_card, 1)
        plat_card = self._panel("Platform evaluation notes (Get Stack)")
        pl = plat_card.layout()
        self.platform_table = self._table(
            ["Severity", "Note", "Count"], min_height=220
        )
        self.platform_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.platform_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.platform_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        pl.addWidget(self.platform_table)
        bottom.addWidget(plat_card, 1)
        layout.addLayout(bottom)
        layout.addStretch(1)
    def _panel(self, title: str) -> QFrame:
        card = QFrame()
        card.setObjectName("dashCardLight")
        card.setStyleSheet(
            "QFrame#dashCardLight { background: white; border-radius: 12px; border: 1px solid #e6eaf2; }"
        )
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(10)
        lab = QLabel(title)
        lab.setStyleSheet(
            "font-weight: 800; font-size: 13px; color: #1f2a44; background: transparent;"
        )
        lay.addWidget(lab)
        return card
    def _table(self, headers: list, min_height: int = 200) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setMinimumHeight(min_height)
        table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        table.setStyleSheet("""
            QTableWidget {
                background: #ffffff;
                color: #0f172a;
                border: 1px solid #eef1f6;
                border-radius: 8px;
                font-size: 13px;
                alternate-background-color: #f8fafc;
                gridline-color: #eef1f6;
            }
            QHeaderView::section {
                background: #1b4f72;
                color: white;
                padding: 8px;
                border: none;
                font-weight: 700;
            }
            QTableWidget::item {
                color: #0f172a;
                padding: 6px;
            }
            QTableWidget::item:selected {
                background: #eaf2ff;
                color: #0f172a;
            }
        """)
        return table
    def _item(self, text: str, color: str = "#0f172a", bold: bool = False) -> QTableWidgetItem:
        item = QTableWidgetItem(str(text))
        item.setForeground(QBrush(QColor(color)))
        if bold:
            item.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        return item
    def _kpi_card(self, title, value, accent, trend):
        card = QFrame()
        card.setObjectName("kpiCard")
        card.setMinimumHeight(96)
        card.setStyleSheet("""
            QFrame#kpiCard {
                background: white;
                border-radius: 12px;
                border: 1px solid #e6eaf2;
            }
            QFrame#kpiCard QLabel { background: transparent; border: none; }
        """)
        lay = QHBoxLayout(card)
        lay.setContentsMargins(16, 12, 16, 12)
        left = QVBoxLayout()
        t = QLabel(title)
        t.setStyleSheet("font-size: 11px; font-weight: 800; color: #8a94a6;")
        v = QLabel(value)
        v.setStyleSheet("font-size: 28px; font-weight: 800; color: #1f2a44;")
        tr = QLabel(trend)
        tr.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {accent};")
        left.addWidget(t)
        left.addWidget(v)
        left.addWidget(tr)
        lay.addLayout(left, 1)
        dot = QLabel("●")
        dot.setStyleSheet(f"font-size: 28px; color: {accent};")
        lay.addWidget(dot)
        card.value_label = v
        card.trend_label = tr
        return card
    def _fill_count_table(self, table: QTableWidget, counts: dict, empty_msg: str, accent: str):
        table.setRowCount(0)
        ordered = sorted(
            (counts or {}).items(),
            key=lambda x: (-int(x[1]), str(x[0])),
        )[:10]
        if not ordered:
            table.setRowCount(1)
            table.setItem(0, 0, self._item(empty_msg, "#94a3b8"))
            table.setItem(0, 1, self._item("—", "#94a3b8"))
            return
        for i, (key, cnt) in enumerate(ordered):
            table.insertRow(i)
            table.setItem(i, 0, self._item(str(key), accent, bold=True))
            cnt_item = self._item(str(cnt), "#0f172a")
            cnt_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            table.setItem(i, 1, cnt_item)
    def clear_global_history(self):
        reply = QMessageBox.question(
            self,
            "Clear all history",
            "Delete ALL cases and scans in the database?\n"
            "(User profiles are kept.)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            from core.db import clear_all_data
            clear_all_data()
            from core.shared_state import SharedState
            SharedState.current_url = None
            SharedState.findings = []
            if hasattr(SharedState, "stack_findings"):
                SharedState.stack_findings = []
            SharedState.case_name = None
            SharedState.scan_type = None
            SharedState.tech_stacks = []
            SharedState.case_id = None
            SharedState.scan_id = None
            if hasattr(SharedState, "_start_scan_active"):
                SharedState._start_scan_active = False
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))
            return
        self.refresh()
        main = self.window()
        if main and hasattr(main, "cases_page"):
            main.cases_page.refresh()
    def refresh(self):
        stats = None
        per_scan = []
        try:
            from core.db import get_dashboard_stats, get_findings_per_scan
            stats = get_dashboard_stats(user_id=None)
            per_scan = get_findings_per_scan(8)
        except Exception as e:
            print("Dashboard error:", e)
        if not stats:
            stats = {
                "cases": 0, "scans": 0, "findings": 0, "technologies": 0,
                "high": 0, "medium": 0, "low": 0,
                "recent_findings": [], "owasp_counts": {}, "cwe_counts": {},
                "nist_counts": {}, "sans_counts": {},
                "top_tech_stacks": [],
                "static_severity": {},
                "static_recent_findings": [],
                "platform_note_counts": [],
            }
        total = stats.get("findings", 0)
        high = stats.get("high", 0)
        medium = stats.get("medium", 0)
        low = stats.get("low", 0)
        scans = stats.get("scans", 0)
        cases = stats.get("cases", 0)
        tech_n = stats.get("technologies", 0)
        recent = stats.get("recent_findings") or []
        scan_findings = [f for f in recent if not _is_platform(f)]
        platform_notes = [f for f in recent if _is_platform(f)]
        self.card_cases.value_label.setText(str(cases))
        self.card_scans.value_label.setText(str(scans))
        self.card_vulns.value_label.setText(str(total))
        self.card_libs.value_label.setText(str(tech_n))
        self.card_cases.trend_label.setText("All users")
        self.card_scans.trend_label.setText("All history")
        self.card_vulns.trend_label.setText(
            f"High {high} · Med {medium} · Low {low}" if total else "No data yet"
        )
        self.card_libs.trend_label.setText("Detected stacks")
        if per_scan:
            labels, totals, highs = [], [], []
            for i, row in enumerate(per_scan, start=1):
                name = row.get("case_name") or row.get("name") or f"Scan {row.get('scan_id', i)}"
                labels.append(str(name)[:10])
                totals.append(int(row.get("total") or 0))
                highs.append(int(row.get("high_count") or row.get("high") or 0))
            self.line_chart.set_data(labels, totals, highs)
        else:
            self.line_chart.set_data([], [], [])
        owasp_counts = {code: 0 for code, _, _ in OWASP_RULES}
        db_owasp = stats.get("owasp_counts") or {}
        if db_owasp:
            for tag, count in db_owasp.items():
                code = map_finding_to_owasp("", "", owasp=str(tag))
                owasp_counts[code] = owasp_counts.get(code, 0) + int(count)
        else:
            for f in scan_findings:
                code = map_finding_to_owasp(
                    str(f.get("vulnerability", f.get("name", ""))),
                    str(f.get("description", "")),
                    owasp=f.get("owasp"),
                    owasp_2021=f.get("owasp_2021"),
                )
                owasp_counts[code] = owasp_counts.get(code, 0) + 1
        self.bar_chart.set_rows(
            [(code, owasp_counts.get(code, 0)) for code, _, _ in OWASP_RULES]
        )
        self.files_table.setRowCount(0)
        if not scan_findings:
            self.files_table.setRowCount(1)
            self.files_table.setItem(0, 0, self._item("No Start Scan findings yet", "#94a3b8"))
            self.files_table.setItem(0, 1, self._item("—", "#94a3b8"))
            self.files_table.setItem(0, 2, self._item("—", "#94a3b8"))
            self.files_table.setItem(0, 3, self._item("—", "#94a3b8"))
        else:
            for i, f in enumerate(scan_findings[:15]):
                self.files_table.insertRow(i)
                loc = str(f.get("location", ""))
                if len(loc) > 48:
                    loc = loc[:47] + "…"
                self.files_table.setItem(i, 0, self._item(loc, "#334155"))
                sev = str(f.get("severity", ""))
                sev_color = {
                    "High": "#c0392b",
                    "Medium": "#d68910",
                    "Low": "#5d6d7e",
                }.get(sev, "#0f172a")
                self.files_table.setItem(i, 1, self._item(sev, sev_color, bold=True))
                cwe = str(f.get("cwe_id") or f.get("cweId") or "—")
                cwe_item = self._item(cwe, "#1d4ed8", bold=True)
                tip_parts = [
                    f"CWE: {f.get('cwe_id') or f.get('cweId') or '—'}",
                    f"WASC: {f.get('wasc_id') or f.get('wascId') or '—'}",
                    f"OWASP: {f.get('owasp') or '—'}",
                    f"NIST: {f.get('nist') or f.get('nist_id') or '—'}",
                    f"SANS: {f.get('sans') or f.get('sans_id') or '—'}",
                ]
                cwe_item.setToolTip("\n".join(tip_parts))
                self.files_table.setItem(i, 2, cwe_item)
                issue_item = self._item(
                    str(f.get("vulnerability", f.get("name", ""))), "#0f172a"
                )
                issue_item.setToolTip("\n".join(tip_parts))
                self.files_table.setItem(i, 3, issue_item)
        self.owasp_table.setRowCount(0)
        scan_total = sum(owasp_counts.values()) or max(total, 1)
        for i, (code, title, _) in enumerate(OWASP_RULES):
            count = owasp_counts.get(code, 0)
            self.owasp_table.insertRow(i)
            self.owasp_table.setRowHeight(i, 36)
            self.owasp_table.setItem(i, 0, self._item(title, "#0f172a"))
            self.owasp_table.setItem(i, 1, self._item(code, "#0f172a", bold=True))
            bar = QProgressBar()
            bar.setRange(0, max(scan_total, 1))
            bar.setValue(count)
            bar.setFormat(f"{count}")
            bar.setTextVisible(True)
            color = "#e74c3c" if count >= max(1, scan_total // 3) else "#27ae60"
            bar.setStyleSheet(f"""
                QProgressBar {{
                    border: none; background: #eef1f6; border-radius: 5px;
                    min-height: 16px; max-height: 16px; text-align: center;
                    font-size: 11px; color: #0f172a;
                }}
                QProgressBar::chunk {{ background: {color}; border-radius: 5px; }}
            """)
            wrap = QWidget()
            wl = QHBoxLayout(wrap)
            wl.setContentsMargins(6, 8, 6, 8)
            wl.addWidget(bar)
            self.owasp_table.setCellWidget(i, 2, wrap)
        cwe_counts = dict(stats.get("cwe_counts") or {})
        nist_counts = dict(stats.get("nist_counts") or {})
        sans_counts = dict(stats.get("sans_counts") or {})
        if scan_findings and (not cwe_counts or not nist_counts or not sans_counts):
            for f in scan_findings:
                cwe = str(f.get("cwe_id") or f.get("cweId") or "").strip()
                nist = str(f.get("nist") or f.get("nist_id") or "").strip()
                sans = str(f.get("sans") or f.get("sans_id") or "").strip()
                if cwe and not cwe_counts:
                    cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
                if nist:
                    nist_counts[nist] = nist_counts.get(nist, 0) + 1
                if sans:
                    sans_counts[sans] = sans_counts.get(sans, 0) + 1
        self._fill_count_table(
            self.cwe_table, cwe_counts, "No CWE data yet — run a Start Scan", "#1d4ed8"
        )
        self._fill_count_table(
            self.nist_table, nist_counts, "No NIST data yet — run a Start Scan", "#b45309"
        )
        self._fill_count_table(
            self.sans_table, sans_counts, "No SANS data yet — run a Start Scan", "#9f1239"
        )
        top_tech = stats.get("top_tech_stacks") or []
        top_tech = [
            t for t in top_tech
            if "unknown" not in str(t.get("name", "")).lower()
            and "undetected" not in str(t.get("name", "")).lower()
        ]
        self.tech_table.setRowCount(0)
        if not top_tech:
            self.tech_table.setRowCount(1)
            self.tech_table.setItem(0, 0, self._item("No tech stack data yet", "#94a3b8"))
            self.tech_table.setItem(0, 1, self._item("—", "#94a3b8"))
        else:
            for i, t in enumerate(top_tech[:10]):
                self.tech_table.insertRow(i)
                self.tech_table.setItem(i, 0, self._item(str(t.get("name", "")), "#0f172a"))
                cnt = self._item(str(t.get("count", 0)), "#0f172a")
                cnt.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.tech_table.setItem(i, 1, cnt)
        plat_rows = _platform_note_counts(
            stats.get("platform_note_counts") or _load_platform_note_rows() or platform_notes
        )
        self.platform_table.setRowCount(0)
        if not plat_rows:
            self.platform_table.setRowCount(1)
            self.platform_table.setItem(0, 0, self._item("—", "#94a3b8"))
            self.platform_table.setItem(0, 1, self._item("No platform notes yet — run Get Stack", "#94a3b8"))
            self.platform_table.setItem(0, 2, self._item("—", "#94a3b8"))
        else:
            for i, row in enumerate(plat_rows[:15]):
                self.platform_table.insertRow(i)
                sev = str(row.get("severity") or "Low")
                sev_color = {
                    "High": "#c0392b",
                    "Medium": "#d68910",
                    "Low": "#5d6d7e",
                }.get(sev, "#0f172a")
                self.platform_table.setItem(i, 0, self._item(sev, sev_color, bold=True))
                self.platform_table.setItem(i, 1, self._item(row.get("note") or "", "#0f172a"))
                cnt = self._item(str(row.get("count") or 0), "#0f172a")
                cnt.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.platform_table.setItem(i, 2, cnt)
