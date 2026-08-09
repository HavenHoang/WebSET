from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QPushButton, QFrame,
    QAbstractItemView, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QBrush
import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)


def _shorten(text: str, limit: int = 48) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _count_severity(rows: list) -> dict:
    out = {"High": 0, "Medium": 0, "Low": 0, "Total": 0}
    for r in rows or []:
        sev = str(r.get("severity", "Low"))
        if sev not in ("High", "Medium", "Low"):
            sev = "Low"
        out[sev] = out.get(sev, 0) + 1
        out["Total"] += 1
    return out


def _enrich(findings: list) -> list:
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


def _std_tip(f: dict) -> str:
    parts = [
        f"CWE: {f.get('cwe_id') or f.get('cweId') or '—'}",
        f"WASC: {f.get('wasc_id') or f.get('wascId') or '—'}",
        f"OWASP: {f.get('owasp') or '—'}",
        f"NIST: {f.get('nist') or f.get('nist_id') or '—'}",
        f"SANS: {f.get('sans') or f.get('sans_id') or '—'}",
        f"Plugin: {f.get('plugin_id') or f.get('pluginId') or '—'}",
        f"Message: {f.get('message_id') or f.get('messageId') or '—'}",
        f"Confidence: {f.get('confidence') or '—'}",
    ]
    rem = str(f.get("remediation") or "").strip()
    if rem:
        parts.append(f"Remediation: {rem}")
    tags = f.get("tags") or f.get("owasp_tags") or []
    if tags:
        parts.append("Tags: " + ", ".join(str(t) for t in tags))
    return "\n".join(parts)


def _standards_cell(f: dict) -> str:
    cwe = str(f.get("cwe_id") or f.get("cweId") or "—")
    nist = str(f.get("nist") or f.get("nist_id") or "—")
    sans = str(f.get("sans") or f.get("sans_id") or "—")
    owasp = str(f.get("owasp") or "").strip()
    lines = [f"CWE: {cwe}"]
    if owasp:
        lines.append(f"OWASP: {owasp}")
    lines.append(f"NIST: {_shorten(nist, 28)}")
    lines.append(f"SANS: {_shorten(sans, 28)}")
    return "\n".join(lines)


class AlertsPage(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.apply_page_theme()
        self.refresh()

    def _is_dark(self) -> bool:
        main = self.window()
        return bool(getattr(main, "dark_mode", False))

    def apply_page_theme(self):
        dark = self._is_dark()
        title_c = "#e2e8f0" if dark else "#1f2a44"
        if hasattr(self, "page_title"):
            self.page_title.setStyleSheet(
                f"font-size: 15px; font-weight: 800; color: {title_c}; background: transparent;"
            )
        for empty in (
            getattr(self, "dyn_empty", None),
            getattr(self, "st_empty", None),
            getattr(self, "empty_state_label", None),
        ):
            if empty is not None:
                empty.setStyleSheet(
                    "color: #64748b; padding: 18px; font-size: 13px; font-weight: 500;"
                )

    def showEvent(self, event):
        super().showEvent(event)
        self.apply_page_theme()

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
        self._body_layout = QVBoxLayout(body)
        self._body_layout.setSpacing(16)
        self._body_layout.setContentsMargins(0, 0, 4, 12)
        self._body_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        scroll.setWidget(body)

        top = QHBoxLayout()
        self.page_title = QLabel("Summary of Rules Triggered")
        self.page_title.setStyleSheet(
            "font-size: 15px; font-weight: 800; color: #1f2a44; background: transparent;"
        )
        top.addWidget(self.page_title)
        top.addStretch()

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.refresh_btn.setFixedHeight(36)
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f2a57;
                color: white;
                font-weight: 700;
                padding: 8px 16px;
                border-radius: 8px;
                border: none;
            }
            QPushButton:hover { background-color: #2f3f7a; }
        """)
        self.refresh_btn.clicked.connect(self.refresh)
        top.addWidget(self.refresh_btn)
        self._body_layout.addLayout(top)

        # Overview — compact, never stretch vertically
        self.overview = QFrame()
        self.overview.setObjectName("overviewCard")
        self.overview.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum
        )
        self.overview.setStyleSheet("""
            QFrame#overviewCard {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 12px;
            }
            QFrame#overviewCard QLabel {
                background: transparent;
                border: none;
            }
        """)
        ov = QVBoxLayout(self.overview)
        ov.setContentsMargins(14, 12, 14, 12)
        ov.setSpacing(6)
        ov.setAlignment(Qt.AlignmentFlag.AlignTop)

        ov_title = QLabel("Current scan overview")
        ov_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #64748b;")
        ov.addWidget(ov_title)

        self.overview_app = QLabel("Application: —")
        self.overview_app.setStyleSheet(
            "font-size: 13px; font-weight: 700; color: #0f172a;"
        )
        self.overview_target = QLabel("Target: —")
        self.overview_target.setWordWrap(True)
        self.overview_target.setStyleSheet(
            "font-size: 13px; font-weight: 600; color: #334155;"
        )
        self.overview_type = QLabel("Type: —")
        self.overview_type.setStyleSheet(
            "font-size: 13px; font-weight: 600; color: #334155;"
        )
        self.overview_map = QLabel(
            "Mappings: CWE / WASC / OWASP / NIST / SANS · remediation per finding"
        )
        self.overview_map.setWordWrap(True)
        self.overview_map.setStyleSheet(
            "font-size: 12px; font-weight: 600; color: #64748b;"
        )
        for lbl in (
            self.overview_app,
            self.overview_target,
            self.overview_type,
            self.overview_map,
        ):
            lbl.setSizePolicy(
                QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum
            )
            ov.addWidget(lbl)
        self._body_layout.addWidget(self.overview)

        # Empty state when no active scan (instead of blank stretched page)
        self.empty_state = QFrame()
        self.empty_state.setObjectName("emptyStateCard")
        self.empty_state.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum
        )
        self.empty_state.setStyleSheet("""
            QFrame#emptyStateCard {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 14px;
            }
        """)
        es_lay = QVBoxLayout(self.empty_state)
        es_lay.setContentsMargins(24, 28, 24, 28)
        es_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_state_label = QLabel(
            "No active scan.\n\n"
            "Go to Create Scan and run a Dynamic scan (URL) or Static scan (ZIP).\n"
            "Findings will appear here with CWE / OWASP / NIST / SANS mappings."
        )
        self.empty_state_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_state_label.setWordWrap(True)
        self.empty_state_label.setStyleSheet(
            "color: #64748b; font-size: 13px; font-weight: 500; background: transparent;"
        )
        es_lay.addWidget(self.empty_state_label)
        self._body_layout.addWidget(self.empty_state)

        self.dyn_section = self._build_section(
            title="Dynamic scan alerts", subtitle=None, is_static=False
        )
        self._body_layout.addWidget(self.dyn_section, 1)

        self.st_section = self._build_section(
            title="Static scan alerts",
            subtitle="Criticality mapping (static) · CWE / NIST / SANS",
            is_static=True,
        )
        self._body_layout.addWidget(self.st_section, 1)

        self._body_layout.addStretch(0)

    def _build_section(self, title: str, subtitle: str | None, is_static: bool) -> QFrame:
        card = QFrame()
        card.setObjectName("sectionCard")
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        card.setStyleSheet("""
            QFrame#sectionCard {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 14px;
            }
            QFrame#sectionCard QLabel {
                background: transparent;
            }
        """)
        lay = QVBoxLayout(card)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(12)

        head = QLabel(title)
        head.setStyleSheet("font-size: 14px; font-weight: 800; color: #0f172a;")
        lay.addWidget(head)

        if subtitle:
            sub = QLabel(subtitle)
            sub.setStyleSheet("font-size: 12px; font-weight: 600; color: #64748b;")
            lay.addWidget(sub)

        kpis = QHBoxLayout()
        kpis.setSpacing(10)
        high = self._kpi_card("HIGH", "0", "#c0392b", "#fdecea")
        medium = self._kpi_card("MEDIUM", "0", "#d68910", "#fef5e7")
        low = self._kpi_card("LOW", "0", "#5d6d7e", "#eef1f4")
        total = self._kpi_card("TOTAL", "0", "#1f2a57", "#eaf0ff")
        for c in (high, medium, low, total):
            kpis.addWidget(c, 1)
        lay.addLayout(kpis)

        table = self._make_table()
        lay.addWidget(table, 1)

        empty = QLabel(
            "No issues found for this static scan."
            if is_static
            else "No issues found for this dynamic scan."
        )
        empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty.setStyleSheet(
            "color: #64748b; padding: 18px; font-size: 13px; font-weight: 500;"
        )
        empty.hide()
        lay.addWidget(empty)

        if is_static:
            self.st_high, self.st_medium, self.st_low, self.st_total = (
                high, medium, low, total
            )
            self.st_table, self.st_empty = table, empty
        else:
            self.dyn_high, self.dyn_medium, self.dyn_low, self.dyn_total = (
                high, medium, low, total
            )
            self.dyn_table, self.dyn_empty = table, empty
        return card

    def _kpi_card(self, title: str, value: str, accent: str, bg: str) -> QFrame:
        card = QFrame()
        card.setObjectName("kpiCard")
        card.setMinimumHeight(72)
        card.setMaximumHeight(80)
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        card.setStyleSheet(f"""
            QFrame#kpiCard {{
                background-color: {bg};
                border-radius: 10px;
                border: 1px solid rgba(0,0,0,0.04);
            }}
            QFrame#kpiCard QLabel {{
                background: transparent;
                border: none;
            }}
        """)
        lay = QVBoxLayout(card)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(4)
        lay.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        t = QLabel(title)
        t.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        t.setStyleSheet(
            f"font-size: 11px; font-weight: 800; color: {accent}; letter-spacing: 0.5px;"
        )
        v = QLabel(value)
        v.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        v.setStyleSheet(f"font-size: 22px; font-weight: 800; color: {accent};")
        lay.addWidget(t)
        lay.addWidget(v)
        card.value_label = v
        return card

    def _make_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels(
            ["Risk", "Name", "Standards", "Conf.", "Location", "Description", "Remediation"]
        )
        hdr = table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        table.setColumnWidth(0, 104)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        table.setColumnWidth(2, 180)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        table.setColumnWidth(3, 72)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        table.setColumnWidth(4, 150)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)

        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(96)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        table.setMouseTracking(True)
        table.viewport().setMouseTracking(True)
        table.setMinimumHeight(280)
        table.setMaximumHeight(16777215)
        table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        table.setWordWrap(True)
        table.setTextElideMode(Qt.TextElideMode.ElideNone)
        table.setStyleSheet("""
            QTableWidget {
                background: #ffffff;
                color: #0f172a;
                border: 1px solid #eef1f6;
                border-radius: 8px;
                font-size: 13px;
                alternate-background-color: #f8fafc;
            }
            QHeaderView::section {
                background-color: #1b4f72;
                color: white;
                padding: 9px 8px;
                border: none;
                font-weight: 700;
                font-size: 11px;
            }
            QTableWidget::item {
                color: #0f172a;
                padding: 8px;
                border-bottom: 1px solid #eef1f6;
            }
            QTableWidget::item:selected {
                background: #eaf2ff;
                color: #0f172a;
            }
        """)
        return table

    def _severity_badge(self, severity: str) -> QWidget:
        colors = {
            "High": ("#c0392b", "#fdecea"),
            "Medium": ("#d68910", "#fef5e7"),
            "Low": ("#5d6d7e", "#eef1f4"),
        }
        fg, bg = colors.get(severity, ("#5d6d7e", "#eef1f4"))
        wrap = QWidget()
        wrap.setStyleSheet("background: transparent; border: none;")
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(0)
        lay.addStretch(1)
        badge = QLabel(severity)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setFixedHeight(24)
        badge.setFixedWidth(72)
        badge.setStyleSheet(f"""
            QLabel {{
                background-color: {bg};
                color: {fg};
                border: 1px solid {fg};
                border-radius: 12px;
                font-size: 11px;
                font-weight: 800;
                padding: 0 6px;
            }}
        """)
        lay.addWidget(badge, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addStretch(1)
        return wrap

    def _expand_table(self, table: QTableWidget, n_rows: int):
        if n_rows <= 0:
            table.setMinimumHeight(160)
            return
        content_h = 40 + sum(table.rowHeight(i) for i in range(table.rowCount())) + 20
        table.setMinimumHeight(max(320, min(content_h, 1200)))

    def _fill_table(
        self, table: QTableWidget, empty_label: QLabel, findings: list, empty_msg: str
    ):
        table.setRowCount(0)
        empty_label.setText(empty_msg)
        if not findings:
            table.hide()
            empty_label.show()
            table.setMinimumHeight(120)
            return
        empty_label.hide()
        table.show()

        name_font = QFont("Arial", 11, QFont.Weight.Bold)
        normal = QFont("Arial", 11)
        std_font = QFont("Arial", 10)
        vcenter = Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft
        vcenter_h = Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignHCenter

        for i, f in enumerate(findings[:40]):
            table.insertRow(i)
            severity = str(f.get("severity", "Low"))
            name = str(f.get("vulnerability", f.get("name", "")))
            conf = str(f.get("confidence") or "—")
            location = str(f.get("location", f.get("url", "")))
            desc = str(f.get("description", "") or "")
            rem = str(f.get("remediation") or "").strip()
            tip = _std_tip(f)
            standards = _standards_cell(f)
            std_lines = standards.count("\n") + 1

            table.setCellWidget(i, 0, self._severity_badge(severity))

            name_item = QTableWidgetItem(name)
            name_item.setFont(name_font)
            name_item.setForeground(QBrush(QColor("#0f172a")))
            name_item.setTextAlignment(vcenter)
            name_item.setToolTip(tip)
            table.setItem(i, 1, name_item)

            std_item = QTableWidgetItem(standards)
            std_item.setFont(std_font)
            std_item.setTextAlignment(vcenter)
            std_item.setForeground(QBrush(QColor("#1e3a8a")))
            std_item.setToolTip(tip)
            table.setItem(i, 2, std_item)

            conf_item = QTableWidgetItem(conf)
            conf_item.setFont(normal)
            conf_item.setTextAlignment(vcenter_h)
            conf_item.setForeground(QBrush(QColor("#334155")))
            conf_item.setToolTip(tip)
            table.setItem(i, 3, conf_item)

            loc_item = QTableWidgetItem(_shorten(location, 40))
            loc_item.setToolTip(location if location else tip)
            loc_item.setFont(normal)
            loc_item.setForeground(QBrush(QColor("#475569")))
            loc_item.setTextAlignment(vcenter)
            table.setItem(i, 4, loc_item)

            desc_item = QTableWidgetItem(desc if len(desc) <= 120 else _shorten(desc, 120))
            desc_item.setToolTip(desc if desc else tip)
            desc_item.setFont(normal)
            desc_item.setForeground(QBrush(QColor("#334155")))
            desc_item.setTextAlignment(vcenter)
            table.setItem(i, 5, desc_item)

            rem_display = rem if rem else "—"
            rem_item = QTableWidgetItem(
                rem_display if len(rem_display) <= 120 else _shorten(rem_display, 120)
            )
            rem_item.setToolTip(rem if rem else tip)
            rem_item.setFont(normal)
            rem_item.setForeground(QBrush(QColor("#0f766e")))
            rem_item.setTextAlignment(vcenter)
            table.setItem(i, 6, rem_item)

            text_factor = max(len(desc), len(rem or ""), 1)
            row_h = max(96, 18 * std_lines + 32)
            if text_factor > 100:
                row_h = max(row_h, 110)
            if text_factor > 160:
                row_h = max(row_h, 126)
            table.setRowHeight(i, row_h)

        self._expand_table(table, len(findings))

    def refresh(self):
        self.apply_page_theme()
        dyn_rows, st_rows = [], []
        has_session = False
        scan_type = "Dynamic"
        try:
            from core.shared_state import SharedState
            has_session = bool(
                hasattr(SharedState, "has_scan_data") and SharedState.has_scan_data()
            )
            if has_session:
                app = getattr(SharedState, "case_name", None) or "—"
                target = SharedState.current_url or "—"
                scan_type = getattr(SharedState, "scan_type", None) or "Dynamic"
                self.overview_app.setText(f"Application: {app}")
                self.overview_target.setText(f"Target: {target}")
                self.overview_target.setToolTip(str(target))
                self.overview_type.setText(f"Type: {scan_type}")
                findings = _enrich(list(getattr(SharedState, "findings", None) or []))
                SharedState.findings = findings
                if str(scan_type).lower() == "static":
                    st_rows = findings
                    dyn_rows = []
                else:
                    dyn_rows = findings
                    st_rows = []
                if findings:
                    cwes = sorted(
                        {str(f.get("cwe_id")) for f in findings if f.get("cwe_id")}
                    )
                    nists = sorted(
                        {
                            str(f.get("nist") or f.get("nist_id"))
                            for f in findings
                            if f.get("nist") or f.get("nist_id")
                        }
                    )
                    sanses = sorted(
                        {
                            str(f.get("sans") or f.get("sans_id"))
                            for f in findings
                            if f.get("sans") or f.get("sans_id")
                        }
                    )
                    bits = []
                    if cwes:
                        bits.append("CWE " + ", ".join(cwes[:4]))
                    if nists:
                        bits.append("NIST " + ", ".join(nists[:2]))
                    if sanses:
                        bits.append("SANS " + ", ".join(sanses[:2]))
                    if bits:
                        self.overview_map.setText("Mappings: " + " · ".join(bits))
                    else:
                        self.overview_map.setText(
                            "Mappings: CWE / WASC / OWASP / NIST / SANS · remediation per finding"
                        )
                else:
                    self.overview_map.setText("Mappings: — (no issues found)")
            else:
                self.overview_app.setText("Application: —")
                self.overview_target.setText("Target: — (no active scan)")
                self.overview_target.setToolTip("")
                self.overview_type.setText("Type: —")
                self.overview_map.setText("Mappings: —")
        except Exception as e:
            print("Alerts error:", e)
            self.overview_app.setText("Application: —")
            self.overview_target.setText("Target: —")
            self.overview_type.setText("Type: —")
            self.overview_map.setText("Mappings: —")

        if not has_session:
            self.empty_state.show()
            self.dyn_section.hide()
            self.st_section.hide()
            empty_dyn = ""
            empty_st = ""
        elif str(scan_type).lower() == "static":
            self.empty_state.hide()
            self.dyn_section.hide()
            self.st_section.show()
            empty_dyn = ""
            empty_st = (
                "No issues found for this static scan."
                if not st_rows
                else "No static alerts for the current scan."
            )
        else:
            self.empty_state.hide()
            self.dyn_section.show()
            self.st_section.hide()
            empty_dyn = (
                "No issues found for this dynamic scan."
                if not dyn_rows
                else "No dynamic alerts for the current scan."
            )
            empty_st = ""

        dyn_c = _count_severity(dyn_rows)
        self.dyn_high.value_label.setText(str(dyn_c["High"]))
        self.dyn_medium.value_label.setText(str(dyn_c["Medium"]))
        self.dyn_low.value_label.setText(str(dyn_c["Low"]))
        self.dyn_total.value_label.setText(str(dyn_c["Total"]))
        self._fill_table(self.dyn_table, self.dyn_empty, dyn_rows, empty_dyn)

        st_c = _count_severity(st_rows)
        self.st_high.value_label.setText(str(st_c["High"]))
        self.st_medium.value_label.setText(str(st_c["Medium"]))
        self.st_low.value_label.setText(str(st_c["Low"]))
        self.st_total.value_label.setText(str(st_c["Total"]))
        self._fill_table(self.st_table, self.st_empty, st_rows, empty_st)
