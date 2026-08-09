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
        """Titles outside cards must adapt: light text on dark shell, dark text on light shell."""
        dark = self._is_dark()
        title_c = "#e2e8f0" if dark else "#1f2a44"
        if hasattr(self, "page_title"):
            self.page_title.setStyleSheet(
                f"font-size: 15px; font-weight: 800; color: {title_c}; background: transparent;"
            )
        for empty in (getattr(self, "dyn_empty", None), getattr(self, "st_empty", None)):
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
        layout = QVBoxLayout(body)
        layout.setSpacing(16)
        layout.setContentsMargins(0, 0, 4, 12)
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
        layout.addLayout(top)

        self.overview = QFrame()
        self.overview.setObjectName("overviewCard")
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
        self.overview_map = QLabel("Mappings: CWE / WASC / OWASP / confidence")
        self.overview_map.setStyleSheet(
            "font-size: 12px; font-weight: 600; color: #64748b;"
        )
        ov.addWidget(self.overview_app)
        ov.addWidget(self.overview_target)
        ov.addWidget(self.overview_type)
        ov.addWidget(self.overview_map)
        layout.addWidget(self.overview)

        layout.addWidget(
            self._build_section(title="Dynamic scan alerts", subtitle=None, is_static=False)
        )
        layout.addWidget(
            self._build_section(
                title="Static scan alerts",
                subtitle="Criticality mapping (static)",
                is_static=True,
            )
        )
        layout.addStretch(1)

    def _build_section(self, title: str, subtitle: str | None, is_static: bool) -> QFrame:
        card = QFrame()
        card.setObjectName("sectionCard")
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
        lay.addWidget(table)

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
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(
            ["Risk", "Name", "CWE", "Conf.", "Location", "Description"]
        )
        hdr = table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        table.setColumnWidth(0, 88)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        table.setColumnWidth(3, 72)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(48)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        table.setMinimumHeight(0)
        table.setMaximumHeight(260)
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
                padding: 6px;
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
        lay.setContentsMargins(6, 0, 6, 0)
        lay.addStretch()
        badge = QLabel(severity)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setFixedHeight(24)
        badge.setMinimumWidth(68)
        badge.setStyleSheet(f"""
            QLabel {{
                background-color: {bg};
                color: {fg};
                border: 1px solid {fg};
                border-radius: 12px;
                font-size: 11px;
                font-weight: 800;
                padding: 0 8px;
            }}
        """)
        lay.addWidget(badge, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addStretch()
        return wrap

    def _fill_table(
        self, table: QTableWidget, empty_label: QLabel, findings: list, empty_msg: str
    ):
        table.setRowCount(0)
        empty_label.setText(empty_msg)
        if not findings:
            table.hide()
            empty_label.show()
            return
        empty_label.hide()
        table.show()

        name_font = QFont("Arial", 11, QFont.Weight.Bold)
        normal = QFont("Arial", 11)
        vcenter = Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft

        for i, f in enumerate(findings[:40]):
            table.insertRow(i)
            table.setRowHeight(i, 48)

            severity = str(f.get("severity", "Low"))
            name = str(f.get("vulnerability", f.get("name", "")))
            cwe = str(f.get("cwe_id") or f.get("cweId") or "—")
            conf = str(f.get("confidence") or "—")
            location = str(f.get("location", f.get("url", "")))
            desc = str(f.get("description", ""))

            table.setCellWidget(i, 0, self._severity_badge(severity))

            name_item = QTableWidgetItem(name)
            name_item.setFont(name_font)
            name_item.setForeground(QBrush(QColor("#0f172a")))
            name_item.setTextAlignment(vcenter)
            tip_parts = [
                f"Plugin: {f.get('plugin_id') or f.get('pluginId') or '—'}",
                f"WASC: {f.get('wasc_id') or f.get('wascId') or '—'}",
                f"OWASP: {f.get('owasp') or '—'}",
                f"Message: {f.get('message_id') or f.get('messageId') or '—'}",
            ]
            tags = f.get("tags") or f.get("owasp_tags") or []
            if tags:
                tip_parts.append("Tags: " + ", ".join(str(t) for t in tags))
            name_item.setToolTip("\n".join(tip_parts))
            table.setItem(i, 1, name_item)

            cwe_item = QTableWidgetItem(cwe)
            cwe_item.setFont(normal)
            cwe_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            cwe_item.setForeground(QBrush(QColor("#1d4ed8")))
            table.setItem(i, 2, cwe_item)

            conf_item = QTableWidgetItem(conf)
            conf_item.setFont(normal)
            conf_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            conf_item.setForeground(QBrush(QColor("#334155")))
            table.setItem(i, 3, conf_item)

            loc_item = QTableWidgetItem(_shorten(location, 40))
            loc_item.setToolTip(location)
            loc_item.setFont(normal)
            loc_item.setForeground(QBrush(QColor("#475569")))
            loc_item.setTextAlignment(vcenter)
            table.setItem(i, 4, loc_item)

            desc_item = QTableWidgetItem(desc)
            desc_item.setFont(normal)
            desc_item.setForeground(QBrush(QColor("#334155")))
            desc_item.setTextAlignment(vcenter)
            table.setItem(i, 5, desc_item)

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

                if scan_type == "Static":
                    st_rows = findings
                    dyn_rows = []
                else:
                    dyn_rows = [
                        f
                        for f in findings
                        if str(f.get("scan_origin", "Dynamic")).lower() != "static"
                    ]
                    st_rows = [
                        f
                        for f in findings
                        if str(f.get("scan_origin", "")).lower() == "static"
                    ]

                cwes = sorted(
                    {str(f.get("cwe_id")) for f in findings if f.get("cwe_id")}
                )
                if findings and cwes:
                    self.overview_map.setText("Mappings: " + ", ".join(cwes[:6]))
                elif findings:
                    self.overview_map.setText(
                        "Mappings: CWE / WASC / OWASP attached per finding"
                    )
                else:
                    # Active session but clean scan (0 findings)
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

        # Empty messages: no session vs clean scan vs wrong section for this scan type
        if not has_session:
            empty_dyn = "No active scan. Run a Dynamic scan from Create Scan."
            empty_st = "No active scan. Run a Static ZIP scan from Create Scan."
        else:
            if scan_type == "Static":
                empty_dyn = "Current scan is Static — no dynamic alerts for this session."
                empty_st = (
                    "No issues found for this static scan."
                    if not st_rows
                    else "No static alerts for the current scan."
                )
            else:
                empty_dyn = (
                    "No issues found for this dynamic scan."
                    if not dyn_rows
                    else "No dynamic alerts for the current scan."
                )
                empty_st = "Current scan is Dynamic — no static alerts for this session."

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
