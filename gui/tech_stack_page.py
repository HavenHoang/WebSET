from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QPushButton, QFrame,
    QLineEdit, QAbstractItemView, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QColor, QBrush, QPainter, QPixmap, QIcon
import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

ICON_COLORS = [
    "#2e86de",
    "#00cec9",
    "#e84393",
    "#6c5ce7",
    "#a55eea",
    "#f39c12",
    "#27ae60",
    "#e74c3c",
]


def _icon_color(name: str) -> str:
    if not name:
        return ICON_COLORS[0]
    return ICON_COLORS[sum(ord(c) for c in name) % len(ICON_COLORS)]


def _make_icon(name: str, size: int = 32) -> QIcon:
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor(_icon_color(name)))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(0, 0, size - 1, size - 1)
    painter.setPen(QColor("#ffffff"))
    painter.setFont(QFont("Arial", 12, QFont.Weight.Bold))
    letter = (name[:1] or "?").upper()
    painter.drawText(pix.rect(), Qt.AlignmentFlag.AlignCenter, letter)
    painter.end()
    return QIcon(pix)


def _shorten(text: str, limit: int = 80) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _platform_tip(f: dict) -> str:
    """Tooltip for platform notes — no CWE/OWASP/NIST/SANS mapping."""
    parts = [
        f"Finding: {f.get('vulnerability') or f.get('name') or '—'}",
        f"Severity: {f.get('severity') or '—'}",
        f"Confidence: {f.get('confidence') or '—'}",
        f"Location: {f.get('location') or f.get('url') or '—'}",
    ]
    desc = str(f.get("description") or "").strip()
    if desc:
        parts.append(f"Detail: {desc}")
    rem = str(f.get("remediation") or "").strip()
    if rem:
        parts.append(f"Remediation: {rem}")
    plugin = f.get("plugin_id") or f.get("pluginId")
    if plugin:
        parts.append(f"Plugin: {plugin}")
    return "\n".join(parts)


class TechStackPage(QWidget):
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
        muted_c = "#94a3b8" if dark else "#64748b"
        for attr in (
            "case_info_title",
            "stack_title",
            "platform_title",
        ):
            w = getattr(self, attr, None)
            if w is not None:
                size = "18px" if attr == "case_info_title" else "15px"
                w.setStyleSheet(
                    f"font-size: {size}; font-weight: 800; color: {title_c}; "
                    f"background: transparent;"
                )
        if hasattr(self, "detail_label"):
            self.detail_label.setStyleSheet(
                f"font-size: 11px; font-weight: 700; color: {muted_c}; "
                f"letter-spacing: 1px; background: transparent;"
            )
        for attr in ("empty_label", "platform_empty"):
            w = getattr(self, attr, None)
            if w is not None:
                w.setStyleSheet(
                    "color: #64748b; font-size: 13px; font-weight: 500; "
                    "background: transparent; border: none;"
                )

    def showEvent(self, event):
        super().showEvent(event)
        self.apply_page_theme()

    def _make_empty_card(self, title: str, body: str) -> tuple[QFrame, QLabel]:
        card = QFrame()
        card.setObjectName("emptyCard")
        card.setMinimumHeight(110)
        card.setStyleSheet("""
            QFrame#emptyCard {
                background: #ffffff;
                border: 1px dashed #cbd5e1;
                border-radius: 12px;
            }
        """)
        lay = QVBoxLayout(card)
        lay.setContentsMargins(20, 22, 20, 22)
        lay.setSpacing(0)
        msg = QLabel(f"{title}\n{body}")
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        msg.setWordWrap(True)
        msg.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        msg.setStyleSheet(
            "color: #64748b; font-size: 13px; font-weight: 500; "
            "background: transparent; border: none;"
        )
        lay.addWidget(msg)
        return card, msg

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
        layout.setSpacing(14)
        layout.setContentsMargins(0, 0, 4, 12)
        scroll.setWidget(body)

        header = QHBoxLayout()
        self.case_info_title = QLabel("Case Info")
        self.case_info_title.setStyleSheet(
            "font-size: 18px; font-weight: 800; color: #1f2a44; background: transparent;"
        )
        header.addWidget(self.case_info_title)
        header.addStretch()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setFixedWidth(100)
        self.refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                font-weight: 700;
                padding: 8px 12px;
                border-radius: 8px;
                border: none;
            }
            QPushButton:hover { background-color: #1a5dcc; }
        """)
        self.refresh_btn.clicked.connect(self.refresh)
        header.addWidget(self.refresh_btn)
        layout.addLayout(header)

        self.detail_label = QLabel(
            "GET STACK · DETECTED TECHNOLOGIES + PLATFORM EVALUATION"
        )
        self.detail_label.setStyleSheet(
            "font-size: 11px; font-weight: 700; color: #64748b; "
            "letter-spacing: 1px; background: transparent;"
        )
        layout.addWidget(self.detail_label)

        info_card = QFrame()
        info_card.setObjectName("card")
        info_card.setStyleSheet("""
            QFrame#card {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 12px;
            }
            QFrame#card QLabel {
                background: transparent;
                border: none;
            }
            QFrame#card QLineEdit {
                background: #f8fafc;
                color: #0f172a;
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                padding: 6px 10px;
            }
        """)
        info_l = QHBoxLayout(info_card)
        info_l.setContentsMargins(18, 16, 18, 16)
        info_l.setSpacing(20)

        left = QVBoxLayout()
        left.setSpacing(6)
        app_lbl = QLabel("Application")
        app_lbl.setStyleSheet("font-size: 12px; font-weight: 700; color: #5d6b86;")
        self.app_field = QLineEdit()
        self.app_field.setReadOnly(True)
        self.app_field.setPlaceholderText("—")
        self.app_field.setMinimumHeight(36)
        left.addWidget(app_lbl)
        left.addWidget(self.app_field)
        info_l.addLayout(left)

        right = QVBoxLayout()
        right.setSpacing(6)
        url_lbl = QLabel("Target")
        url_lbl.setStyleSheet("font-size: 12px; font-weight: 700; color: #5d6b86;")
        self.url_field = QLineEdit()
        self.url_field.setReadOnly(True)
        self.url_field.setPlaceholderText("—")
        self.url_field.setMinimumHeight(36)
        right.addWidget(url_lbl)
        right.addWidget(self.url_field)
        info_l.addLayout(right)
        layout.addWidget(info_card)

        # ---- Detected tech stacks ----
        self.stack_title = QLabel("Detected tech stacks")
        self.stack_title.setStyleSheet(
            "font-size: 15px; font-weight: 800; color: #1f2a44; background: transparent;"
        )
        layout.addWidget(self.stack_title)

        self.table_card = QFrame()
        self.table_card.setObjectName("card")
        self.table_card.setStyleSheet("""
            QFrame#card {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 12px;
            }
        """)
        table_l = QVBoxLayout(self.table_card)
        table_l.setContentsMargins(0, 0, 0, 0)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["", "NAME", "CATEGORY", "VERSION", "DESCRIPTION"]
        )
        self.table.setIconSize(QSize(32, 32))
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 56)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(56)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.setMinimumHeight(180)
        self.table.setStyleSheet("""
            QTableWidget {
                background: white;
                color: #0f172a;
                border: none;
                font-size: 13px;
                gridline-color: transparent;
                alternate-background-color: #f8fafc;
            }
            QHeaderView::section {
                background-color: #1b4f72;
                color: white;
                padding: 12px 10px;
                border: none;
                font-weight: 700;
                font-size: 12px;
            }
            QTableWidget::item {
                color: #0f172a;
                padding: 6px 8px;
                border-bottom: 1px solid #eef1f6;
            }
            QTableWidget::item:selected {
                background: #eaf2ff;
                color: #0f172a;
            }
        """)
        table_l.addWidget(self.table)
        layout.addWidget(self.table_card)

        self.stack_empty_card, self.empty_label = self._make_empty_card(
            "No tech stacks detected",
            "Go to Create Scan, enter a URL or ZIP, then click Get Stack.",
        )
        layout.addWidget(self.stack_empty_card)

        # ---- Platform evaluation (no standards mapping) ----
        self.platform_title = QLabel("Platform evaluation (Get Stack)")
        self.platform_title.setStyleSheet(
            "font-size: 15px; font-weight: 800; color: #1f2a44; background: transparent;"
        )
        layout.addWidget(self.platform_title)

        self.platform_hint = QLabel(
            "Hardening notes from technology detection — guidance only, not confirmed "
            "vulnerabilities."
        )
        self.platform_hint.setWordWrap(True)
        self.platform_hint.setStyleSheet(
            "font-size: 12px; color: #64748b; background: transparent;"
        )
        layout.addWidget(self.platform_hint)

        self.plat_card = QFrame()
        self.plat_card.setObjectName("card")
        self.plat_card.setStyleSheet("""
            QFrame#card {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 12px;
            }
        """)
        plat_l = QVBoxLayout(self.plat_card)
        plat_l.setContentsMargins(0, 0, 0, 0)

        self.platform_table = QTableWidget()
        # Risk | Finding | Conf. | Location | Detail | Remediation  (no Standards)
        self.platform_table.setColumnCount(6)
        self.platform_table.setHorizontalHeaderLabels(
            ["Risk", "Finding", "Conf.", "Location", "Detail", "Remediation"]
        )
        ph = self.platform_table.horizontalHeader()
        ph.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.platform_table.setColumnWidth(0, 90)
        ph.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        ph.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.platform_table.setColumnWidth(2, 72)
        ph.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        self.platform_table.setColumnWidth(3, 150)
        ph.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        ph.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)

        self.platform_table.verticalHeader().setVisible(False)
        self.platform_table.verticalHeader().setDefaultSectionSize(72)
        self.platform_table.setShowGrid(False)
        self.platform_table.setAlternatingRowColors(True)
        self.platform_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.platform_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.platform_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.platform_table.setWordWrap(True)
        self.platform_table.setTextElideMode(Qt.TextElideMode.ElideNone)
        self.platform_table.setMinimumHeight(160)
        self.platform_table.setStyleSheet("""
            QTableWidget {
                background: white;
                color: #0f172a;
                border: none;
                font-size: 13px;
                alternate-background-color: #f8fafc;
            }
            QHeaderView::section {
                background-color: #0f766e;
                color: white;
                padding: 12px 10px;
                border: none;
                font-weight: 700;
                font-size: 12px;
            }
            QTableWidget::item {
                color: #0f172a;
                padding: 8px;
                border-bottom: 1px solid #eef1f6;
            }
            QTableWidget::item:selected {
                background: #ccfbf1;
                color: #0f172a;
            }
        """)
        plat_l.addWidget(self.platform_table)
        layout.addWidget(self.plat_card)

        self.platform_empty_card, self.platform_empty = self._make_empty_card(
            "No platform evaluation yet",
            "Run Get Stack (URL or ZIP) from Create Scan to see hardening notes.",
        )
        layout.addWidget(self.platform_empty_card)
        layout.addStretch()

        self.table_card.hide()
        self.plat_card.hide()
        self.stack_empty_card.show()
        self.platform_empty_card.show()

    def _fill_stacks(self, tech_stacks: list):
        self.table.setRowCount(0)
        if not tech_stacks:
            self.table_card.hide()
            self.stack_empty_card.show()
            return
        self.stack_empty_card.hide()
        self.table_card.show()

        name_font = QFont("Arial", 12, QFont.Weight.Bold)
        normal = QFont("Arial", 12)
        vcenter_left = Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft

        for i, tech in enumerate(tech_stacks):
            self.table.insertRow(i)
            name = str(tech.get("name", ""))
            category = str(tech.get("category", ""))
            version = str(tech.get("version", ""))
            description = str(tech.get("description", ""))

            icon_item = QTableWidgetItem()
            icon_item.setIcon(_make_icon(name))
            icon_item.setFlags(
                Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
            )
            icon_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 0, icon_item)

            name_item = QTableWidgetItem(name)
            name_item.setFont(name_font)
            name_item.setForeground(QBrush(QColor("#0f172a")))
            name_item.setTextAlignment(vcenter_left)
            self.table.setItem(i, 1, name_item)

            cat_item = QTableWidgetItem(category)
            cat_item.setFont(normal)
            cat_item.setForeground(QBrush(QColor("#5d6b86")))
            cat_item.setTextAlignment(vcenter_left)
            self.table.setItem(i, 2, cat_item)

            ver_item = QTableWidgetItem(version)
            ver_item.setFont(normal)
            ver_item.setForeground(QBrush(QColor("#0f172a")))
            ver_item.setTextAlignment(vcenter_left)
            self.table.setItem(i, 3, ver_item)

            desc_item = QTableWidgetItem(description)
            desc_item.setFont(normal)
            desc_item.setForeground(QBrush(QColor("#4a5568")))
            desc_item.setTextAlignment(vcenter_left)
            desc_item.setToolTip(description)
            self.table.setItem(i, 4, desc_item)

    def _severity_colors(self, severity: str):
        colors = {
            "High": ("#c0392b", "#fdecea"),
            "Medium": ("#d68910", "#fef5e7"),
            "Low": ("#5d6d7e", "#eef1f4"),
        }
        return colors.get(severity, ("#5d6d7e", "#eef1f4"))

    def _fill_platform(self, findings: list):
        self.platform_table.setRowCount(0)
        if not findings:
            self.plat_card.hide()
            self.platform_empty_card.show()
            return

        self.platform_empty_card.hide()
        self.plat_card.show()

        name_font = QFont("Arial", 11, QFont.Weight.Bold)
        normal = QFont("Arial", 11)
        vcenter_left = Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft
        vcenter_h = Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignHCenter

        for i, f in enumerate(findings[:40]):
            self.platform_table.insertRow(i)

            severity = str(f.get("severity", "Low"))
            name = str(f.get("vulnerability", f.get("name", "")))
            conf = str(f.get("confidence") or "—")
            location = str(f.get("location", f.get("url", "")))
            detail = str(f.get("description", "") or "")
            rem = str(f.get("remediation") or "").strip() or "—"
            tip = _platform_tip(f)
            fg, _bg = self._severity_colors(severity)

            # 0 Risk
            sev_item = QTableWidgetItem(severity)
            sev_item.setFont(name_font)
            sev_item.setForeground(QBrush(QColor(fg)))
            sev_item.setTextAlignment(vcenter_h)
            self.platform_table.setItem(i, 0, sev_item)

            # 1 Finding
            name_item = QTableWidgetItem(name)
            name_item.setFont(name_font)
            name_item.setForeground(QBrush(QColor("#0f172a")))
            name_item.setTextAlignment(vcenter_left)
            name_item.setToolTip(tip)
            self.platform_table.setItem(i, 1, name_item)

            # 2 Conf.
            conf_item = QTableWidgetItem(conf)
            conf_item.setFont(normal)
            conf_item.setTextAlignment(vcenter_h)
            conf_item.setForeground(QBrush(QColor("#334155")))
            conf_item.setToolTip(tip)
            self.platform_table.setItem(i, 2, conf_item)

            # 3 Location
            loc_item = QTableWidgetItem(_shorten(location, 40))
            loc_item.setToolTip(location)
            loc_item.setFont(normal)
            loc_item.setForeground(QBrush(QColor("#475569")))
            loc_item.setTextAlignment(vcenter_left)
            self.platform_table.setItem(i, 3, loc_item)

            # 4 Detail
            det_item = QTableWidgetItem(detail if detail else "—")
            det_item.setToolTip(detail)
            det_item.setFont(normal)
            det_item.setTextAlignment(vcenter_left)
            det_item.setForeground(QBrush(QColor("#334155")))
            self.platform_table.setItem(i, 4, det_item)

            # 5 Remediation
            rem_item = QTableWidgetItem(rem)
            rem_item.setToolTip(rem)
            rem_item.setFont(normal)
            rem_item.setForeground(QBrush(QColor("#0f766e")))
            rem_item.setTextAlignment(vcenter_left)
            self.platform_table.setItem(i, 5, rem_item)

            chars = max(len(detail), len(rem), 1)
            lines = max((chars // 55) + 1, 2)
            row_h = min(28 + lines * 18, 140)
            self.platform_table.setRowHeight(i, row_h)

    def refresh(self):
        self.apply_page_theme()
        try:
            from core.shared_state import SharedState
        except Exception:
            self.app_field.clear()
            self.url_field.clear()
            self.table_card.hide()
            self.plat_card.hide()
            self.stack_empty_card.show()
            self.platform_empty_card.show()
            self.empty_label.setText(
                "SharedState not available.\nCheck core.shared_state import."
            )
            return

        url = getattr(SharedState, "current_url", None) or ""
        case_name = getattr(SharedState, "case_name", None) or ""
        tech_stacks = getattr(SharedState, "tech_stacks", None) or []
        stack_findings = list(getattr(SharedState, "stack_findings", None) or [])

        self.app_field.setText(case_name)
        self.url_field.setText(url)
        self._fill_stacks(tech_stacks)
        self._fill_platform(stack_findings)
