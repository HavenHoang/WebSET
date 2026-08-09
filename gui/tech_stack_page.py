from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QPushButton, QFrame,
    QLineEdit, QAbstractItemView
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
        if hasattr(self, "case_info_title"):
            self.case_info_title.setStyleSheet(
                f"font-size: 18px; font-weight: 800; color: {title_c}; background: transparent;"
            )
        if hasattr(self, "detail_label"):
            self.detail_label.setStyleSheet(
                f"font-size: 11px; font-weight: 700; color: {muted_c}; "
                f"letter-spacing: 1px; background: transparent;"
            )
        if hasattr(self, "stack_title"):
            self.stack_title.setStyleSheet(
                f"font-size: 15px; font-weight: 800; color: {title_c}; background: transparent;"
            )
        if hasattr(self, "empty_label"):
            self.empty_label.setStyleSheet(
                f"color: {muted_c}; padding: 28px; font-size: 13px; background: transparent;"
            )

    def showEvent(self, event):
        super().showEvent(event)
        self.apply_page_theme()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(0, 0, 0, 0)

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

        self.detail_label = QLabel("DETAIL")
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
        self.app_field.setPlaceholderText("Sample App")
        self.app_field.setMinimumHeight(36)
        left.addWidget(app_lbl)
        left.addWidget(self.app_field)
        info_l.addLayout(left)

        right = QVBoxLayout()
        right.setSpacing(6)
        url_lbl = QLabel("Enter URL")
        url_lbl.setStyleSheet("font-size: 12px; font-weight: 700; color: #5d6b86;")
        self.url_field = QLineEdit()
        self.url_field.setReadOnly(True)
        self.url_field.setPlaceholderText("https://example.com")
        self.url_field.setMinimumHeight(36)
        right.addWidget(url_lbl)
        right.addWidget(self.url_field)
        info_l.addLayout(right)
        layout.addWidget(info_card)

        self.stack_title = QLabel("Tech Stack")
        self.stack_title.setStyleSheet(
            "font-size: 15px; font-weight: 800; color: #1f2a44; background: transparent;"
        )
        layout.addWidget(self.stack_title)

        table_card = QFrame()
        table_card.setObjectName("card")
        table_card.setStyleSheet("""
            QFrame#card {
                background: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 12px;
            }
        """)
        table_l = QVBoxLayout(table_card)
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
        layout.addWidget(table_card, 1)

        self.empty_label = QLabel(
            "No tech stack data yet.\n"
            "Go to Create Scan → enter a URL → click Get Stack."
        )
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setStyleSheet(
            "color: #64748b; padding: 28px; font-size: 13px; background: transparent;"
        )
        layout.addWidget(self.empty_label)

    def refresh(self):
        self.apply_page_theme()
        self.table.setRowCount(0)
        try:
            from core.shared_state import SharedState
        except Exception:
            self.empty_label.setText("SharedState not available.")
            self.empty_label.show()
            self.table.hide()
            return

        url = getattr(SharedState, "current_url", None) or ""
        case_name = getattr(SharedState, "case_name", None) or ""
        tech_stacks = getattr(SharedState, "tech_stacks", None) or []

        self.app_field.setText(case_name)
        self.url_field.setText(url)

        if not tech_stacks:
            self.table.hide()
            self.empty_label.show()
            return

        self.empty_label.hide()
        self.table.show()

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
            self.table.setItem(i, 4, desc_item)
