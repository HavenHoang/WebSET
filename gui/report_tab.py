from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QScrollArea, QSizePolicy, QLayout, QLayoutItem, QFileDialog
)
from PyQt6.QtCore import Qt, QRect, QSize, QPoint
import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)


class _FlowLayout(QLayout):
    def __init__(self, parent=None, margin=0, h_spacing=8, v_spacing=8):
        super().__init__(parent)
        self._items: list[QLayoutItem] = []
        self._hs = h_spacing
        self._vs = v_spacing
        self.setContentsMargins(margin, margin, margin, margin)

    def addItem(self, item):
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, index):
        if 0 <= index < len(self._items):
            return self._items[index]
        return None

    def takeAt(self, index):
        if 0 <= index < len(self._items):
            return self._items.pop(index)
        return None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self._do_layout(QRect(0, 0, width, 0), True)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._do_layout(rect, False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        m = self.contentsMargins()
        size += QSize(m.left() + m.right(), m.top() + m.bottom())
        return size

    def _do_layout(self, rect, test_only):
        x = rect.x()
        y = rect.y()
        line_h = 0
        for item in self._items:
            w = item.sizeHint().width()
            h = item.sizeHint().height()
            if x + w > rect.right() + 1 and line_h > 0:
                x = rect.x()
                y = y + line_h + self._vs
                line_h = 0
            if not test_only:
                item.setGeometry(QRect(QPoint(x, y), item.sizeHint()))
            x = x + w + self._hs
            line_h = max(line_h, h)
        return y + line_h - rect.y()


class ReportTab(QWidget):
    def __init__(self):
        super().__init__()
        self._last_report = None
        self.init_ui()

    def init_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(12)
        root.setContentsMargins(0, 0, 0, 0)

        banner = QFrame()
        banner.setObjectName("reportBanner")
        banner.setStyleSheet("""
            QFrame#reportBanner {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1f2a57, stop:1 #0f3d5e);
                border: none; border-radius: 12px;
            }
            QFrame#reportBanner QLabel {
                background: transparent; border: none; color: #ffffff; padding: 0px;
            }
        """)
        b_l = QVBoxLayout(banner)
        b_l.setContentsMargins(16, 12, 16, 12)
        b_l.setSpacing(4)
        title = QLabel("Security Assessment Report")
        title.setStyleSheet("font-size: 16px; font-weight: 800;")
        b_l.addWidget(title)
        self.meta_label = QLabel(
            "Generate a report after Start Scan and/or Get Stack."
        )
        self.meta_label.setWordWrap(True)
        self.meta_label.setStyleSheet(
            "font-size: 12px; color: rgba(255,255,255,0.88);"
        )
        b_l.addWidget(self.meta_label)
        root.addWidget(banner)

        chips = QHBoxLayout()
        chips.setSpacing(10)
        self.chip_high = self._make_chip("High", "0", "#c0392b", "#fdecea")
        self.chip_medium = self._make_chip("Medium", "0", "#d68910", "#fef5e7")
        self.chip_low = self._make_chip("Low", "0", "#5d6d7e", "#eef1f4")
        self.chip_total = self._make_chip("Total", "0", "#1f2a57", "#eaf0ff")
        for w in (self.chip_high, self.chip_medium, self.chip_low, self.chip_total):
            chips.addWidget(w, 1)
        root.addLayout(chips)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        body = QWidget()
        body.setStyleSheet("background: transparent;")
        self.body_l = QVBoxLayout(body)
        self.body_l.setSpacing(12)
        self.body_l.setContentsMargins(0, 0, 4, 8)

        self.exec_card = self._section_card("Executive summary")
        self.exec_box = QFrame()
        self.exec_box.setObjectName("execBox")
        self.exec_box.setStyleSheet("""
            QFrame#execBox {
                background: #f1f5f9;
                border: 1px solid #e2e8f0;
                border-radius: 10px;
            }
            QFrame#execBox QLabel {
                background: transparent;
                border: none;
            }
        """)
        self.exec_box_l = QVBoxLayout(self.exec_box)
        self.exec_box_l.setContentsMargins(14, 12, 14, 12)
        self.exec_box_l.setSpacing(6)
        self.exec_headline = QLabel("—")
        self.exec_headline.setWordWrap(True)
        self.exec_headline.setStyleSheet(
            "color: #0f172a; font-size: 14px; font-weight: 700;"
        )
        self.exec_box_l.addWidget(self.exec_headline)
        self.exec_points_host = QWidget()
        self.exec_points_host.setStyleSheet("background: transparent;")
        self.exec_points_l = QVBoxLayout(self.exec_points_host)
        self.exec_points_l.setContentsMargins(0, 2, 0, 0)
        self.exec_points_l.setSpacing(4)
        self.exec_box_l.addWidget(self.exec_points_host)
        self.exec_text = QLabel("")
        self.exec_text.setWordWrap(True)
        self.exec_text.setStyleSheet(
            "color: #334155; font-size: 13px; background: transparent; border: none;"
        )
        self.exec_text.hide()
        self.exec_box_l.addWidget(self.exec_text)
        self.exec_card.layout().addWidget(self.exec_box)
        self.body_l.addWidget(self.exec_card)

        self.stacks_card = self._section_card("Tech stacks")
        self.stacks_host = QWidget()
        self.stacks_host.setStyleSheet("background: transparent;")
        self.stacks_layout = QVBoxLayout(self.stacks_host)
        self.stacks_layout.setContentsMargins(0, 0, 0, 0)
        self.stacks_layout.setSpacing(6)
        self.stacks_empty = QLabel("No tech stacks in this session. Run Get Stack first.")
        self.stacks_empty.setWordWrap(True)
        self.stacks_empty.setStyleSheet(
            "color: #94a3b8; font-size: 13px; background: transparent;"
        )
        self.stacks_card.layout().addWidget(self.stacks_host)
        self.stacks_card.layout().addWidget(self.stacks_empty)
        self.body_l.addWidget(self.stacks_card)

        # Standards mapping = Start Scan findings only
        self.map_card = self._section_card(
            "Standards mapping (Start Scan findings)"
        )
        self.map_chips_host = QWidget()
        self.map_chips_host.setStyleSheet("background: transparent;")
        self.map_chips_layout = _FlowLayout(self.map_chips_host, h_spacing=8, v_spacing=8)
        self.map_chips_host.setLayout(self.map_chips_layout)
        self.map_empty = QLabel(
            "No standards mappings from Start Scan findings yet."
        )
        self.map_empty.setWordWrap(True)
        self.map_empty.setStyleSheet(
            "color: #94a3b8; font-size: 13px; background: transparent;"
        )
        self.map_card.layout().addWidget(self.map_chips_host)
        self.map_card.layout().addWidget(self.map_empty)
        self.body_l.addWidget(self.map_card)

        self.findings_card = self._section_card("Scan findings (Start Scan)")
        self.findings_host = QWidget()
        self.findings_host.setStyleSheet("background: transparent;")
        self.findings_layout = QVBoxLayout(self.findings_host)
        self.findings_layout.setContentsMargins(0, 0, 0, 0)
        self.findings_layout.setSpacing(10)
        self.findings_empty = QLabel(
            "No Start Scan findings. Run Start Scan from Create Scan."
        )
        self.findings_empty.setWordWrap(True)
        self.findings_empty.setStyleSheet(
            "color: #94a3b8; font-size: 13px; background: transparent;"
        )
        self.findings_card.layout().addWidget(self.findings_host)
        self.findings_card.layout().addWidget(self.findings_empty)
        self.body_l.addWidget(self.findings_card)

        self.platform_card = self._section_card(
            "Platform evaluation (Get Stack) — guidance only"
        )
        self.platform_host = QWidget()
        self.platform_host.setStyleSheet("background: transparent;")
        self.platform_layout = QVBoxLayout(self.platform_host)
        self.platform_layout.setContentsMargins(0, 0, 0, 0)
        self.platform_layout.setSpacing(10)
        self.platform_empty = QLabel(
            "No platform evaluation notes. Run Get Stack from Create Scan."
        )
        self.platform_empty.setWordWrap(True)
        self.platform_empty.setStyleSheet(
            "color: #94a3b8; font-size: 13px; background: transparent;"
        )
        self.platform_card.layout().addWidget(self.platform_host)
        self.platform_card.layout().addWidget(self.platform_empty)
        self.body_l.addWidget(self.platform_card)

        self.rem_card = self._section_card("Remediation")
        self.rem_host = QWidget()
        self.rem_host.setStyleSheet("background: transparent;")
        self.rem_layout = QVBoxLayout(self.rem_host)
        self.rem_layout.setContentsMargins(0, 0, 0, 0)
        self.rem_layout.setSpacing(6)
        self.rem_empty = QLabel("—")
        self.rem_empty.setStyleSheet(
            "color: #94a3b8; font-size: 13px; background: transparent;"
        )
        self.rem_card.layout().addWidget(self.rem_host)
        self.rem_card.layout().addWidget(self.rem_empty)
        self.body_l.addWidget(self.rem_card)

        self.body_l.addStretch()
        scroll.setWidget(body)
        root.addWidget(scroll, 1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.generate_button = QPushButton("Generate Report")
        self.generate_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.generate_button.setStyleSheet("""
            QPushButton {
                background-color: #1f2a57; color: white; font-weight: 800;
                padding: 10px 18px; border-radius: 8px; border: none;
            }
            QPushButton:hover { background-color: #2f3f7a; }
        """)
        self.export_button = QPushButton("Export PDF")
        self.export_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.export_button.setStyleSheet("""
            QPushButton {
                background-color: #16a34a; color: white; font-weight: 800;
                padding: 10px 18px; border-radius: 8px; border: none;
            }
            QPushButton:hover { background-color: #15803d; }
        """)
        btn_row.addWidget(self.generate_button)
        btn_row.addWidget(self.export_button)
        btn_row.addStretch()
        root.addLayout(btn_row)

        self.generate_button.clicked.connect(self.generate_report)
        self.export_button.clicked.connect(self.export_pdf)

    def _make_chip(self, title: str, value: str, color: str, bg: str) -> QFrame:
        frame = QFrame()
        frame.setObjectName("reportChip")
        frame.setMinimumHeight(68)
        frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        frame.setStyleSheet(f"""
            QFrame#reportChip {{
                background: {bg};
                border: 1px solid rgba(0,0,0,0.05);
                border-radius: 12px;
            }}
            QFrame#reportChip QLabel {{
                background: transparent; border: none; padding: 0px;
            }}
        """)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(2)
        t = QLabel(title.upper())
        t.setStyleSheet(
            f"color: {color}; font-size: 11px; font-weight: 800; letter-spacing: 0.3px;"
        )
        v = QLabel(value)
        v.setStyleSheet(f"color: {color}; font-size: 22px; font-weight: 800;")
        layout.addWidget(t)
        layout.addWidget(v)
        frame.value_label = v
        return frame

    def _section_card(self, title: str) -> QFrame:
        card = QFrame()
        card.setObjectName("reportSection")
        card.setStyleSheet("""
            QFrame#reportSection {
                background: #ffffff;
                border: 1px solid #e8edf3;
                border-radius: 12px;
            }
            QFrame#reportSection QLabel {
                background: transparent; border: none; padding: 0px;
            }
        """)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)
        lab = QLabel(title)
        lab.setStyleSheet("font-size: 13px; font-weight: 800; color: #1f2a44;")
        layout.addWidget(lab)
        return card

    def _badge(self, text: str, fg: str = "#1f2a57", bg: str = "#eaf0ff") -> QLabel:
        lab = QLabel(text)
        lab.setWordWrap(False)
        lab.setStyleSheet(f"""
            QLabel {{
                background: {bg};
                color: {fg};
                border: 1px solid {fg};
                border-radius: 8px;
                padding: 4px 10px;
                font-size: 11px;
                font-weight: 700;
            }}
        """)
        lab.adjustSize()
        return lab

    def _meta_row(self, label: str, value: str) -> QWidget:
        row = QWidget()
        row.setStyleSheet("background: transparent;")
        lay = QHBoxLayout(row)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        k = QLabel(label)
        k.setFixedWidth(100)
        k.setStyleSheet("color: #64748b; font-size: 12px; font-weight: 700;")
        v = QLabel(value or "—")
        v.setWordWrap(True)
        v.setStyleSheet("color: #0f172a; font-size: 12px; font-weight: 600;")
        lay.addWidget(k)
        lay.addWidget(v, 1)
        return row

    def _finding_card(
        self, index: int, f: dict, *, include_standards: bool = True
    ) -> QFrame:
        """
        Start Scan → include_standards=True (CWE / OWASP / NIST / SANS + conf).
        Platform → include_standards=False (conf only, no standards badges).
        """
        sev = str(f.get("severity", "Low"))
        colors = {
            "High": ("#c0392b", "#fdecea"),
            "Medium": ("#d68910", "#fef5e7"),
            "Low": ("#5d6d7e", "#eef1f4"),
        }
        fg, bg = colors.get(sev, ("#5d6d7e", "#eef1f4"))
        card = QFrame()
        card.setObjectName("findingCard")
        card.setStyleSheet(f"""
            QFrame#findingCard {{
                background: #f8fafc;
                border: 1px solid #e8edf3;
                border-left: 4px solid {fg};
                border-radius: 10px;
            }}
            QFrame#findingCard QLabel {{
                background: transparent; border: none;
            }}
        """)
        lay = QVBoxLayout(card)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(6)

        head = QHBoxLayout()
        title = QLabel(f"[{index}] {f.get('vulnerability', f.get('name', 'Finding'))}")
        title.setStyleSheet("font-size: 13px; font-weight: 800; color: #0f172a;")
        title.setWordWrap(True)
        head.addWidget(title, 1)
        head.addWidget(self._badge(sev, fg, bg), 0, Qt.AlignmentFlag.AlignTop)
        lay.addLayout(head)

        origin = str(f.get("scan_origin") or "")
        if origin:
            lay.addWidget(self._meta_row("Origin", origin))
        loc = str(f.get("location", f.get("url", "")))
        if loc:
            lay.addWidget(self._meta_row("Location", loc))
        detail = str(f.get("description", "")).strip()
        if detail:
            lay.addWidget(self._meta_row("Detail", detail))
        rem = str(f.get("remediation") or "").strip()
        if rem:
            lay.addWidget(self._meta_row("Remediation", rem))

        tags_host = QWidget()
        tags_host.setStyleSheet("background: transparent;")
        tags = _FlowLayout(tags_host, h_spacing=6, v_spacing=6)
        tags_host.setLayout(tags)

        if include_standards:
            cwe = f.get("cwe_id") or f.get("cweId")
            wasc = f.get("wasc_id") or f.get("wascId")
            owasp = f.get("owasp")
            nist = f.get("nist") or f.get("nist_id")
            sans = f.get("sans") or f.get("sans_id")
            if cwe:
                tags.addWidget(self._badge(str(cwe), "#1d4ed8", "#dbeafe"))
            if wasc:
                tags.addWidget(self._badge(str(wasc), "#7c3aed", "#ede9fe"))
            if owasp:
                tags.addWidget(self._badge(f"OWASP {owasp}", "#0f766e", "#ccfbf1"))
            if nist:
                tags.addWidget(self._badge(str(nist), "#b45309", "#fef3c7"))
            if sans:
                tags.addWidget(self._badge(str(sans), "#9f1239", "#ffe4e6"))

        conf = f.get("confidence")
        if conf:
            tags.addWidget(self._badge(f"Conf. {conf}", "#475569", "#f1f5f9"))

        if tags.count() > 0:
            lay.addWidget(tags_host)
        return card

    def showEvent(self, event):
        super().showEvent(event)
        try:
            from core.shared_state import SharedState
            if not SharedState.has_scan_data() and not (
                hasattr(SharedState, "has_stack_data") and SharedState.has_stack_data()
            ):
                self._reset_view()
        except Exception:
            pass

    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def _set_executive(self, text: str):
        self._clear_layout(self.exec_points_l)
        self.exec_text.hide()
        self.exec_headline.show()
        self.exec_points_host.show()
        raw = (text or "").strip()
        if not raw or raw == "—":
            self.exec_headline.setText("—")
            return
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        if not lines:
            self.exec_headline.setText("—")
            return
        has_bullets = any(ln.startswith("• ") or ln.startswith("- ") for ln in lines)
        if len(lines) == 1 and not has_bullets:
            self.exec_headline.hide()
            self.exec_points_host.hide()
            self.exec_text.setText(lines[0])
            self.exec_text.show()
            return
        headline = lines[0]
        if headline.startswith("• ") or headline.startswith("- "):
            headline = "Assessment summary"
            points = lines
        else:
            points = lines[1:]
        self.exec_headline.setText(headline)
        for p in points:
            t = p
            if t.startswith("- "):
                t = "• " + t[2:]
            if not t.startswith("• "):
                t = "• " + t
            lab = QLabel(t)
            lab.setWordWrap(True)
            lab.setStyleSheet(
                "color: #334155; font-size: 13px; font-weight: 500;"
            )
            self.exec_points_l.addWidget(lab)

    def _reset_view(self):
        self._last_report = None
        self.meta_label.setText(
            "Generate a report after Start Scan and/or Get Stack."
        )
        for chip, val in (
            (self.chip_high, "0"),
            (self.chip_medium, "0"),
            (self.chip_low, "0"),
            (self.chip_total, "0"),
        ):
            chip.value_label.setText(val)
        self._set_executive("—")
        self._clear_layout(self.stacks_layout)
        self.stacks_empty.setText(
            "No tech stacks in this session. Run Get Stack first."
        )
        self.stacks_empty.show()
        self._clear_layout(self.map_chips_layout)
        self.map_empty.setText(
            "No standards mappings from Start Scan findings yet."
        )
        self.map_empty.show()
        self._clear_layout(self.findings_layout)
        self.findings_empty.setText(
            "No Start Scan findings. Run Start Scan from Create Scan."
        )
        self.findings_empty.show()
        self._clear_layout(self.platform_layout)
        self.platform_empty.setText(
            "No platform evaluation notes. Run Get Stack from Create Scan."
        )
        self.platform_empty.show()
        self._clear_layout(self.rem_layout)
        self.rem_empty.setText("—")
        self.rem_empty.show()

    def _render_report(self, report: dict):
        self._last_report = report
        url = report.get("url", "")
        scan_type = report.get("scan_type", "Dynamic")
        generated = report.get("generated_at", "")
        self.meta_label.setText(f"{url} · {scan_type} · {generated}")

        summary = report.get("summary") or {}
        total = int(summary.get("Total", 0) or 0)
        self.chip_high.value_label.setText(str(summary.get("High", 0)))
        self.chip_medium.value_label.setText(str(summary.get("Medium", 0)))
        self.chip_low.value_label.setText(str(summary.get("Low", 0)))
        self.chip_total.value_label.setText(str(total))

        self._set_executive(report.get("executive_summary") or "—")

        self._clear_layout(self.stacks_layout)
        stacks = report.get("tech_stacks") or []
        if not stacks:
            self.stacks_empty.setText(
                "No tech stacks in this session. Run Get Stack first."
            )
            self.stacks_empty.show()
        else:
            self.stacks_empty.hide()
            for s in stacks:
                name = str(s.get("name", "?"))
                cat = str(s.get("category", ""))
                ver = str(s.get("version", ""))
                desc = str(s.get("description", ""))
                parts = [name]
                if cat:
                    parts.append(f"({cat})")
                if ver:
                    parts.append(ver)
                line = " ".join(parts)
                if desc:
                    line += f" — {desc}"
                row = QLabel(line)
                row.setWordWrap(True)
                row.setStyleSheet(
                    "color: #334155; font-size: 13px; background: #f8fafc; "
                    "border: 1px solid #e8edf3; border-radius: 8px; padding: 8px 10px;"
                )
                self.stacks_layout.addWidget(row)

        # Standards chips — intended for Start Scan only (report_generator should
        # aggregate cwe/owasp/nist/sans from findings, not stack_findings).
        self._clear_layout(self.map_chips_layout)
        cwe_map = report.get("cwe_summary") or {}
        owasp_map = report.get("owasp_summary") or {}
        nist_map = report.get("nist_summary") or {}
        sans_map = report.get("sans_summary") or {}
        has_map = False
        for k, v in list(cwe_map.items())[:8]:
            self.map_chips_layout.addWidget(
                self._badge(f"{k} ×{v}", "#1d4ed8", "#dbeafe")
            )
            has_map = True
        for k, v in list(owasp_map.items())[:6]:
            self.map_chips_layout.addWidget(
                self._badge(f"OWASP {k} ×{v}", "#0f766e", "#ccfbf1")
            )
            has_map = True
        for k, v in list(nist_map.items())[:6]:
            self.map_chips_layout.addWidget(
                self._badge(f"{k} ×{v}", "#b45309", "#fef3c7")
            )
            has_map = True
        for k, v in list(sans_map.items())[:6]:
            self.map_chips_layout.addWidget(
                self._badge(f"{k} ×{v}", "#9f1239", "#ffe4e6")
            )
            has_map = True
        if not has_map:
            self.map_empty.setText(
                "No standards mappings from Start Scan findings."
                if total == 0
                else "No CWE / OWASP / NIST / SANS mappings on Start Scan findings."
            )
        self.map_empty.setVisible(not has_map)
        self.map_chips_host.setVisible(has_map)

        self._clear_layout(self.findings_layout)
        findings = report.get("findings") or []
        if not findings:
            self.findings_empty.setText(
                "No Start Scan findings. Run Start Scan from Create Scan."
            )
            self.findings_empty.show()
        else:
            self.findings_empty.hide()
            for i, f in enumerate(findings, start=1):
                self.findings_layout.addWidget(
                    self._finding_card(i, f, include_standards=True)
                )

        self._clear_layout(self.platform_layout)
        stack_findings = report.get("stack_findings") or []
        if not stack_findings:
            self.platform_empty.setText(
                "No platform evaluation notes. Run Get Stack from Create Scan."
            )
            self.platform_empty.show()
        else:
            self.platform_empty.hide()
            for i, f in enumerate(stack_findings, start=1):
                self.platform_layout.addWidget(
                    self._finding_card(i, f, include_standards=False)
                )

        self._clear_layout(self.rem_layout)
        rem = report.get("remediation") or []
        if not rem:
            self.rem_empty.setText("—")
            self.rem_empty.show()
        else:
            self.rem_empty.hide()
            for i, tip in enumerate(rem, start=1):
                row = QLabel(f"{i}. {tip}")
                row.setWordWrap(True)
                row.setStyleSheet(
                    "color: #334155; font-size: 13px; background: #f8fafc; "
                    "border: 1px solid #e8edf3; border-radius: 8px; padding: 8px 12px;"
                )
                self.rem_layout.addWidget(row)

    def generate_report(self):
        try:
            from core.shared_state import SharedState
        except Exception:
            self._set_executive("[Error] SharedState not available.")
            return

        has_scan = SharedState.has_scan_data()
        has_stack = (
            hasattr(SharedState, "has_stack_data") and SharedState.has_stack_data()
        )
        if not has_scan and not has_stack:
            self._reset_view()
            self._set_executive(
                "No session data. Run Start Scan and/or Get Stack first."
            )
            return

        url = SharedState.current_url
        findings = list(getattr(SharedState, "findings", None) or [])
        stack_findings = list(getattr(SharedState, "stack_findings", None) or [])
        scan_type = getattr(SharedState, "scan_type", None) or "Dynamic"
        tech_stacks = list(getattr(SharedState, "tech_stacks", None) or [])

        try:
            from reporting.report_generator import generate_report
            report = generate_report(
                url=url,
                findings=findings,
                scan_type=scan_type,
                tech_stacks=tech_stacks,
                stack_findings=stack_findings,
            )
        except Exception as exc:
            self._set_executive(f"[Error] Could not generate report: {exc}")
            return

        if not isinstance(report, dict):
            self._set_executive("[Error] Report module must return a dict.")
            return

        self._render_report(report)

        main_window = self.window()
        if main_window and hasattr(main_window, "show_toast"):
            n_scan = len(findings)
            n_plat = len(stack_findings)
            if n_scan == 0 and n_plat == 0:
                main_window.show_toast("Report generated — no issues found")
            else:
                main_window.show_toast(
                    f"Report generated — {n_scan} scan finding(s), {n_plat} platform note(s)"
                )

    def export_pdf(self):
        try:
            from core.shared_state import SharedState
        except Exception:
            self._set_executive("[Error] SharedState not available.")
            return

        has_scan = SharedState.has_scan_data()
        has_stack = (
            hasattr(SharedState, "has_stack_data")
            and SharedState.has_stack_data()
        )

        if not has_scan and not has_stack:
            self._set_executive(
                "No session data. Run Start Scan and/or Get Stack first."
            )
            return

        if self._last_report is None:
            self.generate_report()

        if self._last_report is None:
            self._set_executive(
                "[Error] Report could not be generated before PDF export."
            )
            return

        default_name = "WebSET_Security_Assessment_Report.pdf"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Security Assessment Report",
            default_name,
            "PDF Files (*.pdf)",
        )
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"

        try:
            from reporting.pdf_generator import export_pdf

            saved_path = export_pdf(
                url=SharedState.current_url,
                findings=list(getattr(SharedState, "findings", None) or []),
                output_path=path,
                report=self._last_report,
            )
        except Exception as exc:
            self._set_executive(f"[Error] Could not export PDF: {exc}")
            main_window = self.window()
            if main_window and hasattr(main_window, "show_toast"):
                main_window.show_toast("PDF export failed")
            return

        self.meta_label.setText(f"PDF saved: {saved_path}")
        main_window = self.window()
        if main_window and hasattr(main_window, "show_toast"):
            main_window.show_toast("PDF exported successfully")
