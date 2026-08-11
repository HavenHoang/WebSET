from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QPushButton, QFrame,
    QAbstractItemView, QScrollArea, QSizePolicy, QGridLayout
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QBrush, QFontMetrics
import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Active Test only for injection-style findings (not headers/cookies/CSP)
_ACTIVE_TYPES = frozenset({"xss", "sqli", "path_traversal", "command_injection"})


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


def _infer_vuln_type(f: dict) -> str:
    v = str(f.get("vuln_type") or f.get("vulnerability_type") or "").lower().strip()
    if v in _ACTIVE_TYPES or v == "generic":
        return v
    name = str(f.get("vulnerability") or f.get("name") or "").lower()
    if "xss" in name or "cross-site" in name:
        return "xss"
    if "sql" in name and "injection" in name:
        return "sqli"
    if "sql injection" in name or name.strip() == "sqli":
        return "sqli"
    if "path" in name or "traversal" in name:
        return "path_traversal"
    if "command" in name and "injection" in name:
        return "command_injection"
    return v or "generic"


def _is_active_testable(f: dict) -> bool:
    """
    Active Test = one controlled injection probe.
    Passive findings (headers, cookies, CSP, info disclosure) → no button.
    """
    if str(f.get("scan_origin") or "") == "Platform":
        return False
    vtype = _infer_vuln_type(f)
    if vtype not in _ACTIVE_TYPES:
        return False
    url = str(
        f.get("url") or f.get("endpoint") or f.get("location") or ""
    ).strip()
    if not url:
        return False
    if vtype in {"xss", "sqli"}:
        param = str(
            f.get("param") or f.get("input") or f.get("parameter") or ""
        ).strip()
        if not param:
            return False
    return True


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
    method = f.get("method")
    param = f.get("param") or f.get("input") or f.get("parameter")
    loc = f.get("param_location") or f.get("input_location")
    ctx = f.get("context")
    vtype = f.get("vuln_type") or f.get("vulnerability_type") or _infer_vuln_type(f)
    if method:
        parts.append(f"Method: {method}")
    if param:
        parts.append(f"Parameter: {param}")
    if loc:
        parts.append(f"Param location: {loc}")
    if ctx:
        parts.append(f"Context: {ctx}")
    if vtype:
        parts.append(f"Vuln type: {vtype}")
    rem = str(f.get("remediation") or "").strip()
    if rem:
        parts.append(f"Remediation: {rem}")
    desc = str(f.get("description") or "").strip()
    if desc:
        parts.append(f"Description: {desc}")
    tags = f.get("tags") or f.get("owasp_tags") or []
    if tags:
        parts.append("Tags: " + ", ".join(str(t) for t in tags))
    if not _is_active_testable(f):
        parts.append(
            "Active Test: not available (passive / config finding — no injection probe)."
        )
    return "\n".join(parts)


def _standards_cell(f: dict) -> str:
    """Full standards text (no ellipsis) — row height expands to fit."""
    cwe = str(f.get("cwe_id") or f.get("cweId") or "—")
    nist = str(f.get("nist") or f.get("nist_id") or "—")
    sans = str(f.get("sans") or f.get("sans_id") or "—")
    owasp = str(f.get("owasp") or "").strip()
    lines = [f"CWE: {cwe}"]
    if owasp:
        lines.append(f"OWASP: {owasp}")
    lines.append(f"NIST: {nist}")
    lines.append(f"SANS: {sans}")
    return "\n".join(lines)


def _normalize_finding_for_active_test(f: dict) -> dict:
    out = dict(f or {})
    url = (
        out.get("url")
        or out.get("endpoint")
        or out.get("location")
        or ""
    )
    out.setdefault("url", url)
    out.setdefault("endpoint", url)
    out.setdefault("method", out.get("method") or "GET")
    param = out.get("param") or out.get("input") or out.get("parameter") or ""
    out.setdefault("param", param)
    out.setdefault("input", param)
    out.setdefault(
        "param_location",
        out.get("param_location") or out.get("input_location") or "query",
    )
    out.setdefault("context", out.get("context") or "")
    out["vuln_type"] = _infer_vuln_type(out)
    return out


def _estimate_wrapped_lines(text: str, col_width_px: int, font: QFont) -> int:
    """Rough line count for word-wrapped cell content."""
    text = (text or "").strip()
    if not text:
        return 1
    explicit = text.count("\n") + 1
    fm = QFontMetrics(font)
    w = max(40, col_width_px - 20)
    lines = 0
    for para in text.split("\n"):
        if not para:
            lines += 1
            continue
        br = fm.boundingRect(0, 0, w, 5000, Qt.TextFlag.TextWordWrap, para)
        lines += max(1, (br.height() + fm.lineSpacing() - 1) // max(1, fm.lineSpacing()))
    return max(explicit, lines)


_BADGE_READY = """
    QLabel {
        background: #dcfce7;
        color: #16a34a;
        font-size: 11px;
        font-weight: 700;
        padding: 3px 10px;
        border-radius: 10px;
        border: 1px solid #86efac;
    }
"""
_BADGE_IDLE = """
    QLabel {
        background: #f1f5f9;
        color: #64748b;
        font-size: 11px;
        font-weight: 700;
        padding: 3px 10px;
        border-radius: 10px;
        border: 1px solid #cbd5e1;
    }
"""

_ACTIVE_BTN_QSS = """
    QPushButton {
        background: #0f766e;
        color: #ffffff;
        font-weight: 700;
        font-size: 11px;
        border: none;
        border-radius: 8px;
        padding: 6px 10px;
        min-height: 28px;
    }
    QPushButton:hover { background: #0d9488; }
    QPushButton:pressed { background: #115e59; }
    QPushButton:disabled {
        background: #cbd5e1;
        color: #64748b;
    }
"""


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
                    "color: #64748b; padding: 12px 8px; font-size: 13px; font-weight: 500;"
                )

    def showEvent(self, event):
        super().showEvent(event)
        self.apply_page_theme()
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
        ov.setContentsMargins(16, 14, 16, 14)
        ov.setSpacing(10)

        ov_head = QHBoxLayout()
        ov_title = QLabel("Current scan overview")
        ov_title.setStyleSheet(
            "font-size: 12px; font-weight: 800; color: #64748b; letter-spacing: 0.4px;"
        )
        ov_head.addWidget(ov_title)
        ov_head.addStretch()
        self.overview_badge = QLabel("No active scan")
        self.overview_badge.setStyleSheet(_BADGE_IDLE)
        ov_head.addWidget(self.overview_badge)
        ov.addLayout(ov_head)

        grid = QGridLayout()
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(8)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)

        def _field(label: str) -> tuple[QLabel, QLabel]:
            k = QLabel(label)
            k.setStyleSheet("font-size: 11px; font-weight: 700; color: #94a3b8;")
            v = QLabel("—")
            v.setWordWrap(True)
            v.setStyleSheet("font-size: 13px; font-weight: 700; color: #0f172a;")
            v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            return k, v

        k_app, self.overview_app = _field("Application")
        k_type, self.overview_type = _field("Type")
        k_tgt, self.overview_target = _field("Target")
        k_map, self.overview_map = _field("Standards")
        grid.addWidget(k_app, 0, 0)
        grid.addWidget(self.overview_app, 0, 1)
        grid.addWidget(k_type, 0, 2)
        grid.addWidget(self.overview_type, 0, 3)
        grid.addWidget(k_tgt, 1, 0)
        grid.addWidget(self.overview_target, 1, 1, 1, 3)
        grid.addWidget(k_map, 2, 0)
        grid.addWidget(self.overview_map, 2, 1, 1, 3)
        ov.addLayout(grid)
        self._body_layout.addWidget(self.overview)

        self.empty_state = QFrame()
        self.empty_state.setObjectName("emptyStateCard")
        self.empty_state.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum
        )
        self.empty_state.setStyleSheet("""
            QFrame#emptyStateCard {
                background: #ffffff;
                border: 1px dashed #cbd5e1;
                border-radius: 14px;
            }
        """)
        es_lay = QVBoxLayout(self.empty_state)
        es_lay.setContentsMargins(24, 28, 24, 28)
        es_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_state_label = QLabel(
            "No active scan.\n\n"
            "Go to Create Scan and run Start Scan (URL or ZIP).\n"
            "Security findings appear here.\n"
            "Get Stack results appear on the Tech Stack page."
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
        self._body_layout.addWidget(self.dyn_section)

        self.st_section = self._build_section(
            title="Static scan alerts",
            subtitle="Criticality mapping (static) · CWE / NIST / SANS",
            is_static=True,
        )
        self._body_layout.addWidget(self.st_section)

        self._body_layout.addStretch(1)

    def _build_section(self, title: str, subtitle: str | None, is_static: bool) -> QFrame:
        card = QFrame()
        card.setObjectName("sectionCard")
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
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
            "color: #64748b; padding: 12px 8px; font-size: 13px; font-weight: 500;"
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
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels(
            [
                "Risk",
                "Name",
                "Standards",
                "Conf.",
                "Location",
                "Description",
                "Remediation",
                "Action",
            ]
        )
        hdr = table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        table.setColumnWidth(0, 104)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        table.setColumnWidth(1, 160)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        table.setColumnWidth(2, 170)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        table.setColumnWidth(3, 72)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        table.setColumnWidth(4, 160)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(7, QHeaderView.ResizeMode.Fixed)
        table.setColumnWidth(7, 118)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(96)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        table.setMouseTracking(True)
        table.viewport().setMouseTracking(True)
        table.setMinimumHeight(0)
        table.setMaximumHeight(16777215)
        table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
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

    def _active_test_button(self, finding: dict) -> QWidget:
        wrap = QWidget()
        wrap.setStyleSheet("background: transparent; border: none;")
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(6, 8, 6, 8)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        btn = QPushButton("Active Test")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(_ACTIVE_BTN_QSS)
        btn.setToolTip(
            "One controlled verification request on Payload "
            "(injection-style finding only)."
        )
        btn.clicked.connect(lambda _=False, f=finding: self._on_active_test(f))
        lay.addWidget(btn)
        return wrap

    def _passive_action_placeholder(self, finding: dict) -> QWidget:
        """No Active Test for header/cookie/CSP-style findings."""
        wrap = QWidget()
        wrap.setStyleSheet("background: transparent; border: none;")
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(6, 8, 6, 8)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lab = QLabel("—")
        lab.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lab.setStyleSheet("color: #94a3b8; font-size: 12px; font-weight: 600;")
        lab.setToolTip(
            "Passive finding — verified from scan response.\n"
            "No injection probe (Active Test not applicable)."
        )
        lay.addWidget(lab)
        return wrap

    def _on_active_test(self, finding: dict):
        if not _is_active_testable(finding):
            main = self.window()
            if main and hasattr(main, "show_toast"):
                main.show_toast("Active Test not available for this finding")
            return

        target = _normalize_finding_for_active_test(finding)
        try:
            from core.shared_state import SharedState
            if hasattr(SharedState, "set_active_test_finding"):
                SharedState.set_active_test_finding(target)
            else:
                SharedState.active_test_finding = target
        except Exception as e:
            print("Active Test SharedState error:", e)
            return

        main = self.window()
        payload_page = getattr(main, "payload_page", None) if main else None
        if payload_page is not None and hasattr(payload_page, "load_from_finding"):
            try:
                payload_page.load_from_finding(target)
            except Exception as e:
                print("Payload load_from_finding error:", e)

        if main is not None:
            for attr in ("show_payload_page", "open_payload_page", "go_to_payload"):
                fn = getattr(main, attr, None)
                if callable(fn):
                    try:
                        fn()
                        break
                    except Exception:
                        pass
            else:
                for attr in ("stack", "pages", "content_stack"):
                    stack = getattr(main, attr, None)
                    if stack is not None and payload_page is not None:
                        try:
                            stack.setCurrentWidget(payload_page)
                            break
                        except Exception:
                            pass
                tabs = getattr(main, "tabs", None) or getattr(main, "tab_widget", None)
                if tabs is not None and payload_page is not None:
                    try:
                        idx = tabs.indexOf(payload_page)
                        if idx >= 0:
                            tabs.setCurrentIndex(idx)
                    except Exception:
                        pass

        if main is not None and hasattr(main, "show_toast"):
            name = str(target.get("vulnerability") or target.get("name") or "Finding")
            main.show_toast(f"Active Test ready — {name}")

    def _expand_table(self, table: QTableWidget, n_rows: int):
        if n_rows <= 0:
            table.setMinimumHeight(0)
            table.setMaximumHeight(0)
            return
        content_h = 40 + sum(table.rowHeight(i) for i in range(table.rowCount())) + 20
        h = max(280, min(content_h, 1600))
        table.setMinimumHeight(h)
        table.setMaximumHeight(16777215)

    def _fill_table(
        self, table: QTableWidget, empty_label: QLabel, findings: list, empty_msg: str
    ):
        table.setRowCount(0)
        empty_label.setText(empty_msg)
        if not findings:
            table.hide()
            empty_label.show()
            table.setMinimumHeight(0)
            table.setMaximumHeight(0)
            return

        empty_label.hide()
        table.show()

        name_font = QFont("Arial", 11, QFont.Weight.Bold)
        normal = QFont("Arial", 11)
        std_font = QFont("Arial", 10)
        # Vertical centre for all text cells; Conf. also horizontal centre
        vcenter_left = Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft
        vcenter_h = Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignHCenter

        table_w = max(table.viewport().width(), 900)
        fixed = 104 + 72 + 118 + 160 + 170 + 160
        stretch_each = max(140, (table_w - fixed) // 2)

        for i, f in enumerate(findings[:40]):
            table.insertRow(i)
            severity = str(f.get("severity", "Low"))
            name = str(f.get("vulnerability", f.get("name", "")))
            conf = str(f.get("confidence") or "—")
            location = str(f.get("location", f.get("url", "")) or "")
            desc = str(f.get("description", "") or "")
            rem = str(f.get("remediation") or "").strip()
            tip = _std_tip(f)
            standards = _standards_cell(f)

            table.setCellWidget(i, 0, self._severity_badge(severity))

            name_item = QTableWidgetItem(name)
            name_item.setFont(name_font)
            name_item.setForeground(QBrush(QColor("#0f172a")))
            name_item.setTextAlignment(vcenter_left)
            name_item.setToolTip(name if name else tip)
            table.setItem(i, 1, name_item)

            std_item = QTableWidgetItem(standards)
            std_item.setFont(std_font)
            std_item.setTextAlignment(vcenter_left)
            std_item.setForeground(QBrush(QColor("#1e3a8a")))
            std_item.setToolTip(tip)
            table.setItem(i, 2, std_item)

            conf_item = QTableWidgetItem(conf)
            conf_item.setFont(normal)
            conf_item.setTextAlignment(vcenter_h)
            conf_item.setForeground(QBrush(QColor("#334155")))
            conf_item.setToolTip(tip)
            table.setItem(i, 3, conf_item)

            loc_item = QTableWidgetItem(location)
            loc_item.setToolTip(location if location else tip)
            loc_item.setFont(normal)
            loc_item.setForeground(QBrush(QColor("#475569")))
            loc_item.setTextAlignment(vcenter_left)
            table.setItem(i, 4, loc_item)

            desc_item = QTableWidgetItem(desc)
            desc_item.setToolTip(desc if desc else tip)
            desc_item.setFont(normal)
            desc_item.setForeground(QBrush(QColor("#334155")))
            desc_item.setTextAlignment(vcenter_left)
            table.setItem(i, 5, desc_item)

            rem_display = rem if rem else "—"
            rem_item = QTableWidgetItem(rem_display)
            rem_item.setToolTip(rem if rem else tip)
            rem_item.setFont(normal)
            rem_item.setForeground(QBrush(QColor("#0f766e")))
            rem_item.setTextAlignment(vcenter_left)
            table.setItem(i, 6, rem_item)

            if _is_active_testable(f):
                table.setCellWidget(i, 7, self._active_test_button(f))
            else:
                table.setCellWidget(i, 7, self._passive_action_placeholder(f))

            lines_std = _estimate_wrapped_lines(standards, 170, std_font)
            lines_loc = _estimate_wrapped_lines(location, 160, normal)
            lines_desc = _estimate_wrapped_lines(desc, stretch_each, normal)
            lines_rem = _estimate_wrapped_lines(rem_display, stretch_each, normal)
            lines_name = _estimate_wrapped_lines(name, 160, name_font)
            lines = max(lines_std, lines_loc, lines_desc, lines_rem, lines_name, 2)
            row_h = min(28 + lines * 18, 220)
            row_h = max(row_h, 96)
            table.setRowHeight(i, row_h)

        self._expand_table(table, len(findings))

    def _set_section_compact(self, section: QFrame, compact: bool):
        if compact:
            section.setSizePolicy(
                QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum
            )
        else:
            section.setSizePolicy(
                QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
            )

    def _show_clear_state(self):
        self.overview_app.setText("—")
        self.overview_target.setText("—")
        self.overview_target.setToolTip("")
        self.overview_type.setText("—")
        self.overview_map.setText("—")
        self.overview_badge.setText("No active scan")
        self.overview_badge.setStyleSheet(_BADGE_IDLE)

        self.empty_state.show()
        self.dyn_section.hide()
        self.st_section.hide()
        self.empty_state_label.setText(
            "No active scan.\n\n"
            "Go to Create Scan and run Start Scan (URL or ZIP).\n"
            "Security findings appear here.\n"
            "Get Stack results appear on the Tech Stack page."
        )

        for lab in (
            self.dyn_high, self.dyn_medium, self.dyn_low, self.dyn_total,
            self.st_high, self.st_medium, self.st_low, self.st_total,
        ):
            lab.value_label.setText("0")
        self._fill_table(self.dyn_table, self.dyn_empty, [], "")
        self._fill_table(self.st_table, self.st_empty, [], "")

    def refresh(self):
        self.apply_page_theme()

        try:
            from core.shared_state import SharedState
        except Exception as e:
            print("Alerts error:", e)
            self._show_clear_state()
            return

        has_start_scan = bool(SharedState.has_scan_data())

        if not has_start_scan:
            self._show_clear_state()
            return

        dyn_rows, st_rows = [], []
        scan_type = getattr(SharedState, "scan_type", None) or "Dynamic"

        self.overview_app.setText(str(getattr(SharedState, "case_name", None) or "—"))
        target = SharedState.current_url or "—"
        self.overview_target.setText(str(target))
        self.overview_target.setToolTip(str(target))
        self.overview_type.setText(str(scan_type))
        self.overview_badge.setText("Ready")
        self.overview_badge.setStyleSheet(_BADGE_READY)

        findings = _enrich(list(getattr(SharedState, "findings", None) or []))
        SharedState.findings = findings

        if str(scan_type).lower() == "static":
            st_rows, dyn_rows = findings, []
        else:
            dyn_rows, st_rows = findings, []

        if findings:
            cwes = sorted({str(f.get("cwe_id")) for f in findings if f.get("cwe_id")})
            nists = sorted({
                str(f.get("nist") or f.get("nist_id"))
                for f in findings if f.get("nist") or f.get("nist_id")
            })
            sanses = sorted({
                str(f.get("sans") or f.get("sans_id"))
                for f in findings if f.get("sans") or f.get("sans_id")
            })
            bits = []
            if cwes:
                bits.append(", ".join(cwes[:4]))
            if nists:
                bits.append("NIST " + ", ".join(nists[:2]))
            if sanses:
                bits.append("SANS " + ", ".join(sanses[:2]))
            self.overview_map.setText(
                " · ".join(bits) if bits else "CWE / OWASP / NIST / SANS"
            )
        else:
            self.overview_map.setText("No scan issues found")

        self.empty_state.hide()

        if str(scan_type).lower() == "static":
            self.dyn_section.hide()
            self.st_section.show()
            empty_dyn = ""
            empty_st = (
                "No issues found for this static scan."
                if not st_rows
                else "No static alerts for the current scan."
            )
        else:
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
        self._set_section_compact(self.dyn_section, compact=not dyn_rows)

        st_c = _count_severity(st_rows)
        self.st_high.value_label.setText(str(st_c["High"]))
        self.st_medium.value_label.setText(str(st_c["Medium"]))
        self.st_low.value_label.setText(str(st_c["Low"]))
        self.st_total.value_label.setText(str(st_c["Total"]))
        self._fill_table(self.st_table, self.st_empty, st_rows, empty_st)
        self._set_section_compact(self.st_section, compact=not st_rows)
