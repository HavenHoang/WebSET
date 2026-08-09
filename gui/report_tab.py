from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QScrollArea, QSizePolicy, QGridLayout
)
from PyQt6.QtCore import Qt
from datetime import datetime
import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ========== DELETE when Member 6 generate_report() is connected ==========
# Local helpers only support build_report_dict().
# Member 6 owns executive_summary, cwe/owasp/nist/sans summaries, findings list,
# tech_stacks, and remediation aggregation inside generate_report().
# GUI only renders the returned dict.
# Per-finding remediation text is owned by Member 1 (field: "remediation").


def _count_severity(findings: list) -> dict:
    summary = {"High": 0, "Medium": 0, "Low": 0, "Total": 0}
    for f in findings or []:
        sev = str(f.get("severity", "Low"))
        if sev not in ("High", "Medium", "Low"):
            sev = "Low"
        summary[sev] = summary.get(sev, 0) + 1
        summary["Total"] += 1
    return summary


def _remediation_from_findings(findings: list) -> list:
    """
    Aggregate unique remediation strings from Member 1 findings.
    Report does NOT invent tips from keywords — only displays what analysis provides.
    """
    tips = []
    seen = set()
    for f in findings or []:
        r = str(f.get("remediation") or "").strip()
        if not r:
            continue
        key = r.lower()
        if key in seen:
            continue
        seen.add(key)
        tips.append(r)
    if not tips:
        if not findings:
            tips.append(
                "No vulnerabilities were detected. Continue periodic scans and "
                "keep dependencies updated."
            )
        else:
            tips.append(
                "No per-finding remediation provided by the analysis engine."
            )
    return tips


def _summaries_from_findings(findings: list) -> tuple[dict, dict, dict, dict]:
    """Build CWE / OWASP / NIST / SANS counts from fields already on findings."""
    cwe_map, owasp_map, nist_map, sans_map = {}, {}, {}, {}
    for f in findings or []:
        cwe = str(f.get("cwe_id") or f.get("cweId") or "").strip()
        owasp = str(f.get("owasp") or "").strip()
        nist = str(f.get("nist") or f.get("nist_id") or "").strip()
        sans = str(f.get("sans") or f.get("sans_id") or "").strip()
        if cwe:
            cwe_map[cwe] = cwe_map.get(cwe, 0) + 1
        if owasp:
            owasp_map[owasp] = owasp_map.get(owasp, 0) + 1
        if nist:
            nist_map[nist] = nist_map.get(nist, 0) + 1
        if sans:
            sans_map[sans] = sans_map.get(sans, 0) + 1
    return cwe_map, owasp_map, nist_map, sans_map


def build_report_dict(
    url: str,
    findings: list,
    scan_type: str = "Dynamic",
    tech_stacks: list | None = None,
) -> dict:
    """
    Local structured builder until Member 6 module is ready.
    Member 6 should return the SAME shape from generate_report()
    (including optional tech_stacks and nist_summary / sans_summary).
    remediation = unique finding["remediation"] values from Member 1.
    """
    # ========== DELETE when Member 1 always returns full CWE/WASC/OWASP/NIST/SANS fields ==========
    try:
        from core.cwe_map import (
            enrich_findings,
            cwe_summary,
            owasp_summary,
            nist_summary,
            sans_summary,
        )
        findings = enrich_findings(findings or [])
        cwe_map = cwe_summary(findings)
        owasp_map = owasp_summary(findings)
        nist_map = nist_summary(findings)
        sans_map = sans_summary(findings)
    except Exception:
        findings = findings or []
        cwe_map, owasp_map, nist_map, sans_map = _summaries_from_findings(findings)
    # ========== DELETE end ==========
    # ========== UNCOMMENT when Member 1 always returns full CWE/WASC/OWASP/NIST/SANS fields ==========
    # findings = findings or []
    # cwe_map, owasp_map, nist_map, sans_map = _summaries_from_findings(findings)
    # ========== UNCOMMENT end ==========

    summary = _count_severity(findings)
    stacks = list(tech_stacks or [])
    target = url or "target"
    if summary["Total"] == 0:
        executive = (
            f"Automated assessment of {target} completed. "
            "No vulnerabilities were detected in this assessment."
        )
    else:
        executive = (
            f"Automated assessment of {target} completed. "
            f"Found {summary['Total']} issue(s): "
            f"{summary['High']} High, {summary['Medium']} Medium, {summary['Low']} Low. "
            "Findings may include scan results and platform evaluation (Get Stack). "
            "Issues are mapped to CWE, WASC, OWASP, NIST and SANS where available. "
            "Remediation guidance is taken from each finding (Member 1)."
        )
    if stacks:
        names = ", ".join(
            str(s.get("name", "")) for s in stacks[:6] if s.get("name")
        )
        if names:
            executive += f" Detected tech stacks: {names}."

    return {
        "title": "WebSET Security Assessment Report",
        "url": url or "",
        "scan_type": scan_type or "Dynamic",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "findings": findings,
        "tech_stacks": stacks,
        "cwe_summary": cwe_map,
        "owasp_summary": owasp_map,
        "nist_summary": nist_map,
        "sans_summary": sans_map,
        "remediation": _remediation_from_findings(findings),
        "executive_summary": executive,
    }


# ========== DELETE end ==========


class ReportTab(QWidget):
    def __init__(self):
        super().__init__()
        self._last_report = None
        self.init_ui()

    def init_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(14)
        root.setContentsMargins(0, 0, 0, 0)

        banner = QFrame()
        banner.setObjectName("reportBanner")
        banner.setStyleSheet("""
            QFrame#reportBanner {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1f2a57, stop:1 #0f3d5e);
                border: none; border-radius: 14px;
            }
            QFrame#reportBanner QLabel {
                background: transparent; border: none; color: #ffffff; padding: 0px;
            }
        """)
        b_l = QVBoxLayout(banner)
        b_l.setContentsMargins(18, 14, 18, 14)
        b_l.setSpacing(4)
        title = QLabel("Security Assessment Report")
        title.setStyleSheet("font-size: 17px; font-weight: 800;")
        b_l.addWidget(title)
        self.meta_label = QLabel(
            "Generate a report after a scan and/or Get Stack. "
            "Mappings: CWE / WASC / OWASP / NIST / SANS. "
            "Remediation is taken from each finding (Member 1)."
        )
        self.meta_label.setWordWrap(True)
        self.meta_label.setStyleSheet("font-size: 12px; color: rgba(255,255,255,0.9);")
        b_l.addWidget(self.meta_label)
        root.addWidget(banner)

        chips = QHBoxLayout()
        chips.setSpacing(12)
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
        self.body_l.setSpacing(14)
        self.body_l.setContentsMargins(0, 0, 4, 12)

        self.exec_card = self._section_card("Executive summary")
        self.exec_text = QLabel("—")
        self.exec_text.setWordWrap(True)
        self.exec_text.setStyleSheet(
            "color: #334155; font-size: 13px; background: transparent; border: none;"
        )
        self.exec_card.layout().addWidget(self.exec_text)
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

        self.map_card = self._section_card("Standards mapping (CWE / OWASP / NIST / SANS)")
        self.map_chips_host = QWidget()
        self.map_chips_host.setStyleSheet("background: transparent;")
        self.map_chips_layout = QHBoxLayout(self.map_chips_host)
        self.map_chips_layout.setContentsMargins(0, 0, 0, 0)
        self.map_chips_layout.setSpacing(8)
        self.map_empty = QLabel(
            "No standards mappings — no issues found or not yet generated."
        )
        self.map_empty.setWordWrap(True)
        self.map_empty.setStyleSheet(
            "color: #94a3b8; font-size: 13px; background: transparent;"
        )
        self.map_card.layout().addWidget(self.map_chips_host)
        self.map_card.layout().addWidget(self.map_empty)
        self.body_l.addWidget(self.map_card)

        self.findings_card = self._section_card(
            "Findings (scan + platform evaluation)"
        )
        self.findings_host = QWidget()
        self.findings_host.setStyleSheet("background: transparent;")
        self.findings_layout = QVBoxLayout(self.findings_host)
        self.findings_layout.setContentsMargins(0, 0, 0, 0)
        self.findings_layout.setSpacing(10)
        self.findings_empty = QLabel(
            "No issues found for this session. Run Start Scan and/or Get Stack."
        )
        self.findings_empty.setWordWrap(True)
        self.findings_empty.setStyleSheet(
            "color: #94a3b8; font-size: 13px; background: transparent;"
        )
        self.findings_card.layout().addWidget(self.findings_host)
        self.findings_card.layout().addWidget(self.findings_empty)
        self.body_l.addWidget(self.findings_card)

        self.rem_card = self._section_card(
            "Remediation (from Member 1 findings)"
        )
        self.rem_host = QWidget()
        self.rem_host.setStyleSheet("background: transparent;")
        self.rem_layout = QVBoxLayout(self.rem_host)
        self.rem_layout.setContentsMargins(0, 0, 0, 0)
        self.rem_layout.setSpacing(8)
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
        frame.setMinimumHeight(72)
        frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        frame.setStyleSheet(f"""
            QFrame#reportChip {{
                background: {bg};
                border: 1px solid rgba(0,0,0,0.06);
                border-radius: 12px;
            }}
            QFrame#reportChip QLabel {{
                background: transparent; border: none; padding: 0px;
            }}
        """)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)
        t = QLabel(title.upper())
        t.setStyleSheet(
            f"color: {color}; font-size: 11px; font-weight: 800; letter-spacing: 0.4px;"
        )
        v = QLabel(value)
        v.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: 800;")
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
                border: 1px solid #e2e8f0;
                border-radius: 14px;
            }
            QFrame#reportSection QLabel {
                background: transparent; border: none; padding: 0px;
            }
        """)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)
        lab = QLabel(title)
        lab.setStyleSheet("font-size: 13px; font-weight: 800; color: #1f2a44;")
        layout.addWidget(lab)
        return card

    def _badge(self, text: str, fg: str = "#1f2a57", bg: str = "#eaf0ff") -> QLabel:
        lab = QLabel(text)
        lab.setWordWrap(True)
        lab.setStyleSheet(f"""
            QLabel {{
                background: {bg};
                color: {fg};
                border: 1px solid {fg};
                border-radius: 10px;
                padding: 4px 10px;
                font-size: 11px;
                font-weight: 700;
            }}
        """)
        return lab

    def _meta_row(self, label: str, value: str) -> QWidget:
        row = QWidget()
        row.setStyleSheet("background: transparent;")
        lay = QHBoxLayout(row)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        k = QLabel(label)
        k.setFixedWidth(110)
        k.setStyleSheet("color: #64748b; font-size: 12px; font-weight: 700;")
        v = QLabel(value or "—")
        v.setWordWrap(True)
        v.setStyleSheet("color: #0f172a; font-size: 12px; font-weight: 600;")
        lay.addWidget(k)
        lay.addWidget(v, 1)
        return row

    def _finding_card(self, index: int, f: dict) -> QFrame:
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
                border: 1px solid #e2e8f0;
                border-left: 4px solid {fg};
                border-radius: 10px;
            }}
            QFrame#findingCard QLabel {{
                background: transparent; border: none;
            }}
        """)
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 12, 14, 12)
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
        lay.addWidget(
            self._meta_row("Location", str(f.get("location", f.get("url", ""))))
        )
        lay.addWidget(self._meta_row("Detail", str(f.get("description", ""))))
        rem = str(f.get("remediation") or "").strip()
        if rem:
            lay.addWidget(self._meta_row("Remediation", rem))

        tags = QHBoxLayout()
        tags.setSpacing(6)
        cwe = f.get("cwe_id") or f.get("cweId")
        wasc = f.get("wasc_id") or f.get("wascId")
        owasp = f.get("owasp")
        nist = f.get("nist") or f.get("nist_id")
        sans = f.get("sans") or f.get("sans_id")
        conf = f.get("confidence")
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
        if conf:
            tags.addWidget(self._badge(f"Conf. {conf}", "#475569", "#f1f5f9"))
        tags.addStretch()
        lay.addLayout(tags)

        plugin = f.get("plugin_id") or f.get("pluginId")
        msg = f.get("message_id") or f.get("messageId")
        if plugin or msg:
            extra = QLabel(
                (f"Plugin: {plugin}" if plugin else "")
                + (" · " if plugin and msg else "")
                + (f"Message: {msg}" if msg else "")
            )
            extra.setStyleSheet("color: #94a3b8; font-size: 11px;")
            extra.setWordWrap(True)
            lay.addWidget(extra)
        return card

    def showEvent(self, event):
        super().showEvent(event)
        try:
            from core.shared_state import SharedState
            if not SharedState.has_scan_data():
                self._reset_view()
        except Exception:
            pass

    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def _reset_view(self):
        self._last_report = None
        self.meta_label.setText(
            "Generate a report after a scan and/or Get Stack. "
            "Mappings: CWE / WASC / OWASP / NIST / SANS. "
            "Remediation is taken from each finding (Member 1)."
        )
        for chip, val in (
            (self.chip_high, "0"),
            (self.chip_medium, "0"),
            (self.chip_low, "0"),
            (self.chip_total, "0"),
        ):
            chip.value_label.setText(val)
        self.exec_text.setText("—")
        self._clear_layout(self.stacks_layout)
        self.stacks_empty.setText(
            "No tech stacks in this session. Run Get Stack first."
        )
        self.stacks_empty.show()
        self._clear_layout(self.map_chips_layout)
        self.map_empty.setText(
            "No standards mappings — no issues found or not yet generated."
        )
        self.map_empty.show()
        self._clear_layout(self.findings_layout)
        self.findings_empty.setText(
            "No issues found for this session. Run Start Scan and/or Get Stack."
        )
        self.findings_empty.show()
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

        self.exec_text.setText(report.get("executive_summary") or "—")

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
                line = f"• {name}"
                if cat:
                    line += f" ({cat})"
                if ver:
                    line += f" {ver}"
                if desc:
                    line += f" — {desc}"
                row = QLabel(line)
                row.setWordWrap(True)
                row.setStyleSheet(
                    "color: #334155; font-size: 13px; background: #f8fafc; "
                    "border: 1px solid #e2e8f0; border-radius: 8px; padding: 8px 10px;"
                )
                self.stacks_layout.addWidget(row)

        self._clear_layout(self.map_chips_layout)
        cwe_map = report.get("cwe_summary") or {}
        owasp_map = report.get("owasp_summary") or {}
        nist_map = report.get("nist_summary") or {}
        sans_map = report.get("sans_summary") or {}
        has_map = False
        for k, v in list(cwe_map.items())[:6]:
            self.map_chips_layout.addWidget(
                self._badge(f"{k} ×{v}", "#1d4ed8", "#dbeafe")
            )
            has_map = True
        for k, v in list(owasp_map.items())[:4]:
            self.map_chips_layout.addWidget(
                self._badge(f"OWASP {k} ×{v}", "#0f766e", "#ccfbf1")
            )
            has_map = True
        for k, v in list(nist_map.items())[:4]:
            self.map_chips_layout.addWidget(
                self._badge(f"{k} ×{v}", "#b45309", "#fef3c7")
            )
            has_map = True
        for k, v in list(sans_map.items())[:4]:
            self.map_chips_layout.addWidget(
                self._badge(f"{k} ×{v}", "#9f1239", "#ffe4e6")
            )
            has_map = True
        self.map_chips_layout.addStretch()
        if not has_map:
            self.map_empty.setText(
                "No standards mappings — no issues were found in this assessment."
                if total == 0
                else "No CWE / OWASP / NIST / SANS mappings available."
            )
        self.map_empty.setVisible(not has_map)

        self._clear_layout(self.findings_layout)
        findings = report.get("findings") or []
        if not findings:
            self.findings_empty.setText(
                "No issues found for this session. The assessment completed with zero findings."
            )
            self.findings_empty.show()
        else:
            self.findings_empty.hide()
            for i, f in enumerate(findings, start=1):
                self.findings_layout.addWidget(self._finding_card(i, f))

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
                    "border: 1px solid #e2e8f0; border-radius: 8px; padding: 10px 12px;"
                )
                self.rem_layout.addWidget(row)

    def generate_report(self):
        try:
            from core.shared_state import SharedState
        except Exception:
            self.exec_text.setText("[Error] SharedState not available.")
            return
        if not SharedState.has_scan_data():
            self._reset_view()
            self.exec_text.setText(
                "No scan data available. Run Start Scan and/or Get Stack first."
            )
            return
        url = SharedState.current_url
        findings = list(SharedState.findings or [])
        scan_type = getattr(SharedState, "scan_type", None) or "Dynamic"
        tech_stacks = list(getattr(SharedState, "tech_stacks", None) or [])

        # ========== UNCOMMENT when connecting to Member 6 report module ==========
        # from reporting.report_generator import generate_report
        # report = generate_report(
        #     url, findings, scan_type=scan_type, tech_stacks=tech_stacks
        # )
        # ========== UNCOMMENT end ==========

        # ========== DELETE when connecting to Member 6 report module ==========
        report = build_report_dict(
            url, findings, scan_type=scan_type, tech_stacks=tech_stacks
        )
        # ========== DELETE end ==========

        if not isinstance(report, dict):
            self.exec_text.setText("[Error] Report module must return a dict.")
            return
        self._render_report(report)
        main_window = self.window()
        if main_window and hasattr(main_window, "show_toast"):
            n = len(findings)
            if n == 0:
                main_window.show_toast("Report generated — no issues found")
            else:
                main_window.show_toast(f"Report generated — {n} finding(s)")

    def export_pdf(self):
        try:
            from core.shared_state import SharedState
        except Exception:
            return
        if not SharedState.has_scan_data():
            self.exec_text.setText("No scan data available. Run a scan first.")
            return
        if self._last_report is None:
            self.generate_report()

        # ========== UNCOMMENT when connecting to Member 6 PDF ==========
        # from reporting.pdf_generator import export_pdf
        # path = export_pdf(
        #     SharedState.current_url,
        #     SharedState.findings,
        #     report=self._last_report,
        # )
        # self.meta_label.setText(f"PDF saved: {path}")
        # return
        # ========== UNCOMMENT end ==========

        # ========== DELETE when connecting to Member 6 PDF ==========
        self.meta_label.setText(
            (self.meta_label.text() or "")
            + " · PDF export will use Member 6 module"
        )
        # ========== DELETE end ==========

        main_window = self.window()
        if main_window and hasattr(main_window, "show_toast"):
            main_window.show_toast("PDF export pending Member 6")
