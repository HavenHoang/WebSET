import os
from datetime import datetime
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    NextPageTemplate,
    KeepTogether,
    HRFlowable,
)
from reportlab.platypus.tableofcontents import TableOfContents

PAGE_WIDTH, PAGE_HEIGHT = A4

# ============================================================
# WebSET brand palette
# ============================================================
NAVY = colors.HexColor("#07192D")
NAVY_2 = colors.HexColor("#10284A")
NAVY_3 = colors.HexColor("#1F2A57")
TEAL = colors.HexColor("#0F8F86")
TEAL_LIGHT = colors.HexColor("#22C7BA")
BLUE = colors.HexColor("#0F3D5E")
TEXT = colors.HexColor("#172033")
TEXT_SOFT = colors.HexColor("#334155")
MUTED = colors.HexColor("#64748B")
WHITE = colors.white
LIGHT = colors.HexColor("#F8FAFC")
LIGHT_BLUE = colors.HexColor("#EFF6FF")
BORDER = colors.HexColor("#DCE4EE")
BORDER_STRONG = colors.HexColor("#B9C4D2")
HIGH = colors.HexColor("#C0392B")
HIGH_BG = colors.HexColor("#FDECEA")
MEDIUM = colors.HexColor("#B9770E")
MEDIUM_BG = colors.HexColor("#FEF5E7")
LOW = colors.HexColor("#3B4A5A")
LOW_BG = colors.HexColor("#EEF1F4")
CLEAN = colors.HexColor("#15803D")
CLEAN_BG = colors.HexColor("#DCFCE7")


# ============================================================
# Helpers
# ============================================================
def _safe(value):
    if value is None:
        return "-"
    text = str(value).strip()
    return text if text else "-"


def _html(value):
    return escape(_safe(value))


def _make_report_id(report):
    generated = str(report.get("generated_at") or "")
    try:
        dt = datetime.strptime(generated, "%Y-%m-%d %H:%M:%S")
    except Exception:
        dt = datetime.now()
    return dt.strftime("WEBSET-%Y%m%d-%H%M%S")


def _friendly_date(report):
    generated = str(report.get("generated_at") or "")
    try:
        dt = datetime.strptime(generated, "%Y-%m-%d %H:%M:%S")
    except Exception:
        dt = datetime.now()
    return dt.strftime("%d %B %Y \u00b7 %I:%M %p")


def _assessment_type(report):
    scan_type = str(report.get("scan_type") or "Dynamic").strip()
    lowered = scan_type.lower()
    if lowered == "dynamic":
        return "Dynamic Security Assessment"
    if lowered == "static":
        return "Static Security Assessment"
    return f"{scan_type} Security Assessment"


def _overall_risk(report):
    summary = report.get("summary") or {}
    high = int(summary.get("High", 0) or 0)
    medium = int(summary.get("Medium", 0) or 0)
    low = int(summary.get("Low", 0) or 0)
    total = int(summary.get("Total", 0) or 0)
    if high > 0:
        return "HIGH", HIGH
    if medium > 0:
        return "MEDIUM", MEDIUM
    if low > 0:
        return "LOW", LOW
    if total == 0:
        return "CLEAN", CLEAN
    return "INFORMATIONAL", MUTED


def _styles():
    sample = getSampleStyleSheet()
    return {
        "cover_brand": ParagraphStyle(
            "CoverBrand", parent=sample["Normal"],
            fontName="Helvetica-Bold", fontSize=26, leading=30, textColor=NAVY,
        ),
        "cover_product": ParagraphStyle(
            "CoverProduct", parent=sample["Normal"],
            fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=BLUE,
        ),
        "cover_title": ParagraphStyle(
            "CoverTitle", parent=sample["Title"],
            fontName="Helvetica-Bold", fontSize=26, leading=30, textColor=NAVY, spaceAfter=9,
        ),
        "cover_subtitle": ParagraphStyle(
            "CoverSubtitle", parent=sample["Normal"],
            fontName="Helvetica", fontSize=12, leading=17, textColor=TEXT_SOFT,
        ),
        "section": ParagraphStyle(
            "Heading1TOC", parent=sample["Heading2"],
            fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=NAVY_3,
            spaceBefore=10, spaceAfter=9,
        ),
        "subsection": ParagraphStyle(
            "Heading2TOC", parent=sample["Heading3"],
            fontName="Helvetica-Bold", fontSize=11.5, leading=15, textColor=NAVY_3,
            spaceBefore=8, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "Body", parent=sample["BodyText"],
            fontName="Helvetica", fontSize=9.2, leading=13.5, textColor=TEXT,
            wordWrap="CJK", spaceAfter=5, alignment=TA_JUSTIFY,
        ),
        "body_bold": ParagraphStyle(
            "BodyBold", parent=sample["BodyText"],
            fontName="Helvetica-Bold", fontSize=9.2, leading=13, textColor=TEXT,
            wordWrap="CJK",
        ),
        "small": ParagraphStyle(
            "Small", parent=sample["BodyText"],
            fontName="Helvetica", fontSize=7.8, leading=10.5, textColor=MUTED,
            wordWrap="CJK",
        ),
        "italic_small": ParagraphStyle(
            "ItalicSmall", parent=sample["BodyText"],
            fontName="Helvetica-Oblique", fontSize=8.4, leading=12, textColor=MUTED,
            wordWrap="CJK",
        ),
        "center": ParagraphStyle(
            "Center", parent=sample["BodyText"],
            fontName="Helvetica", fontSize=9, leading=12, alignment=TA_CENTER, textColor=TEXT,
        ),
        "center_bold": ParagraphStyle(
            "CenterBold", parent=sample["BodyText"],
            fontName="Helvetica-Bold", fontSize=9, leading=12, alignment=TA_CENTER, textColor=TEXT,
        ),
        "card_label": ParagraphStyle(
            "CardLabel", parent=sample["Normal"],
            fontName="Helvetica-Bold", fontSize=8, leading=10, alignment=TA_CENTER,
        ),
        "card_value": ParagraphStyle(
            "CardValue", parent=sample["Normal"],
            fontName="Helvetica-Bold", fontSize=20, leading=24, alignment=TA_CENTER,
        ),
        "toc_title": ParagraphStyle(
            "TOCTitle", parent=sample["Heading1"],
            fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=NAVY_3,
            spaceAfter=12,
        ),
    }


def _toc_styles(styles):
    return [
        ParagraphStyle(
            "TOCLevel0", parent=styles["body"],
            fontName="Helvetica-Bold", fontSize=10.5, leading=16, textColor=NAVY_3,
            leftIndent=0, alignment=TA_LEFT, spaceAfter=2,
        ),
        ParagraphStyle(
            "TOCLevel1", parent=styles["body"],
            fontName="Helvetica", fontSize=9.5, leading=14, textColor=TEXT_SOFT,
            leftIndent=10, alignment=TA_LEFT, spaceAfter=1,
        ),
    ]


# ============================================================
# Numbered canvas
# ============================================================
class _NumberedCanvas(pdfcanvas.Canvas):
    def __init__(self, *args, **kwargs):
        pdfcanvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_states = []

    def showPage(self):
        self._saved_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        content_states = [s for s in self._saved_states if s.get("_websec_content_page")]
        total = len(content_states)
        seen = 0
        for state in self._saved_states:
            self.__dict__.update(state)
            if state.get("_websec_content_page"):
                seen += 1
                self._draw_content_footer(seen, total)
            pdfcanvas.Canvas.showPage(self)
        pdfcanvas.Canvas.save(self)

    def _draw_content_footer(self, page_no, total_pages):
        self.saveState()
        self.setStrokeColor(BORDER)
        self.setLineWidth(0.5)
        self.line(18 * mm, 14 * mm, PAGE_WIDTH - 18 * mm, 14 * mm)
        self.setFont("Helvetica", 7.5)
        self.setFillColor(MUTED)
        self.drawString(18 * mm, 9 * mm, "WebSET \u00b7 Security Assessment Report")
        self.drawCentredString(PAGE_WIDTH / 2, 9 * mm, "CONFIDENTIAL")
        self.drawRightString(
            PAGE_WIDTH - 18 * mm, 9 * mm, f"Page {page_no} of {total_pages}"
        )
        self.restoreState()


# ============================================================
# Cover / end-page backgrounds
# ============================================================
def _draw_geometric_background(canvas, closing=False):
    canvas.saveState()
    if closing:
        canvas.translate(PAGE_WIDTH, 0)
        canvas.scale(-1, 1)
    canvas.setFillColor(WHITE)
    canvas.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, fill=1, stroke=0)
    hero_height = PAGE_HEIGHT * 0.66
    canvas.setFillColor(NAVY)
    canvas.rect(0, PAGE_HEIGHT - hero_height, PAGE_WIDTH, hero_height, fill=1, stroke=0)
    gradient_colors = [
        colors.HexColor("#061629"),
        colors.HexColor("#071B31"),
        colors.HexColor("#08213A"),
        colors.HexColor("#092640"),
    ]
    band_h = hero_height / len(gradient_colors)
    for i, colour in enumerate(gradient_colors):
        canvas.setFillColor(colour)
        canvas.rect(0, PAGE_HEIGHT - ((i + 1) * band_h), PAGE_WIDTH, band_h + 1, fill=1, stroke=0)
    hero_bottom = PAGE_HEIGHT - hero_height
    tilt = 24 * mm
    seam_left_y = hero_bottom + tilt / 2
    seam_right_y = hero_bottom - tilt / 2
    canvas.setFillColor(WHITE)
    p = canvas.beginPath()
    p.moveTo(0, seam_left_y)
    p.lineTo(PAGE_WIDTH, seam_right_y)
    p.lineTo(PAGE_WIDTH, 0)
    p.lineTo(0, 0)
    p.close()
    canvas.drawPath(p, fill=1, stroke=0)
    canvas.setStrokeColor(TEAL)
    canvas.setLineWidth(1.5)
    canvas.line(0, seam_left_y, PAGE_WIDTH, seam_right_y)
    outer_a, outer_b = 92 * mm, 70 * mm
    inner_a, inner_b = 50 * mm, 38 * mm
    canvas.setFillColor(NAVY_2)
    p = canvas.beginPath()
    p.moveTo(PAGE_WIDTH - outer_a, PAGE_HEIGHT)
    p.lineTo(PAGE_WIDTH, PAGE_HEIGHT)
    p.lineTo(PAGE_WIDTH, PAGE_HEIGHT - outer_b)
    p.close()
    canvas.drawPath(p, fill=1, stroke=0)
    canvas.setFillColor(TEAL)
    p = canvas.beginPath()
    p.moveTo(PAGE_WIDTH - inner_a, PAGE_HEIGHT)
    p.lineTo(PAGE_WIDTH, PAGE_HEIGHT)
    p.lineTo(PAGE_WIDTH, PAGE_HEIGHT - inner_b)
    p.close()
    canvas.drawPath(p, fill=1, stroke=0)
    canvas.setStrokeColor(TEAL_LIGHT)
    canvas.setLineWidth(1.1)
    canvas.line(PAGE_WIDTH - inner_a, PAGE_HEIGHT, PAGE_WIDTH, PAGE_HEIGHT - inner_b)
    canvas.setFillColor(colors.HexColor("#E3F5F3"))
    p = canvas.beginPath()
    p.moveTo(0, 0)
    p.lineTo(32 * mm, 0)
    p.lineTo(0, 22 * mm)
    p.close()
    canvas.drawPath(p, fill=1, stroke=0)
    canvas.setStrokeColor(TEAL)
    canvas.setLineWidth(1)
    canvas.line(0, 22 * mm, 32 * mm, 0)
    canvas.setFillColor(colors.HexColor("#EEF2F7"))
    p = canvas.beginPath()
    p.moveTo(PAGE_WIDTH - 28 * mm, 0)
    p.lineTo(PAGE_WIDTH, 0)
    p.lineTo(PAGE_WIDTH, 18 * mm)
    p.close()
    canvas.drawPath(p, fill=1, stroke=0)
    canvas.setStrokeColor(colors.HexColor("#B9C4D2"))
    canvas.setLineWidth(0.8)
    canvas.line(PAGE_WIDTH - 28 * mm, 0, PAGE_WIDTH, 18 * mm)
    canvas.setFillColor(colors.Color(0.2, 0.85, 0.82, alpha=0.22))
    start_x = 13 * mm
    start_y = PAGE_HEIGHT * 0.79
    for row in range(6):
        for col in range(8):
            canvas.circle(start_x + col * 3 * mm, start_y + row * 3 * mm, 0.35 * mm, fill=1, stroke=0)
    centre_x = PAGE_WIDTH * 0.72
    centre_y = PAGE_HEIGHT * 0.62
    canvas.setStrokeColor(colors.Color(0.05, 0.78, 0.72, alpha=0.45))
    canvas.setLineWidth(0.7)
    for radius in (22 * mm, 30 * mm, 38 * mm):
        canvas.circle(centre_x, centre_y, radius, fill=0, stroke=1)
    nodes = [(-26, 20), (-18, -25), (22, -22), (29, 18), (-38, 0), (39, 0)]
    canvas.setFillColor(TEAL_LIGHT)
    for dx, dy in nodes:
        x = centre_x + dx * mm / 2
        y = centre_y + dy * mm / 2
        canvas.circle(x, y, 1.35 * mm, fill=1, stroke=0)
        canvas.setStrokeColor(colors.Color(0.1, 0.8, 0.75, alpha=0.50))
        canvas.line(centre_x, centre_y, x, y)
    canvas.setStrokeColor(WHITE)
    canvas.setLineWidth(2.2)
    shield = canvas.beginPath()
    shield.moveTo(centre_x, centre_y + 24 * mm)
    shield.lineTo(centre_x + 17 * mm, centre_y + 16 * mm)
    shield.lineTo(centre_x + 15 * mm, centre_y - 5 * mm)
    shield.curveTo(
        centre_x + 12 * mm, centre_y - 17 * mm,
        centre_x + 5 * mm, centre_y - 24 * mm,
        centre_x, centre_y - 28 * mm,
    )
    shield.curveTo(
        centre_x - 5 * mm, centre_y - 24 * mm,
        centre_x - 12 * mm, centre_y - 17 * mm,
        centre_x - 15 * mm, centre_y - 5 * mm,
    )
    shield.lineTo(centre_x - 17 * mm, centre_y + 16 * mm)
    shield.close()
    canvas.drawPath(shield, fill=0, stroke=1)
    canvas.setFillColor(TEAL_LIGHT)
    canvas.roundRect(centre_x - 6.5 * mm, centre_y - 4.5 * mm, 13 * mm, 12 * mm, 2.5 * mm, fill=1, stroke=0)
    canvas.setStrokeColor(WHITE)
    canvas.setLineWidth(1.8)
    canvas.arc(centre_x - 5 * mm, centre_y + 2 * mm, centre_x + 5 * mm, centre_y + 15 * mm, startAng=0, extent=180)
    canvas.setFillColor(NAVY)
    canvas.circle(centre_x, centre_y + 1 * mm, 1.1 * mm, fill=1, stroke=0)
    canvas.rect(centre_x - 0.45 * mm, centre_y - 2.5 * mm, 0.9 * mm, 3 * mm, fill=1, stroke=0)
    canvas.setStrokeColor(colors.Color(1, 1, 1, alpha=0.35))
    canvas.setLineWidth(0.6)
    canvas.rect(7 * mm, 7 * mm, PAGE_WIDTH - 14 * mm, PAGE_HEIGHT - 14 * mm, fill=0, stroke=1)
    canvas.restoreState()


def _cover_page(canvas, doc):
    canvas._websec_content_page = False
    _draw_geometric_background(canvas)


def _end_page(canvas, doc):
    canvas._websec_content_page = False
    _draw_geometric_background(canvas, closing=True)


def _content_page(canvas, doc):
    canvas._websec_content_page = True
    canvas.saveState()
    canvas.setFillColor(NAVY_3)
    canvas.setFont("Helvetica-Bold", 8.5)
    canvas.drawString(18 * mm, PAGE_HEIGHT - 13 * mm, "WebSET")
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(30 * mm, PAGE_HEIGHT - 13 * mm, "Website Security Evaluation Tool")
    report_id = getattr(doc, "_report_id", "")
    canvas.drawRightString(PAGE_WIDTH - 18 * mm, PAGE_HEIGHT - 13 * mm, report_id)
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, PAGE_HEIGHT - 16 * mm, PAGE_WIDTH - 18 * mm, PAGE_HEIGHT - 16 * mm)
    canvas.restoreState()


# ============================================================
# Cover content
# ============================================================
def _risk_badge_row(risk, risk_color, styles, dark_panel=True):
    label_style = ParagraphStyle(
        "RiskBadgeLabel", parent=styles["small"], fontName="Helvetica-Bold",
        fontSize=8, leading=10, textColor=WHITE if risk_color != colors.white else NAVY,
        alignment=TA_CENTER,
    )
    badge = Table(
        [[Paragraph(f"OVERALL RISK RATING&nbsp;&nbsp;<b>{_html(risk)}</b>", label_style)]],
        colWidths=[62 * mm],
        rowHeights=[9 * mm],
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), risk_color),
        ("BOX", (0, 0), (-1, -1), 0.75, WHITE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    return badge


def _cover_story(report, styles):
    summary = report.get("summary") or {}
    risk, risk_color = _overall_risk(report)
    total = int(summary.get("Total", 0) or 0)
    report_id = _make_report_id(report)
    story = []
    story.append(Spacer(1, 7 * mm))
    story.append(Paragraph(
        "CONFIDENTIAL SECURITY ASSESSMENT",
        ParagraphStyle("CoverClass", parent=styles["small"], fontName="Helvetica-Bold",
                        fontSize=7.5, leading=10, textColor=TEAL_LIGHT, letterSpacing=0.8),
    ))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "WebSET",
        ParagraphStyle("CoverWebSET", parent=styles["cover_brand"], fontName="Helvetica-Bold",
                        fontSize=25, leading=29, textColor=WHITE),
    ))
    story.append(Paragraph(
        "Website Security Evaluation Tool",
        ParagraphStyle("CoverWebSETSub", parent=styles["cover_product"], fontName="Helvetica",
                        fontSize=9, leading=12, textColor=colors.HexColor("#A8DBD7")),
    ))
    story.append(Spacer(1, 12 * mm))
    story.append(Paragraph(
        "WEBSITE SECURITY<br/>ASSESSMENT REPORT",
        ParagraphStyle("CoverMainTitle", parent=styles["cover_title"], fontName="Helvetica-Bold",
                        fontSize=25, leading=28, textColor=WHITE),
    ))
    story.append(Spacer(1, 3 * mm))
    accent = Table([[""]], colWidths=[38 * mm], rowHeights=[1.2 * mm])
    accent.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), TEAL_LIGHT)]))
    story.append(accent)
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(
        "Automated Vulnerability, Technology &amp;<br/>Platform Evaluation",
        ParagraphStyle("CoverDescription", parent=styles["cover_subtitle"], fontName="Helvetica",
                        fontSize=11, leading=15, textColor=colors.HexColor("#D9E8F0")),
    ))
    story.append(Spacer(1, 10 * mm))
    story.append(_risk_badge_row(risk, risk_color, styles))
    story.append(Spacer(1, 42 * mm))
    label_style = ParagraphStyle("CoverInfoLabel", parent=styles["small"], fontName="Helvetica-Bold",
                                  fontSize=7.4, leading=10, textColor=WHITE)
    value_style = ParagraphStyle("CoverInfoValue", parent=styles["body"], fontName="Helvetica-Bold",
                                  fontSize=8.5, leading=11, textColor=TEXT, alignment=TA_LEFT)
    risk_style = ParagraphStyle("CoverRisk", parent=value_style, textColor=risk_color, fontSize=9)
    metadata = [
        [Paragraph("TARGET", label_style), Paragraph(_html(report.get("url")), value_style)],
        [Paragraph("ASSESSMENT TYPE", label_style), Paragraph(_html(_assessment_type(report)), value_style)],
        [Paragraph("REPORT ID", label_style), Paragraph(_html(report_id), value_style)],
        [Paragraph("ASSESSMENT DATE", label_style), Paragraph(_html(_friendly_date(report)), value_style)],
        [Paragraph("OVERALL RISK", label_style), Paragraph(f"<b>{_html(risk)}</b>", risk_style)],
        [Paragraph("FINDINGS IDENTIFIED", label_style), Paragraph(str(total), value_style)],
        [Paragraph("REPORT CLASSIFICATION", label_style), Paragraph("Confidential", value_style)],
    ]
    panel = Table(metadata, colWidths=[45 * mm, 105 * mm], hAlign="LEFT")
    panel.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), NAVY_3),
        ("BACKGROUND", (1, 0), (1, -1), WHITE),
        ("BOX", (0, 0), (-1, -1), 1.2, TEAL),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER_STRONG),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(panel)
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(
        "<b>Generated by WebSET</b><br/><font size='7.5'>Website Security Evaluation Tool</font>",
        ParagraphStyle("CoverFooterBrand", parent=styles["center"], alignment=TA_CENTER,
                        fontName="Helvetica", fontSize=9, leading=12, textColor=NAVY_3),
    ))
    return story


def _toc_page(report, styles):
    story = []
    story.append(Paragraph("Table of Contents", styles["toc_title"]))
    story.append(HRFlowable(width="100%", thickness=0.8, color=BORDER, spaceAfter=8))
    toc = TableOfContents()
    toc.levelStyles = _toc_styles(styles)
    toc.dotsMinLevel = 0
    story.append(toc)
    return story


def _risk_summary_table(summary, styles):
    items = [
        ("HIGH", summary.get("High", 0), HIGH),
        ("MEDIUM", summary.get("Medium", 0), MEDIUM),
        ("LOW", summary.get("Low", 0), LOW),
        ("TOTAL", summary.get("Total", 0), NAVY_3),
    ]
    row = []
    for label, value, fg in items:
        label_p = Paragraph(f"<b>{label}</b>", ParagraphStyle(
            f"CardLabel{label}", parent=styles["card_label"], textColor=WHITE))
        value_p = Paragraph(str(value), ParagraphStyle(
            f"CardValue{label}", parent=styles["card_value"], textColor=WHITE))
        card = Table(
            [[label_p], [value_p]],
            colWidths=[39 * mm],
            rowHeights=[8 * mm, 16 * mm],
        )
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), fg),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#0B1220")),
            ("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
            ("VALIGN", (0, 1), (-1, 1), "TOP"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, 0), 4),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 0),
            ("TOPPADDING", (0, 1), (-1, 1), 0),
            ("BOTTOMPADDING", (0, 1), (-1, 1), 4),
        ]))
        row.append(card)
    result = Table([row], colWidths=[42 * mm, 42 * mm, 42 * mm, 42 * mm], hAlign="LEFT")
    result.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 1.5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 1.5),
    ]))
    return result


def _severity_legend(styles):
    rows = [
        [
            Paragraph("<font color='%s'><b>HIGH</b></font>" % HIGH.hexval(), styles["body_bold"]),
            Paragraph(
                "Issues that pose an immediate, significant risk to confidentiality, integrity, "
                "or availability. Remediate as a priority.",
                styles["body"],
            ),
        ],
        [
            Paragraph("<font color='%s'><b>MEDIUM</b></font>" % MEDIUM.hexval(), styles["body_bold"]),
            Paragraph(
                "Issues that weaken the security posture and should be scheduled for remediation "
                "in the near term.",
                styles["body"],
            ),
        ],
        [
            Paragraph("<font color='%s'><b>LOW</b></font>" % LOW.hexval(), styles["body_bold"]),
            Paragraph(
                "Minor issues or hardening opportunities with limited standalone impact.",
                styles["body"],
            ),
        ],
    ]
    table = Table(rows, colWidths=[24 * mm, 142 * mm])
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.6, BORDER_STRONG),
        ("BOX", (0, 0), (-1, -1), 1, BORDER_STRONG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("BACKGROUND", (1, 0), (1, -1), WHITE),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _scan_breakdown_table(report, styles):
    scan = report.get("scan_summary") or {}
    platform = report.get("platform_summary") or {}
    rows = [
        [
            Paragraph("<b>Assessment Source</b>", styles["body"]),
            Paragraph("<b>High</b>", styles["center"]),
            Paragraph("<b>Medium</b>", styles["center"]),
            Paragraph("<b>Low</b>", styles["center"]),
            Paragraph("<b>Total</b>", styles["center"]),
        ],
        [
            Paragraph("Start Scan", styles["body"]),
            scan.get("High", 0), scan.get("Medium", 0), scan.get("Low", 0), scan.get("Total", 0),
        ],
        [
            Paragraph("Platform Evaluation", styles["body"]),
            platform.get("High", 0), platform.get("Medium", 0), platform.get("Low", 0), platform.get("Total", 0),
        ],
    ]
    table = Table(rows, colWidths=[70 * mm, 24 * mm, 24 * mm, 24 * mm, 24 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY_3),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.6, BORDER_STRONG),
        ("BOX", (0, 0), (-1, -1), 1, BORDER_STRONG),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 1), (-1, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _tech_stack_table(report, styles):
    stacks = report.get("tech_stacks") or []
    if not stacks:
        return Paragraph(
            "No technology-stack information was recorded for this assessment.",
            styles["body"],
        )
    rows = [[
        Paragraph("<b>Technology</b>", styles["body"]),
        Paragraph("<b>Category</b>", styles["body"]),
        Paragraph("<b>Version</b>", styles["body"]),
        Paragraph("<b>Description</b>", styles["body"]),
    ]]
    for stack in stacks:
        rows.append([
            Paragraph(_html(stack.get("name")), styles["body"]),
            Paragraph(_html(stack.get("category")), styles["body"]),
            Paragraph(_html(stack.get("version")), styles["body"]),
            Paragraph(_html(stack.get("description")), styles["body"]),
        ])
    table = Table(rows, colWidths=[32 * mm, 32 * mm, 24 * mm, 78 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.6, BORDER_STRONG),
        ("BOX", (0, 0), (-1, -1), 1, BORDER_STRONG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _standards_table(report, styles):
    """Start Scan standards only (report generator excludes Platform)."""
    mappings = [
        ("CWE", report.get("cwe_summary") or {}),
        ("OWASP", report.get("owasp_summary") or {}),
        ("NIST", report.get("nist_summary") or {}),
        ("SANS", report.get("sans_summary") or {}),
    ]
    rows = []
    for category, values in mappings:
        if not values:
            continue
        text = ", ".join(f"{key} ({count})" for key, count in values.items())
        rows.append([
            Paragraph(f"<font color='{WHITE.hexval()}'><b>{category}</b></font>", styles["body"]),
            Paragraph(_html(text), styles["body"]),
        ])
    if not rows:
        return Paragraph(
            "No security-standard mappings from Start Scan findings were available.",
            styles["body"],
        )
    table = Table(rows, colWidths=[31 * mm, 135 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), BLUE),
        ("BACKGROUND", (1, 0), (1, -1), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.6, BORDER_STRONG),
        ("BOX", (0, 0), (-1, -1), 1, BORDER_STRONG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _finding_elements(index, finding, styles, *, include_standards: bool = True):
    """
    Start Scan cards: include_standards=True (CWE/OWASP/NIST/SANS when present).
    Platform cards: include_standards=False (guidance only + confidence).
    """
    severity = str(finding.get("severity") or "Low").title()
    if severity == "High":
        sev_fg, sev_bg = HIGH, HIGH_BG
    elif severity == "Medium":
        sev_fg, sev_bg = MEDIUM, MEDIUM_BG
    else:
        sev_fg, sev_bg = LOW, LOW_BG
    vulnerability = finding.get("vulnerability") or finding.get("name") or "Finding"
    header = Table(
        [[
            Paragraph(f"<b>{index}. {_html(vulnerability)}</b>", styles["body_bold"]),
            Paragraph(
                f"<font color='{WHITE.hexval()}'><b>{_html(severity).upper()}</b></font>",
                styles["center"],
            ),
        ]],
        colWidths=[138 * mm, 28 * mm],
    )
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#EAEFF6")),
        ("BACKGROUND", (1, 0), (1, 0), sev_fg),
        ("GRID", (0, 0), (-1, -1), 0.8, BORDER_STRONG),
        ("BOX", (0, 0), (-1, -1), 1.1, NAVY_3),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))

    details = [
        ("Origin", finding.get("scan_origin")),
        ("Location", finding.get("location") or finding.get("url")),
        ("Description", finding.get("description")),
        ("Remediation", finding.get("remediation")),
    ]

    if include_standards:
        standards = []
        cwe = finding.get("cwe_id") or finding.get("cweId")
        wasc = finding.get("wasc_id") or finding.get("wascId")
        owasp = finding.get("owasp")
        nist = finding.get("nist") or finding.get("nist_id")
        sans = finding.get("sans") or finding.get("sans_id")
        if cwe:
            standards.append(str(cwe))
        if wasc:
            standards.append(str(wasc))
        if owasp:
            standards.append(f"OWASP {owasp}")
        if nist:
            standards.append(str(nist))
        if sans:
            standards.append(str(sans))
        if standards:
            details.append(("Standards", " | ".join(standards)))

    details.append(("Confidence", finding.get("confidence")))
    details.append(("Plugin ID", finding.get("plugin_id")))
    if include_standards:
        details.append(("Message ID", finding.get("message_id")))

    rows = []
    for label, value in details:
        if value in (None, "", []):
            continue
        rows.append([
            Paragraph(f"<font color='{WHITE.hexval()}'><b>{label}</b></font>", styles["body"]),
            Paragraph(_html(value), styles["body"]),
        ])
    body = Table(rows, colWidths=[32 * mm, 134 * mm], splitByRow=1)
    body.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), NAVY_3),
        ("BACKGROUND", (1, 0), (1, -1), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.6, BORDER_STRONG),
        ("BOX", (0, 0), (-1, -1), 1, NAVY_3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return [KeepTogether([header, body]), Spacer(1, 7)]


def _end_story(report, styles):
    summary = report.get("summary") or {}
    risk, risk_color = _overall_risk(report)
    total = int(summary.get("Total", 0) or 0)
    report_id = _make_report_id(report)
    story = [
        Spacer(1, 18 * mm),
        Paragraph("END OF REPORT", ParagraphStyle(
            "EndTitle", parent=styles["cover_title"], textColor=WHITE, fontSize=27, leading=31)),
        Spacer(1, 6 * mm),
        Paragraph("WebSET Security Assessment", ParagraphStyle(
            "EndSubtitle", parent=styles["cover_subtitle"], textColor=colors.HexColor("#C7E7E4"),
            fontSize=13, leading=17)),
        Paragraph(
            "Automated Vulnerability, Technology &amp;<br/>Platform Evaluation",
            ParagraphStyle("EndSub2", parent=styles["cover_subtitle"], textColor=WHITE,
                            fontSize=10.5, leading=15),
        ),
        Spacer(1, 16 * mm),
    ]
    story.append(_risk_badge_row(risk, risk_color, styles))
    story.append(Spacer(1, 38 * mm))
    label_style = ParagraphStyle("EndInfoLabel", parent=styles["body"], fontName="Helvetica-Bold",
                                  fontSize=9, textColor=WHITE)
    value_style = styles["body"]
    info = [
        [Paragraph("Target", label_style), Paragraph(_html(report.get("url")), value_style)],
        [Paragraph("Report ID", label_style), Paragraph(report_id, value_style)],
        [Paragraph("Assessment Type", label_style), Paragraph(_html(_assessment_type(report)), value_style)],
        [Paragraph("Final Risk Rating", label_style),
         Paragraph(f"<font color='{risk_color.hexval()}'><b>{risk}</b></font>", styles["body_bold"])],
        [Paragraph("Total Findings", label_style), Paragraph(str(total), value_style)],
        [Paragraph("Classification", label_style), Paragraph("Confidential", value_style)],
    ]
    table = Table(info, colWidths=[45 * mm, 105 * mm])
    table.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 1.2, TEAL),
        ("GRID", (0, 0), (-1, -1), 0.6, BORDER_STRONG),
        ("BACKGROUND", (0, 0), (0, -1), NAVY_3),
        ("BACKGROUND", (1, 0), (1, -1), WHITE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    story.append(Spacer(1, 14 * mm))
    story.append(Paragraph(
        "<b>Generated by WebSET</b><br/>Website Security Evaluation Tool",
        ParagraphStyle("EndGenerated", parent=styles["center"], alignment=TA_CENTER,
                        textColor=NAVY_3, fontSize=10, leading=14),
    ))
    story.append(Spacer(1, 7 * mm))
    story.append(Paragraph(
        "Identify vulnerabilities. Understand exposure. Prioritise remediation. Strengthen security.",
        ParagraphStyle("ClosingStatement", parent=styles["center"], alignment=TA_CENTER,
                        textColor=TEAL, fontName="Helvetica-Bold", fontSize=9, leading=13),
    ))
    story.append(Spacer(1, 12 * mm))
    story.append(HRFlowable(width="55%", thickness=0.8, color=BORDER, hAlign="CENTER", spaceAfter=6))
    story.append(Paragraph(
        "www.webset-security.example &nbsp;\u00b7&nbsp; This report is confidential and intended solely for the recipient organisation.",
        ParagraphStyle("EndFooterNote", parent=styles["small"], alignment=TA_CENTER,
                        textColor=MUTED, fontSize=7.6, leading=11),
    ))
    return story


class _ReportDocTemplate(BaseDocTemplate):
    def afterFlowable(self, flowable):
        if not isinstance(flowable, Paragraph):
            return
        style_name = flowable.style.name
        text = flowable.getPlainText()
        if style_name == "Heading1TOC":
            self.canv.bookmarkPage(text)
            self.canv.addOutlineEntry(text, text, level=0, closed=False)
            self.notify("TOCEntry", (0, text, self.page))
        elif style_name == "Heading2TOC":
            self.canv.bookmarkPage(text)
            self.notify("TOCEntry", (1, text, self.page))


# ============================================================
# PDF export
# ============================================================
def export_pdf(
    url: str,
    findings: list[dict],
    output_path: str | None = None,
    report: dict | None = None,
) -> str:
    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.abspath(f"WebSET_Security_Assessment_{timestamp}.pdf")
    if not output_path.lower().endswith(".pdf"):
        output_path += ".pdf"
    if report is None:
        from reporting.report_generator import generate_report
        report = generate_report(url=url, findings=findings)
    styles = _styles()
    report_id = _make_report_id(report)

    doc = _ReportDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm,
        title=report.get("title", "WebSET Security Assessment Report"),
        author="WebSET",
        subject="Website Security Assessment",
        creator="WebSET Website Security Evaluation Tool",
    )
    doc._report_id = report_id
    cover_frame = Frame(21 * mm, 12 * mm, PAGE_WIDTH - 42 * mm, PAGE_HEIGHT - 24 * mm,
                         id="coverFrame", showBoundary=0)
    content_frame = Frame(18 * mm, 20 * mm, PAGE_WIDTH - 36 * mm, PAGE_HEIGHT - 44 * mm,
                           id="contentFrame", showBoundary=0)
    end_frame = Frame(21 * mm, 12 * mm, PAGE_WIDTH - 42 * mm, PAGE_HEIGHT - 24 * mm,
                       id="endFrame", showBoundary=0)
    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[cover_frame], onPage=_cover_page),
        PageTemplate(id="Content", frames=[content_frame], onPage=_content_page),
        PageTemplate(id="End", frames=[end_frame], onPage=_end_page),
    ])

    story = []
    story.extend(_cover_story(report, styles))
    story.append(NextPageTemplate("Content"))
    story.append(PageBreak())
    story.extend(_toc_page(report, styles))
    story.append(PageBreak())

    # 1. Executive Summary
    story.append(Paragraph("1. Executive Summary", styles["section"]))
    summary = report.get("summary") or {}
    risk, risk_color = _overall_risk(report)
    total = int(summary.get("Total", 0) or 0)
    intro = (
        f"WebSET performed an automated security assessment of "
        f"<b>{_html(report.get('url'))}</b> on {_html(_friendly_date(report))}. "
        f"The assessment combined a Start Scan of the live application with a "
        f"platform/technology evaluation. Start Scan findings are mapped to "
        f"industry-standard classification frameworks (CWE, WASC, OWASP, NIST and SANS) "
        f"where applicable; platform evaluation notes are guidance only and are not "
        f"standards-mapped. "
        f"A total of <b>{total}</b> finding(s) / note(s) were identified, resulting in an overall "
        f"risk rating of <font color='{risk_color.hexval()}'><b>{_html(risk)}</b></font>."
    )
    story.append(Paragraph(intro, styles["body"]))
    executive = str(report.get("executive_summary") or "-")
    for line in executive.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("\u2022") or line.startswith("•"):
            text = line[1:].strip() if line.startswith("\u2022") else line[1:].strip()
            story.append(Paragraph(f"&bull; {_html(text)}", styles["body"]))
        else:
            story.append(Paragraph(_html(line), styles["body"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("1.1 Severity Rating Definitions", styles["subsection"]))
    story.append(_severity_legend(styles))
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph("1.2 Scope &amp; Methodology", styles["subsection"]))
    story.append(Paragraph(
        "This assessment was performed using automated, non-intrusive techniques against the "
        "publicly reachable surface of the target application. Two evaluation passes were run: "
        "a <b>Start Scan</b>, which probes live HTTP responses, headers and session handling for "
        "common web-application weaknesses, and a <b>Platform Evaluation</b>, which fingerprints "
        "the underlying technology stack for hardening opportunities. "
        "Only Start Scan findings were cross-referenced against CWE, WASC, OWASP, NIST SP 800-53 "
        "and SANS reference material. Platform evaluation notes are configuration guidance and "
        "do not carry standards mapping.",
        styles["body"],
    ))
    story.append(Paragraph(
        "This report reflects the security posture of the target at the time of assessment only "
        "and is not exhaustive; it does not replace a manual penetration test or code review. "
        "Findings should be independently validated prior to remediation planning.",
        styles["italic_small"],
    ))
    story.append(PageBreak())

    # 2. Risk Overview
    story.append(Paragraph("2. Risk Overview", styles["section"]))
    story.append(_risk_summary_table(summary, styles))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("2.1 Assessment Breakdown", styles["subsection"]))
    story.append(_scan_breakdown_table(report, styles))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("2.2 Detected Technology Stack", styles["subsection"]))
    story.append(_tech_stack_table(report, styles))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "2.3 Security Standards Mapping (Start Scan findings)",
        styles["subsection"],
    ))
    story.append(Paragraph(
        "Standards counts below exclude Platform evaluation notes.",
        styles["italic_small"],
    ))
    story.append(_standards_table(report, styles))
    story.append(PageBreak())

    # 3. Start Scan findings
    scan_findings = report.get("findings") or []
    story.append(Paragraph("3. Security Findings \u2014 Start Scan", styles["section"]))
    if scan_findings:
        for index, finding in enumerate(scan_findings, start=1):
            story.extend(
                _finding_elements(index, finding, styles, include_standards=True)
            )
    else:
        story.append(Paragraph("No Start Scan vulnerabilities were detected.", styles["body"]))
    story.append(Spacer(1, 7 * mm))

    # 4. Platform evaluation — no standards
    platform_findings = report.get("stack_findings") or []
    story.append(Paragraph(
        "4. Platform Evaluation \u2014 Get Stack (guidance only)",
        styles["section"],
    ))
    story.append(Paragraph(
        "Platform notes are hardening guidance derived from detected technology. "
        "They are not mapped to CWE, OWASP, NIST or SANS.",
        styles["italic_small"],
    ))
    if platform_findings:
        for index, finding in enumerate(platform_findings, start=1):
            story.extend(
                _finding_elements(index, finding, styles, include_standards=False)
            )
    else:
        story.append(Paragraph("No platform-evaluation findings were recorded.", styles["body"]))
    story.append(PageBreak())

    # 5. Remediation
    story.append(Paragraph("5. Remediation Recommendations", styles["section"]))
    remediation = report.get("remediation") or []
    if remediation:
        for index, tip in enumerate(remediation, start=1):
            recommendation = Table(
                [[
                    Paragraph(f"<b>{index}</b>", ParagraphStyle(
                        "RecIndex", parent=styles["center_bold"], textColor=WHITE)),
                    Paragraph(_html(tip), styles["body"]),
                ]],
                colWidths=[10 * mm, 156 * mm],
            )
            recommendation.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), NAVY_3),
                ("BACKGROUND", (1, 0), (1, 0), WHITE),
                ("GRID", (0, 0), (-1, -1), 0.6, BORDER_STRONG),
                ("BOX", (0, 0), (-1, -1), 1, BORDER_STRONG),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(recommendation)
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph("No remediation recommendations were required.", styles["body"]))

    # 6. Disclaimer
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("6. Confidentiality &amp; Disclaimer", styles["section"]))
    story.append(Paragraph(
        "This report and its contents are classified <b>Confidential</b> and are intended solely "
        "for the recipient organisation. It may contain information about security weaknesses in "
        "the assessed system and must not be distributed outside the intended audience without "
        "authorisation.",
        styles["body"],
    ))
    story.append(Paragraph(
        "WebSET performs automated testing and, while effort is made to minimise false positives, "
        "results should be validated by qualified personnel before remediation or disclosure "
        "decisions are made. WebSET and its operators accept no liability for actions taken, or not "
        "taken, on the basis of this report.",
        styles["body"],
    ))

    story.append(NextPageTemplate("End"))
    story.append(PageBreak())
    story.extend(_end_story(report, styles))

    doc.multiBuild(story, canvasmaker=_NumberedCanvas)
    return os.path.abspath(output_path)
