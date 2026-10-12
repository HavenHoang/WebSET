import os
import re
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.graphics.shapes import Drawing, Rect, String
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
    HRFlowable,
    CondPageBreak,
)
from reportlab.platypus.tableofcontents import TableOfContents


PAGE_WIDTH, PAGE_HEIGHT = A4
CONTENT_WIDTH = PAGE_WIDTH - 36 * mm

TABLE_GAP = 6 * mm
SECTION_GAP = 9 * mm
SUBSECTION_GAP = 8 * mm
FINDING_GAP = 7 * mm


NAVY = colors.HexColor("#07192D")
NAVY_2 = colors.HexColor("#10284A")

NAVY_3 = colors.HexColor("#1F2A57")

TEAL = colors.HexColor("#0F8F86")
TEAL_LIGHT = colors.HexColor("#22C7BA")

BLUE = NAVY_3

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

P1_BG = colors.HexColor("#FFF1F0")
P2_BG = colors.HexColor("#FFF7E8")
P3_BG = colors.HexColor("#F3F6FA")


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
        dt = datetime.strptime(
            generated,
            "%Y-%m-%d %H:%M:%S",
        )
    except Exception:
        dt = datetime.now()

    return dt.strftime("WEBSET-%Y%m%d-%H%M%S")


def _as_int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _severity_counts(findings):
    counts = {"High": 0, "Medium": 0, "Low": 0, "Total": 0}

    for finding in findings or []:
        severity = str(finding.get("severity") or "Low").strip().title()
        if severity not in ("High", "Medium", "Low"):
            severity = "Low"
        counts[severity] += 1
        counts["Total"] += 1

    return counts


def _report_counts(report):
    scan_findings = report.get("findings") or []
    platform_findings = report.get("stack_findings") or []

    scan = dict(report.get("scan_summary") or {})
    platform = dict(report.get("platform_summary") or {})

    if not scan or not any(_as_int(scan.get(k)) for k in ("High", "Medium", "Low", "Total")):
        scan = _severity_counts(scan_findings)
    if not platform or not any(_as_int(platform.get(k)) for k in ("High", "Medium", "Low", "Total")):
        platform = _severity_counts(platform_findings)

    for bucket in (scan, platform):
        bucket["High"] = _as_int(bucket.get("High"))
        bucket["Medium"] = _as_int(bucket.get("Medium"))
        bucket["Low"] = _as_int(bucket.get("Low"))
        bucket["Total"] = _as_int(bucket.get("Total")) or (
            bucket["High"] + bucket["Medium"] + bucket["Low"]
        )

    return scan, platform


def _count_phrase(count, singular, plural=None):
    plural = plural or f"{singular}s"
    return f"{count} {singular if count == 1 else plural}"


def _redact_evidence(value):
    text = str(value)

    def replace_email(match):
        local, domain = match.group(1), match.group(2)
        visible = local[:2] if len(local) > 1 else local[:1]
        return f"{visible}***@{domain}"

    return re.sub(
        r"\b([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,})\b",
        replace_email,
        text,
        flags=re.IGNORECASE,
    )


def _display_value(value, label=""):
    if isinstance(value, (list, tuple, set)):
        parts = [str(item).strip() for item in value if str(item).strip()]
    else:
        raw = _safe(value)
        if label == "Evidence":
            raw = _redact_evidence(raw)
        if label in ("Location", "Affected endpoints"):
            parts = [part.strip() for part in re.split(r"\s+(?=https?://)", raw) if part.strip()]
        else:
            parts = [raw]

    if len(parts) > 1:
        return "<br/>".join(f"&bull; {_html(part)}" for part in parts)
    return _html(parts[0] if parts else "-")


def _polish_executive_line(line):
    prefix = "\u2022" if line.startswith("\u2022") else ""
    content = line[1:].strip() if prefix else line.strip()

    match = re.fullmatch(r"Start Scan:\s*(\d+)\s+issue\(s\)(.*)", content, re.IGNORECASE)
    if match:
        count = int(match.group(1))
        content = f"Start Scan: {_count_phrase(count, 'security finding')}{match.group(2)}"

    match = re.fullmatch(r"Platform evaluation:\s*(\d+)\s+note\(s\)(.*)", content, re.IGNORECASE)
    if match:
        count = int(match.group(1))
        content = f"Platform observations: {_count_phrase(count, 'observation')}{match.group(2)}"

    return f"{prefix} {content}".strip()


def _friendly_date(report):
    generated = str(report.get("generated_at") or "")

    try:
        dt = datetime.strptime(
            generated,
            "%Y-%m-%d %H:%M:%S",
        )
    except Exception:
        dt = datetime.now()

    return dt.strftime(
        "%d %B %Y \u00b7 %I:%M %p"
    )


def _assessment_type(report):
    scan_type = str(
        report.get("scan_type") or "Dynamic"
    ).strip()

    lowered = scan_type.lower()

    if lowered == "dynamic":
        return "Dynamic Security Assessment"

    if lowered == "static":
        return "Static Security Assessment"

    return f"{scan_type} Security Assessment"


def _overall_risk(report):
    summary, _ = _report_counts(report)

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


def _add_section_heading(
    story,
    title,
    styles,
    minimum_space=42 * mm,
):
    story.append(
        CondPageBreak(minimum_space)
    )

    story.append(
        Paragraph(
            title,
            styles["section"],
        )
    )


def _add_subsection_heading(
    story,
    title,
    styles,
    minimum_space=28 * mm,
):
    story.append(
        CondPageBreak(minimum_space)
    )

    story.append(
        Paragraph(
            title,
            styles["subsection"],
        )
    )


class _FindingTable(Table):
    
    def __init__(self, *args, continuation_title=None, continuation_style=None, **kwargs):
        self._continuation_title = continuation_title
        self._continuation_style = continuation_style
        super().__init__(*args, **kwargs)

    def split(self, availWidth, availHeight):
        parts = super().split(availWidth, availHeight)

        if len(parts) > 1 and self._continuation_title and self._continuation_style:
            for part in parts:
                part.hAlign = self.hAlign
                part._continuation_title = self._continuation_title
                part._continuation_style = self._continuation_style

            for part in parts[1:]:
                part._continuation_title = self._continuation_title
                part._continuation_style = self._continuation_style
                part._cellvalues[0][0] = Paragraph(
                    f"{_html(self._continuation_title)} "
                    "<font color='#B9C4D2'>(continued)</font>",
                    self._continuation_style,
                )

            separated = []
            for index, part in enumerate(parts):
                if index:
                    separated.append(CondPageBreak(245 * mm))
                separated.append(part)
            return separated

        return parts


def _styles():
    sample = getSampleStyleSheet()

    return {
        "cover_brand": ParagraphStyle(
            "CoverBrand",
            parent=sample["Normal"],
            fontName="Helvetica-Bold",
            fontSize=26,
            leading=30,
            textColor=NAVY,
        ),

        "cover_product": ParagraphStyle(
            "CoverProduct",
            parent=sample["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=BLUE,
        ),

        "cover_title": ParagraphStyle(
            "CoverTitle",
            parent=sample["Title"],
            fontName="Helvetica-Bold",
            fontSize=26,
            leading=30,
            textColor=NAVY,
            spaceAfter=9,
        ),

        "cover_subtitle": ParagraphStyle(
            "CoverSubtitle",
            parent=sample["Normal"],
            fontName="Helvetica",
            fontSize=12,
            leading=17,
            textColor=TEXT_SOFT,
        ),

        "section": ParagraphStyle(
            "Heading1TOC",
            parent=sample["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=19,
            textColor=NAVY_3,
            spaceBefore=14,
            spaceAfter=10,

            keepWithNext=1,
        ),

        "subsection": ParagraphStyle(
            "Heading2TOC",
            parent=sample["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=15,
            textColor=NAVY_3,
            spaceBefore=11,
            spaceAfter=7,

            keepWithNext=1,
        ),

        "body": ParagraphStyle(
            "Body",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=9.2,
            leading=14,
            textColor=TEXT,
            wordWrap="LTR",
            splitLongWords=False,
            spaceAfter=7,
            alignment=TA_JUSTIFY,
        ),

        "body_bold": ParagraphStyle(
            "BodyBold",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9.2,
            leading=14,
            textColor=TEXT,
            wordWrap="LTR",
            splitLongWords=False,
            spaceAfter=3,
        ),

        "small": ParagraphStyle(
            "Small",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=7.8,
            leading=10.5,
            textColor=MUTED,
            wordWrap="LTR",
            splitLongWords=False,
        ),

        "italic_small": ParagraphStyle(
            "ItalicSmall",
            parent=sample["BodyText"],
            fontName="Helvetica-Oblique",
            fontSize=8.4,
            leading=12.5,
            textColor=MUTED,
            wordWrap="LTR",
            splitLongWords=False,
            spaceBefore=2,
            spaceAfter=7,
        ),

        "url": ParagraphStyle(
            "UrlText",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=8.6,
            leading=12.5,
            textColor=TEXT,
            wordWrap="CJK",
            splitLongWords=True,
            spaceAfter=4,
        ),

        "roadmap": ParagraphStyle(
            "RoadmapText",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=8.0,
            leading=11,
            textColor=TEXT,
            wordWrap="LTR",
            splitLongWords=False,
        ),

        "center": ParagraphStyle(
            "Center",
            parent=sample["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            alignment=TA_CENTER,
            textColor=TEXT,
        ),

        "center_bold": ParagraphStyle(
            "CenterBold",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            alignment=TA_CENTER,
            textColor=TEXT,
        ),

        "table_header": ParagraphStyle(
            "TableHeader",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            alignment=TA_LEFT,
            textColor=WHITE,
        ),

        "table_header_center": ParagraphStyle(
            "TableHeaderCenter",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            alignment=TA_CENTER,
            textColor=WHITE,
        ),

        "detail_label": ParagraphStyle(
            "DetailLabel",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8.3,
            leading=11.5,
            textColor=WHITE,
            wordWrap="LTR",
            splitLongWords=False,
        ),

        "finding_title": ParagraphStyle(
            "FindingTitle",
            parent=sample["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9.4,
            leading=14,
            textColor=WHITE,
            wordWrap="LTR",
            splitLongWords=False,
        ),

        "card_label": ParagraphStyle(
            "CardLabel",
            parent=sample["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            alignment=TA_CENTER,
        ),

        "card_value": ParagraphStyle(
            "CardValue",
            parent=sample["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            alignment=TA_CENTER,
        ),

        "toc_title": ParagraphStyle(
            "TOCTitle",
            parent=sample["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=17,
            leading=21,
            textColor=NAVY_3,
            spaceAfter=12,
        ),
    }


def _toc_styles(styles):
    return [
        ParagraphStyle(
            "TOCLevel0",
            parent=styles["body"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=16,
            textColor=NAVY_3,
            leftIndent=0,
            alignment=TA_LEFT,
            spaceAfter=2,
        ),

        ParagraphStyle(
            "TOCLevel1",
            parent=styles["body"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=TEXT_SOFT,
            leftIndent=10,
            alignment=TA_LEFT,
            spaceAfter=1,
        ),
    ]


class _NumberedCanvas(pdfcanvas.Canvas):

    def __init__(self, *args, **kwargs):
        pdfcanvas.Canvas.__init__(
            self,
            *args,
            **kwargs,
        )

        self._saved_states = []

    def showPage(self):
        self._saved_states.append(
            dict(self.__dict__)
        )

        self._startPage()

    def save(self):
        content_states = [
            state
            for state in self._saved_states
            if state.get("_websec_content_page")
        ]

        total = len(content_states)
        seen = 0

        for state in self._saved_states:
            self.__dict__.update(state)

            if state.get("_websec_content_page"):
                seen += 1

                self._draw_content_footer(
                    seen,
                    total,
                )

            pdfcanvas.Canvas.showPage(self)

        pdfcanvas.Canvas.save(self)

    def _draw_content_footer(
        self,
        page_no,
        total_pages,
    ):
        self.saveState()

        self.setStrokeColor(BORDER)
        self.setLineWidth(0.5)

        self.line(
            18 * mm,
            14 * mm,
            PAGE_WIDTH - 18 * mm,
            14 * mm,
        )

        self.setFont(
            "Helvetica",
            7.5,
        )

        self.setFillColor(MUTED)

        self.drawString(
            18 * mm,
            9 * mm,
            "WebSET \u00b7 Security Assessment Report",
        )

        self.drawCentredString(
            PAGE_WIDTH / 2,
            9 * mm,
            "CONFIDENTIAL",
        )

        self.drawRightString(
            PAGE_WIDTH - 18 * mm,
            9 * mm,
            f"Page {page_no} of {total_pages}",
        )

        self.restoreState()


def _draw_geometric_background(
    canvas,
    closing=False,
):
    canvas.saveState()

    if closing:
        canvas.translate(
            PAGE_WIDTH,
            0,
        )

        canvas.scale(
            -1,
            1,
        )

    canvas.setFillColor(WHITE)

    canvas.rect(
        0,
        0,
        PAGE_WIDTH,
        PAGE_HEIGHT,
        fill=1,
        stroke=0,
    )

    hero_height = PAGE_HEIGHT * 0.66

    canvas.setFillColor(NAVY)

    canvas.rect(
        0,
        PAGE_HEIGHT - hero_height,
        PAGE_WIDTH,
        hero_height,
        fill=1,
        stroke=0,
    )

    gradient_colors = [
        colors.HexColor("#061629"),
        colors.HexColor("#071B31"),
        colors.HexColor("#08213A"),
        colors.HexColor("#092640"),
    ]

    band_h = hero_height / len(
        gradient_colors
    )

    for i, colour in enumerate(
        gradient_colors
    ):
        canvas.setFillColor(colour)

        canvas.rect(
            0,
            PAGE_HEIGHT - ((i + 1) * band_h),
            PAGE_WIDTH,
            band_h + 1,
            fill=1,
            stroke=0,
        )

    canvas.setFillColor(
        colors.Color(
            1,
            1,
            1,
            alpha=0.035,
        )
    )

    sheen = canvas.beginPath()
    sheen.moveTo(PAGE_WIDTH * 0.15, PAGE_HEIGHT)
    sheen.lineTo(PAGE_WIDTH * 0.55, PAGE_HEIGHT)
    sheen.lineTo(PAGE_WIDTH * 0.20, PAGE_HEIGHT - hero_height)
    sheen.lineTo(PAGE_WIDTH * -0.05, PAGE_HEIGHT - hero_height)
    sheen.close()
    canvas.drawPath(sheen, fill=1, stroke=0)

    hero_bottom = PAGE_HEIGHT - hero_height
    tilt = 24 * mm

    seam_left_y = (
        hero_bottom
        + tilt / 2
    )

    seam_right_y = (
        hero_bottom
        - tilt / 2
    )

    canvas.setFillColor(WHITE)

    path = canvas.beginPath()

    path.moveTo(
        0,
        seam_left_y,
    )

    path.lineTo(
        PAGE_WIDTH,
        seam_right_y,
    )

    path.lineTo(
        PAGE_WIDTH,
        0,
    )

    path.lineTo(
        0,
        0,
    )

    path.close()

    canvas.drawPath(
        path,
        fill=1,
        stroke=0,
    )

    canvas.setStrokeColor(TEAL)
    canvas.setLineWidth(1.5)

    canvas.line(
        0,
        seam_left_y,
        PAGE_WIDTH,
        seam_right_y,
    )

    outer_a = 92 * mm
    outer_b = 70 * mm

    inner_a = 50 * mm
    inner_b = 38 * mm

    canvas.setFillColor(NAVY_2)

    path = canvas.beginPath()

    path.moveTo(
        PAGE_WIDTH - outer_a,
        PAGE_HEIGHT,
    )

    path.lineTo(
        PAGE_WIDTH,
        PAGE_HEIGHT,
    )

    path.lineTo(
        PAGE_WIDTH,
        PAGE_HEIGHT - outer_b,
    )

    path.close()

    canvas.drawPath(
        path,
        fill=1,
        stroke=0,
    )

    canvas.setFillColor(TEAL)

    path = canvas.beginPath()

    path.moveTo(
        PAGE_WIDTH - inner_a,
        PAGE_HEIGHT,
    )

    path.lineTo(
        PAGE_WIDTH,
        PAGE_HEIGHT,
    )

    path.lineTo(
        PAGE_WIDTH,
        PAGE_HEIGHT - inner_b,
    )

    path.close()

    canvas.drawPath(
        path,
        fill=1,
        stroke=0,
    )

    canvas.setStrokeColor(
        TEAL_LIGHT
    )

    canvas.setLineWidth(1.1)

    canvas.line(
        PAGE_WIDTH - inner_a,
        PAGE_HEIGHT,
        PAGE_WIDTH,
        PAGE_HEIGHT - inner_b,
    )

    canvas.setFillColor(
        colors.HexColor("#E3F5F3")
    )

    path = canvas.beginPath()

    path.moveTo(
        0,
        0,
    )

    path.lineTo(
        32 * mm,
        0,
    )

    path.lineTo(
        0,
        22 * mm,
    )

    path.close()

    canvas.drawPath(
        path,
        fill=1,
        stroke=0,
    )

    canvas.setStrokeColor(TEAL)
    canvas.setLineWidth(1)

    canvas.line(
        0,
        22 * mm,
        32 * mm,
        0,
    )

    canvas.setFillColor(
        colors.HexColor("#EEF2F7")
    )

    path = canvas.beginPath()

    path.moveTo(
        PAGE_WIDTH - 28 * mm,
        0,
    )

    path.lineTo(
        PAGE_WIDTH,
        0,
    )

    path.lineTo(
        PAGE_WIDTH,
        18 * mm,
    )

    path.close()

    canvas.drawPath(
        path,
        fill=1,
        stroke=0,
    )

    canvas.setStrokeColor(
        colors.HexColor("#B9C4D2")
    )

    canvas.setLineWidth(0.8)

    canvas.line(
        PAGE_WIDTH - 28 * mm,
        0,
        PAGE_WIDTH,
        18 * mm,
    )

    canvas.setFillColor(
        colors.Color(
            0.2,
            0.85,
            0.82,
            alpha=0.22,
        )
    )

    start_x = 13 * mm
    start_y = PAGE_HEIGHT * 0.79

    for row in range(6):
        for col in range(8):
            canvas.circle(
                start_x + col * 3 * mm,
                start_y + row * 3 * mm,
                0.35 * mm,
                fill=1,
                stroke=0,
            )

    centre_x = PAGE_WIDTH * 0.72
    centre_y = PAGE_HEIGHT * 0.62

    for radius, alpha in (
        (48 * mm, 0.05),
        (39 * mm, 0.07),
        (30 * mm, 0.10),
        (21 * mm, 0.14),
    ):
        canvas.setFillColor(
            colors.Color(
                0.13,
                0.78,
                0.72,
                alpha=alpha,
            )
        )

        canvas.circle(
            centre_x,
            centre_y,
            radius,
            fill=1,
            stroke=0,
        )

    canvas.setStrokeColor(
        colors.Color(
            0.05,
            0.78,
            0.72,
            alpha=0.45,
        )
    )

    canvas.setLineWidth(0.7)

    for radius in (
        22 * mm,
        30 * mm,
        38 * mm,
    ):
        canvas.circle(
            centre_x,
            centre_y,
            radius,
            fill=0,
            stroke=1,
        )

    nodes = [
        (-26, 20),
        (-18, -25),
        (22, -22),
        (29, 18),
        (-38, 0),
        (39, 0),
    ]

    canvas.setFillColor(
        TEAL_LIGHT
    )

    for dx, dy in nodes:
        x = (
            centre_x
            + dx * mm / 2
        )

        y = (
            centre_y
            + dy * mm / 2
        )

        canvas.circle(
            x,
            y,
            1.35 * mm,
            fill=1,
            stroke=0,
        )

        canvas.setStrokeColor(
            colors.Color(
                0.1,
                0.8,
                0.75,
                alpha=0.50,
            )
        )

        canvas.line(
            centre_x,
            centre_y,
            x,
            y,
        )

    canvas.setStrokeColor(WHITE)
    canvas.setLineWidth(2.2)

    shield = canvas.beginPath()

    shield.moveTo(
        centre_x,
        centre_y + 24 * mm,
    )

    shield.lineTo(
        centre_x + 17 * mm,
        centre_y + 16 * mm,
    )

    shield.lineTo(
        centre_x + 15 * mm,
        centre_y - 5 * mm,
    )

    shield.curveTo(
        centre_x + 12 * mm,
        centre_y - 17 * mm,
        centre_x + 5 * mm,
        centre_y - 24 * mm,
        centre_x,
        centre_y - 28 * mm,
    )

    shield.curveTo(
        centre_x - 5 * mm,
        centre_y - 24 * mm,
        centre_x - 12 * mm,
        centre_y - 17 * mm,
        centre_x - 15 * mm,
        centre_y - 5 * mm,
    )

    shield.lineTo(
        centre_x - 17 * mm,
        centre_y + 16 * mm,
    )

    shield.close()

    canvas.drawPath(
        shield,
        fill=0,
        stroke=1,
    )

    canvas.setFillColor(
        TEAL_LIGHT
    )

    canvas.roundRect(
        centre_x - 6.5 * mm,
        centre_y - 4.5 * mm,
        13 * mm,
        12 * mm,
        2.5 * mm,
        fill=1,
        stroke=0,
    )

    canvas.setStrokeColor(WHITE)
    canvas.setLineWidth(1.8)

    canvas.arc(
        centre_x - 5 * mm,
        centre_y + 2 * mm,
        centre_x + 5 * mm,
        centre_y + 15 * mm,
        startAng=0,
        extent=180,
    )

    canvas.setFillColor(NAVY)

    canvas.circle(
        centre_x,
        centre_y + 1 * mm,
        1.1 * mm,
        fill=1,
        stroke=0,
    )

    canvas.rect(
        centre_x - 0.45 * mm,
        centre_y - 2.5 * mm,
        0.9 * mm,
        3 * mm,
        fill=1,
        stroke=0,
    )

    canvas.setStrokeColor(
        colors.Color(
            1,
            1,
            1,
            alpha=0.35,
        )
    )

    canvas.setLineWidth(0.6)

    canvas.rect(
        7 * mm,
        7 * mm,
        PAGE_WIDTH - 14 * mm,
        PAGE_HEIGHT - 14 * mm,
        fill=0,
        stroke=1,
    )

    canvas.restoreState()


def _cover_page(canvas, doc):
    canvas._websec_content_page = False
    _draw_geometric_background(canvas)


def _end_page(canvas, doc):
    canvas._websec_content_page = False

    _draw_geometric_background(
        canvas,
        closing=True,
    )


def _content_page(canvas, doc):
    canvas._websec_content_page = True

    canvas.saveState()

    canvas.setFillColor(NAVY_3)

    canvas.setFont(
        "Helvetica-Bold",
        8.5,
    )

    canvas.drawString(
        18 * mm,
        PAGE_HEIGHT - 13 * mm,
        "WebSET",
    )

    canvas.setFillColor(MUTED)

    canvas.setFont(
        "Helvetica",
        7.5,
    )

    # More space after WebSET
    canvas.drawString(
        34 * mm,
        PAGE_HEIGHT - 13 * mm,
        "Website Security Evaluation Tool",
    )

    report_id = getattr(
        doc,
        "_report_id",
        "",
    )

    canvas.drawRightString(
        PAGE_WIDTH - 18 * mm,
        PAGE_HEIGHT - 13 * mm,
        report_id,
    )

    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)

    canvas.line(
        18 * mm,
        PAGE_HEIGHT - 16 * mm,
        PAGE_WIDTH - 18 * mm,
        PAGE_HEIGHT - 16 * mm,
    )

    canvas.restoreState()


def _risk_badge_row(
    risk,
    risk_color,
    styles,
    dark_panel=True,
):
    label_style = ParagraphStyle(
        "RiskBadgeLabel",
        parent=styles["small"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=WHITE,
        alignment=TA_CENTER,
    )

    badge = Table(
        [[
            Paragraph(
                f"OVERALL RISK RATING&nbsp;&nbsp;"
                f"<b>{_html(risk)}</b>",
                label_style,
            )
        ]],
        colWidths=[
            62 * mm
        ],
        rowHeights=[
            9 * mm
        ],
    )

    badge.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                risk_color,
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.75,
                WHITE,
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE",
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER",
            ),
        ])
    )

    return badge


def _cover_story(report, styles):
    scan_summary, platform_summary = _report_counts(report)

    risk, risk_color = _overall_risk(
        report
    )

    scan_total = scan_summary["Total"]
    platform_total = platform_summary["Total"]

    report_id = _make_report_id(
        report
    )

    story = []

    story.append(
        Spacer(
            1,
            7 * mm,
        )
    )

    story.append(
        Paragraph(
            "CONFIDENTIAL SECURITY ASSESSMENT",
            ParagraphStyle(
                "CoverClass",
                parent=styles["small"],
                fontName="Helvetica-Bold",
                fontSize=7.5,
                leading=10,
                textColor=TEAL_LIGHT,
                letterSpacing=0.8,
            ),
        )
    )

    story.append(
        Spacer(
            1,
            4 * mm,
        )
    )

    story.append(
        Paragraph(
            "WebSET",
            ParagraphStyle(
                "CoverWebSET",
                parent=styles["cover_brand"],
                fontName="Helvetica-Bold",
                fontSize=25,
                leading=29,
                textColor=WHITE,
            ),
        )
    )

    story.append(
        Paragraph(
            "Website Security Evaluation Tool",
            ParagraphStyle(
                "CoverWebSETSub",
                parent=styles["cover_product"],
                fontName="Helvetica",
                fontSize=9,
                leading=12,
                textColor=colors.HexColor("#A8DBD7"),
            ),
        )
    )

    story.append(
        Spacer(
            1,
            12 * mm,
        )
    )

    story.append(
        Paragraph(
            "WEBSITE SECURITY<br/>"
            "ASSESSMENT REPORT",
            ParagraphStyle(
                "CoverMainTitle",
                parent=styles["cover_title"],
                fontName="Helvetica-Bold",
                fontSize=25,
                leading=28,
                textColor=WHITE,
            ),
        )
    )

    story.append(
        Spacer(
            1,
            3 * mm,
        )
    )

    accent = Table(
        [[""]],
        colWidths=[
            38 * mm
        ],
        rowHeights=[
            1.2 * mm
        ],
    )

    accent.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                TEAL_LIGHT,
            )
        ])
    )

    story.append(accent)

    story.append(
        Spacer(
            1,
            5 * mm,
        )
    )

    story.append(
        Paragraph(
            "Automated Vulnerability, Technology &amp;<br/>"
            "Security Standards Evaluation",
            ParagraphStyle(
                "CoverDescription",
                parent=styles["cover_subtitle"],
                fontName="Helvetica",
                fontSize=11,
                leading=15,
                textColor=colors.HexColor("#D9E8F0"),
            ),
        )
    )

    story.append(
        Spacer(
            1,
            10 * mm,
        )
    )

    story.append(
        _risk_badge_row(
            risk,
            risk_color,
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            42 * mm,
        )
    )

    label_style = ParagraphStyle(
        "CoverInfoLabel",
        parent=styles["small"],
        fontName="Helvetica-Bold",
        fontSize=7.4,
        leading=10,
        textColor=WHITE,
    )

    value_style = ParagraphStyle(
        "CoverInfoValue",
        parent=styles["body"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=TEXT,
        alignment=TA_LEFT,
    )

    risk_style = ParagraphStyle(
        "CoverRisk",
        parent=value_style,
        textColor=risk_color,
        fontSize=9,
    )

    metadata = [
        [
            Paragraph(
                "TARGET",
                label_style,
            ),
            Paragraph(
                _html(
                    report.get("url")
                ),
                value_style,
            ),
        ],
        [
            Paragraph(
                "ASSESSMENT TYPE",
                label_style,
            ),
            Paragraph(
                _html(
                    _assessment_type(report)
                ),
                value_style,
            ),
        ],
        [
            Paragraph(
                "REPORT ID",
                label_style,
            ),
            Paragraph(
                _html(report_id),
                value_style,
            ),
        ],
        [
            Paragraph(
                "ASSESSMENT DATE",
                label_style,
            ),
            Paragraph(
                _html(
                    _friendly_date(report)
                ),
                value_style,
            ),
        ],
        [
            Paragraph(
                "OVERALL RISK",
                label_style,
            ),
            Paragraph(
                f"<b>{_html(risk)}</b>",
                risk_style,
            ),
        ],
        [
            Paragraph(
                "SECURITY FINDINGS",
                label_style,
            ),
            Paragraph(
                str(scan_total),
                value_style,
            ),
        ],
        [
            Paragraph(
                "PLATFORM OBSERVATIONS",
                label_style,
            ),
            Paragraph(
                str(platform_total),
                value_style,
            ),
        ],
        [
            Paragraph(
                "REPORT CLASSIFICATION",
                label_style,
            ),
            Paragraph(
                "Confidential",
                value_style,
            ),
        ],
    ]

    panel = Table(
        metadata,
        colWidths=[
            45 * mm,
            105 * mm,
        ],
        hAlign="LEFT",
    )

    panel.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                NAVY_3,
            ),
            (
                "BACKGROUND",
                (1, 0),
                (1, -1),
                WHITE,
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                1.2,
                TEAL,
            ),
            (
                "INNERGRID",
                (0, 0),
                (-1, -1),
                0.4,
                BORDER_STRONG,
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE",
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8,
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                8,
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6,
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6,
            ),
        ])
    )

    story.append(panel)

    story.append(
        Spacer(
            1,
            TABLE_GAP,
        )
    )

    story.append(
        Paragraph(
            "<b>Generated by WebSET</b><br/>"
            "<font size='7.5'>"
            "Website Security Evaluation Tool"
            "</font>",
            ParagraphStyle(
                "CoverFooterBrand",
                parent=styles["center"],
                alignment=TA_CENTER,
                fontName="Helvetica",
                fontSize=9,
                leading=12,
                textColor=NAVY_3,
            ),
        )
    )

    return story


def _toc_page(report, styles):
    story = []

    story.append(
        Paragraph(
            "Table of Contents",
            styles["toc_title"],
        )
    )

    story.append(
        HRFlowable(
            width="100%",
            thickness=0.8,
            color=BORDER,
            spaceAfter=6,
        )
    )

    story.append(Spacer(1, 2 * mm))

    metadata = Table(
        [
            [
                Paragraph(
                    "CONFIDENTIAL \u2014 AUTHORISED SECURITY TESTING ONLY",
                    styles["table_header_center"],
                ),
                "",
            ],
            [
                Paragraph(f"<b>Target:</b> {_html(report.get('url'))}", styles["small"]),
                Paragraph(f"<b>Report ID:</b> {_html(_make_report_id(report))}", styles["small"]),
            ],
        ],
        colWidths=[104 * mm, 70 * mm],
        hAlign="LEFT",
    )
    metadata.setStyle(TableStyle([
        ("SPAN", (0, 0), (-1, 0)),
        ("BACKGROUND", (0, 0), (-1, 0), NAVY_3),
        ("BACKGROUND", (0, 1), (-1, 1), LIGHT_BLUE),
        ("BOX", (0, 0), (-1, -1), 0.7, BORDER_STRONG),
        ("LINEBELOW", (0, 0), (-1, 0), 0.7, BORDER_STRONG),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(metadata)
    story.append(Spacer(1, 5 * mm))

    toc = TableOfContents()

    toc.levelStyles = _toc_styles(
        styles
    )

    toc.dotsMinLevel = 0

    story.append(toc)

    return story


def _risk_summary_table(summary, styles):
    items = [
        (
            "HIGH",
            summary.get("High", 0),
            HIGH,
        ),
        (
            "MEDIUM",
            summary.get("Medium", 0),
            MEDIUM,
        ),
        (
            "LOW",
            summary.get("Low", 0),
            LOW,
        ),
        (
            "TOTAL",
            summary.get("Total", 0),
            NAVY_3,
        ),
    ]

    row = []

    for label, value, colour in items:
        label_p = Paragraph(
            f"<b>{label}</b>",
            ParagraphStyle(
                f"CardLabel{label}",
                parent=styles["card_label"],
                textColor=WHITE,
            ),
        )

        value_p = Paragraph(
            str(value),
            ParagraphStyle(
                f"CardValue{label}",
                parent=styles["card_value"],
                textColor=WHITE,
            ),
        )

        card = Table(
            [
                [label_p],
                [value_p],
            ],
            colWidths=[
                39 * mm
            ],
            rowHeights=[
                8 * mm,
                16 * mm,
            ],
        )

        card.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colour,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    1,
                    NAVY_3,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, 0),
                    "MIDDLE",
                ),
                (
                    "VALIGN",
                    (0, 1),
                    (-1, 1),
                    "TOP",
                ),
                (
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, 0),
                    4,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, 0),
                    0,
                ),
                (
                    "TOPPADDING",
                    (0, 1),
                    (-1, 1),
                    0,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 1),
                    (-1, 1),
                    4,
                ),
            ])
        )

        row.append(card)

    result = Table(
        [row],
        colWidths=[
            42 * mm,
            42 * mm,
            42 * mm,
            42 * mm,
        ],
        hAlign="LEFT",
    )

    result.setStyle(
        TableStyle([
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP",
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                1.5,
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                1.5,
            ),
        ])
    )

    return result


def _severity_chart(summary):
    """Compact horizontal chart for quick executive-level comparison."""
    values = [
        ("High", _as_int(summary.get("High")), HIGH),
        ("Medium", _as_int(summary.get("Medium")), MEDIUM),
        ("Low", _as_int(summary.get("Low")), LOW),
    ]
    maximum = max([value for _, value, _ in values] + [1])

    width = 174 * mm
    height = 29 * mm
    drawing = Drawing(width, height)
    label_x = 0
    bar_x = 27 * mm
    bar_width = 132 * mm
    row_height = 8.2 * mm

    for row, (label, value, colour) in enumerate(values):
        y = height - (row + 1) * row_height + 1.5 * mm
        drawing.add(String(label_x, y + 1.2 * mm, label.upper(), fontName="Helvetica-Bold", fontSize=7.5, fillColor=TEXT_SOFT))
        drawing.add(Rect(bar_x, y, bar_width, 4.4 * mm, fillColor=colors.HexColor("#E8EDF3"), strokeColor=None))
        filled = bar_width * (value / maximum) if value else 0
        if filled:
            drawing.add(Rect(bar_x, y, filled, 4.4 * mm, fillColor=colour, strokeColor=None))
        drawing.add(String(bar_x + bar_width + 3 * mm, y + 1.1 * mm, str(value), fontName="Helvetica-Bold", fontSize=8, fillColor=colour))

    return drawing


def _severity_legend(styles):
    rows = [
        [
            Paragraph(
                "<font color='%s'><b>HIGH</b></font>"
                % HIGH.hexval(),
                styles["body_bold"],
            ),
            Paragraph(
                "Issues that pose an immediate, significant risk "
                "to confidentiality, integrity, or availability. "
                "Remediate as a priority.",
                styles["body"],
            ),
        ],
        [
            Paragraph(
                "<font color='%s'><b>MEDIUM</b></font>"
                % MEDIUM.hexval(),
                styles["body_bold"],
            ),
            Paragraph(
                "Issues that weaken the security posture and should "
                "be scheduled for remediation in the near term.",
                styles["body"],
            ),
        ],
        [
            Paragraph(
                "<font color='%s'><b>LOW</b></font>"
                % LOW.hexval(),
                styles["body_bold"],
            ),
            Paragraph(
                "Minor issues or hardening opportunities with "
                "limited standalone impact.",
                styles["body"],
            ),
        ],
    ]

    table = Table(
        rows,
        colWidths=[
            28 * mm,
            146 * mm,
        ],
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.6,
                BORDER_STRONG,
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                1,
                BORDER_STRONG,
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE",
            ),
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                LIGHT,
            ),
            (
                "BACKGROUND",
                (1, 0),
                (1, -1),
                WHITE,
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8,
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                8,
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
        ])
    )

    return table


def _scan_breakdown_table(report, styles):
    scan, platform = _report_counts(report)

    rows = [
        [
            Paragraph(
                "Assessment Source",
                styles["table_header"],
            ),
            Paragraph(
                "High",
                styles["table_header_center"],
            ),
            Paragraph(
                "Medium",
                styles["table_header_center"],
            ),
            Paragraph(
                "Low",
                styles["table_header_center"],
            ),
            Paragraph(
                "Total",
                styles["table_header_center"],
            ),
        ],
        [
            Paragraph(
                "Start Scan",
                styles["body"],
            ),
            scan.get("High", 0),
            scan.get("Medium", 0),
            scan.get("Low", 0),
            scan.get("Total", 0),
        ],
        [
            Paragraph(
                "Platform Observations",
                styles["body"],
            ),
            platform.get("High", 0),
            platform.get("Medium", 0),
            platform.get("Low", 0),
            platform.get("Total", 0),
        ],
    ]

    table = Table(
        rows,
        colWidths=[
            70 * mm,
            26 * mm,
            26 * mm,
            26 * mm,
            26 * mm,
        ],
        repeatRows=1,
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                NAVY_3,
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                WHITE,
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    WHITE,
                    LIGHT,
                ],
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.6,
                BORDER_STRONG,
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                1,
                BORDER_STRONG,
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE",
            ),
            (
                "ALIGN",
                (1, 1),
                (-1, -1),
                "CENTER",
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8,
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                8,
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
        ])
    )

    return table


def _assessment_information_table(report, styles):
    """Show reproducibility details when the scanner supplies them."""
    rows = [[
        Paragraph("Assessment Detail", styles["table_header"]),
        Paragraph("Recorded Value", styles["table_header"]),
    ]]

    details = [
        ("Target", report.get("url")),
        ("Assessment type", _assessment_type(report)),
        ("Generated", _friendly_date(report)),
        ("WebSET version", report.get("webset_version") or report.get("app_version")),
        ("Scanner / ruleset", report.get("scanner_version") or report.get("ruleset_version")),
        ("Build / Git commit", report.get("git_commit") or report.get("build_id")),
        ("Authentication", report.get("authentication") or report.get("auth_context")),
        ("Environment", report.get("environment")),
        ("Scope", report.get("scope") or "Target URL and discovered application routes"),
    ]

    for label, value in details:
        if value in (None, "", []):
            continue
        rows.append([
            Paragraph(f"<b>{_html(label)}</b>", styles["body"]),
            Paragraph(_display_value(value, label), styles["body"]),
        ])

    table = Table(rows, colWidths=[44 * mm, 130 * mm], repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY_3),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.6, BORDER_STRONG),
        ("BOX", (0, 0), (-1, -1), 1, BORDER_STRONG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _remediation_roadmap(report, styles):
    """Create an actionable, prioritised plan rather than repeating prose."""
    security = report.get("findings") or []
    platform = report.get("stack_findings") or []
    items = [(f, "Security finding") for f in security] + [(f, "Platform observation") for f in platform]

    if not items:
        return Paragraph("No remediation recommendations were required.", styles["body"])

    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    items.sort(key=lambda item: severity_order.get(str(item[0].get("severity") or "Low").title(), 3))

    rows = [[
        Paragraph("Priority", styles["table_header_center"]),
        Paragraph("Finding", styles["table_header"]),
        Paragraph("Recommended action", styles["table_header"]),
        Paragraph("Target", styles["table_header_center"]),
    ]]
    priority_rows = []

    for finding, item_type in items:
        severity = str(finding.get("severity") or "Low").title()
        priority = {"High": "P1", "Medium": "P2", "Low": "P3"}.get(severity, "P3")
        target = {"High": "Now", "Medium": "Within 30 days", "Low": "Within 90 days"}.get(severity, "Within 90 days")
        name = finding.get("vulnerability") or finding.get("name") or "Finding"
        action = finding.get("remediation") or "Review, validate and assign an owner."
        display_name = f"Platform: {name}" if item_type == "Platform observation" else name
        row_number = len(rows)
        row_bg = {"High": P1_BG, "Medium": P2_BG, "Low": P3_BG}.get(severity, P3_BG)
        priority_colour = {"High": HIGH, "Medium": MEDIUM, "Low": LOW}.get(severity, LOW)
        rows.append([
            Paragraph(
                f"<font color='{WHITE.hexval()}'><b>{priority}</b><br/>"
                f"<font size='7'>{_html(severity)}</font></font>",
                styles["center"],
            ),
            Paragraph(_html(display_name), styles["roadmap"]),
            Paragraph(_html(action), styles["roadmap"]),
            Paragraph(_html(target), styles["center"]),
        ])
        priority_rows.append((row_number, row_bg, priority_colour))

    table = Table(
        rows,
        colWidths=[18 * mm, 47 * mm, 88 * mm, 21 * mm],
        repeatRows=1,
        splitByRow=1,
        splitInRow=1,
        hAlign="LEFT",
    )
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY_3),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_STRONG),
        ("BOX", (0, 0), (-1, -1), 1, BORDER_STRONG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]

    for row_number, row_bg, priority_colour in priority_rows:
        commands.append(("BACKGROUND", (0, row_number), (-1, row_number), row_bg))
        commands.append(("BACKGROUND", (0, row_number), (0, row_number), priority_colour))

    table.setStyle(TableStyle(commands))
    return table


def _tech_stack_table(report, styles):
    stacks = report.get("tech_stacks") or []

    if not stacks:
        return Paragraph(
            "No technology-stack information was recorded "
            "for this assessment.",
            styles["body"],
        )

    rows = [[
        Paragraph(
            "Technology",
            styles["table_header"],
        ),
        Paragraph(
            "Category",
            styles["table_header"],
        ),
        Paragraph(
            "Version",
            styles["table_header"],
        ),
        Paragraph(
            "Description",
            styles["table_header"],
        ),
    ]]

    for stack in stacks:
        rows.append([
            Paragraph(
                _html(
                    stack.get("name")
                ),
                styles["body"],
            ),
            Paragraph(
                _html(
                    stack.get("category")
                ),
                styles["body"],
            ),
            Paragraph(
                _html(
                    stack.get("version")
                ),
                styles["body"],
            ),
            Paragraph(
                _html(
                    stack.get("description")
                ),
                styles["body"],
            ),
        ])

    table = Table(
        rows,
        colWidths=[
            32 * mm,
            32 * mm,
            24 * mm,
            86 * mm,
        ],
        repeatRows=1,
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                NAVY_3,
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                WHITE,
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    WHITE,
                    LIGHT,
                ],
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.6,
                BORDER_STRONG,
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                1,
                BORDER_STRONG,
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP",
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
        ])
    )

    return table


def _standards_table(report, styles):
    mappings = [
        (
            "CWE",
            report.get("cwe_summary") or {},
        ),
        (
            "OWASP",
            report.get("owasp_summary") or {},
        ),
        (
            "NIST",
            report.get("nist_summary") or {},
        ),
        (
            "SANS",
            report.get("sans_summary") or {},
        ),
    ]

    rows = []

    for category, values in mappings:
        if not values:
            continue

        text = ", ".join(
            f"{key} ({count})"
            for key, count in values.items()
        )

        rows.append([
            Paragraph(
                category,
                styles["table_header"],
            ),
            Paragraph(
                _html(text),
                styles["body"],
            ),
        ])

    if not rows:
        return Paragraph(
            "No security-standard mappings were available.",
            styles["body"],
        )

    header_row = [
        Paragraph(
            "Standard",
            styles["table_header"],
        ),
        Paragraph(
            "Findings Mapped",
            styles["table_header"],
        ),
    ]
    rows.insert(0, header_row)

    table = Table(
        rows,
        colWidths=[
            31 * mm,
            143 * mm,
        ],
        repeatRows=1,
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                NAVY_3,
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                WHITE,
            ),
            (
                "BACKGROUND",
                (0, 1),
                (0, -1),
                NAVY_3,
            ),
            (
                "BACKGROUND",
                (1, 1),
                (1, -1),
                WHITE,
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.6,
                BORDER_STRONG,
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                1,
                BORDER_STRONG,
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP",
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8,
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                8,
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
        ])
    )

    return table


def _finding_elements(index, finding, styles):
    severity = str(
        finding.get("severity") or "Low"
    ).title()

    if severity == "High":
        sev_fg = HIGH

    elif severity == "Medium":
        sev_fg = MEDIUM

    else:
        sev_fg = LOW

    vulnerability = (
        finding.get("vulnerability")
        or finding.get("name")
        or "Finding"
    )

    standards = []

    cwe = (
        finding.get("cwe_id")
        or finding.get("cweId")
    )

    wasc = (
        finding.get("wasc_id")
        or finding.get("wascId")
    )

    owasp = finding.get("owasp")

    nist = (
        finding.get("nist")
        or finding.get("nist_id")
    )

    sans = (
        finding.get("sans")
        or finding.get("sans_id")
    )

    if cwe:
        standards.append(
            str(cwe)
        )

    if wasc:
        standards.append(
            str(wasc)
        )

    if owasp:
        standards.append(
            f"OWASP {owasp}"
        )

    if nist:
        standards.append(
            str(nist)
        )

    if sans:
        standards.append(
            str(sans)
        )

    details = [
        (
            "Origin",
            finding.get("scan_origin"),
        ),
        (
            "Location",
            finding.get("location")
            or finding.get("url"),
        ),
        (
            "HTTP Method",
            finding.get("http_method") or finding.get("method"),
        ),
        (
            "Parameter",
            finding.get("parameter") or finding.get("parameter_name"),
        ),
        (
            "Payload",
            finding.get("payload") or finding.get("test_payload"),
        ),
        (
            "HTTP Status",
            finding.get("http_status") or finding.get("status_code"),
        ),
        (
            "Evidence",
            finding.get("evidence") or finding.get("response_evidence"),
        ),
        (
            "Authentication",
            finding.get("authentication") or finding.get("auth_context"),
        ),
        (
            "Detected At",
            finding.get("detected_at") or finding.get("timestamp"),
        ),
        (
            "Description",
            finding.get("description"),
        ),
        (
            "Remediation",
            finding.get("remediation"),
        ),
        (
            "Standards",
            (
                " | ".join(standards)
                if standards
                else None
            ),
        ),
        (
            "Plugin ID",
            finding.get("plugin_id"),
        ),
        (
            "Message ID",
            finding.get("message_id"),
        ),
    ]
        

    rows = [[
        Paragraph(
            f"{index}. {_html(vulnerability)}",
            styles["finding_title"],
        ),
        "",
        Paragraph(
            f"<font color='{WHITE.hexval()}'><b>{_html(severity).upper()}</b></font>",
            styles["center"],
        ),
    ]]
    evidence_rows = []

    for label, value in details:
        if value in (
            None,
            "",
            [],
        ):
            continue

        value_style = styles["url"] if label in ("Location", "Affected endpoints") else styles["body"]

        row_number = len(rows)
        rows.append([
            Paragraph(
                label,
                styles["detail_label"],
            ),
            Paragraph(
                _display_value(value, label),
                value_style,
            ),
            "",
        ])

        if label == "Evidence":
            evidence_rows.append(row_number)

    title_text = f"{index}. {vulnerability}"
    body = _FindingTable(
        rows,
        colWidths=[
            32 * mm,
            114 * mm,
            28 * mm,
        ],
        repeatRows=1,
        splitByRow=1,
        splitInRow=1,
        hAlign="LEFT",
        continuation_title=title_text,
        continuation_style=styles["finding_title"],
    )

    commands = [
            ("SPAN", (0, 0), (1, 0)),
            ("BACKGROUND", (0, 0), (1, 0), NAVY_3),
            ("BACKGROUND", (2, 0), (2, 0), sev_fg),
            (
                "BACKGROUND",
                (0, 1),
                (0, -1),
                NAVY_3,
            ),
            (
                "BACKGROUND",
                (1, 1),
                (2, -1),
                WHITE,
            ),
            (
                "LINEBELOW",
                (0, 0),
                (-1, -2),
                0.5,
                BORDER,
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                1.0,
                NAVY_3,
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP",
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                9,
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                9,
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                8,
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                8,
            ),
        ]

    for row_number in range(1, len(rows)):
        commands.append(("SPAN", (1, row_number), (2, row_number)))

    body.setStyle(TableStyle(commands))

    return [
        CondPageBreak(62 * mm),
        body,
        Spacer(
            1,
            FINDING_GAP,
        ),
    ]


def _end_story(report, styles):
    scan_summary, platform_summary = _report_counts(report)

    risk, risk_color = _overall_risk(
        report
    )

    security_total = scan_summary["Total"]
    platform_total = platform_summary["Total"]

    report_id = _make_report_id(
        report
    )

    story = [
        Spacer(
            1,
            18 * mm,
        ),

        Paragraph(
            "END OF REPORT",
            ParagraphStyle(
                "EndTitle",
                parent=styles["cover_title"],
                textColor=WHITE,
                fontSize=27,
                leading=31,
            ),
        ),

        Spacer(
            1,
            6 * mm,
        ),

        Paragraph(
            "WebSET Security Assessment",
            ParagraphStyle(
                "EndSubtitle",
                parent=styles["cover_subtitle"],
                textColor=colors.HexColor("#C7E7E4"),
                fontSize=13,
                leading=17,
            ),
        ),

        Paragraph(
            "Automated Vulnerability, Technology &amp;<br/>"
            "Security Standards Evaluation",
            ParagraphStyle(
                "EndSub2",
                parent=styles["cover_subtitle"],
                textColor=WHITE,
                fontSize=10.5,
                leading=15,
            ),
        ),

        Spacer(
            1,
            16 * mm,
        ),
    ]

    story.append(
        _risk_badge_row(
            risk,
            risk_color,
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            38 * mm,
        )
    )

    label_style = ParagraphStyle(
        "EndInfoLabel",
        parent=styles["body"],
        fontName="Helvetica-Bold",
        fontSize=9,
        textColor=WHITE,
    )

    value_style = styles["body"]

    info = [
        [
            Paragraph(
                "Target",
                label_style,
            ),
            Paragraph(
                _html(
                    report.get("url")
                ),
                value_style,
            ),
        ],
        [
            Paragraph(
                "Report ID",
                label_style,
            ),
            Paragraph(
                _html(report_id),
                value_style,
            ),
        ],
        [
            Paragraph(
                "Assessment Type",
                label_style,
            ),
            Paragraph(
                _html(
                    _assessment_type(report)
                ),
                value_style,
            ),
        ],
        [
            Paragraph(
                "Final Risk Rating",
                label_style,
            ),
            Paragraph(
                f"<font color='{risk_color.hexval()}'>"
                f"<b>{_html(risk)}</b>"
                f"</font>",
                styles["body_bold"],
            ),
        ],
        [
            Paragraph(
                "Security Findings",
                label_style,
            ),
            Paragraph(
                str(security_total),
                value_style,
            ),
        ],
        [
            Paragraph(
                "Platform Observations",
                label_style,
            ),
            Paragraph(
                str(platform_total),
                value_style,
            ),
        ],
        [
            Paragraph(
                "Classification",
                label_style,
            ),
            Paragraph(
                "Confidential",
                value_style,
            ),
        ],
    ]

    table = Table(
        info,
        colWidths=[
            45 * mm,
            105 * mm,
        ],
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle([
            (
                "BOX",
                (0, 0),
                (-1, -1),
                1.2,
                TEAL,
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.6,
                BORDER_STRONG,
            ),
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                NAVY_3,
            ),
            (
                "BACKGROUND",
                (1, 0),
                (1, -1),
                WHITE,
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8,
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                8,
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP",
            ),
        ])
    )

    story.append(table)

    story.append(
        Spacer(
            1,
            14 * mm,
        )
    )

    story.append(
        Paragraph(
            "<b>Generated by WebSET</b><br/>"
            "Website Security Evaluation Tool",
            ParagraphStyle(
                "EndGenerated",
                parent=styles["center"],
                alignment=TA_CENTER,
                textColor=NAVY_3,
                fontSize=10,
                leading=14,
            ),
        )
    )

    story.append(
        Spacer(
            1,
            7 * mm,
        )
    )

    story.append(
        Paragraph(
            "Identify vulnerabilities. Understand exposure. "
            "Prioritise remediation. Strengthen security.",
            ParagraphStyle(
                "ClosingStatement",
                parent=styles["center"],
                alignment=TA_CENTER,
                textColor=TEAL,
                fontName="Helvetica-Bold",
                fontSize=9,
                leading=13,
            ),
        )
    )

    story.append(
        Spacer(
            1,
            12 * mm,
        )
    )

    story.append(
        HRFlowable(
            width="55%",
            thickness=0.8,
            color=BORDER,
            hAlign="CENTER",
            spaceAfter=6,
        )
    )

    story.append(
        Paragraph(
            "This report is confidential, intended solely for the recipient "
            "organisation, and limited to authorised security testing.",
            ParagraphStyle(
                "EndFooterNote",
                parent=styles["small"],
                alignment=TA_CENTER,
                textColor=MUTED,
                fontSize=7.6,
                leading=11,
            ),
        )
    )

    return story


class _ReportDocTemplate(BaseDocTemplate):

    def afterFlowable(
        self,
        flowable,
    ):
        if not isinstance(
            flowable,
            Paragraph,
        ):
            return

        style_name = flowable.style.name
        text = flowable.getPlainText()

        if style_name == "Heading1TOC":
            self.canv.bookmarkPage(
                text
            )

            self.canv.addOutlineEntry(
                text,
                text,
                level=0,
                closed=False,
            )

            self.notify(
                "TOCEntry",
                (
                    0,
                    text,
                    self.page,
                ),
            )

        elif style_name == "Heading2TOC":
            self.canv.bookmarkPage(
                text
            )

            self.notify(
                "TOCEntry",
                (
                    1,
                    text,
                    self.page,
                ),
            )


def export_pdf(
    url: str,
    findings: list[dict],
    output_path: str | None = None,
    report: dict | None = None,
) -> str:

    if not output_path:
        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        output_path = os.path.abspath(
            f"WebSET_Security_Assessment_{timestamp}.pdf"
        )

    if not output_path.lower().endswith(
        ".pdf"
    ):
        output_path += ".pdf"

    if report is None:
        from reporting.report_generator import generate_report

        report = generate_report(
            url=url,
            findings=findings,
        )

    styles = _styles()

    report_id = _make_report_id(
        report
    )

    doc = _ReportDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm,
        title=report.get(
            "title",
            "WebSET Security Assessment Report",
        ),
        author="WebSET",
        subject="Website Security Assessment",
        creator="WebSET Website Security Evaluation Tool",
    )

    doc._report_id = report_id

    cover_frame = Frame(
        21 * mm,
        12 * mm,
        PAGE_WIDTH - 42 * mm,
        PAGE_HEIGHT - 24 * mm,
        id="coverFrame",
        showBoundary=0,
    )

    content_frame = Frame(
        18 * mm,
        20 * mm,
        PAGE_WIDTH - 36 * mm,
        PAGE_HEIGHT - 44 * mm,
        id="contentFrame",
        showBoundary=0,
    )

    end_frame = Frame(
        21 * mm,
        12 * mm,
        PAGE_WIDTH - 42 * mm,
        PAGE_HEIGHT - 24 * mm,
        id="endFrame",
        showBoundary=0,
    )

    doc.addPageTemplates([
        PageTemplate(
            id="Cover",
            frames=[
                cover_frame
            ],
            onPage=_cover_page,
        ),

        PageTemplate(
            id="Content",
            frames=[
                content_frame
            ],
            onPage=_content_page,
        ),

        PageTemplate(
            id="End",
            frames=[
                end_frame
            ],
            onPage=_end_page,
        ),
    ])

    story = []

    story.extend(
        _cover_story(
            report,
            styles,
        )
    )

    story.append(
        NextPageTemplate(
            "Content"
        )
    )

    story.append(
        PageBreak()
    )

    story.extend(
        _toc_page(
            report,
            styles,
        )
    )

    story.append(
        PageBreak()
    )

    _add_section_heading(
        story,
        "1. Executive Summary",
        styles,
        minimum_space=45 * mm,
    )

    scan_summary, platform_summary = _report_counts(report)

    risk, risk_color = _overall_risk(
        report
    )

    security_total = scan_summary["Total"]
    platform_total = platform_summary["Total"]

    intro = (
        f"WebSET performed an automated security assessment of "
        f"<b>{_html(report.get('url'))}</b> "
        f"on {_html(_friendly_date(report))}. "
        f"The assessment combined a dynamic start scan of the live "
        f"application with a platform/technology evaluation, mapping "
        f"identified issues to industry-standard classification "
        f"frameworks where mappings were available. "
        f"The Start Scan identified "
        f"<b>{_count_phrase(security_total, 'security finding')}</b>, "
        f"while the separate platform evaluation recorded "
        f"<b>{_count_phrase(platform_total, 'platform observation')}</b>. "
        f"The security findings "
        f"resulted "
        f"in an overall risk rating of "
        f"<font color='{risk_color.hexval()}'>"
        f"<b>{_html(risk)}</b>"
        f"</font>."
    )

    story.append(
        Paragraph(
            intro,
            styles["body"],
        )
    )

    story.append(
        Paragraph(
            "<b>Risk-rating basis:</b> The overall rating is calculated "
            "from Start Scan security findings only. Platform observations "
            "are reported separately and do not raise the overall rating "
            "unless independently validated as vulnerabilities.",
            styles["italic_small"],
        )
    )

    executive = str(
        report.get("executive_summary")
        or "-"
    )

    for line in executive.splitlines():
        line = _polish_executive_line(line.strip())

        if not line:
            continue

        if line.startswith("\u2022"):
            story.append(
                Paragraph(
                    f"&bull; {_html(line[1:].strip())}",
                    styles["body"],
                )
            )

        else:
            story.append(
                Paragraph(
                    _html(line),
                    styles["body"],
                )
            )

    story.append(
        Spacer(
            1,
            SECTION_GAP,
        )
    )

    _add_subsection_heading(
        story,
        "1.1 Severity Rating Definitions",
        styles,
        minimum_space=42 * mm,
    )

    story.append(
        _severity_legend(
            styles
        )
    )

    story.append(
        Spacer(
            1,
            TABLE_GAP,
        )
    )

    _add_subsection_heading(
        story,
        "1.2 Scope &amp; Methodology",
        styles,
        minimum_space=40 * mm,
    )

    story.append(
        Paragraph(
            "This assessment was performed using automated, "
            "non-intrusive techniques against the reachable surface of "
            "the configured target application. Two evaluation passes "
            "were run: a <b>Start Scan</b>, which probes live HTTP "
            "responses, headers and session handling for common "
            "web-application weaknesses, and a "
            "<b>Platform Evaluation</b>, which fingerprints the "
            "underlying technology stack for outdated or misconfigured "
            "components. Findings were cross-referenced against CWE, "
            "WASC, OWASP, NIST SP 800-53 and SANS reference material "
            "where a mapping was available.",
            styles["body"],
        )
    )

    target_url = str(report.get("url") or "").lower()
    if "127.0.0.1" in target_url or "localhost" in target_url:
        story.append(
            Paragraph(
                "<b>Local-lab context:</b> Transport and deployment findings "
                "may reflect the authorised training configuration. Reassess "
                "their severity before applying these results to production.",
                styles["italic_small"],
            )
        )

    _add_subsection_heading(
        story,
        "1.3 Assessment Information",
        styles,
        minimum_space=45 * mm,
    )

    story.append(_assessment_information_table(report, styles))

    story.append(
        Spacer(
            1,
            2 * mm,
        )
    )

    story.append(
        Paragraph(
            "This report reflects the security posture of the target "
            "at the time of assessment only and is not exhaustive; "
            "it does not replace a manual penetration test or code "
            "review. Findings should be independently validated prior "
            "to remediation planning.",
            styles["italic_small"],
        )
    )

    story.append(
        PageBreak()
    )

    _add_section_heading(
        story,
        "2. Risk Overview",
        styles,
        minimum_space=55 * mm,
    )

    story.append(
        _risk_summary_table(
            scan_summary,
            styles,
        )
    )

    story.append(Spacer(1, 4 * mm))
    story.append(_severity_chart(scan_summary))

    story.append(
        Paragraph(
            "Risk cards represent Start Scan security findings only; "
            f"{_count_phrase(platform_total, 'platform observation')} "
            "listed separately.",
            styles["italic_small"],
        )
    )

    story.append(
        Spacer(
            1,
            TABLE_GAP,
        )
    )

    _add_subsection_heading(
        story,
        "2.1 Assessment Breakdown",
        styles,
        minimum_space=38 * mm,
    )

    story.append(
        _scan_breakdown_table(
            report,
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            TABLE_GAP + 2 * mm,
        )
    )

    _add_subsection_heading(
        story,
        "2.2 Detected Technology Stack",
        styles,
        minimum_space=38 * mm,
    )

    story.append(
        _tech_stack_table(
            report,
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            TABLE_GAP + 2 * mm,
        )
    )

    _add_subsection_heading(
        story,
        "2.3 Security Standards Mapping",
        styles,
        minimum_space=40 * mm,
    )

    story.append(
        _standards_table(
            report,
            styles,
        )
    )

    story.append(
        PageBreak()
    )

    scan_findings = (
        report.get("findings")
        or []
    )

    _add_section_heading(
        story,
        "3. Security Findings \u2014 Start Scan",
        styles,
        minimum_space=65 * mm,
    )

    if scan_findings:
        for index, finding in enumerate(
            scan_findings,
            start=1,
        ):
            story.extend(
                _finding_elements(
                    index,
                    finding,
                    styles,
                )
            )

    else:
        story.append(
            Paragraph(
                "No Start Scan vulnerabilities were detected.",
                styles["body"],
            )
        )

    story.append(
        Spacer(
            1,
            SECTION_GAP,
        )
    )

    platform_findings = (
        report.get("stack_findings")
        or []
    )

    _add_section_heading(
        story,
        "4. Platform Observations",
        styles,
        minimum_space=55 * mm,
    )

    if platform_findings:
        for index, finding in enumerate(
            platform_findings,
            start=1,
        ):
            story.extend(
                _finding_elements(
                    index,
                    finding,
                    styles,
                )
            )

    else:
        story.append(
            Paragraph(
                "No platform observations were recorded.",
                styles["body"],
            )
        )

    story.append(
        PageBreak()
    )

    _add_section_heading(
        story,
        "5. Prioritised Remediation Roadmap",
        styles,
        minimum_space=50 * mm,
    )

    story.append(
        Paragraph(
            "Target timeframes are guidance for triage. Confirm validity, "
            "business impact, ownership and implementation effort before "
            "committing remediation dates.",
            styles["italic_small"],
        )
    )
    story.append(_remediation_roadmap(report, styles))

    story.append(
        Spacer(
            1,
            SECTION_GAP,
        )
    )

    _add_section_heading(
        story,
        "6. Confidentiality &amp; Disclaimer",
        styles,
        minimum_space=45 * mm,
    )

    story.append(
        Paragraph(
            "This report and its contents are classified "
            "<b>Confidential</b> and are intended solely for the "
            "recipient organisation. It may contain information about "
            "security weaknesses in the assessed system and must not "
            "be distributed outside the intended audience without "
            "authorisation.",
            styles["body"],
        )
    )

    story.append(
        Spacer(
            1,
            2 * mm,
        )
    )

    story.append(
        Paragraph(
            "WebSET performs automated testing and, while effort is "
            "made to minimise false positives, results should be "
            "validated by qualified personnel before remediation or "
            "disclosure decisions are made. WebSET and its operators "
            "accept no liability for actions taken, or not taken, on "
            "the basis of this report.",
            styles["body"],
        )
    )

    story.append(
        NextPageTemplate(
            "End"
        )
    )

    story.append(
        PageBreak()
    )

    story.extend(
        _end_story(
            report,
            styles,
        )
    )

    doc.multiBuild(
        story,
        canvasmaker=_NumberedCanvas,
    )

    return os.path.abspath(
        output_path
    )
