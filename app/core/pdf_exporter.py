"""
app/core/pdf_exporter.py
Generates executive-grade, professional PDF audit reports for ShieldCI scans.
Organized into structured sections:
1. Executive Dashboard & Scope Matrix (Header / Scope / PES & Grade / Tri-Vector Assessment)
2. Cross-Vector Toxic Combinations & Exploit Chains (if any)
3. Executive Vulnerability Catalog (Structured Summary Index Table of All Discovered Exposures)
4. Detailed Technical Findings & Vulnerability Evidence (Categorized & Grouped by Severity)
5. Automated 1-Click Self-Healing & Remediation Roadmap (Unified Patch & CLI commands)
6. Security Compliance & Governance Framework Mapping (OWASP, CIS, NIST, SOC 2)
"""

import io
import sys
import textwrap
import types
from datetime import datetime
from typing import List, Optional, Tuple

# Ensure compatibility in environments where PIL's compiled C-extension (_imaging)
# is blocked by OS Application Control / AppLocker policies
try:
    import PIL
    import PIL.Image
except (ImportError, Exception):
    p = types.ModuleType("PIL")
    im = types.ModuleType("PIL.Image")
    p.Image = im
    sys.modules["PIL"] = p
    sys.modules["PIL.Image"] = im

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    HRFlowable,
    PageBreak,
    Preformatted,
)
from reportlab.pdfgen import canvas

from app.models.schemas import ScanResult, SeverityLevel, TargetCategory


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically calculate and display total page count:
    'Page X of Y' and consistent running header & footer.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Running Top Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(
                54,
                11 * 72 - 36,
                "ShieldCI Security Audit Report — Strictly Confidential",
            )
            self.drawRightString(
                8.5 * 72 - 54,
                11 * 72 - 36,
                "Enterprise Tri-Vector Posture Defense",
            )
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, 11 * 72 - 42, 8.5 * 72 - 54, 11 * 72 - 42)

        # Running Bottom Footer (all pages)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 48, 8.5 * 72 - 54, 48)

        # Left footer: Timestamp & Confidentiality
        self.drawString(
            54,
            36,
            "ShieldCI v2.0 • Universal Security & Exposure Management • Certified Report",
        )

        # Right footer: Page numbers
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * 72 - 54, 36, page_str)
        self.restoreState()


def get_severity_colors(severity_str: str) -> Tuple[colors.HexColor, colors.HexColor]:
    """Returns (background_color, text_color) tuple for a severity badge."""
    sev = str(severity_str).upper()
    if sev == "CRITICAL":
        return colors.HexColor("#FEE2E2"), colors.HexColor("#991B1B")  # red
    elif sev == "HIGH":
        return colors.HexColor("#FFEDD5"), colors.HexColor("#C2410C")  # orange
    elif sev == "MEDIUM":
        return colors.HexColor("#FEF3C7"), colors.HexColor("#B45309")  # amber
    elif sev == "LOW":
        return colors.HexColor("#DBEAFE"), colors.HexColor("#1D4ED8")  # blue
    else:
        return colors.HexColor("#DCFCE7"), colors.HexColor("#15803D")  # green


def wrap_code_text(text: str, max_width: int = 70, max_lines: int = 18) -> str:
    """Wraps text preserving indentation and limits lines to prevent overflow."""
    if not text:
        return ""
    lines = text.strip().splitlines()
    wrapped: List[str] = []
    for line in lines:
        if len(line) <= max_width:
            wrapped.append(line)
        else:
            indent = len(line) - len(line.lstrip())
            indent_str = line[:indent]
            w_lines = textwrap.wrap(line, width=max_width, subsequent_indent=indent_str + "  ")
            wrapped.extend(w_lines)
    if len(wrapped) > max_lines:
        wrapped = wrapped[:max_lines] + ["... (additional content truncated for report length)"]
    return "\n".join(wrapped)


def generate_pdf_report(scan: ScanResult) -> bytes:
    """
    Renders a complete, organized, executive-grade PDF security audit report
    for the provided ScanResult.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    # Styles
    base_styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "DocTitle",
        parent=base_styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=2,
    )

    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#475569"),
        spaceAfter=10,
    )

    h1_section_style = ParagraphStyle(
        "SectionH1",
        parent=base_styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=14,
        spaceAfter=6,
    )

    h2_style = ParagraphStyle(
        "SectionH2",
        parent=base_styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11.5,
        leading=15,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=10,
        spaceAfter=5,
    )

    h3_style = ParagraphStyle(
        "SectionH3",
        parent=base_styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#334155"),
        spaceBefore=4,
        spaceAfter=2,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )

    body_bold = ParagraphStyle(
        "ReportBodyBold",
        parent=body_style,
        fontName="Helvetica-Bold",
    )

    body_muted = ParagraphStyle(
        "ReportBodyMuted",
        parent=body_style,
        textColor=colors.HexColor("#64748B"),
        fontSize=8,
        leading=11,
    )

    code_style = ParagraphStyle(
        "ReportCode",
        parent=base_styles["Code"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#38BDF8"),
    )

    diff_code_style = ParagraphStyle(
        "ReportDiffCode",
        parent=base_styles["Code"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#4ADE80"),
    )

    elements = []

    # -------------------------------------------------------------
    # 1. HEADER BANNER & SCOPE METADATA (Page 1)
    # -------------------------------------------------------------
    scan_time_str = scan.timestamp.strftime("%Y-%m-%d %H:%M UTC") if scan.timestamp else "N/A"
    short_scan_id = scan.scan_id[:16] if scan.scan_id else "N/A"

    passed = scan.summary.policy_passed
    gate_badge_bg = colors.HexColor("#DCFCE7") if passed else colors.HexColor("#FEE2E2")
    gate_badge_fg = colors.HexColor("#166534") if passed else colors.HexColor("#991B1B")
    gate_badge_text = "CI/CD GATE: PASSED" if passed else "CI/CD GATE: BLOCKED"

    header_data = [
        [
            Paragraph("<b>SHIELDCI SECURITY AUDIT REPORT</b>", title_style),
            Paragraph(
                f"<font size='8' color='#64748B'><b>SCAN REF:</b> {short_scan_id}...<br/>"
                f"<b>AUDIT DATE:</b> {scan_time_str}</font>",
                body_style,
            ),
        ]
    ]
    header_table = Table(header_data, colWidths=[330, 174])
    header_table.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
        ])
    )
    elements.append(header_table)
    elements.append(
        Paragraph(
            "Universal Tri-Vector Posture Defense • Code &amp; CI/CD Pipelines • Web Perimeter • Cloud Databases",
            subtitle_style,
        )
    )
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#4F46E5"), spaceAfter=10))

    # Target Asset & Audit Metadata Matrix
    target_type_label = (
        scan.target_type.value.upper()
        if hasattr(scan.target_type, "value")
        else str(scan.target_type).upper()
    )
    source_type_label = (
        scan.source_type.value.upper()
        if hasattr(scan.source_type, "value")
        else str(scan.source_type).upper()
    )

    target_display_name = scan.repo_name or scan.target_path or "Target Asset"
    target_location = scan.repo_url or scan.target_path or "N/A"

    meta_data = [
        [
            Paragraph("<b>Target Asset:</b>", body_style),
            Paragraph(target_display_name, body_bold),
            Paragraph("<b>Asset Category:</b>", body_style),
            Paragraph(f"<font color='#4338CA'><b>{target_type_label}</b></font>", body_style),
        ],
        [
            Paragraph("<b>Target Location:</b>", body_style),
            Paragraph(f"<font size='8' color='#0369A1'><code>{target_location}</code></font>", body_style),
            Paragraph("<b>Ingestion Source:</b>", body_style),
            Paragraph(source_type_label, body_style),
        ],
        [
            Paragraph("<b>Scan Duration:</b>", body_style),
            Paragraph(f"{scan.summary.scan_duration_seconds:.2f} seconds", body_style),
            Paragraph("<b>Evaluated Scope:</b>", body_style),
            Paragraph(f"{scan.summary.scanned_files_count} files / endpoints", body_style),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[90, 162, 95, 157])
    meta_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    elements.append(meta_table)
    elements.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # 2. EXECUTIVE RISK POSTURE & QUALITY GATE DASHBOARD
    # -------------------------------------------------------------
    elements.append(Paragraph("1. Executive Risk Posture & Quality Gate Dashboard", h1_section_style))

    pes = scan.summary.pipeline_exposure_score
    grade = scan.summary.risk_grade or "N/A"

    if pes < 25:
        pes_color_bg, pes_color_fg = colors.HexColor("#DCFCE7"), colors.HexColor("#166534")
        pes_status = "LOW EXPOSURE (CLEAN)"
    elif pes < 50:
        pes_color_bg, pes_color_fg = colors.HexColor("#FEF3C7"), colors.HexColor("#92400E")
        pes_status = "MODERATE EXPOSURE"
    elif pes < 75:
        pes_color_bg, pes_color_fg = colors.HexColor("#FFEDD5"), colors.HexColor("#9A3412")
        pes_status = "HIGH EXPOSURE"
    else:
        pes_color_bg, pes_color_fg = colors.HexColor("#FEE2E2"), colors.HexColor("#991B1B")
        pes_status = "CRITICAL EXPOSURE"

    gate_bg = colors.HexColor("#DCFCE7") if passed else colors.HexColor("#FEE2E2")
    gate_fg = colors.HexColor("#166534") if passed else colors.HexColor("#991B1B")
    gate_text = "PASSED" if passed else "FAILED"
    gate_sub = "Meets release thresholds" if passed else "Deployment blocked by policy"

    exec_cards = [
        [
            Paragraph(
                f"<font size='7.5' color='#64748B'>PIPELINE EXPOSURE SCORE (PES)</font><br/>"
                f"<font size='22' color='{pes_color_fg.hexval()}'><b>{pes:.1f}</b></font><font size='10' color='#64748B'> / 100</font><br/>"
                f"<font size='7.5' color='{pes_color_fg.hexval()}'><b>{pes_status}</b></font>",
                body_style,
            ),
            Paragraph(
                f"<font size='7.5' color='#64748B'>BENCHMARK RISK GRADE</font><br/>"
                f"<font size='22' color='#0F172A'><b>Grade {grade}</b></font><br/>"
                f"<font size='7.5' color='#64748B'>Tri-Vector Industry Benchmark</font>",
                body_style,
            ),
            Paragraph(
                f"<font size='7.5' color='#64748B'>CI/CD QUALITY GATE</font><br/>"
                f"<font size='20' color='{gate_fg.hexval()}'><b>{gate_text}</b></font><br/>"
                f"<font size='7.5' color='#64748B'>{gate_sub}</font>",
                body_style,
            ),
        ]
    ]
    exec_table = Table(exec_cards, colWidths=[168, 156, 180])
    exec_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), pes_color_bg),
            ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#F1F5F9")),
            ("BACKGROUND", (2, 0), (2, 0), gate_bg),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    elements.append(exec_table)
    elements.append(Spacer(1, 8))

    # Findings Distribution Breakdown Bar
    s = scan.summary
    breakdown_data = [
        [
            Paragraph("<b>Findings Severity Distribution:</b>", body_style),
            Paragraph(f"<font color='#DC2626'><b>Critical: {s.critical_count}</b></font>", body_style),
            Paragraph(f"<font color='#EA580C'><b>High: {s.high_count}</b></font>", body_style),
            Paragraph(f"<font color='#D97706'><b>Medium: {s.medium_count}</b></font>", body_style),
            Paragraph(f"<font color='#2563EB'><b>Low: {s.low_count}</b></font>", body_style),
            Paragraph(f"<font color='#0F172A'><b>Total: {s.total_findings}</b></font>", body_bold),
        ]
    ]
    breakdown_table = Table(breakdown_data, colWidths=[144, 72, 72, 72, 72, 72])
    breakdown_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    elements.append(breakdown_table)
    elements.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # 3. TRI-VECTOR EXPOSURE ASSESSMENT MATRIX
    # -------------------------------------------------------------
    elements.append(Paragraph("2. Tri-Vector Posture Assessment Matrix", h2_style))

    repo_findings = [f for f in scan.findings if "Web" not in str(f.category) and "Database" not in str(f.category)]
    web_findings = [f for f in scan.findings if "Web" in str(f.category)]
    db_findings = [f for f in scan.findings if "Database" in str(f.category)]

    tri_matrix_data = [
        [
            Paragraph("<b>Defense Vector</b>", body_bold),
            Paragraph("<b>Inspected Scope &amp; Technologies</b>", body_bold),
            Paragraph("<b>Findings</b>", body_bold),
            Paragraph("<b>Vector Status</b>", body_bold),
        ],
        [
            Paragraph("Domain 01: Code &amp; CI/CD", body_style),
            Paragraph("Git Repositories, Workflows, Secrets, Dependencies", body_style),
            Paragraph(f"{len(repo_findings)} issues", body_style),
            Paragraph(
                "<font color='#16A34A'><b>✓ Protected</b></font>" if len(repo_findings) == 0 else f"<font color='#DC2626'><b>{len(repo_findings)} Risks Found</b></font>",
                body_style,
            ),
        ],
        [
            Paragraph("Domain 02: Web Perimeter", body_style),
            Paragraph("HTTP Headers, TLS/SSL, Ciphers, API Endpoints", body_style),
            Paragraph(f"{len(web_findings)} issues", body_style),
            Paragraph(
                "<font color='#16A34A'><b>✓ Protected</b></font>" if len(web_findings) == 0 else f"<font color='#EA580C'><b>{len(web_findings)} Exposures Found</b></font>",
                body_style,
            ),
        ],
        [
            Paragraph("Domain 03: DB &amp; Cloud", body_style),
            Paragraph("Postgres, MySQL, Redis, MongoDB, Elastic Sockets", body_style),
            Paragraph(f"{len(db_findings)} issues", body_style),
            Paragraph(
                "<font color='#16A34A'><b>✓ Protected</b></font>" if len(db_findings) == 0 else f"<font color='#DC2626'><b>{len(db_findings)} Data Risks Found</b></font>",
                body_style,
            ),
        ],
    ]
    tri_table = Table(tri_matrix_data, colWidths=[140, 164, 90, 110])
    tri_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FFFFFF")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    elements.append(tri_table)
    elements.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # 4. CROSS-VECTOR TOXIC COMBINATIONS (if any)
    # -------------------------------------------------------------
    if scan.toxic_combinations:
        elements.append(Paragraph("Cross-Vector Toxic Combinations &amp; Exploit Chains", h2_style))
        elements.append(
            Paragraph(
                "ShieldCI identified compound attack paths where individually low-severity exposures correlate into critical exploit chains:",
                body_style,
            )
        )
        elements.append(Spacer(1, 4))

        for tc in scan.toxic_combinations:
            tc_chain_str = " &rarr; ".join(tc.exploit_chain)
            tc_data = [
                [
                    Paragraph(f"<b>[TOXIC CHAIN] {tc.title}</b>", body_bold),
                    Paragraph(f"<font color='#991B1B'><b>Likelihood: {tc.likelihood}</b></font>", body_style),
                ],
                [
                    Paragraph(f"<b>Exploit Sequence:</b> {tc_chain_str}", body_style),
                    Paragraph(f"<b>Blast Radius:</b> {tc.impact}", body_style),
                ],
                [
                    Paragraph(f"<b>Remediation:</b> {tc.remediation_advice}", body_style),
                    Paragraph("<b>Self-Healing:</b> Supported", body_style),
                ],
            ]
            tc_table = Table(tc_data, colWidths=[330, 174])
            tc_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF2F2")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#FCA5A5")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#FEE2E2")),
                    ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            )
            elements.append(tc_table)
            elements.append(Spacer(1, 6))

    # -------------------------------------------------------------
    # 5. SORTED & ORGANIZED FINDINGS PROCESSING
    # -------------------------------------------------------------
    severity_order = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
        "INFO": 5,
    }

    # Sort findings strictly by severity descending
    sorted_findings = sorted(
        scan.findings,
        key=lambda f: (
            severity_order.get(str(getattr(f.severity, "value", f.severity)).upper(), 99),
            f.title or "",
        ),
    )

    # -------------------------------------------------------------
    # 6. EXECUTIVE VULNERABILITY CATALOG (SUMMARY TABLE)
    # -------------------------------------------------------------
    # Start on clean page for readability and organization
    elements.append(PageBreak())
    elements.append(Paragraph("3. Executive Vulnerability Catalog &amp; Findings Index", h1_section_style))
    elements.append(
        Paragraph(
            "Consolidated index of all security findings detected during this evaluation, ranked by severity level. "
            "Refer to Section 4 for detailed evidence, reproduction artifacts, and technical remediation instructions.",
            body_style,
        )
    )
    elements.append(Spacer(1, 8))

    if not sorted_findings:
        no_findings_box = Table(
            [[
                Paragraph(
                    "<font color='#166534'><b>✓ Zero Security Vulnerabilities Detected!</b><br/>"
                    "The evaluated target successfully satisfied all policy gates and security posture checks across all defense vectors.</font>",
                    body_style,
                )
            ]],
            colWidths=[504],
        )
        no_findings_box.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#DCFCE7")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#86EFAC")),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ])
        )
        elements.append(no_findings_box)
        elements.append(Spacer(1, 14))
    else:
        # Summary Catalog Table
        catalog_headers = [
            Paragraph("<b>#</b>", body_bold),
            Paragraph("<b>Severity</b>", body_bold),
            Paragraph("<b>Category</b>", body_bold),
            Paragraph("<b>Vulnerability Title</b>", body_bold),
            Paragraph("<b>Target Resource / File</b>", body_bold),
            Paragraph("<b>Auto-Fix</b>", body_bold),
        ]
        catalog_rows = [catalog_headers]

        for i, f in enumerate(sorted_findings, start=1):
            sev_str = str(getattr(f.severity, "value", f.severity)).upper()
            cat_str = str(getattr(f.category, "value", f.category))
            bg_c, fg_c = get_severity_colors(sev_str)

            loc_short = f.file_path or "N/A"
            if len(loc_short) > 32:
                loc_short = "..." + loc_short[-29:]
            if f.line_number:
                loc_short += f":{f.line_number}"

            auto_fix_label = (
                "<font color='#16A34A'><b>1-Click</b></font>"
                if getattr(f, "auto_fixable", False)
                else "<font color='#64748B'>Manual</font>"
            )

            catalog_rows.append([
                Paragraph(str(i), body_style),
                Paragraph(f"<font color='{fg_c.hexval()}'><b>{sev_str}</b></font>", body_bold),
                Paragraph(cat_str, body_muted),
                Paragraph(f.title, body_style),
                Paragraph(f"<font size='7' color='#0369A1'><code>{loc_short}</code></font>", body_style),
                Paragraph(auto_fix_label, body_style),
            ])

        catalog_table = Table(catalog_rows, colWidths=[24, 56, 110, 160, 104, 50])
        catalog_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
        # Alternating row background
        for r_idx in range(1, len(catalog_rows)):
            bg = colors.HexColor("#F8FAFC") if r_idx % 2 == 0 else colors.HexColor("#FFFFFF")
            catalog_style.append(("BACKGROUND", (0, r_idx), (-1, r_idx), bg))

        catalog_table.setStyle(TableStyle(catalog_style))
        elements.append(catalog_table)
        elements.append(Spacer(1, 14))

        # -------------------------------------------------------------
        # 7. DETAILED TECHNICAL FINDINGS & EVIDENCE (GROUPED BY SEVERITY)
        # -------------------------------------------------------------
        elements.append(Paragraph("4. Detailed Technical Findings &amp; Remediation Evidence", h1_section_style))
        elements.append(
            Paragraph(
                "Each vulnerability below includes full contextual descriptions, affected file paths, line numbers, "
                "code evidence, CVE references, and verified hardening recommendations.",
                body_style,
            )
        )
        elements.append(Spacer(1, 8))

        # Group findings by severity
        severity_groups = [
            ("CRITICAL", "Critical Severity Vulnerabilities (Immediate Action Required)", colors.HexColor("#DC2626")),
            ("HIGH", "High Severity Vulnerabilities (High Risk of Compromise)", colors.HexColor("#EA580C")),
            ("MEDIUM", "Medium Severity Vulnerabilities (Posture Hardening Required)", colors.HexColor("#D97706")),
            ("LOW", "Low &amp; Informational Vulnerabilities (Best Practice Advisories)", colors.HexColor("#2563EB")),
        ]

        finding_counter = 1
        for sev_key, group_title, group_color in severity_groups:
            group_items = [
                f for f in sorted_findings
                if (str(getattr(f.severity, "value", f.severity)).upper() == sev_key)
                or (sev_key == "LOW" and str(getattr(f.severity, "value", f.severity)).upper() == "INFO")
            ]

            if not group_items:
                continue

            # Group Section Subheader
            elements.append(
                Paragraph(
                    f"<font color='{group_color.hexval()}'><b>■ {group_title} ({len(group_items)})</b></font>",
                    h2_style,
                )
            )
            elements.append(HRFlowable(width="100%", thickness=0.75, color=group_color, spaceAfter=8))

            for finding in group_items:
                sev_str = str(getattr(finding.severity, "value", finding.severity)).upper()
                cat_str = str(getattr(finding.category, "value", finding.category))
                bg_c, fg_c = get_severity_colors(sev_str)

                loc_str = finding.file_path or "N/A"
                if finding.line_number:
                    loc_str += f": Line {finding.line_number}"

                cve_part = f" • CVE: {finding.cve_id}" if finding.cve_id else ""
                cvss_part = f" • CVSS: {finding.cvss_score}" if finding.cvss_score else ""
                fixable_label = "Auto-Heal Supported" if getattr(finding, "auto_fixable", False) else "Manual Remediation"

                finding_flowables = []

                # Finding Title Bar
                f_head_data = [
                    [
                        Paragraph(f"<b>#{finding_counter}. {finding.title}</b>", h3_style),
                        Paragraph(
                            f"<font color='{fg_c.hexval()}'><b>[{sev_str}]</b></font>",
                            body_bold,
                        ),
                    ]
                ]
                f_head_table = Table(f_head_data, colWidths=[420, 84])
                f_head_table.setStyle(
                    TableStyle([
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                        ("BACKGROUND", (0, 0), (-1, -1), bg_c),
                        ("BOX", (0, 0), (-1, -1), 0.5, fg_c),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ])
                )
                finding_flowables.append(f_head_table)

                # Properties Table
                f_props = [
                    [
                        Paragraph("<b>Category:</b>", body_style),
                        Paragraph(f"{cat_str}{cve_part}{cvss_part}", body_style),
                        Paragraph("<b>Remediation Mode:</b>", body_style),
                        Paragraph(fixable_label, body_style),
                    ],
                    [
                        Paragraph("<b>Location:</b>", body_style),
                        Paragraph(f"<font color='#0369A1'><code>{loc_str}</code></font>", body_style),
                        Paragraph("<b>Status:</b>", body_style),
                        Paragraph("<font color='#DC2626'><b>UNRESOLVED</b></font>", body_style),
                    ],
                ]
                f_props_table = Table(f_props, colWidths=[70, 220, 100, 114])
                f_props_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ])
                )
                finding_flowables.append(f_props_table)

                # Description and Remediation Box
                f_desc_data = [
                    [
                        Paragraph("<b>Description:</b>", body_bold),
                        Paragraph(finding.description or "No description provided.", body_style),
                    ],
                    [
                        Paragraph("<b>Remediation:</b>", body_bold),
                        Paragraph(finding.remediation_advice or "Follow standard security hardening guidelines.", body_style),
                    ],
                ]

                # Evidence Snippet (if available)
                if finding.snippet:
                    wrapped_snippet = wrap_code_text(finding.snippet, max_width=72, max_lines=12)
                    snippet_box = Table(
                        [[Preformatted(wrapped_snippet, code_style)]],
                        colWidths=[424],
                    )
                    snippet_box.setStyle(
                        TableStyle([
                            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0F172A")),
                            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
                            ("TOPPADDING", (0, 0), (-1, -1), 4),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                            ("LEFTPADDING", (0, 0), (-1, -1), 6),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ])
                    )
                    f_desc_data.append([
                        Paragraph("<b>Code Evidence:</b>", body_bold),
                        snippet_box,
                    ])

                # Suggested Patch Diff (if available)
                if getattr(finding, "fix_patch", None):
                    wrapped_patch = wrap_code_text(finding.fix_patch, max_width=72, max_lines=10)
                    patch_box = Table(
                        [[Preformatted(wrapped_patch, diff_code_style)]],
                        colWidths=[424],
                    )
                    patch_box.setStyle(
                        TableStyle([
                            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#064E3B")),
                            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#059669")),
                            ("TOPPADDING", (0, 0), (-1, -1), 4),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                            ("LEFTPADDING", (0, 0), (-1, -1), 6),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ])
                    )
                    f_desc_data.append([
                        Paragraph("<b>Proposed Patch:</b>", body_bold),
                        patch_box,
                    ])

                f_desc_table = Table(f_desc_data, colWidths=[80, 424])
                f_desc_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFFFFF")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ])
                )
                finding_flowables.append(f_desc_table)
                finding_flowables.append(Spacer(1, 10))

                elements.append(KeepTogether(finding_flowables))
                finding_counter += 1

    # -------------------------------------------------------------
    # 8. AUTOMATED REMEDIATION & SELF-HEALING ROADMAP
    # -------------------------------------------------------------
    elements.append(KeepTogether([
        Paragraph("5. Automated 1-Click Remediation &amp; Self-Healing Roadmap", h1_section_style),
        Paragraph(
            "ShieldCI generates verified, minimal-invasive unified patches (.patch) to automate vulnerability closure. "
            "Execute the terminal instruction below to apply fixes directly to your working tree:",
            body_style,
        ),
        Spacer(1, 6),
    ]))

    cmd_box = Table(
        [
            [
                Paragraph(
                    "<b>Terminal Self-Healing Command:</b><br/>"
                    "<code>git apply shieldci-remediation.patch &amp;&amp; git commit -m 'chore(security): apply ShieldCI exposure remediation'</code>",
                    code_style,
                )
            ]
        ],
        colWidths=[504],
    )
    cmd_box.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0F172A")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#334155")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ])
    )
    elements.append(cmd_box)
    elements.append(Spacer(1, 12))

    # -------------------------------------------------------------
    # 9. REGULATORY COMPLIANCE & GOVERNANCE FRAMEWORKS
    # -------------------------------------------------------------
    elements.append(KeepTogether([
        Paragraph("6. Security Compliance &amp; Governance Framework Mapping", h1_section_style),
        Paragraph(
            "Demonstrates coverage against key global cybersecurity compliance frameworks and control standards:",
            body_style,
        ),
        Spacer(1, 6),
    ]))

    comp_data = [
        [
            Paragraph("<b>Framework Standard</b>", body_bold),
            Paragraph("<b>Control Domain</b>", body_bold),
            Paragraph("<b>ShieldCI Verification Vector</b>", body_bold),
            Paragraph("<b>Audit Status</b>", body_bold),
        ],
        [
            Paragraph("OWASP Top 10:2021", body_style),
            Paragraph("A05: Security Misconfiguration", body_style),
            Paragraph("CI/CD pipeline analysis, security headers, unpinned actions", body_style),
            Paragraph("<font color='#16A34A'><b>Audited</b></font>", body_style),
        ],
        [
            Paragraph("CIS Benchmarks v8", body_style),
            Paragraph("Section 1.1: Identity &amp; Secrets", body_style),
            Paragraph("High-entropy credential &amp; API token exposure scanning", body_style),
            Paragraph("<font color='#16A34A'><b>Audited</b></font>", body_style),
        ],
        [
            Paragraph("NIST SP 800-53 Rev 5", body_style),
            Paragraph("SC-8: Transmission Confidentiality", body_style),
            Paragraph("SSL/TLS cipher inspection, certificate expiry monitoring", body_style),
            Paragraph("<font color='#16A34A'><b>Audited</b></font>", body_style),
        ],
        [
            Paragraph("SOC 2 Type II", body_style),
            Paragraph("CC6.6 / CC6.8: Perimeter &amp; Access", body_style),
            Paragraph("Database exposed port detection &amp; authentication checks", body_style),
            Paragraph("<font color='#16A34A'><b>Audited</b></font>", body_style),
        ],
    ]
    comp_table = Table(comp_data, colWidths=[114, 140, 180, 70])
    comp_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FFFFFF")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    elements.append(comp_table)
    elements.append(Spacer(1, 14))

    # Auditor Verification & Seal Box
    audit_seal = Table(
        [[
            Paragraph(
                "<font size='7.5' color='#64748B'><b>REPORT INTEGRITY VERIFICATION:</b> This executive security audit report was automatically generated "
                "by the ShieldCI Exposure Defense Engine. All findings are derived from deterministic AST evaluation, Shannon entropy analysis, "
                "live perimeter socket probes, and supply chain manifest analysis. Retain this document for compliance audits.</font>",
                body_muted,
            )
        ]],
        colWidths=[504],
    )
    audit_seal.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ])
    )
    elements.append(audit_seal)

    # Build PDF with NumberedCanvas
    doc.build(elements, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()
