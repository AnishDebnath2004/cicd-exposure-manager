"""
app/core/pdf_exporter.py
Generates executive-grade, professional PDF audit reports for ShieldCI scans.
Includes executive summary, Posture Exposure Score (PES), Tri-Vector exposure breakdown,
toxic attack paths, detailed findings with remediation steps, and compliance mapping.
"""

import io
import sys
import types
from datetime import datetime
from typing import List, Optional

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
                "ShieldCI Security Audit Report — Confidential",
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
            "ShieldCI v2.0 • Tri-Vector Exposure Defense Platform • Strictly Confidential",
        )

        # Right footer: Page numbers
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * 72 - 54, 36, page_str)
        self.restoreState()


def get_severity_colors(severity_str: str):
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


def generate_pdf_report(scan: ScanResult) -> bytes:
    """
    Renders a complete, professional PDF security audit report for the provided ScanResult.
    Returns bytes of the PDF file.
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
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=4,
    )

    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
        spaceAfter=14,
    )

    h2_style = ParagraphStyle(
        "SectionH2",
        parent=base_styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=12,
        spaceAfter=6,
    )

    h3_style = ParagraphStyle(
        "SectionH3",
        parent=base_styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor("#334155"),
        spaceBefore=6,
        spaceAfter=3,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )

    body_bold = ParagraphStyle(
        "ReportBodyBold",
        parent=body_style,
        fontName="Helvetica-Bold",
    )

    code_style = ParagraphStyle(
        "ReportCode",
        parent=base_styles["Code"],
        fontName="Courier",
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor("#0F172A"),
    )

    elements = []

    # -------------------------------------------------------------
    # 1. HEADER BANNER
    # -------------------------------------------------------------
    header_data = [
        [
            Paragraph("<b>SHIELDCI SECURITY AUDIT REPORT</b>", title_style),
            Paragraph(
                f"<font size='8' color='#64748B'><b>SCAN ID:</b> {scan.scan_id[:16]}...<br/>"
                f"<b>GENERATED:</b> {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</font>",
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
            "Universal Tri-Vector Posture Defense • Code & CI/CD • Web Perimeter • Cloud Databases",
            subtitle_style,
        )
    )
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#4F46E5"), spaceAfter=12))

    # -------------------------------------------------------------
    # 2. TARGET ASSET & AUDIT METADATA
    # -------------------------------------------------------------
    target_type_label = (
        scan.target_type.value.upper()
        if hasattr(scan.target_type, "value")
        else str(scan.target_type).upper()
    )
    scan_time_str = scan.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.timestamp else "N/A"

    meta_data = [
        [
            Paragraph("<b>Target Asset:</b>", body_style),
            Paragraph(scan.repo_name or scan.target_path or "Target", body_bold),
            Paragraph("<b>Asset Category:</b>", body_style),
            Paragraph(target_type_label, body_bold),
        ],
        [
            Paragraph("<b>Target Location:</b>", body_style),
            Paragraph(scan.repo_url or scan.target_path or "N/A", body_style),
            Paragraph("<b>Scan Timestamp:</b>", body_style),
            Paragraph(scan_time_str, body_style),
        ],
        [
            Paragraph("<b>Scan Duration:</b>", body_style),
            Paragraph(f"{scan.summary.scan_duration_seconds:.2f} seconds", body_style),
            Paragraph("<b>Files / Endpoints:</b>", body_style),
            Paragraph(f"{scan.summary.scanned_files_count} evaluated", body_style),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[95, 170, 95, 144])
    meta_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#EDF2F7")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    elements.append(meta_table)
    elements.append(Spacer(1, 12))

    # -------------------------------------------------------------
    # 3. EXECUTIVE SUMMARY & POSTURE EXPOSURE SCORE (PES)
    # -------------------------------------------------------------
    elements.append(Paragraph("Executive Summary & Risk Posture", h2_style))

    pes = scan.summary.pipeline_exposure_score
    grade = scan.summary.risk_grade or "N/A"
    passed = scan.summary.policy_passed

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

    exec_cards = [
        [
            Paragraph(
                f"<font size='8' color='#64748B'>PIPELINE EXPOSURE SCORE</font><br/>"
                f"<font size='22' color='{pes_color_fg.hexval()}'><b>{pes:.1f}</b></font><font size='11' color='#64748B'> / 100</font><br/>"
                f"<font size='8' color='{pes_color_fg.hexval()}'><b>{pes_status}</b></font>",
                body_style,
            ),
            Paragraph(
                f"<font size='8' color='#64748B'>POSTURE GRADE</font><br/>"
                f"<font size='22' color='#0F172A'><b>Grade {grade}</b></font><br/>"
                f"<font size='8' color='#64748B'>Universal Benchmark</font>",
                body_style,
            ),
            Paragraph(
                f"<font size='8' color='#64748B'>CI/CD QUALITY GATE</font><br/>"
                f"<font size='20' color='{gate_fg.hexval()}'><b>{gate_text}</b></font><br/>"
                f"<font size='8' color='#64748B'>{'Policy compliant' if passed else 'Production deployment blocked'}</font>",
                body_style,
            ),
        ]
    ]
    exec_table = Table(exec_cards, colWidths=[174, 150, 180])
    exec_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), pes_color_bg),
            ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#F1F5F9")),
            ("BACKGROUND", (2, 0), (2, 0), gate_bg),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ])
    )
    elements.append(exec_table)
    elements.append(Spacer(1, 10))

    # Findings Distribution Breakdown
    s = scan.summary
    breakdown_data = [
        [
            Paragraph("<b>Finding Severity Breakdown:</b>", body_style),
            Paragraph(f"<font color='#DC2626'><b>Critical:</b> {s.critical_count}</font>", body_style),
            Paragraph(f"<font color='#EA580C'><b>High:</b> {s.high_count}</font>", body_style),
            Paragraph(f"<font color='#D97706'><b>Medium:</b> {s.medium_count}</font>", body_style),
            Paragraph(f"<font color='#2563EB'><b>Low:</b> {s.low_count}</font>", body_style),
            Paragraph(f"<font color='#64748B'><b>Total:</b> {s.total_findings}</font>", body_bold),
        ]
    ]
    breakdown_table = Table(breakdown_data, colWidths=[154, 70, 70, 70, 70, 70])
    breakdown_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    elements.append(breakdown_table)
    elements.append(Spacer(1, 14))

    # -------------------------------------------------------------
    # 4. TRI-VECTOR EXPOSURE MATRIX
    # -------------------------------------------------------------
    elements.append(Paragraph("Tri-Vector Defense Posture Summary", h2_style))
    tri_desc = (
        "ShieldCI conducts automated tri-vector correlation to detect chained vulnerabilities "
        "spanning source code, internet-facing perimeters, and internal datastores."
    )
    elements.append(Paragraph(tri_desc, body_style))
    elements.append(Spacer(1, 6))

    repo_findings = [f for f in scan.findings if "Web" not in str(f.category) and "Database" not in str(f.category)]
    web_findings = [f for f in scan.findings if "Web" in str(f.category)]
    db_findings = [f for f in scan.findings if "Database" in str(f.category)]

    tri_matrix_data = [
        [
            Paragraph("<b>Defense Vector</b>", body_bold),
            Paragraph("<b>Target Domain</b>", body_bold),
            Paragraph("<b>Findings Detected</b>", body_bold),
            Paragraph("<b>Status Assessment</b>", body_bold),
        ],
        [
            Paragraph("Domain 01: Code & CI/CD", body_style),
            Paragraph("GitHub / Workflows / Secrets / IaC", body_style),
            Paragraph(f"{len(repo_findings)} issues", body_style),
            Paragraph(
                "<font color='#16A34A'><b>Protected</b></font>" if len(repo_findings) == 0 else f"<font color='#DC2626'><b>{len(repo_findings)} Risks Identified</b></font>",
                body_style,
            ),
        ],
        [
            Paragraph("Domain 02: Web Perimeter", body_style),
            Paragraph("SSL / Headers / Exposed Endpoints", body_style),
            Paragraph(f"{len(web_findings)} issues", body_style),
            Paragraph(
                "<font color='#16A34A'><b>Protected</b></font>" if len(web_findings) == 0 else f"<font color='#EA580C'><b>{len(web_findings)} Exposures Found</b></font>",
                body_style,
            ),
        ],
        [
            Paragraph("Domain 03: DB & Cloud", body_style),
            Paragraph("Postgres / MySQL / Redis / Mongo", body_style),
            Paragraph(f"{len(db_findings)} issues", body_style),
            Paragraph(
                "<font color='#16A34A'><b>Protected</b></font>" if len(db_findings) == 0 else f"<font color='#DC2626'><b>{len(db_findings)} Data Risks Found</b></font>",
                body_style,
            ),
        ],
    ]
    tri_table = Table(tri_matrix_data, colWidths=[130, 174, 95, 105])
    tri_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FFFFFF")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    elements.append(tri_table)
    elements.append(Spacer(1, 14))

    # -------------------------------------------------------------
    # 5. TOXIC ATTACK PATHS (if any)
    # -------------------------------------------------------------
    if scan.toxic_combinations:
        elements.append(Paragraph("Cross-Vector Toxic Combinations & Exploit Chains", h2_style))
        elements.append(
            Paragraph(
                "The following compound attack paths correlate individually low-severity exposures into high-impact exploit chains:",
                body_style,
            )
        )
        elements.append(Spacer(1, 6))

        for tc in scan.toxic_combinations:
            tc_chain_str = " &rarr; ".join(tc.exploit_chain)
            tc_data = [
                [
                    Paragraph(f"<b>[TOXIC CHAIN] {tc.title}</b>", body_bold),
                    Paragraph(f"<font color='#991B1B'><b>Likelihood: {tc.likelihood}</b></font>", body_style),
                ],
                [
                    Paragraph(f"<b>Attack Flow:</b> {tc_chain_str}", body_style),
                    Paragraph(f"<b>Impact:</b> {tc.impact}", body_style),
                ],
                [
                    Paragraph(f"<b>Fix Advice:</b> {tc.remediation_advice}", body_style),
                    Paragraph("<b>Auto-Heal:</b> Supported", body_style),
                ],
            ]
            tc_table = Table(tc_data, colWidths=[330, 174])
            tc_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF2F2")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#FCA5A5")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#FEE2E2")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            )
            elements.append(tc_table)
            elements.append(Spacer(1, 8))
        elements.append(Spacer(1, 6))

    # -------------------------------------------------------------
    # 6. DETAILED FINDINGS BREAKDOWN
    # -------------------------------------------------------------
    elements.append(Paragraph("Detailed Security Findings & Vulnerability Evidence", h2_style))

    if not scan.findings:
        no_findings_box = Table(
            [[
                Paragraph(
                    "<font color='#166534'><b>✓ Zero Security Vulnerabilities Detected!</b><br/>"
                    "The target successfully satisfied all inspected posture rules across code, perimeter, and database vectors.</font>",
                    body_style,
                )
            ]],
            colWidths=[504],
        )
        no_findings_box.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#DCFCE7")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#86EFAC")),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ])
        )
        elements.append(no_findings_box)
        elements.append(Spacer(1, 14))
    else:
        for idx, finding in enumerate(scan.findings, start=1):
            sev_str = (
                finding.severity.value
                if hasattr(finding.severity, "value")
                else str(finding.severity)
            )
            cat_str = (
                finding.category.value
                if hasattr(finding.category, "value")
                else str(finding.category)
            )
            bg_c, fg_c = get_severity_colors(sev_str)

            loc_str = finding.file_path or "N/A"
            if finding.line_number:
                loc_str += f": Line {finding.line_number}"

            cve_part = f" • CVE: {finding.cve_id}" if finding.cve_id else ""
            cvss_part = f" • CVSS: {finding.cvss_score}" if finding.cvss_score else ""

            finding_flowables = []

            # Finding Header Table
            f_head_data = [
                [
                    Paragraph(f"<b>#{idx}. {finding.title}</b>", h3_style),
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
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ])
            )
            finding_flowables.append(f_head_table)

            # Finding Details Block
            f_body_data = [
                [
                    Paragraph("<b>Category:</b>", body_style),
                    Paragraph(f"{cat_str}{cve_part}{cvss_part}", body_style),
                ],
                [
                    Paragraph("<b>Location:</b>", body_style),
                    Paragraph(f"<font color='#0369A1'><code>{loc_str}</code></font>", body_style),
                ],
                [
                    Paragraph("<b>Description:</b>", body_style),
                    Paragraph(finding.description or "No description provided.", body_style),
                ],
                [
                    Paragraph("<b>Remediation:</b>", body_style),
                    Paragraph(finding.remediation_advice or "Follow standard hardening guidelines.", body_style),
                ],
            ]

            # Snippet if available
            if finding.snippet:
                snippet_safe = finding.snippet.strip().replace("<", "&lt;").replace(">", "&gt;")[:400]
                f_body_data.append([
                    Paragraph("<b>Evidence:</b>", body_style),
                    Paragraph(f"<code>{snippet_safe}</code>", code_style),
                ])

            f_table = Table(f_body_data, colWidths=[80, 424])
            f_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            )
            finding_flowables.append(f_table)
            finding_flowables.append(Spacer(1, 10))

            elements.append(KeepTogether(finding_flowables))

    # -------------------------------------------------------------
    # 7. 1-CLICK SELF-HEALING & AUTOMATED REMEDIATION
    # -------------------------------------------------------------
    elements.append(Paragraph("Automated Self-Healing & Remediation Options", h2_style))
    remed_text = (
        "ShieldCI provides 1-click automated self-healing patches to eliminate manual remediation toil. "
        "For repository scans, download the unified git patch (.patch) and apply with a single command:"
    )
    elements.append(Paragraph(remed_text, body_style))
    elements.append(Spacer(1, 6))

    cmd_box = Table(
        [
            [
                Paragraph(
                    "<b>Terminal Command:</b><br/>"
                    "<code>git apply shieldci-remediation.patch &amp;&amp; git commit -m 'chore: apply ShieldCI security hardening'</code>",
                    code_style,
                )
            ]
        ],
        colWidths=[504],
    )
    cmd_box.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0F172A")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#38BDF8")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#1E293B")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ])
    )
    elements.append(cmd_box)
    elements.append(Spacer(1, 14))

    # -------------------------------------------------------------
    # 8. COMPLIANCE & GOVERNANCE FRAMEWORKS
    # -------------------------------------------------------------
    elements.append(Paragraph("Security Compliance Framework Mapping", h2_style))
    comp_data = [
        [
            Paragraph("<b>Framework Standard</b>", body_bold),
            Paragraph("<b>Control Domain</b>", body_bold),
            Paragraph("<b>ShieldCI Verification Vector</b>", body_bold),
        ],
        [
            Paragraph("OWASP Top 10:2021", body_style),
            Paragraph("A05: Security Misconfiguration", body_style),
            Paragraph("CI/CD pipeline analysis, security headers, unpinned actions", body_style),
        ],
        [
            Paragraph("CIS Benchmarks", body_style),
            Paragraph("Section 1.1: Identity & Secrets Management", body_style),
            Paragraph("High-entropy credential & API token exposure scanning", body_style),
        ],
        [
            Paragraph("NIST SP 800-53 Rev 5", body_style),
            Paragraph("SC-8: Transmission Confidentiality", body_style),
            Paragraph("SSL/TLS cipher inspection, certificate expiry monitoring", body_style),
        ],
        [
            Paragraph("SOC 2 Type II", body_style),
            Paragraph("CC6.6 / CC6.8: Perimeter & Access Defense", body_style),
            Paragraph("Database exposed port detection & authentication checks", body_style),
        ],
    ]
    comp_table = Table(comp_data, colWidths=[124, 150, 230])
    comp_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FFFFFF")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    elements.append(comp_table)
    elements.append(Spacer(1, 14))

    # Build PDF with NumberedCanvas
    doc.build(elements, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()
