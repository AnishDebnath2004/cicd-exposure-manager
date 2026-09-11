"""
scripts/export_docs_to_word.py
Converts Markdown documentation into professionally styled Microsoft Word (.docx) documents.
Supports headings, bold/italic inline formatting, tables, code blocks, bullet lists, and horizontal rules.
"""

import os
import re
import sys
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def set_cell_background(cell, color_hex: str):
    """Sets cell background color (e.g., '1E3A8A')."""
    shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{color_hex}"/>')
    cell._tc.get_or_add_tcPr().append(shading)


def set_cell_margins(cell, top=120, bottom=120, left=150, right=150):
    """Sets inner padding for a table cell."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)


def add_inline_formatted_text(paragraph, text: str):
    """Parses basic inline bold (**text**), inline code (`code`), and italics (*text*)."""
    tokens = re.split(r'(\*\*.*?\*\*|`.*?`|\*.*?\*)', text)
    for token in tokens:
        if not token:
            continue
        if token.startswith('**') and token.endswith('**') and len(token) >= 4:
            run = paragraph.add_run(token[2:-2])
            run.bold = True
        elif token.startswith('`') and token.endswith('`') and len(token) >= 2:
            run = paragraph.add_run(token[1:-1])
            run.font.name = 'Consolas'
            run.font.size = Pt(9.5)
            run.font.color.rgb = RGBColor(180, 40, 60)
        elif token.startswith('*') and token.endswith('*') and len(token) >= 2:
            run = paragraph.add_run(token[1:-1])
            run.italic = True
        else:
            paragraph.add_run(token)


def markdown_to_docx(md_path: str, docx_path: str, title: str):
    """Converts a single markdown file to a styled .docx document."""
    doc = Document()

    # Set 1-inch margins
    sections = doc.sections
    for s in sections:
        s.top_margin = Inches(1.0)
        s.bottom_margin = Inches(1.0)
        s.left_margin = Inches(1.0)
        s.right_margin = Inches(1.0)

    # Base Normal Style
    style = doc.styles['Normal']
    style.font.name = 'Calibri'
    style.font.size = Pt(11)
    style.font.color.rgb = RGBColor(30, 41, 59)

    with open(md_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    in_code_block = False
    code_lines = []
    in_table = False
    table_lines = []

    def flush_code():
        nonlocal code_lines
        if not code_lines:
            return
        code_text = ''.join(code_lines).rstrip('\n')
        # Add a shaded single-cell table for code block
        tbl = doc.add_table(rows=1, cols=1)
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        tbl.autofit = False
        tbl.columns[0].width = Inches(6.5)

        cell = tbl.cell(0, 0)
        set_cell_background(cell, "F1F5F9")
        set_cell_margins(cell, top=140, bottom=140, left=180, right=180)

        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(4)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.line_spacing = 1.15
        run = p.add_run(code_text)
        run.font.name = 'Consolas'
        run.font.size = Pt(9.5)
        run.font.color.rgb = RGBColor(15, 23, 42)

        doc.add_paragraph()  # Spacing
        code_lines = []

    def flush_table():
        nonlocal table_lines
        if not table_lines:
            return

        # Parse table lines
        parsed_rows = []
        for line in table_lines:
            raw = line.strip()
            if not raw or not raw.startswith('|'):
                continue
            cells = [c.strip() for c in raw.split('|')[1:-1]]
            # Check if divider line (e.g. :--- | :---)
            if all(set(c).issubset({'-', ':', ' '}) for c in cells):
                continue
            parsed_rows.append(cells)

        if parsed_rows:
            num_cols = max(len(r) for r in parsed_rows)
            tbl = doc.add_table(rows=len(parsed_rows), cols=num_cols)
            tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
            tbl.autofit = True

            for r_idx, row_data in enumerate(parsed_rows):
                for c_idx in range(num_cols):
                    cell = tbl.cell(r_idx, c_idx)
                    val = row_data[c_idx] if c_idx < len(row_data) else ""
                    set_cell_margins(cell, top=100, bottom=100, left=120, right=120)

                    p = cell.paragraphs[0]
                    p.paragraph_format.space_before = Pt(2)
                    p.paragraph_format.space_after = Pt(2)

                    if r_idx == 0:
                        set_cell_background(cell, "1E3A8A")  # Navy Blue header
                        run = p.add_run(val)
                        run.bold = True
                        run.font.color.rgb = RGBColor(255, 255, 255)
                    else:
                        bg_color = "F8FAFC" if r_idx % 2 == 1 else "FFFFFF"
                        set_cell_background(cell, bg_color)
                        add_inline_formatted_text(p, val)

            doc.add_paragraph()  # Spacing

        table_lines = []

    for line in lines:
        stripped = line.strip()

        # Handle Code blocks
        if stripped.startswith('```'):
            if in_code_block:
                in_code_block = False
                flush_code()
            else:
                if in_table:
                    in_table = False
                    flush_table()
                in_code_block = True
                code_lines = []
            continue

        if in_code_block:
            code_lines.append(line)
            continue

        # Handle Tables
        if stripped.startswith('|') and stripped.endswith('|'):
            in_table = True
            table_lines.append(line)
            continue
        elif in_table:
            in_table = False
            flush_table()

        # Skip horizontal rules
        if stripped in ('---', '***', '___'):
            continue

        # Headings
        if stripped.startswith('# ') and not stripped.startswith('## '):
            p = doc.add_heading(level=1)
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(6)
            run = p.add_run(stripped[2:].strip())
            run.font.color.rgb = RGBColor(30, 58, 138)  # Deep Blue
            run.bold = True
            continue

        if stripped.startswith('## '):
            p = doc.add_heading(level=2)
            p.paragraph_format.space_before = Pt(12)
            p.paragraph_format.space_after = Pt(4)
            run = p.add_run(stripped[3:].strip())
            run.font.color.rgb = RGBColor(37, 99, 235)  # Blue
            run.bold = True
            continue

        if stripped.startswith('### '):
            p = doc.add_heading(level=3)
            p.paragraph_format.space_before = Pt(8)
            p.paragraph_format.space_after = Pt(2)
            run = p.add_run(stripped[4:].strip())
            run.font.color.rgb = RGBColor(71, 85, 105)  # Slate
            run.bold = True
            continue

        # Bullet List Items
        if stripped.startswith('- ') or stripped.startswith('* '):
            item_text = stripped[2:].strip()
            p = doc.add_paragraph(style='List Bullet')
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after = Pt(2)
            add_inline_formatted_text(p, item_text)
            continue

        # Numbered List Items
        num_match = re.match(r'^(\d+)\.\s+(.*)$', stripped)
        if num_match:
            item_text = num_match.group(2)
            p = doc.add_paragraph(style='List Number')
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after = Pt(2)
            add_inline_formatted_text(p, item_text)
            continue

        # Empty lines
        if not stripped:
            continue

        # Standard Paragraph
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.line_spacing = 1.15
        add_inline_formatted_text(p, stripped)

    if in_code_block:
        flush_code()
    if in_table:
        flush_table()

    doc.save(docx_path)
    print(f"[OK] Generated Word Document: {docx_path}")


def main():
    docs_dir = os.path.join(ROOT_DIR, "docs")
    os.makedirs(docs_dir, exist_ok=True)

    # 1. Generate ARCHITECTURE.docx
    arch_md = os.path.join(docs_dir, "ARCHITECTURE.md")
    arch_docx = os.path.join(docs_dir, "ARCHITECTURE.docx")
    if os.path.isfile(arch_md):
        markdown_to_docx(arch_md, arch_docx, "ShieldCI Architecture & Technical Design")

    # 2. Generate README.docx
    readme_md = os.path.join(ROOT_DIR, "README.md")
    readme_docx = os.path.join(docs_dir, "README.docx")
    if os.path.isfile(readme_md):
        markdown_to_docx(readme_md, readme_docx, "ShieldCI Platform Overview")

    # 3. Generate API_REFERENCE.docx
    api_md = os.path.join(docs_dir, "API_REFERENCE.md")
    api_docx = os.path.join(docs_dir, "API_REFERENCE.docx")
    if os.path.isfile(api_md):
        markdown_to_docx(api_md, api_docx, "ShieldCI REST API Reference")

    # 4. Generate CLI_REFERENCE.docx
    cli_md = os.path.join(docs_dir, "CLI_REFERENCE.md")
    cli_docx = os.path.join(docs_dir, "CLI_REFERENCE.docx")
    if os.path.isfile(cli_md):
        markdown_to_docx(cli_md, cli_docx, "ShieldCI CLI Reference")

    # 5. Generate SCANNERS.docx
    scanners_md = os.path.join(docs_dir, "SCANNERS.md")
    scanners_docx = os.path.join(docs_dir, "SCANNERS.docx")
    if os.path.isfile(scanners_md):
        markdown_to_docx(scanners_md, scanners_docx, "ShieldCI Scanner Heuristics")

    # 6. Generate DEPLOYMENT.docx
    dep_md = os.path.join(docs_dir, "DEPLOYMENT.md")
    dep_docx = os.path.join(docs_dir, "DEPLOYMENT.docx")
    if os.path.isfile(dep_md):
        markdown_to_docx(dep_md, dep_docx, "ShieldCI Deployment Guide")

    # 7. Generate Master Unified Document: ShieldCI_Complete_Documentation.docx
    master_docx = os.path.join(docs_dir, "ShieldCI_Complete_Documentation.docx")
    print("\nGenerating Master Complete Documentation...")
    master_doc = Document()
    # Apply styling
    for s in master_doc.sections:
        s.top_margin = Inches(1.0)
        s.bottom_margin = Inches(1.0)
        s.left_margin = Inches(1.0)
        s.right_margin = Inches(1.0)

    # Title Page
    p_title = master_doc.add_paragraph()
    p_title.paragraph_format.space_before = Pt(72)
    p_title.paragraph_format.space_after = Pt(12)
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p_title.add_run("ShieldCI")
    r.bold = True
    r.font.size = Pt(36)
    r.font.color.rgb = RGBColor(30, 58, 138)

    p_sub = master_doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub.paragraph_format.space_after = Pt(36)
    r_sub = p_sub.add_run("DevSecOps CI/CD Exposure Manager\nComplete Technical & Architectural Documentation")
    r_sub.font.size = Pt(16)
    r_sub.font.color.rgb = RGBColor(71, 85, 105)

    master_doc.add_page_break()

    # Iterate and append all docs
    md_files = [
        ("README.md", os.path.join(ROOT_DIR, "README.md")),
        ("Architecture", arch_md),
        ("REST API Reference", api_md),
        ("CLI & CI/CD Guide", cli_md),
        ("Scanner Heuristics", scanners_md),
        ("Deployment Guide", dep_md)
    ]

    for section_title, fpath in md_files:
        if not os.path.isfile(fpath):
            continue
        p_sec = master_doc.add_heading(level=1)
        p_sec.paragraph_format.space_before = Pt(24)
        p_sec.paragraph_format.space_after = Pt(8)
        r_sec = p_sec.add_run(f"=== {section_title} ===")
        r_sec.font.color.rgb = RGBColor(30, 58, 138)

        with open(fpath, 'r', encoding='utf-8') as f:
            for l in f:
                s = l.strip()
                if not s or s.startswith('# ') or s in ('---', '***'):
                    continue
                if s.startswith('## '):
                    h = master_doc.add_heading(level=2)
                    h.add_run(s[3:].strip())
                elif s.startswith('### '):
                    h = master_doc.add_heading(level=3)
                    h.add_run(s[4:].strip())
                elif s.startswith('- ') or s.startswith('* '):
                    p = master_doc.add_paragraph(style='List Bullet')
                    add_inline_formatted_text(p, s[2:].strip())
                else:
                    p = master_doc.add_paragraph()
                    add_inline_formatted_text(p, s)

        master_doc.add_page_break()

    master_doc.save(master_docx)
    print(f"[OK] Master Documentation generated: {master_docx}")


if __name__ == "__main__":
    main()
