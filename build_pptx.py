"""
Build slides.pptx from slides.md (markdown -> PowerPoint, python-pptx).

Usage:
    python build_pptx.py slides.md slides.pptx

Renders each `---`-separated slide as a 16:9 slide:
  # heading  -> title band
  ## heading -> bold lead-in inside the body
  - / 1.     -> bulleted list
  tables     -> native pptx tables (right column when body text exists)
  code fence -> monospace box (pipeline diagram)
  > quote    -> italic callout band at the bottom
  **bold**   -> bold runs
"""
import re
import sys
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, MSO_AUTO_SIZE, PP_ALIGN
from pptx.util import Emu, Inches, Pt

DARK = RGBColor(0x0F, 0x51, 0x32)
INK = RGBColor(0x1C, 0x27, 0x33)
GREY = RGBColor(0x88, 0x92, 0x9C)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT = RGBColor(0xEE, 0xF4, 0xF1)
ZEBRA = RGBColor(0xF6, 0xF9, 0xF7)
QUOTE_BG = RGBColor(0xF7, 0xFA, 0xF8)
CODE_BG = RGBColor(0xF4, 0xF6, 0xF8)
FONT = "Calibri"
MONO = "Consolas"

BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
SEP_ROW_RE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$")


def split_slides(md: str) -> list[str]:
    return [b.strip() for b in md.split("\n---\n") if b.strip()]


def add_runs(par, text, size=13, color=INK, bold=False, italic=False, font=FONT):
    """Add text to a paragraph, honouring **bold** markers."""
    pos = 0
    for m in BOLD_RE.finditer(text):
        if m.start() > pos:
            _run(par, text[pos:m.start()], size, color, bold, italic, font)
        _run(par, m.group(1), size, color, True, italic, font)
        pos = m.end()
    if pos < len(text):
        _run(par, text[pos:], size, color, bold, italic, font)


def _run(par, text, size, color, bold, italic, font):
    r = par.add_run()
    r.text = text
    r.font.size = Pt(size)
    r.font.color.rgb = color
    r.font.bold = bold
    r.font.italic = italic
    r.font.name = font
    return r


def parse_table(block):
    rows = []
    for line in block:
        if SEP_ROW_RE.match(line):
            continue
        rows.append([c.strip() for c in line.strip().strip("|").split("|")])
    return rows


def content_kind(line):
    if line.startswith("```"):
        return "fence"
    if re.match(r"^\s*\|", line):
        return "table"
    if re.match(r"^\s*([-*]|\d+[.)])\s+", line):
        return "bullet"
    if line.startswith(">"):
        return "quote"
    if line.startswith("## "):
        return "head"
    if line.strip() == "":
        return "blank"
    return "para"


def strip_bullet(line):
    return re.sub(r"^\s*([-*]|\d+[.)])\s+", "", line)


def blockify(lines):
    """Group lines into typed blocks: ('table', rows), ('bullet', text), ..."""
    blocks = []
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        k = content_kind(line)
        if k == "fence":
            i += 1
            buf = []
            while i < n and not lines[i].startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1  # closing fence
            blocks.append(("code", "\n".join(buf)))
        elif k == "table":
            buf = []
            while i < n and content_kind(lines[i]) == "table":
                buf.append(lines[i])
                i += 1
            blocks.append(("table", parse_table(buf)))
        elif k == "bullet":
            blocks.append(("bullet", strip_bullet(line)))
            i += 1
        elif k == "quote":
            blocks.append(("quote", line.lstrip("> ").strip()))
            i += 1
        elif k == "head":
            blocks.append(("head", line[3:].strip()))
            i += 1
        elif k == "blank":
            i += 1
        else:
            blocks.append(("para", line.strip()))
            i += 1
    return blocks


def add_table(slide, rows, left, top, width, font=10.5):
    n_rows, n_cols = len(rows), max(len(r) for r in rows)
    tbl_h = Inches(0.3 * n_rows + 0.1)
    shape = slide.shapes.add_table(n_rows, n_cols, left, top, width, tbl_h)
    tbl = shape.table
    tbl.first_row = True
    col_w = Emu(int(width / n_cols))
    for c in tbl.columns:
        c.width = col_w
    for ri, row in enumerate(rows):
        for ci in range(n_cols):
            cell = tbl.cell(ri, ci)
            cell.margin_top = Inches(0.02)
            cell.margin_bottom = Inches(0.02)
            cell.margin_left = Inches(0.06)
            cell.margin_right = Inches(0.06)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            par = cell.text_frame.paragraphs[0]
            text = row[ci] if ci < len(row) else ""
            if ri == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = DARK
                add_runs(par, text, size=font, color=WHITE, bold=True)
            else:
                cell.fill.solid()
                cell.fill.fore_color.rgb = ZEBRA if ri % 2 else WHITE
                add_runs(par, text, size=font, color=INK)
    return shape.height


def text_block(slide, blocks, x, y, width, height):
    """Render non-table blocks (heads, paras, bullets) into one textbox."""
    box = slide.shapes.add_textbox(x, y, width, height)
    tf = box.text_frame
    tf.word_wrap = True
    tf.auto_size = MSO_AUTO_SIZE.NONE
    first = True
    for kind, val in blocks:
        if kind == "table":
            continue
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        if kind == "head":
            p.space_before = Pt(8)
            p.space_after = Pt(4)
            add_runs(p, val, size=13, color=DARK, bold=True)
        elif kind == "bullet":
            p.space_after = Pt(5)
            add_runs(p, "•  " + val, size=13, color=INK)
        elif kind == "para":
            p.space_after = Pt(5)
            add_runs(p, val, size=14, color=INK)
        elif kind == "quote":
            p.space_after = Pt(3)
            add_runs(p, val, size=12, color=DARK, italic=True)
    if first:  # nothing was added
        box._element.getparent().remove(box._element)
        return None
    return box


def render_slide(prs, md_slide):
    SW, SH = Inches(13.333), Inches(7.5)
    slide = prs.slides.add_slide(prs.slide_layouts[6])

    lines = md_slide.splitlines()
    title = lines[0][2:].strip() if lines and lines[0].startswith("# ") else ""
    subtitle = lines[1][3:].strip() if len(lines) > 1 and lines[1].startswith("## ") else ""
    body = lines[2:] if subtitle else lines[1:] if title else lines

    # Title band
    if title:
        band = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SW, Inches(1.05))
        band.fill.solid()
        band.fill.fore_color.rgb = DARK
        band.line.fill.background()
        band.shadow.inherit = False
        tf = band.text_frame
        tf.word_wrap = True
        tf.auto_size = MSO_AUTO_SIZE.NONE
        tf.margin_left = Inches(0.5)
        tf.margin_right = Inches(0.4)
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        t_size = 27 if len(title) <= 40 else 23 if len(title) <= 55 else 20
        add_runs(tf.paragraphs[0], title, size=t_size, color=WHITE, bold=True)
        if subtitle:
            p = tf.add_paragraph()
            add_runs(p, subtitle, size=12.5, color=RGBColor(0xCF, 0xE8, 0xD8), italic=True)

    blocks = blockify(body)
    tables = [b for b in blocks if b[0] == "table"]
    codes = [b for b in blocks if b[0] == "code"]
    has_text = any(b[0] in ("head", "para", "bullet") for b in blocks)

    top = Inches(1.3)
    bottom_h = Inches(6.85)

    if codes:  # pipeline diagram slide: centered code box + caption
        cap = [b for b in blocks if b[0] in ("para", "bullet", "head")]
        cb = slide.shapes.add_shape(
            MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.15), Inches(1.5), Inches(11.0), Inches(3.5))
        cb.fill.solid()
        cb.fill.fore_color.rgb = CODE_BG
        cb.line.color.rgb = GREY
        cb.shadow.inherit = False
        ctf = cb.text_frame
        ctf.word_wrap = True
        ctf.auto_size = MSO_AUTO_SIZE.NONE
        ctf.vertical_anchor = MSO_ANCHOR.MIDDLE
        for i, ln in enumerate(codes[0][1].splitlines()):
            p = ctf.paragraphs[0] if i == 0 else ctf.add_paragraph()
            p.alignment = PP_ALIGN.LEFT
            _run(p, ln, size=10, color=INK, bold=False, italic=False, font=MONO)
        if cap:
            text_block(slide, cap, Inches(1.15), Inches(5.2), Inches(11.0), Inches(1.6))
        return

    if tables and has_text:
        text_block(slide, blocks, Inches(0.45), top, Inches(7.0), Inches(5.5))
        ty = top + Inches(0.15)
        for _, rows in [(b[0], b[1]) for b in tables]:
            h = add_table(slide, rows, Inches(7.7), ty, Inches(5.2))
            ty += h + Inches(0.2)
    elif tables:
        ty = top + Inches(0.1)
        for _, rows in [(b[0], b[1]) for b in tables]:
            cols = max(len(r) for r in rows)
            w = Inches(12.3) if cols > 3 else Inches(9.5)
            x = Inches(0.5) if cols > 3 else Inches(1.9)
            h = add_table(slide, rows, x, ty, w)
            ty += h + Inches(0.25)
        # any stray text under tables
        if has_text:
            text_block(slide, blocks, Inches(0.45), ty, Inches(12.3), Inches(7.0) - ty)
    else:
        text_block(slide, blocks, Inches(0.55), top, Inches(12.2), Inches(5.6))


def build(src_md, out):
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    slides = split_slides(Path(src_md).read_text(encoding="utf-8"))
    for s in slides:
        render_slide(prs, s)
    prs.save(out)
    print(f"saved {out} ({len(slides)} slides)")


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "slides.md",
          sys.argv[2] if len(sys.argv) > 2 else "slides.pptx")