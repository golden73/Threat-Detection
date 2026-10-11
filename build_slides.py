"""
Build slides.pdf from slides.md (markdown -> HTML -> WeasyPrint).

Usage:
    python build_slides.py slides.md slides.pdf

Splits the markdown on `---` rules into slides and renders each as an
A4-landscape page via WeasyPrint (pinned in requirements.txt).
"""
import sys

import markdown
from weasyprint import HTML

CSS = """
@page { size: A4 landscape; margin: 24px 32px; }
body { font-family: 'DejaVu Sans', sans-serif; font-size: 13pt; color: #1c2733;
       margin: 0; }
.slide { page-break-after: always; padding: 18px 12px; }
.slide:last-of-type { page-break-after: auto; }
h1 { font-size: 26pt; color: #0f5132; border-bottom: 3px solid #0f5132;
     padding-bottom: 6px; margin: 0 0 14px 0; }
h2 { font-size: 17pt; color: #0f5132; margin: 14px 0 8px; }
h4 { margin: 10px 0 4px; }
p, li { line-height: 1.35; }
ul { margin: 4px 0 8px; padding-left: 22px; }
table { border-collapse: collapse; width: 100%; font-size: 11.5pt; margin: 8px 0; }
th, td { border: 1px solid #b9c4cf; padding: 4px 7px; text-align: left; }
th { background: #eef4f1; }
code, pre { font-family: 'DejaVu Sans Mono', monospace; font-size: 10pt;
            background: #f4f6f8; }
pre { padding: 6px; overflow: hidden; }
blockquote { border-left: 4px solid #0f5132; margin: 8px 0; padding: 2px 12px;
             background: #f7faf8; }
strong { color: #0f5132; }
"""


def split_slides(md: str) -> list[str]:
    return [b.strip() for b in md.split("\n---\n") if b.strip()]


def main(src: str, out: str) -> None:
    md = open(src, encoding="utf-8").read()
    html = "".join(
        f'<section class="slide">{markdown.markdown(s, extensions=["tables"])}</section>'
        for s in split_slides(md)
    )
    full = f'<html><head><meta charset="utf-8"><style>{CSS}</style></head><body>{html}</body></html>'
    HTML(string=full).write_pdf(out)
    print(f"saved {out} ({len(split_slides(md))} slides)")


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "slides.md"
    out = sys.argv[2] if len(sys.argv) > 2 else "slides.pdf"
    main(src, out)