"""Writes the fonts the planted-font test (planted-font.ps1, next to this file) installs for the user.

Run: `python -I gen.py <out dir>`. Needs fontTools (tested with 4.66.1). Nothing is downloaded: every
outline is a filled box written here, so a glyph of these files cannot be mistaken for Segoe UI's.

Five files, under family names the toolkit dialog's fonts were found by before TK-1 (the
first entries of mdshared-ui's UI_FAMILY, and a free name asked before the generic family for a
character the Segoe fonts lack): "Segoe UI Variable Text", "Segoe UI" (400 and 600), "Noto Sans", and "Segoe UI Symbol" (the family of the
dialog's third file). Each has
every printable ASCII character, U+26A0, U+2022, U+00B7, U+2026 and U+0430.
"""

import sys
from pathlib import Path

from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen


def box(x0, y0, x1, y1):
    pen = TTGlyphPen(None)
    pen.moveTo((x0, y0))
    pen.lineTo((x0, y1))
    pen.lineTo((x1, y1))
    pen.lineTo((x1, y0))
    pen.closePath()
    return pen.glyph()


def build(path, family, style, weight):
    codes = list(range(0x21, 0x7F)) + [0x26A0, 0x2022, 0xB7, 0x2026, 0x430]
    glyphs = [(".notdef", None, box(0, 0, 900, 900), 1000), ("space", 0x20, TTGlyphPen(None).glyph(), 400)]
    for c in codes:
        # Every character a tall box of its own width: nothing like a letter.
        w = 300 + (c * 41) % 500
        glyphs.append((f"u{c:04X}", c, box(20, -150, 20 + w, 950), w + 40))
    fb = FontBuilder(1000, isTTF=True)
    fb.setupGlyphOrder([g[0] for g in glyphs])
    fb.setupCharacterMap({g[1]: g[0] for g in glyphs if g[1] is not None})
    fb.setupGlyf({g[0]: g[2] for g in glyphs})
    metrics = {}
    for name, _, glyph, advance in glyphs:
        glyph.recalcBounds(fb.font["glyf"])
        metrics[name] = (advance, getattr(glyph, "xMin", 0))
    fb.setupHorizontalMetrics(metrics)
    fb.setupHorizontalHeader(ascent=950, descent=-250)
    fb.setupNameTable(
        {
            "familyName": family,
            "styleName": style,
            "uniqueFontIdentifier": f"{family} {style} purge planted test",
            "fullName": f"{family} {style}",
            "psName": f"{family}-{style}".replace(" ", ""),
            "version": "Version 1.000",
        }
    )
    fb.setupOS2(
        usWeightClass=weight,
        sTypoAscender=950,
        sTypoDescender=-250,
        sTypoLineGap=0,
        usWinAscent=950,
        usWinDescent=250,
        fsSelection=0x40 if weight == 400 else 0x00,
    )
    fb.setupPost()
    fb.font["head"].created = fb.font["head"].modified = 3850329600
    fb.font.recalcTimestamp = False
    fb.save(str(path))


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    build(out / "planted-variable-text.ttf", "Segoe UI Variable Text", "Regular", 400)
    build(out / "planted-segoe-ui.ttf", "Segoe UI", "Regular", 400)
    build(out / "planted-segoe-ui-semibold.ttf", "Segoe UI", "Semibold", 600)
    build(out / "planted-noto-sans.ttf", "Noto Sans", "Regular", 400)
    build(out / "planted-segoe-ui-symbol.ttf", "Segoe UI Symbol", "Regular", 400)


if __name__ == "__main__":
    main()
