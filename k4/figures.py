"""
Draw the figures used in the README, straight from the project's data.

Static SVG on a light surface (they are embedded as images on GitHub, so there is no
hover layer); two accent colours, validated as a colour-blind-safe pair; all text in
neutral ink.

Run:  python figures.py        writes ../docs/figures/*.svg
"""
from __future__ import annotations

import os
import random
from collections import Counter

from kryptos import CIPHERTEXT
from frontier import CRIB

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "figures")
SURFACE, INK, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e3e2dc"
BLUE, ORANGE, NEUTRAL = "#2a78d6", "#eb6834", "#c9c8c1"
FONT = "font-family=\"ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif\""
MONO = "font-family=\"ui-monospace, SFMono-Regular, Menlo, Consolas, monospace\""
KNOWN = dict(CRIB)
N = 97


def _svg(w, h, body, title):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" '
            f'aria-label="{title}">\n<rect width="{w}" height="{h}" fill="{SURFACE}"/>\n' + "\n".join(body) + "\n</svg>\n")


def _text(x, y, s, size=12, fill=INK, anchor="start", weight="400", font=FONT):
    return f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" text-anchor="{anchor}" font-weight="{weight}" {font}>{s}</text>'


def _crib_colour(i):
    return BLUE if 21 <= i <= 33 else ORANGE


def layout():
    """K4 as it sits on the copper: 4 letters, then three rows of 31."""
    cell, x0, y0 = 26, 40, 70
    b = [_text(20, 28, "K4 as carved: 97 letters, with the two confirmed clue words", 16, weight="600"),
         _text(20, 48, "Cipher letter above, confirmed plaintext letter below. Row numbers are the position of the first letter.", 12, MUTED)]
    for i, ch in enumerate(CIPHERTEXT):
        g = i + 27                                   # K4 starts at column 27 of a 31-wide row
        r, c = divmod(g, 31)
        x, y = x0 + c * cell, y0 + r * 58
        if i in KNOWN:
            b.append(f'<rect x="{x}" y="{y}" width="{cell - 2}" height="46" rx="3" fill="{_crib_colour(i)}" fill-opacity="0.16" '
                     f'stroke="{_crib_colour(i)}" stroke-width="1.5"/>')
            b.append(_text(x + cell / 2 - 1, y + 39, KNOWN[i], 13, INK, "middle", "700", MONO))
        else:
            b.append(f'<rect x="{x}" y="{y}" width="{cell - 2}" height="24" rx="3" fill="none" stroke="{GRID}"/>')
        b.append(_text(x + cell / 2 - 1, y + 17, ch, 14, INK, "middle", "500", MONO))
    for r, first in enumerate((1, 5, 36, 67)):
        b.append(_text(x0 - 8, y0 + r * 58 + 17, str(first), 11, MUTED, "end"))
    ly = y0 + 4 * 58 + 8
    for x, col, label in ((x0, BLUE, "EASTNORTHEAST, positions 22-34"), (x0 + 270, ORANGE, "BERLINCLOCK, positions 64-74")):
        b.append(f'<rect x="{x}" y="{ly}" width="14" height="14" rx="3" fill="{col}" fill-opacity="0.16" stroke="{col}" stroke-width="1.5"/>')
        b.append(_text(x + 22, ly + 12, label, 12, MUTED))
    return _svg(x0 + 31 * cell + 20, ly + 34, b, "K4 ciphertext layout with the clue words")


def doubles():
    """K4 in rows of 7: the doubled letters line up."""
    cell, x0, y0 = 30, 70, 78
    dbl = {i for i in range(N - 1) if CIPHERTEXT[i] == CIPHERTEXT[i + 1]}
    dbl |= {i + 1 for i in dbl}
    b = [_text(20, 28, "K4 written in rows of 7: five of the six doubled letters start in column 5", 16, weight="600"),
         _text(20, 48, "QQ, ZZ and TT sit exactly 21 letters apart. Where the plaintext is known it is not doubled: NO, ST, IN.", 12, MUTED)]
    for c in range(7):
        b.append(_text(x0 + c * cell + cell / 2 - 1, y0 - 8, str(c + 1), 11, MUTED, "middle"))
    for i, ch in enumerate(CIPHERTEXT):
        r, c = divmod(i, 7)
        x, y = x0 + c * cell, y0 + r * 28
        if i in dbl:
            b.append(f'<rect x="{x}" y="{y}" width="{cell - 2}" height="24" rx="3" fill="{ORANGE}" fill-opacity="0.2" stroke="{ORANGE}" stroke-width="1.5"/>')
        else:
            b.append(f'<rect x="{x}" y="{y}" width="{cell - 2}" height="24" rx="3" fill="none" stroke="{GRID}"/>')
        b.append(_text(x + cell / 2 - 1, y + 17, ch, 14, INK, "middle", "700" if i in dbl else "500", MONO))
        if c == 0:
            b.append(_text(x0 - 8, y + 17, str(i + 1), 11, MUTED, "end"))
    notes = {3: "BB", 4: "QQ  plaintext NO", 5: "SS  plaintext ST", 7: "SS (column 1), ZZ", 10: "TT  plaintext IN"}
    for r, s in notes.items():
        b.append(_text(x0 + 7 * cell + 14, y0 + (r - 1) * 28 + 17, s, 12, MUTED))
    return _svg(560, y0 + 14 * 28 + 16, b, "K4 in rows of seven with doubled letters highlighted")


def _repeats(ct, d):
    c = Counter((ct[i], ct[i + d]) for i in range(len(ct) - d))
    return sum(v - 1 for v in c.values() if v > 1)


def pair_repeats():
    """Repeated letter pairs by spacing, against shuffles."""
    rng = random.Random(1)
    real = [_repeats(CIPHERTEXT, d) for d in range(1, 49)]
    sh = {d: [] for d in range(1, 49)}
    for _ in range(2000):
        s = list(CIPHERTEXT)
        rng.shuffle(s)
        for d in sh:
            sh[d].append(_repeats(s, d))
    p99 = [sorted(sh[d])[int(0.99 * 2000)] for d in range(1, 49)]
    med = [sorted(sh[d])[1000] for d in range(1, 49)]
    w, h, x0, y0, pw, ph = 860, 330, 56, 70, 780, 200
    bw, top = pw / 48, 12
    Y = lambda v: y0 + ph - v / top * ph
    b = [_text(20, 28, "Repeated letter pairs in K4 by spacing", 16, weight="600"),
         _text(20, 48, "Pairs of letters the same distance apart that occur more than once. Line: level reached by 1 in 100 shuffles of the same letters.", 12, MUTED)]
    for v in range(0, top + 1, 4):
        b.append(f'<line x1="{x0}" x2="{x0 + pw}" y1="{Y(v)}" y2="{Y(v)}" stroke="{GRID}"/>')
        b.append(_text(x0 - 8, Y(v) + 4, str(v), 11, MUTED, "end"))
    for k, v in enumerate(real):
        d = k + 1
        x = x0 + k * bw + 1
        col = ORANGE if d == 21 else (BLUE if d % 7 == 0 else NEUTRAL)
        if v:
            b.append(f'<path d="M{x},{Y(0)} V{Y(v) + 3} q0,-3 3,-3 h{bw - 8} q3,0 3,3 V{Y(0)} Z" fill="{col}"/>')
        if d == 1 or d % 7 == 0:
            b.append(_text(x + (bw - 2) / 2, Y(0) + 16, str(d), 11, MUTED, "middle"))
    pts = " ".join(f"{x0 + k * bw + bw / 2:.1f},{Y(v):.1f}" for k, v in enumerate(p99))
    b.append(f'<polyline points="{pts}" fill="none" stroke="{INK}" stroke-width="1.5" stroke-dasharray="4 3"/>')
    b.append(_text(x0 + pw, Y(p99[-1]) - 8, "1-in-100 level", 11, MUTED, "end"))
    x21 = x0 + 20 * bw + bw / 2
    b.append(_text(x21, Y(real[20]) - 8, "spacing 21: 11 repeats", 12, INK, "middle", "600"))
    b.append(_text(x0 + pw / 2, Y(0) + 36, "spacing between the two letters (multiples of 7 in blue, 21 in orange)", 12, MUTED, "middle"))
    b.append(_text(16, y0 + ph / 2, "repeats", 12, MUTED, "middle") .replace("<text ", f'<text transform="rotate(-90 16 {y0 + ph / 2})" '))
    return _svg(w, h, b, "Repeated letter pairs by spacing"), real, p99, med


def clue_letters():
    """Each plaintext letter and the cipher letters it becomes, on an A-Z axis."""
    groups = {}
    for i, P in CRIB:
        groups.setdefault(P, []).append((CIPHERTEXT[i], i + 1))
    order = sorted(groups, key=lambda P: (-len(groups[P]), P))
    x0, y0, cw, rh = 150, 86, 24, 26
    b = [_text(20, 28, "Where each clue letter lands", 16, weight="600"),
         _text(20, 48, "Each row is a plaintext letter; dots mark the cipher letters it becomes. Most stay within five neighbouring letters (band).", 12, MUTED)]
    for c in range(26):
        b.append(_text(x0 + c * cw + cw / 2, y0 - 10, chr(65 + c), 12, MUTED, "middle", font=MONO))
    for r, P in enumerate(order):
        y = y0 + r * rh
        b.append(f'<line x1="{x0}" x2="{x0 + 26 * cw}" y1="{y + rh / 2}" y2="{y + rh / 2}" stroke="{GRID}"/>')
        b.append(_text(x0 - 14, y + rh / 2 + 4, f"plain {P}", 12, INK, "end", "600", MONO))
        vals = sorted(ord(c) - 65 for c, _ in groups[P])
        # tightest window of 5 covering the most cipher letters
        best = max(range(26), key=lambda s: sum(1 for v in vals if (v - s) % 26 < 5))
        inside = [v for v in vals if (v - best) % 26 < 5]
        lo, hi = min(inside), max(inside)
        if len(vals) > 1:
            b.append(f'<rect x="{x0 + lo * cw + 2}" y="{y + 4}" width="{(hi - lo + 1) * cw - 4}" height="{rh - 8}" rx="9" fill="{BLUE}" fill-opacity="0.14"/>')
        for v in vals:
            out = v not in inside
            cx, cy = x0 + v * cw + cw / 2, y + rh / 2
            if out:
                b.append(f'<circle cx="{cx}" cy="{cy}" r="5.5" fill="{SURFACE}" stroke="{ORANGE}" stroke-width="2"/>')
            else:
                b.append(f'<circle cx="{cx}" cy="{cy}" r="5.5" fill="{BLUE}" stroke="{SURFACE}" stroke-width="2"/>')
    ly = y0 + len(order) * rh + 14
    b.append(f'<circle cx="{x0 + 8}" cy="{ly}" r="5.5" fill="{BLUE}"/>')
    b.append(_text(x0 + 20, ly + 4, "within five neighbouring letters", 12, MUTED))
    b.append(f'<circle cx="{x0 + 250}" cy="{ly}" r="5.5" fill="{SURFACE}" stroke="{ORANGE}" stroke-width="2"/>')
    b.append(_text(x0 + 262, ly + 4, "outside: E to Y at 65, and one of the two O's (27 or 72)", 12, MUTED))
    return _svg(x0 + 26 * cw + 30, ly + 22, b, "Cipher letters for each clue letter")


def main():
    os.makedirs(OUT, exist_ok=True)
    pr, real, p99, med = pair_repeats()
    for name, svg in (("k4_layout.svg", layout()), ("doubles_width7.svg", doubles()),
                      ("pair_repeats.svg", pr), ("clue_letters.svg", clue_letters())):
        with open(os.path.join(OUT, name), "w") as fh:
            fh.write(svg)
        print("wrote", name, len(svg), "bytes")
    with open(os.path.join(OUT, "pair_repeats.csv"), "w") as fh:
        fh.write("spacing,repeated_pairs,shuffle_median,shuffle_1_in_100\n")
        for d in range(48):
            fh.write(f"{d + 1},{real[d]},{med[d]},{p99[d]}\n")


if __name__ == "__main__":
    main()
