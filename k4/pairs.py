"""
Pair-based (digraphic) ciphers on a grid: K4 written in rows of width w, letters
enciphered two at a time as VERTICAL pairs (a letter and the one w places later).

Why: the ciphertext has 11 repeated letter-pairs at spacing 21 (about 1 in 1,400 for
that spacing; NSA also noted "a slight interval 7 property"). A cipher that works on
one letter at a time with a non-repeating key does not do that; a cipher on pairs does.

  fingerprint  for every width and block alignment, count repeated cipher pairs among
               the pairs the layout actually forms, against shuffles of the same text
  generic      any pair-for-pair substitution (unknown square or table): the same plain
               pair must give the same cipher pair, and the reverse
  slidefair    pairs looked up on the Vigenere / KRYPTOS table with one key letter per
               pair (the ACA "Slidefair": first letter moves +k, second moves -k, read
               straight or crossed). For a pair whose two letters are both clue letters
               the key cancels, so the test needs no key at all; then the key letters
               implied by every clue letter are tested for a repeat.

Run:  python pairs.py [control]
"""
from __future__ import annotations

import random
import sys
from collections import Counter

from kryptos import CIPHERTEXT
from frontier import CRIB, N, ALPHAS

KNOWN = dict(CRIB)


def layout(w, o):
    """Vertical pairs (top, bottom) for rows of width w, two-row blocks starting o letters in."""
    return [(i, i + w) for i in range(N - w) if (i + o) % (2 * w) < w]


def repeats(ct, pairs):
    c = Counter((ct[a], ct[b]) for a, b in pairs)
    return sum(v - 1 for v in c.values() if v > 1)


def run_fingerprint(ct=CIPHERTEXT, shuffles=2000, quiet=False):
    rng = random.Random(11)
    rows = []
    for w in range(1, 49):
        lays = {tuple(layout(w, o)) for o in range(2 * w)}
        lays = [l for l in lays if len(l) >= 20]
        if not lays:
            continue
        real = max(repeats(ct, l) for l in lays)
        null = []
        for _ in range(shuffles):
            s = list(ct)
            rng.shuffle(s)
            null.append(max(repeats(s, l) for l in lays))
        p = sum(x >= real for x in null) / shuffles
        rows.append((p, w, real, len(lays), max(len(l) for l in lays)))
    rows.sort()
    if not quiet:
        print("\n=== fingerprint: repeated cipher pairs when K4 is paired vertically in rows of width w ===")
        print("  (best block alignment per width; p = share of shuffled texts doing as well, same search)")
        for p, w, real, nl, np_ in rows[:8]:
            print(f"    width {w:2d}: {real:2d} repeats among about {np_} pairs   p = {p:.4f}")
        print(f"  widths tested: {len(rows)}; with that many, the smallest p expected by luck is about {1 / len(rows):.3f}")
    return rows


def _both_known(pairs):
    return [(a, b) for a, b in pairs if a in KNOWN and b in KNOWN]


def run_generic(ct=CIPHERTEXT, quiet=False):
    """Any pair substitution: equal plain pairs <=> equal cipher pairs, on the fully known pairs."""
    worst, tested, most = [], 0, 0
    for w in range(1, 49):
        for o in range(2 * w):
            kp = _both_known(layout(w, o))
            most = max(most, len(kp))
            if len(kp) < 2:
                continue
            tested += 1
            f, g, ok = {}, {}, True
            for a, b in kp:
                P, C = (KNOWN[a], KNOWN[b]), (ct[a], ct[b])
                if f.setdefault(P, C) != C or g.setdefault(C, P) != P:
                    ok = False
            if not ok:
                worst.append((w, o))
    if not quiet:
        print("\n=== generic pair substitution (any square or table) ===")
        print(f"  layouts with 2+ fully known pairs: {tested}; ruled out: {len(worst)}"
              f" (widths {sorted({w for w, _ in worst}) or 'none'})")
        print(f"  the clues contain at most {most} fully known pairs in any layout and almost no repeated plain pair,")
        print("  so an arbitrary pair table cannot be confirmed or excluded from 24 letters")
    return worst


def run_slidefair(ct=CIPHERTEXT, quiet=False, flag=5):
    """Key-free test on fully known pairs, then a repeating key over the pairs."""
    hits, best = [], (0, 0, None)
    for w in range(1, 49):
        for o in range(2 * w):
            pairs = layout(w, o)
            kp = _both_known(pairs)
            for pa in "AK":
                for ca in "AK":
                    rp = {ch: i for i, ch in enumerate(ALPHAS[pa])}
                    rc = {ch: i for i, ch in enumerate(ALPHAS[ca])}
                    for cross in (False, True):
                        # straight: c_top from p_top, c_bot from p_bot; crossed: c_top from p_bot, c_bot from p_top
                        def shifts(a, b):
                            pt, pb = (KNOWN.get(b), KNOWN.get(a)) if cross else (KNOWN.get(a), KNOWN.get(b))
                            t = (rc[ct[a]] - rp[pt]) % 26 if pt else None
                            u = (rc[ct[b]] - rp[pb]) % 26 if pb else None
                            return t, u
                        for rel, rname in ((1, "second letter moves the opposite way"), (-1, "both move the same way")):
                            if len(kp) >= 3:
                                vals = []
                                for a, b in kp:
                                    t, u = shifts(a, b)
                                    vals.append((t + rel * u) % 26)
                                cnt = Counter(vals).most_common(1)[0][1]
                                score = (cnt, len(kp))
                                desc = f"width {w} start {o} plain {pa} cipher {ca} {'crossed' if cross else 'straight'}, {rname}"
                                if cnt > best[0] or (cnt == best[0] and len(kp) < best[1]):
                                    best = (cnt, len(kp), desc)
                                if cnt >= flag and cnt >= len(kp) - 1:
                                    hits.append((cnt, len(kp), desc))
                            # repeating key over the pairs (key letter per pair, period L in pair order)
                            keys = []
                            for j, (a, b) in enumerate(pairs):
                                t, u = shifts(a, b)
                                if t is not None:
                                    keys.append((j, t))
                                elif u is not None:
                                    keys.append((j, (rel * -u) % 26 if rel == 1 else u))
                            for L in range(1, 13):
                                slot, eq, ok = {}, 0, True
                                for j, k in keys:
                                    if j % L in slot:
                                        eq += 1
                                        if slot[j % L] != k:
                                            ok = False
                                            break
                                    slot[j % L] = k
                                if ok and eq >= 6:
                                    hits.append((eq, len(keys), f"width {w} start {o} plain {pa} cipher {ca} "
                                                 f"{'crossed' if cross else 'straight'}, {rname}, repeating key of {L} pairs"))
    hits.sort(reverse=True)
    if not quiet:
        print("\n=== Slidefair on vertical pairs (table lookup, one key letter per pair) ===")
        print(f"  best key-free agreement: {best[0]} of {best[1]} fully known pairs  [{best[2]}]")
        for h in hits[:8]:
            print(f"    PASS {h[0]} (of {h[1]})  {h[2]}")
        if not hits:
            print(f"  no layout has {flag}+ pairs agreeing, and no repeating key over the pairs fits (6+ equalities)")
    return hits


def control():
    """Plant a width-7 Slidefair on the KRYPTOS table with a 5-letter key over the pairs."""
    from recipes import _planted_text
    K = ALPHAS["K"]
    pt, w, o, key = _planted_text(), 7, 3, [3, 17, 8, 22, 5]
    ct = list(pt)
    for j, (a, b) in enumerate(layout(w, o)):
        k = key[j % 5]
        ct[a] = K[(K.index(pt[a]) + k) % 26]
        ct[b] = K[(K.index(pt[b]) - k) % 26]
    ct = "".join(ct)
    hits = run_slidefair(ct, quiet=True)
    ok = any("width 7 start 3 plain K cipher K straight, second letter moves the opposite way" in h[2] for h in hits)
    fp = run_fingerprint(ct, shuffles=300, quiet=True)
    print(f"[control pairs] planted width-7 Slidefair recovered: {ok}; its fingerprint rank among widths: "
          f"{[r[1] for r in fp].index(7) + 1} of {len(fp)}")
    return ok


# --- squares: four-square / two-square on a 26-letter rectangle -----------------------------
#
# The classic pair ciphers (Playfair, two-square, four-square) use a 5 x 5 square and so only
# 25 letters; K4 uses all 26. On a 2 x 13 or 13 x 2 rectangle they work unchanged with 26
# letters. Playfair itself is out whatever the rectangle (a letter can never stay itself, and
# position 74 is K -> K), but four-square and two-square are not. With the squares given, the
# cipher has no further key, so every candidate is simply decrypted and compared with the clues.

_SQ_CHECKS = []
_SQ_ALPHAS = []


def _square_layouts(ct):
    """Distinct lists of (cipher top, cipher bottom, wanted top or None, wanted bottom or None)."""
    seen, out = set(), []
    for w in range(1, 49):
        for o in range(2 * w):
            chk = tuple((ord(ct[a]) - 65, ord(ct[b]) - 65, KNOWN.get(a), KNOWN.get(b))
                        for a, b in layout(w, o) if a in KNOWN or b in KNOWN)
            n = sum((x[2] is not None) + (x[3] is not None) for x in chk)
            if n >= 12 and chk not in seen:
                seen.add(chk)
                out.append((w, o, n, chk))
    return out


def _grid(alpha, rows, cols, by_columns):
    """position (r, c) of each letter and the letter at each (r, c)."""
    pos, at = {}, {}
    for i, ch in enumerate(alpha):
        r, c = (i % rows, i // rows) if by_columns else (i // cols, i % cols)
        pos[ch] = (r, c)
        at[(r, c)] = ch
    return pos, at


def _square_task(args):
    i2, shape = args
    rows, cols, bycol = shape
    name2, a2 = _SQ_ALPHAS[i2]
    pos2, _ = _grid(a2, rows, cols, bycol)
    best, hits = (0, None), []
    grids = [(n, _grid(a, rows, cols, bycol)) for n, a in _SQ_ALPHAS]
    plain = [g for g in grids if g[0] in ("A-Z", "KRYPTOS")]
    for name3, (pos3, _) in grids:
        for n1, (_, at1) in plain:
            for n4, (_, at4) in plain:
                # cipher top x is in square 2, cipher bottom y in square 3
                D = {}
                for x in range(26):
                    r, c = pos2[chr(65 + x)]
                    for y in range(26):
                        r2, c2 = pos3[chr(65 + y)]
                        D[(x, y)] = (at1[(r, c2)], at4[(r2, c)])
                for w, o, n, chk in _SQ_CHECKS:
                    good = 0
                    for x, y, w1, w2 in chk:
                        p1, p2 = D[(x, y)]
                        good += (w1 == p1) + (w2 == p2)
                    if good > best[0]:
                        best = (good, (n, w, o, n1, name2, name3, n4, shape))
                    if good >= n - 2:
                        hits.append((good, n, w, o, n1, name2, name3, n4, shape))
    return best, hits


def run_squares(ct=CIPHERTEXT, words=None, procs=30, quiet=False):
    global _SQ_CHECKS, _SQ_ALPHAS
    import multiprocessing as mp
    import time
    from kryptos import ALPHABET, KRYPTOS_KEYED, keyed_alphabet
    import recipes as R
    t0 = time.time()
    words = words or R.THEMED
    alph = {"A-Z": ALPHABET, "KRYPTOS": KRYPTOS_KEYED}
    for wd in words:
        alph.setdefault(wd, keyed_alphabet(wd))
    _SQ_ALPHAS = list(alph.items())
    _SQ_CHECKS = _square_layouts(ct)
    shapes = [(2, 13, False), (13, 2, False), (2, 13, True), (13, 2, True)]
    jobs = [(i, s) for i in range(len(_SQ_ALPHAS)) for s in shapes]
    best, hits = (0, None), []
    with mp.get_context("fork").Pool(procs) as pool:
        for b, h in pool.imap_unordered(_square_task, jobs, chunksize=2):
            hits += h
            if b[0] > best[0]:
                best = b
    hits.sort(reverse=True)
    if not quiet:
        n = len(_SQ_ALPHAS)
        print("\n=== four-square / two-square on a 26-letter rectangle (2 x 13, 13 x 2), vertical pairs ===")
        print(f"  cipher squares from {n} keyword alphabets (pairs: {n * n:,}), plain squares A-Z or KRYPTOS, 4 fillings,"
              f" {len(_SQ_CHECKS)} pair layouts (widths 1-48) = {n * n * 4 * 4 * len(_SQ_CHECKS):,} decryptions ({time.time() - t0:.0f} s)")
        print(f"  best: {best[0]} clue letters right out of {best[1][0] if best[1] else 0} testable  {best[1][1:] if best[1] else ''}")
        for h in hits[:5]:
            print(f"    PASS {h[0]}/{h[1]}  width {h[2]} start {h[3]} squares {h[4:8]} shape {h[8]}")
        if not hits:
            print("  no set of squares reproduces the clues (a solution needs all of them)")
    return best, hits


def squares_control():
    from recipes import _planted_text
    from kryptos import ALPHABET as A, KRYPTOS_KEYED as K, keyed_alphabet
    pt, w, o = _planted_text(), 21, 37
    s1, s2, s3, s4 = A, keyed_alphabet("PALIMPSEST"), keyed_alphabet("ABSCISSA"), K
    g = [_grid(a, 2, 13, False) for a in (s1, s2, s3, s4)]
    ct = list(pt)
    for a, b in layout(w, o):
        (r1, c1), (r2, c2) = g[0][0][pt[a]], g[3][0][pt[b]]
        ct[a], ct[b] = g[1][1][(r1, c2)], g[2][1][(r2, c1)]
    best, hits = run_squares("".join(ct), words=["PALIMPSEST", "ABSCISSA", "SHADOW"], procs=4, quiet=True)
    ok = any(h[0] == h[1] and h[2] == 21 and h[5] == "PALIMPSEST" and h[6] == "ABSCISSA" for h in hits)
    print(f"[control pairs] planted four-square on a 2 x 13 rectangle, vertical pairs 21 apart, recovered: {ok}")
    return ok


if __name__ == "__main__":
    if not control():
        sys.exit("control failed")
    if not squares_control():
        sys.exit("control failed")
    if len(sys.argv) < 2 or sys.argv[1] != "control":
        run_fingerprint()
        run_generic()
        run_slidefair()
        run_squares()
