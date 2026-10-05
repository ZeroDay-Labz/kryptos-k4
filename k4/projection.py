"""
Light-projection pairing: a ray of sunlight passes through a K4 letter on the cipher
side and lands on (or passes through) some letter of the tableau side. If that
pairing is the key, then for parallel rays and gently curved panels the tableau cell
is an AFFINE function of the K4 cell:

    tableau row    = row + dr + shear * col        (sun elevation)
    tableau column = scale * col + offset          (sun azimuth, curvature, mirroring)

structural.py tested scale = +1 / -1 with no shear. This sweeps scale from -3 to 3,
any offset, any row shift, and a range of shears, on the tableau grid and on the
cipher-side grid itself (light through two parts of the same screen). A placement
scores the number of clue letters whose required key agrees (up to a constant
offset) with the letter the ray lands on; chance gives about 8-11 of 24.

Run:  python projection.py
"""
from __future__ import annotations

import multiprocessing as mp
import time

from kryptos import CIPHERTEXT
from frontier import CRIB_IDX, COMBOS, ALPHAS
from sculpture import CIPHER_ROWS, TABLEAU_ROWS, K4_CELLS
from structural import _shift_sets, _best_agreement

_CTX = mp.get_context("fork")
S = _shift_sets(CIPHERTEXT)
RANKS = {x: {ch: i for i, ch in enumerate(a)} for x, a in ALPHAS.items()}
CELLS = [K4_CELLS[i] for i in CRIB_IDX]
GRIDS = {"tableau": TABLEAU_ROWS, "cipher side": CIPHER_ROWS}
SCALES = [round(-3 + 0.02 * k, 2) for k in range(301) if abs(-3 + 0.02 * k) >= 0.2]
SHEARS = [round(-0.5 + 0.1 * k, 1) for k in range(11)]
FLAG = 14


def _task(args):
    gname, scale = args
    grid = GRIDS[gname]
    best, hits, tests = (0, None), [], 0
    for b4 in range(-160, 281):                    # offset in quarter columns
        off = b4 / 4
        cols = [int(round(scale * c + off)) for _, c in CELLS]
        if min(cols) < -2 or max(cols) > 36:
            continue
        for shear in SHEARS:
            drow = [int(round(shear * c)) for _, c in CELLS]
            for dr in range(-30, 6):
                key = []
                for (r, _), cc, d in zip(CELLS, cols, drow):
                    rr = r + dr + d
                    if not 0 <= rr < len(grid) or not 0 <= cc < len(grid[rr]) or not grid[rr][cc].isalpha():
                        break
                    key.append(grid[rr][cc])
                if len(key) < 24:
                    continue
                tests += 1
                cnt, who = _best_agreement(S, key, RANKS)
                if cnt > best[0]:
                    best = (cnt, (gname, scale, off, shear, dr, who, "".join(key)))
                if cnt >= FLAG:
                    hits.append((cnt, gname, scale, off, shear, dr, who, "".join(key)))
    return tests, best, hits


def run(procs=28):
    t0 = time.time()
    jobs = [(g, s) for g in GRIDS for s in SCALES]
    tests, best, hits = 0, (0, None), []
    with _CTX.Pool(procs) as pool:
        for n, b, h in pool.imap_unordered(_task, jobs):
            tests += n
            hits += h
            if b[0] > best[0]:
                best = b
    print("\n=== light-projection pairing: K4 cell -> tableau / cipher-side cell by an affine map ===")
    print(f"  placements tested: {tests:,} x 16 alphabet/arithmetic settings ({time.time() - t0:.0f} s)")
    print(f"  best agreement: {best[0]}/24  {best[1][:5] if best[1] else ''}")
    for h in sorted(hits, reverse=True)[:8]:
        print(f"  {h[0]}/24  {h[1]} scale={h[2]} offset={h[3]} shear={h[4]} row shift={h[5]}"
              f"  {'/'.join(COMBOS[h[6][0]])} key alphabet {h[6][1]}  key letters {h[7]}")
    if not hits:
        print(f"  nothing reaches {FLAG}/24")
    return best, hits


if __name__ == "__main__":
    run()


# --- any smooth warp (curved screen): order-preserving pairing with the tableau ---------

def _lis(seq):
    """Length of the longest strictly increasing subsequence."""
    import bisect
    tails = []
    for x in seq:
        i = bisect.bisect_left(tails, x)
        if i == len(tails):
            tails.append(x)
        else:
            tails[i] = x
    return len(tails)


def run_warp():
    """A curved screen stretches the projection unevenly, but light cannot reorder letters:
    along one row, letters further right still land further right (or all reversed). Every
    tableau row holds every letter, so for each clue letter the tableau column it would need
    is fixed; ask whether those columns come out in order along the 13 letters of
    EASTNORTHEAST (all on one row of the copper). Random order gives runs of about 5-7."""
    import random
    row = CELLS[0][0]
    assert all(r == row for r, _ in CELLS[:13])
    best, tests = (0, None), 0
    for k, s in enumerate(S):
        for xname, xa in ALPHAS.items():
            for const in range(26):
                need = [xa[(v + const) % 26] for v in s[:13]]         # key letters, up to a constant
                for tr in range(1, 27):                               # tableau row the light lands on
                    body = TABLEAU_ROWS[tr]
                    cols = [body.index(ch, 1) for ch in need]          # first of at most two places
                    cols2 = [body.rindex(ch) for ch in need]
                    for cs in (cols, cols2):
                        for seq in (cs, [-c for c in cs]):
                            tests += 1
                            n = _lis(seq)
                            if n > best[0]:
                                best = (n, ("/".join(COMBOS[k]), xname, const, tr))
    rng = random.Random(3)
    null = sorted(max(_lis(rng.sample(range(30), 13)) for _ in range(tests // 50)) for _ in range(40))
    print("\n=== curved-screen projection: any order-preserving warp onto a tableau row ===")
    print(f"  settings tested: {tests:,}; longest in-order run among the 13 letters of EASTNORTHEAST: {best[0]}"
          f"  {best[1]}")
    print(f"  the same number of random tries gives a best run of about {null[len(null) // 2]}"
          f" (a real pairing needs 13, or 11-12 with slips)")
    return best


if __name__ == "__main__":
    run_warp()


# --- "Code Breaker" overlay (Sanborn sketch IMG_1555): one sheet laid on the other ------------

def run_overlay():
    """Sanborn's sketch shows a sheet labelled "Code Breaker" lying at an angle on a sheet
    labelled "Coded". If the tableau plate (or a copy of the cipher plate) is laid over the
    cipher plate, each K4 letter sits under one letter of the upper sheet. structural.py tried
    the upright and mirrored positions; here the upper sheet may also be upside down, turned a
    quarter turn either way, or flipped, at every offset."""
    best, tests, hits = (0, None), 0, []
    names = ["upright", "mirrored", "upside down", "upside down + mirrored",
             "quarter turn", "quarter turn + mirrored", "three-quarter turn", "three-quarter turn + mirrored"]
    for gname, grid in GRIDS.items():
        R, Wd = len(grid), max(len(r) for r in grid)
        for t in range(8):
            for dr in range(-40, 41):
                for dc in range(-40, 41):
                    key = []
                    for r, c in CELLS:
                        a, b = (r, c) if t < 4 else (c, r)                 # quarter turns swap the axes
                        if t in (1, 3, 5, 7):
                            b = (Wd - 1 if t < 4 else R - 1) - b
                        if t in (2, 3, 6, 7):
                            a = (R - 1 if t < 4 else Wd - 1) - a
                        rr, cc = a + dr, b + dc
                        if not 0 <= rr < R or not 0 <= cc < len(grid[rr]) or not grid[rr][cc].isalpha():
                            break
                        key.append(grid[rr][cc])
                    if len(key) < 24:
                        continue
                    tests += 1
                    cnt, who = _best_agreement(S, key, RANKS)
                    if cnt > best[0]:
                        best = (cnt, f"{gname} sheet {names[t]}, shifted {dr} rows, {dc} columns")
                    if cnt >= 13:
                        hits.append((cnt, gname, names[t], dr, dc))
    print("\n=== overlay: one plate laid on the other in any of 8 orientations ===")
    print(f"  placements where all 24 clue letters are covered: {tests:,} x 16 settings")
    print(f"  best agreement: {best[0]}/24  [{best[1]}]   (chance: about 9-11)")
    return best, hits
