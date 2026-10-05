"""
K3 + ? + K4 as ONE block (Sanborn: "two systems of enciphering the bottom text"; his
worksheet holds K3, the question mark and K4 together as 14 lines of 31).

Earlier modules cut K4 out and treat it alone. Here the rest of the bottom plate supplies
K4's key:

  above     the key letter for a K4 cell is the letter a fixed number of rows above it
            (and a fixed number of columns across, plain or mirrored) in the 14 x 31
            grid, from the K3 ciphertext, the K3 plaintext written into the same cells,
            or the half-way text of K3's own two-step transposition
  routes    K3's letters (ciphertext, plaintext, half-way text) read off in the orders
            its own method uses (grids 4, 7, 8, 14, 24, 31, 42, 48, 86 wide; rows,
            columns, both rotations) as a running key from any start, alone and decoded
            by any repeating key first (the key-chain test)

Run:  python block.py
"""
from __future__ import annotations

import time

from kryptos import CIPHERTEXT
from frontier import CRIB_IDX, COMBOS
from sculpture import K3_CT
from solve import K3_PT
import structural
import chain

W, ROWS = 31, 14
S = structural._shift_sets(CIPHERTEXT)
RANKS = {x: {ch: i for i, ch in enumerate(a)} for x, a in structural.ALPHAS.items()}


def _rotate(text, w, clockwise=True):
    rows = -(-len(text) // w)
    cols = range(w) if clockwise else range(w - 1, -1, -1)
    return "".join(text[r * w + c] for c in cols
                   for r in (range(rows - 1, -1, -1) if clockwise else range(rows)) if r * w + c < len(text))


K3_MID = _rotate(K3_CT, 24)                 # K3 after the first of its two rotations
assert _rotate(K3_MID, 8) == K3_PT


def run_above():
    texts = {"K3 ciphertext": K3_CT, "K3 plaintext": K3_PT, "K3 half-way text": K3_MID}
    best, tests = (0, None), 0
    for name, t in texts.items():
        grid = t + "?" + CIPHERTEXT                       # 434 cells, K4 starts at cell 337
        assert len(grid) == W * ROWS
        for mirror in (False, True):
            for dr in range(1, ROWS):
                for dc in range(-30, 31):
                    key = []
                    for i in CRIB_IDX:
                        r, c = divmod(337 + i, W)
                        cell = (r - dr) * W + (W - 1 - c if mirror else c) + dc     # wraps into the next row
                        if not 0 <= cell < 336:
                            break
                        key.append(grid[cell])
                    if len(key) < 24:
                        continue
                    tests += 1
                    cnt, who = structural._best_agreement(S, key, RANKS)
                    if cnt > best[0]:
                        best = (cnt, f"{name}, {dr} rows up, {dc:+d} columns{', mirrored' if mirror else ''}")
    print("\n=== K3 + ? + K4 as one 14 x 31 block: key letter from the cell above ===")
    print(f"  placements: {tests:,} x 16 settings; best agreement {best[0]}/24  [{best[1]}]  (chance: about 9-10)")


def routes():
    out = {}
    for name, t in (("K3 ciphertext", K3_CT), ("K3 plaintext", K3_PT), ("K3 half-way text", K3_MID)):
        for w in (4, 7, 8, 14, 24, 31, 42, 48, 86):
            out[f"{name}, width {w}, by columns"] = "".join(t[c::w] for c in range(w))
            out[f"{name}, width {w}, rotated clockwise"] = _rotate(t, w)
            out[f"{name}, width {w}, rotated anticlockwise"] = _rotate(t, w, False)
    return out


def run_routes():
    srcs = routes()
    t0 = time.time()
    best = (0, None)
    for name, t in srcs.items():
        hits, top = structural.sources_report(max_stride=3, flag=13, quiet=True, only={name: t})
        if top[0] > best[0]:
            best = top
    print("\n=== K3's letters in the orders its own method uses, as K4's key ===")
    print(f"  {len(srcs)} readings, every start, strides 1-3, both directions: best agreement {best[0]}/24"
          f"  [{best[1]}]  ({time.time() - t0:.0f} s)")
    rows = chain.run_level2(srcs=srcs, max_stride=3, quiet=True)
    print(f"  the same readings decoded by ANY repeating key first: {len(rows)} consistent with the clues")
    for eq, q, h, pt in rows[:4]:
        print(f"    {eq} equalities quad={q:.2f} {h[:5]}\n      {pt}")


if __name__ == "__main__":
    run_above()
    run_routes()
